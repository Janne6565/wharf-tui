// Package api is Wharf's hand-rolled HTTP client for the sync backend
// (wharf-backend). It covers exactly the five calls the TUI needs — device
// pairing, token refresh, profile, vault get/put — with Bearer injection and
// a single transparent refresh-and-retry on 401. Errors from the backend are
// RFC 7807 problem+json; their detail is surfaced via *Error.
//
// The client is safe for concurrent use; tokens rotate under an internal
// mutex. It is DIRECT-token-mode only (the TUI has no cookie jar): the
// refresh token travels in request bodies and rotated tokens come back in
// response bodies.
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// DefaultBaseURL is the production deployment (backend path-routed at /api).
const DefaultBaseURL = "https://wharf.jannekeipert.de"

// maxErrBody caps how much of an error body is read for the problem detail.
const maxErrBody = 64 << 10

// BaseURL resolves the backend base URL: WHARF_API_BASE overrides the
// production default.
func BaseURL() string {
	if v := strings.TrimRight(strings.TrimSpace(os.Getenv("WHARF_API_BASE")), "/"); v != "" {
		return v
	}
	return DefaultBaseURL
}

// DeviceURL is the human-facing browser page that issues pairing codes,
// shown on the sign-in screen.
func DeviceURL(base string) string {
	return strings.TrimRight(base, "/") + "/device"
}

var (
	// ErrSessionExpired means the refresh token was rejected: the session is
	// dead (expired, or revoked by a recovery reset) and the device must
	// re-pair.
	ErrSessionExpired = errors.New("api: session expired — sign in again")
	// ErrNoVault is returned by GetVault when the account has no vault yet.
	ErrNoVault = errors.New("api: no remote vault")
	// ErrVaultConflict is returned by PutVault on a version conflict (409):
	// another device wrote first; pull before retrying. Reused by
	// PutProjectVault, RotateProject and SubmitMemberKey for their 409s.
	ErrVaultConflict = errors.New("api: vault version conflict")
	// ErrProjectNotFound is returned by project-scoped calls when the project
	// does not exist or the caller is not a member (404).
	ErrProjectNotFound = errors.New("api: project not found")
	// ErrNoPublicKey is returned by CreateProject when the account has not yet
	// published a public key (412).
	ErrNoPublicKey = errors.New("api: account has no published public key")
	// ErrPublicKeyExists is returned by PublishPublicKey when a key is already
	// set and rotate was not requested (409).
	ErrPublicKeyExists = errors.New("api: public key already set")
	// ErrInviteConflict is returned by CreateInvite when the invitee is already
	// a member or already invited (409).
	ErrInviteConflict = errors.New("api: already a member or invited")
	// ErrInviteExpired is returned by AcceptInvite when the invite has expired
	// (410).
	ErrInviteExpired = errors.New("api: invite expired")
)

// Error is a structured backend error (RFC 7807 problem+json).
type Error struct {
	Status int
	Detail string
}

func (e *Error) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return fmt.Sprintf("backend returned %d", e.Status)
}

// Session is the result of a device-code exchange: an account identity plus
// a DIRECT-mode token pair.
type Session struct {
	UserID       string
	Email        string
	AccessToken  string
	RefreshToken string
}

// Profile is GET /users/me.
type Profile struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	HasPassword bool   `json:"hasPassword"`
	HasRecovery bool   `json:"hasRecovery"`
	HasVault    bool   `json:"hasVault"`
	PublicKey   string `json:"publicKey"`
}

// Vault is the remote encrypted blob with its optimistic-concurrency version.
type Vault struct {
	Blob      []byte
	Version   int64
	UpdatedAt time.Time
}

// Client talks to one backend. Zero value is not usable; use New.
type Client struct {
	base string
	hc   *http.Client

	mu      sync.Mutex
	access  string
	refresh string
}

// New builds a client for base (no trailing slash needed). Timeouts are
// generous enough for a 1 MiB vault blob on a slow link.
func New(base string) *Client {
	return &Client{
		base: strings.TrimRight(base, "/"),
		hc:   &http.Client{Timeout: 30 * time.Second},
	}
}

// SetTokens installs a token pair (e.g. restored from the session file; the
// access token may be empty — the first 401 will refresh).
func (c *Client) SetTokens(access, refresh string) {
	c.mu.Lock()
	c.access, c.refresh = access, refresh
	c.mu.Unlock()
}

// RefreshToken returns the current refresh token so callers can persist
// rotations.
func (c *Client) RefreshToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.refresh
}

// NormalizeCode canonicalizes a typed pairing code: dashes and spaces
// stripped, upper-cased (the web shows codes as XXXX-XXXX).
func NormalizeCode(code string) string {
	code = strings.ReplaceAll(code, "-", "")
	code = strings.ReplaceAll(code, " ", "")
	return strings.ToUpper(strings.TrimSpace(code))
}

// ExchangeDeviceCode redeems a one-time pairing code for a session (DIRECT
// mode: tokens in the body). On success the client adopts the new tokens.
func (c *Client) ExchangeDeviceCode(ctx context.Context, code, deviceName string) (Session, error) {
	body := map[string]string{"code": NormalizeCode(code)}
	if deviceName != "" {
		body["deviceName"] = deviceName
	}
	var resp struct {
		User struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/device-codes/exchange", body, &resp, false); err != nil {
		return Session{}, err
	}
	c.SetTokens(resp.AccessToken, resp.RefreshToken)
	return Session{
		UserID:       resp.User.ID,
		Email:        resp.User.Email,
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
	}, nil
}

// Me fetches the authenticated account profile.
func (c *Client) Me(ctx context.Context) (Profile, error) {
	var p Profile
	err := c.doJSON(ctx, http.MethodGet, "/api/v1/users/me", nil, &p, true)
	return p, err
}

// GetVault fetches the remote encrypted vault blob. ErrNoVault when the
// account has none yet.
func (c *Client) GetVault(ctx context.Context) (Vault, error) {
	var resp struct {
		Vault     string    `json:"vault"`
		Version   int64     `json:"version"`
		UpdatedAt time.Time `json:"updatedAt"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/vault", nil, &resp, true); err != nil {
		var ae *Error
		if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
			return Vault{}, ErrNoVault
		}
		return Vault{}, err
	}
	blob, err := base64.StdEncoding.DecodeString(resp.Vault)
	if err != nil {
		return Vault{}, fmt.Errorf("api: remote vault is not valid base64: %w", err)
	}
	return Vault{Blob: blob, Version: resp.Version, UpdatedAt: resp.UpdatedAt}, nil
}

// PutVault uploads blob if the server is still at expectedVersion, returning
// the new version. ErrVaultConflict on a lost race (pull, then re-evaluate).
func (c *Client) PutVault(ctx context.Context, blob []byte, expectedVersion int64) (int64, error) {
	body := map[string]any{
		"vault":           base64.StdEncoding.EncodeToString(blob),
		"expectedVersion": expectedVersion,
	}
	var resp struct {
		Version int64 `json:"version"`
	}
	if err := c.doJSON(ctx, http.MethodPut, "/api/v1/vault", body, &resp, true); err != nil {
		var ae *Error
		if errors.As(err, &ae) && ae.Status == http.StatusConflict {
			return 0, ErrVaultConflict
		}
		return 0, err
	}
	return resp.Version, nil
}

// ChangePassword rotates the account's password auth key and replaces the
// remote vault blob with one re-encrypted under the new password, returning the
// new vault version. currentAuthKey / newAuthKey are the base64 keys derived
// from the old and new passwords (see internal/cred). The recovery code is left
// untouched, and the session stays valid.
func (c *Client) ChangePassword(ctx context.Context, currentAuthKey, newAuthKey string, blob []byte) (int64, error) {
	body := map[string]string{
		"currentAuthKey": currentAuthKey,
		"newAuthKey":     newAuthKey,
		"vault":          base64.StdEncoding.EncodeToString(blob),
	}
	var resp struct {
		Version int64 `json:"version"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/auth/password", body, &resp, true); err != nil {
		return 0, err
	}
	return resp.Version, nil
}

// refresh exchanges the refresh token for a new pair (DIRECT mode). A 401
// here means the session is dead.
func (c *Client) refreshTokens(ctx context.Context) error {
	c.mu.Lock()
	rt := c.refresh
	c.mu.Unlock()
	if rt == "" {
		return ErrSessionExpired
	}
	body := map[string]string{"refreshToken": rt, "tokenMode": "DIRECT"}
	var resp struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/auth/refresh", body, &resp, false); err != nil {
		var ae *Error
		if errors.As(err, &ae) && (ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden) {
			return ErrSessionExpired
		}
		return err
	}
	c.mu.Lock()
	c.access = resp.AccessToken
	if resp.RefreshToken != "" {
		c.refresh = resp.RefreshToken
	}
	c.mu.Unlock()
	return nil
}

// doJSON performs one call, decoding a 2xx JSON body into out (which may be
// nil). With auth it injects the Bearer token and, on 401, refreshes once and
// retries; a second 401 (or a failed refresh) surfaces ErrSessionExpired.
func (c *Client) doJSON(ctx context.Context, method, path string, in, out any, auth bool) error {
	err := c.once(ctx, method, path, in, out, auth)
	if !auth {
		return err
	}
	var ae *Error
	if errors.As(err, &ae) && ae.Status == http.StatusUnauthorized {
		if rerr := c.refreshTokens(ctx); rerr != nil {
			return rerr
		}
		err = c.once(ctx, method, path, in, out, auth)
		if errors.As(err, &ae) && ae.Status == http.StatusUnauthorized {
			return ErrSessionExpired
		}
	}
	return err
}

// once is a single HTTP round trip with JSON encoding on both sides.
func (c *Client) once(ctx context.Context, method, path string, in, out any, auth bool) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		c.mu.Lock()
		if c.access != "" {
			req.Header.Set("Authorization", "Bearer "+c.access)
		}
		c.mu.Unlock()
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return decodeError(resp)
	}
	if out == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrBody))
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// decodeError extracts an RFC 7807 problem detail (falling back to the
// status text) into *Error.
func decodeError(resp *http.Response) error {
	e := &Error{Status: resp.StatusCode}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBody))
	var problem struct {
		Detail string `json:"detail"`
		Title  string `json:"title"`
	}
	if json.Unmarshal(b, &problem) == nil {
		if problem.Detail != "" {
			e.Detail = problem.Detail
		} else if problem.Title != "" {
			e.Detail = problem.Title
		}
	}
	return e
}
