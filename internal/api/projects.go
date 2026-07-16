package api

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ProjectSummary is one entry of GET /projects.
type ProjectSummary struct {
	ID                 string
	Name               string
	Description        string
	Role               string
	MemberCount        int64
	PendingInviteCount int64
	VaultVersion       int64
	AwaitingKey        bool
}

// ProjectMember is a member row inside a ProjectDetail. PublicKey is nil when
// the member has not published one.
type ProjectMember struct {
	UserID    string
	Email     string
	Role      string
	Keyed     bool
	PublicKey []byte
}

// ProjectInvite is a pending invite row inside a ProjectDetail (also the
// response of CreateInvite).
type ProjectInvite struct {
	ID        string
	Email     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// ProjectDetail is GET /projects/{id} (and the CreateProject response).
type ProjectDetail struct {
	ID           string
	Name         string
	Description  string
	Role         string
	CreatedAt    time.Time
	VaultVersion int64
	Members      []ProjectMember
	Invites      []ProjectInvite
}

// ProjectVaultResp is GET /projects/{id}/vault. WrappedDek is nil when the
// server sends a null wrappedDek (the caller is still awaiting their key).
type ProjectVaultResp struct {
	Blob       []byte
	Version    int64
	UpdatedAt  time.Time
	WrappedDek []byte
}

// ReceivedInvite is one entry of GET /users/me/invites.
type ReceivedInvite struct {
	ID             string
	ProjectID      string
	ProjectName    string
	InvitedByEmail string
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

// PendingKey is one member of GET /projects/{id}/pending-keys awaiting a
// wrapped DEK.
type PendingKey struct {
	UserID    string
	Email     string
	PublicKey []byte
}

// WrappedKey binds a member to their DEK wrapped under that member's public
// key, for RotateProject.
type WrappedKey struct {
	UserID     string
	WrappedDek []byte
}

// RotateRequest re-keys a project's vault. RemoveUserID is optional: when empty
// the removeUserId field is omitted (nobody is removed).
type RotateRequest struct {
	RemoveUserID    string
	Blob            []byte
	ExpectedVersion int64
	WrappedKeys     []WrappedKey
}

// b64 decodes a base64 field into bytes; "" decodes to nil (no key / no blob).
func b64(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// PublishPublicKey uploads the account's public key. rotate must be set to
// replace an already-published key; otherwise a second publish is
// ErrPublicKeyExists (409).
func (c *Client) PublishPublicKey(ctx context.Context, pub []byte, rotate bool) error {
	body := map[string]any{
		"publicKey": base64.StdEncoding.EncodeToString(pub),
		"rotate":    rotate,
	}
	if err := c.doJSON(ctx, http.MethodPut, "/api/v1/users/me/public-key", body, nil, true); err != nil {
		var ae *Error
		if errors.As(err, &ae) && ae.Status == http.StatusConflict {
			return ErrPublicKeyExists
		}
		return err
	}
	return nil
}

// ListProjects returns the caller's project memberships.
func (c *Client) ListProjects(ctx context.Context) ([]ProjectSummary, error) {
	var resp []struct {
		ID                 string `json:"id"`
		Name               string `json:"name"`
		Description        string `json:"description"`
		Role               string `json:"role"`
		MemberCount        int64  `json:"memberCount"`
		PendingInviteCount int64  `json:"pendingInviteCount"`
		VaultVersion       int64  `json:"vaultVersion"`
		AwaitingKey        bool   `json:"awaitingKey"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/projects", nil, &resp, true); err != nil {
		return nil, err
	}
	out := make([]ProjectSummary, len(resp))
	for i, p := range resp {
		out[i] = ProjectSummary{
			ID:                 p.ID,
			Name:               p.Name,
			Description:        p.Description,
			Role:               p.Role,
			MemberCount:        p.MemberCount,
			PendingInviteCount: p.PendingInviteCount,
			VaultVersion:       p.VaultVersion,
			AwaitingKey:        p.AwaitingKey,
		}
	}
	return out, nil
}

// projectDetailJSON is the wire shape shared by GetProject and CreateProject.
type projectDetailJSON struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"createdAt"`
	VaultVersion int64     `json:"vaultVersion"`
	Members      []struct {
		UserID    string `json:"userId"`
		Email     string `json:"email"`
		Role      string `json:"role"`
		Keyed     bool   `json:"keyed"`
		PublicKey string `json:"publicKey"`
	} `json:"members"`
	Invites []struct {
		ID        string    `json:"id"`
		Email     string    `json:"email"`
		CreatedAt time.Time `json:"createdAt"`
		ExpiresAt time.Time `json:"expiresAt"`
	} `json:"invites"`
}

func (j projectDetailJSON) toDetail() (ProjectDetail, error) {
	d := ProjectDetail{
		ID:           j.ID,
		Name:         j.Name,
		Description:  j.Description,
		Role:         j.Role,
		CreatedAt:    j.CreatedAt,
		VaultVersion: j.VaultVersion,
	}
	for _, m := range j.Members {
		pk, err := b64(m.PublicKey)
		if err != nil {
			return ProjectDetail{}, fmt.Errorf("api: member public key is not valid base64: %w", err)
		}
		d.Members = append(d.Members, ProjectMember{
			UserID:    m.UserID,
			Email:     m.Email,
			Role:      m.Role,
			Keyed:     m.Keyed,
			PublicKey: pk,
		})
	}
	for _, inv := range j.Invites {
		d.Invites = append(d.Invites, ProjectInvite{
			ID:        inv.ID,
			Email:     inv.Email,
			CreatedAt: inv.CreatedAt,
			ExpiresAt: inv.ExpiresAt,
		})
	}
	return d, nil
}

// GetProject fetches full project detail. ErrProjectNotFound when the project
// does not exist or the caller is not a member (404).
func (c *Client) GetProject(ctx context.Context, id string) (ProjectDetail, error) {
	var resp projectDetailJSON
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/projects/"+id, nil, &resp, true); err != nil {
		var ae *Error
		if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
			return ProjectDetail{}, ErrProjectNotFound
		}
		return ProjectDetail{}, err
	}
	return resp.toDetail()
}

// CreateProject creates a project seeded with an encrypted vault blob and the
// creator's wrapped DEK. ErrNoPublicKey when the account has no published
// public key (412).
func (c *Client) CreateProject(ctx context.Context, name, description string, blob, wrappedDek []byte) (ProjectDetail, error) {
	body := map[string]any{
		"name":        name,
		"description": description,
		"vault":       base64.StdEncoding.EncodeToString(blob),
		"wrappedDek":  base64.StdEncoding.EncodeToString(wrappedDek),
	}
	var resp projectDetailJSON
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/projects", body, &resp, true); err != nil {
		var ae *Error
		if errors.As(err, &ae) && ae.Status == http.StatusPreconditionFailed {
			return ProjectDetail{}, ErrNoPublicKey
		}
		return ProjectDetail{}, err
	}
	return resp.toDetail()
}

// GetProjectVault fetches the project's encrypted vault together with the
// caller's wrapped DEK (nil when still awaiting a key). ErrProjectNotFound on
// 404.
func (c *Client) GetProjectVault(ctx context.Context, id string) (ProjectVaultResp, error) {
	var resp struct {
		Vault      string    `json:"vault"`
		Version    int64     `json:"version"`
		UpdatedAt  time.Time `json:"updatedAt"`
		WrappedDek *string   `json:"wrappedDek"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/projects/"+id+"/vault", nil, &resp, true); err != nil {
		var ae *Error
		if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
			return ProjectVaultResp{}, ErrProjectNotFound
		}
		return ProjectVaultResp{}, err
	}
	blob, err := b64(resp.Vault)
	if err != nil {
		return ProjectVaultResp{}, fmt.Errorf("api: project vault is not valid base64: %w", err)
	}
	var wrapped []byte
	if resp.WrappedDek != nil {
		wrapped, err = b64(*resp.WrappedDek)
		if err != nil {
			return ProjectVaultResp{}, fmt.Errorf("api: wrapped DEK is not valid base64: %w", err)
		}
	}
	return ProjectVaultResp{Blob: blob, Version: resp.Version, UpdatedAt: resp.UpdatedAt, WrappedDek: wrapped}, nil
}

// versionResp is the {version, updatedAt} shape returned by vault-write calls.
type versionResp struct {
	Version   int64     `json:"version"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// PutProjectVault uploads blob if the server is still at expectedVersion,
// returning the new version and its timestamp. ErrVaultConflict on a lost race
// (409), ErrProjectNotFound on 404.
func (c *Client) PutProjectVault(ctx context.Context, id string, blob []byte, expectedVersion int64) (int64, time.Time, error) {
	body := map[string]any{
		"vault":           base64.StdEncoding.EncodeToString(blob),
		"expectedVersion": expectedVersion,
	}
	var resp versionResp
	if err := c.doJSON(ctx, http.MethodPut, "/api/v1/projects/"+id+"/vault", body, &resp, true); err != nil {
		var ae *Error
		if errors.As(err, &ae) {
			switch ae.Status {
			case http.StatusConflict:
				return 0, time.Time{}, ErrVaultConflict
			case http.StatusNotFound:
				return 0, time.Time{}, ErrProjectNotFound
			}
		}
		return 0, time.Time{}, err
	}
	return resp.Version, resp.UpdatedAt, nil
}

// RotateProject re-keys the project vault (optionally removing a member),
// returning the new version and timestamp. ErrVaultConflict on 409,
// ErrProjectNotFound on 404.
func (c *Client) RotateProject(ctx context.Context, id string, req RotateRequest) (int64, time.Time, error) {
	wrapped := make([]map[string]any, len(req.WrappedKeys))
	for i, wk := range req.WrappedKeys {
		wrapped[i] = map[string]any{
			"userId":     wk.UserID,
			"wrappedDek": base64.StdEncoding.EncodeToString(wk.WrappedDek),
		}
	}
	body := map[string]any{
		"vault":           base64.StdEncoding.EncodeToString(req.Blob),
		"expectedVersion": req.ExpectedVersion,
		"wrappedKeys":     wrapped,
	}
	if req.RemoveUserID != "" {
		body["removeUserId"] = req.RemoveUserID
	}
	var resp versionResp
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/projects/"+id+"/rotate", body, &resp, true); err != nil {
		var ae *Error
		if errors.As(err, &ae) {
			switch ae.Status {
			case http.StatusConflict:
				return 0, time.Time{}, ErrVaultConflict
			case http.StatusNotFound:
				return 0, time.Time{}, ErrProjectNotFound
			}
		}
		return 0, time.Time{}, err
	}
	return resp.Version, resp.UpdatedAt, nil
}

// CreateInvite invites email to the project. ErrInviteConflict when the invitee
// is already a member or already invited (409).
func (c *Client) CreateInvite(ctx context.Context, id, email string) (ProjectInvite, error) {
	body := map[string]string{"email": email}
	var resp struct {
		ID        string    `json:"id"`
		Email     string    `json:"email"`
		CreatedAt time.Time `json:"createdAt"`
		ExpiresAt time.Time `json:"expiresAt"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/projects/"+id+"/invites", body, &resp, true); err != nil {
		var ae *Error
		if errors.As(err, &ae) && ae.Status == http.StatusConflict {
			return ProjectInvite{}, ErrInviteConflict
		}
		return ProjectInvite{}, err
	}
	return ProjectInvite{ID: resp.ID, Email: resp.Email, CreatedAt: resp.CreatedAt, ExpiresAt: resp.ExpiresAt}, nil
}

// DeleteInvite revokes a pending invite.
func (c *Client) DeleteInvite(ctx context.Context, projectID, inviteID string) error {
	return c.doJSON(ctx, http.MethodDelete, "/api/v1/projects/"+projectID+"/invites/"+inviteID, nil, nil, true)
}

// ListMyInvites returns the invites addressed to the authenticated account.
func (c *Client) ListMyInvites(ctx context.Context) ([]ReceivedInvite, error) {
	var resp []struct {
		ID             string    `json:"id"`
		ProjectID      string    `json:"projectId"`
		ProjectName    string    `json:"projectName"`
		InvitedByEmail string    `json:"invitedByEmail"`
		CreatedAt      time.Time `json:"createdAt"`
		ExpiresAt      time.Time `json:"expiresAt"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/users/me/invites", nil, &resp, true); err != nil {
		return nil, err
	}
	out := make([]ReceivedInvite, len(resp))
	for i, inv := range resp {
		out[i] = ReceivedInvite{
			ID:             inv.ID,
			ProjectID:      inv.ProjectID,
			ProjectName:    inv.ProjectName,
			InvitedByEmail: inv.InvitedByEmail,
			CreatedAt:      inv.CreatedAt,
			ExpiresAt:      inv.ExpiresAt,
		}
	}
	return out, nil
}

// AcceptInvite accepts an invite, returning the joined project's summary.
// ErrInviteExpired when the invite has lapsed (410).
func (c *Client) AcceptInvite(ctx context.Context, id string) (ProjectSummary, error) {
	var resp struct {
		ID                 string `json:"id"`
		Name               string `json:"name"`
		Description        string `json:"description"`
		Role               string `json:"role"`
		MemberCount        int64  `json:"memberCount"`
		PendingInviteCount int64  `json:"pendingInviteCount"`
		VaultVersion       int64  `json:"vaultVersion"`
		AwaitingKey        bool   `json:"awaitingKey"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/users/me/invites/"+id+"/accept", nil, &resp, true); err != nil {
		var ae *Error
		if errors.As(err, &ae) && ae.Status == http.StatusGone {
			return ProjectSummary{}, ErrInviteExpired
		}
		return ProjectSummary{}, err
	}
	return ProjectSummary{
		ID:                 resp.ID,
		Name:               resp.Name,
		Description:        resp.Description,
		Role:               resp.Role,
		MemberCount:        resp.MemberCount,
		PendingInviteCount: resp.PendingInviteCount,
		VaultVersion:       resp.VaultVersion,
		AwaitingKey:        resp.AwaitingKey,
	}, nil
}

// DeclineInvite declines an invite.
func (c *Client) DeclineInvite(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodPost, "/api/v1/users/me/invites/"+id+"/decline", nil, nil, true)
}

// GetPendingKeys returns the members of a project still awaiting a wrapped DEK,
// with their public keys so the caller can wrap for them.
func (c *Client) GetPendingKeys(ctx context.Context, id string) ([]PendingKey, error) {
	var resp []struct {
		UserID    string `json:"userId"`
		Email     string `json:"email"`
		PublicKey string `json:"publicKey"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/projects/"+id+"/pending-keys", nil, &resp, true); err != nil {
		return nil, err
	}
	out := make([]PendingKey, len(resp))
	for i, k := range resp {
		pk, err := b64(k.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("api: pending-key public key is not valid base64: %w", err)
		}
		out[i] = PendingKey{UserID: k.UserID, Email: k.Email, PublicKey: pk}
	}
	return out, nil
}

// SubmitMemberKey hands a member their DEK wrapped under their public key,
// asserting it wraps vaultVersion. ErrVaultConflict when the vault has since
// moved on (409).
func (c *Client) SubmitMemberKey(ctx context.Context, projectID, userID string, wrappedDek []byte, vaultVersion int64) error {
	body := map[string]any{
		"wrappedDek":   base64.StdEncoding.EncodeToString(wrappedDek),
		"vaultVersion": vaultVersion,
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/projects/"+projectID+"/members/"+userID+"/key", body, nil, true); err != nil {
		var ae *Error
		if errors.As(err, &ae) && ae.Status == http.StatusConflict {
			return ErrVaultConflict
		}
		return err
	}
	return nil
}
