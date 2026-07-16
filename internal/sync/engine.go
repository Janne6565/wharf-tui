package sync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	stdsync "sync"
	"time"

	"github.com/Janne6565/wharf-tui/internal/api"
	"github.com/Janne6565/wharf-tui/internal/cred"
)

// ErrSignedOut is returned by operations that require a paired session when
// none is loaded.
var ErrSignedOut = errors.New("sync: not signed in")

// API is the slice of the backend client the engine depends on, behind an
// interface so tests inject a fake. *api.Client satisfies it.
type API interface {
	ExchangeDeviceCode(ctx context.Context, code, deviceName string) (api.Session, error)
	GetVault(ctx context.Context) (api.Vault, error)
	PutVault(ctx context.Context, blob []byte, expectedVersion int64) (int64, error)
	ChangePassword(ctx context.Context, currentAuthKey, newAuthKey string, blob []byte) (int64, error)
	SetTokens(access, refresh string)
	RefreshToken() string

	// Projects (M3). All project-scoped routes 404 for non-members.
	Me(ctx context.Context) (api.Profile, error)
	PublishPublicKey(ctx context.Context, pub []byte, rotate bool) error
	ListProjects(ctx context.Context) ([]api.ProjectSummary, error)
	GetProject(ctx context.Context, id string) (api.ProjectDetail, error)
	CreateProject(ctx context.Context, name, description string, blob, wrappedDek []byte) (api.ProjectDetail, error)
	GetProjectVault(ctx context.Context, id string) (api.ProjectVaultResp, error)
	PutProjectVault(ctx context.Context, id string, blob []byte, expectedVersion int64) (int64, time.Time, error)
	RotateProject(ctx context.Context, id string, req api.RotateRequest) (int64, time.Time, error)
	CreateInvite(ctx context.Context, id, email string) (api.ProjectInvite, error)
	DeleteInvite(ctx context.Context, projectID, inviteID string) error
	ListMyInvites(ctx context.Context) ([]api.ReceivedInvite, error)
	AcceptInvite(ctx context.Context, id string) (api.ProjectSummary, error)
	DeclineInvite(ctx context.Context, id string) error
	GetPendingKeys(ctx context.Context, id string) ([]api.PendingKey, error)
	SubmitMemberKey(ctx context.Context, projectID, userID string, wrappedDek []byte, vaultVersion int64) error
}

// ProjectCrypto is the project-blob crypto the engine depends on, behind an
// interface so tests fake it (production wires internal/vault). The engine
// itself never imports the vault package, mirroring the OpenBlob hook.
type ProjectCrypto interface {
	NewDEK() ([]byte, error)
	Seal(dek, payload []byte) ([]byte, error)
	Open(dek, blob []byte) ([]byte, error)
	Wrap(dek, recipientPub []byte) ([]byte, error)
	Unwrap(wrapped, pub, priv []byte) ([]byte, error)
}

// Config wires an Engine to its collaborators. All fields are required except
// DeviceName.
type Config struct {
	API         API
	SessionPath string
	// Key seals the session file (a vault-derived subkey, see SessionKeyInfo).
	Key []byte
	// Password is the master password retained for the unlocked-vault
	// lifetime: adopting a remote blob requires it (remote blobs carry their
	// own salts and DEK). It is zeroed by Close and never written to disk.
	Password []byte
	// DeviceName labels the pairing on the account (e.g. the hostname).
	DeviceName string
	// ReadBlob returns the local vault file bytes for a push. Reading is safe
	// concurrently with vault saves because saves replace the file atomically.
	ReadBlob func() ([]byte, error)
	// OpenBlob decrypts a remote WHARFV blob with the master password and
	// returns its payload (vault.OpenPayload in production).
	OpenBlob func(blob, password []byte) ([]byte, error)
	// ProjectCrypto seals/opens project blobs and wraps/unwraps project DEKs.
	// Nil disables the projects feature (personal-only tests leave it unset).
	ProjectCrypto ProjectCrypto
}

// Conflict describes a both-sides-changed situation the user must resolve.
type Conflict struct {
	LocalHosts    int
	RemoteHosts   int
	RemoteVersion int64
	// RemoteUpdatedAt is when the server last wrote the remote vault (zero if
	// the backend did not report it). The local side's "last changed" is the
	// vault file mtime, read by the UI where it has the path.
	RemoteUpdatedAt time.Time
}

// Result is the outcome of one Sync/Resolve pass. The UI turns it into
// display state; it never carries secrets.
type Result struct {
	// SignedOut: no paired session — nothing to sync.
	SignedOut bool
	// SessionDead: the refresh token was rejected (expired or revoked by a
	// recovery reset). The session file has been deleted; re-pair.
	SessionDead bool
	// Err is a network/protocol failure (rendered as offline).
	Err error
	// Conflict is non-nil when the user must choose a side (Resolve).
	Conflict *Conflict
	// Adopt is a remote payload the caller must write into the local vault
	// (re-encrypting under the local DEK) and then confirm via CommitAdopt.
	Adopt        []byte
	AdoptVersion int64
	// Pushed reports that local changes were uploaded.
	Pushed bool
	// Version is the remote version the device is in agreement with.
	Version int64
}

// Engine owns the sync session and bookkeeping for one unlocked vault. All
// methods are safe for concurrent use; long operations (network) hold the
// lock, serializing overlapping syncs. Sync state lives here — the UI model
// only renders snapshots delivered as messages.
type Engine struct {
	mu   stdsync.Mutex
	cfg  Config
	sess *session

	// pending stashes the remote side of an unresolved conflict so Resolve
	// need not refetch.
	pending *pendingRemote

	// identity is the caller's X25519 keypair (from the personal vault payload),
	// set via SetIdentity. Nil until the UI bootstraps identity.
	identity *identityKeys
	// projectDEKs caches each keyed project's unwrapped DEK for the unlocked
	// session so edits can be re-sealed and pending members re-keyed without a
	// re-unwrap. Session-scoped, never persisted.
	projectDEKs map[string][]byte
	// pendingProjects stashes the remote side of an unresolved per-project
	// conflict, keyed by project ID (resolved one at a time by the UI).
	pendingProjects map[string]*pendingRemote

	closed bool
}

// identityKeys holds the caller's raw X25519 keypair for the unlocked session.
type identityKeys struct {
	pub  []byte
	priv []byte
}

type pendingRemote struct {
	payload []byte
	version int64
}

// New builds an engine. It performs no I/O; call Resume to restore a paired
// session.
func New(cfg Config) *Engine {
	return &Engine{
		cfg:             cfg,
		projectDEKs:     map[string][]byte{},
		pendingProjects: map[string]*pendingRemote{},
	}
}

// Close zeroes the retained secrets. The engine is unusable afterwards.
func (e *Engine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	zero(e.cfg.Password)
	zero(e.cfg.Key)
	if e.identity != nil {
		zero(e.identity.priv)
	}
	for id, dek := range e.projectDEKs {
		zero(dek)
		delete(e.projectDEKs, id)
	}
	e.identity = nil
	e.sess = nil
	e.pending = nil
	e.pendingProjects = nil
	e.closed = true
}

// SignedIn reports whether a paired session is loaded.
func (e *Engine) SignedIn() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sess != nil
}

// Email returns the paired account's email ("" when signed out).
func (e *Engine) Email() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess == nil {
		return ""
	}
	return e.sess.Email
}

// Resume loads the session file, if any. A file that exists but cannot be
// opened (vault re-created → new subkey) is deleted: the device is simply
// signed out and must re-pair.
func (e *Engine) Resume() (email string, ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return "", false
	}
	s, err := loadSession(e.cfg.SessionPath, e.cfg.Key)
	if err != nil {
		if !errors.Is(err, errNoSession) {
			os.Remove(e.cfg.SessionPath)
		}
		return "", false
	}
	e.sess = s
	e.cfg.API.SetTokens("", s.RefreshToken)
	return s.Email, true
}

// Pair exchanges a device code for a session and persists it. The code may
// carry the display dash (XXXX-XXXX).
func (e *Engine) Pair(ctx context.Context, code string) (email string, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return "", errors.New("sync: engine closed")
	}
	as, err := e.cfg.API.ExchangeDeviceCode(ctx, code, e.cfg.DeviceName)
	if err != nil {
		return "", err
	}
	e.sess = &session{
		RefreshToken: as.RefreshToken,
		Email:        as.Email,
		UserID:       as.UserID,
		Projects:     map[string]ProjectSyncState{},
	}
	if err := saveSession(e.cfg.SessionPath, e.cfg.Key, e.sess); err != nil {
		return as.Email, err
	}
	return as.Email, nil
}

// SignOut deletes the session file and forgets the session. The local vault
// is untouched.
func (e *Engine) SignOut() {
	e.mu.Lock()
	defer e.mu.Unlock()
	os.Remove(e.cfg.SessionPath)
	e.sess = nil
	e.pending = nil
	e.cfg.API.SetTokens("", "")
}

// SetPassword replaces the retained master password, zeroing the old one. The
// caller changed the master password on an unlocked vault; the engine needs the
// new one to unlock remote blobs (and, after an offline change, to keep the
// retained secret consistent for the next sign-in and sync).
func (e *Engine) SetPassword(newPassword []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	zero(e.cfg.Password)
	e.cfg.Password = append([]byte(nil), newPassword...)
}

// ChangePassword rotates the account's server-side auth key and uploads the
// vault blob re-encrypted under the new password (produced by the caller's
// local vault.ChangePassword), then records agreement at the returned version
// so the next sync is a no-op. The auth keys are derived here from the paired
// account's email. On success the retained master password is updated too.
//
// currentPassword and newPassword are the plaintext master passwords; payload
// is the current (unchanged) vault payload, captured by the caller on the UI
// goroutine. This performs argon2id twice, so it is slow — run it off the UI
// goroutine like every other engine call.
func (e *Engine) ChangePassword(ctx context.Context, currentPassword, newPassword, payload []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess == nil || e.closed {
		return ErrSignedOut
	}
	email := e.sess.Email
	currentAuthKey, err := cred.AuthKey(string(currentPassword), email)
	if err != nil {
		return err
	}
	newAuthKey, err := cred.AuthKey(string(newPassword), email)
	if err != nil {
		return err
	}
	blob, err := e.cfg.ReadBlob()
	if err != nil {
		return err
	}
	version, err := e.cfg.API.ChangePassword(ctx, currentAuthKey, newAuthKey, blob)
	if err != nil {
		return err
	}
	// The retained password must now be the new one (remote-blob unlocks).
	zero(e.cfg.Password)
	e.cfg.Password = append([]byte(nil), newPassword...)
	// Record agreement at the new version so a follow-up sync doesn't treat the
	// server-side rewrite as a remote change and try to re-adopt it.
	_ = e.commit(version, fingerprint(payload))
	e.persistRotation()
	return nil
}

// Sync runs one full sync pass against payload, the current local vault
// payload (captured by the caller on the UI goroutine — the engine never
// touches the live vault handle, avoiding data races with UI saves).
//
// The state machine, keyed on (local changed since last sync?, remote moved
// since last sync?):
//
//	no / no   → in sync, nothing to do
//	yes / no  → push (PUT with expectedVersion; a 409 re-runs the pass)
//	no / yes  → fast-forward pull: unlock the remote blob with the master
//	            password and hand its payload to the caller (Adopt)
//	yes / yes → conflict — unless one side has zero hosts, in which case the
//	            non-empty side wins automatically (first sync after pairing);
//	            otherwise the user chooses via Resolve.
func (e *Engine) Sync(ctx context.Context, payload []byte) Result {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess == nil || e.closed {
		return Result{SignedOut: true}
	}
	res := e.syncLocked(ctx, payload, true)
	e.persistRotation()
	return res
}

// syncLocked is one evaluation pass. retryOn409 allows a single re-pass after
// a lost push race (the remote is refetched and re-evaluated).
func (e *Engine) syncLocked(ctx context.Context, payload []byte, retryOn409 bool) Result {
	fp := fingerprint(payload)

	remote, err := e.cfg.API.GetVault(ctx)
	if errors.Is(err, api.ErrNoVault) {
		// No remote vault yet: upload ours if it holds anything worth
		// syncing; an empty local vault has nothing to establish.
		if countHosts(payload) == 0 {
			return Result{}
		}
		return e.pushLocked(ctx, payload, fp, 0, retryOn409)
	}
	if err != nil {
		return e.failure(err)
	}

	localChanged := fp != e.sess.LastSyncedFingerprint
	remoteMoved := remote.Version != e.sess.LastSyncedVersion

	if !localChanged && !remoteMoved {
		return Result{Version: remote.Version}
	}
	if localChanged && !remoteMoved {
		return e.pushLocked(ctx, payload, fp, remote.Version, retryOn409)
	}

	// Remote moved: we need its payload — master-password unlock (the remote
	// blob has its own salts and DEK; the local DEK cannot open it).
	remotePayload, err := e.cfg.OpenBlob(remote.Blob, e.cfg.Password)
	if err != nil {
		return Result{Err: err}
	}
	if rfp := fingerprint(remotePayload); rfp == fp {
		// Same content on both sides — just record the agreement.
		if err := e.commit(remote.Version, fp); err != nil {
			return Result{Err: err}
		}
		return Result{Version: remote.Version}
	}
	if !localChanged {
		return Result{Adopt: remotePayload, AdoptVersion: remote.Version}
	}

	// Both changed. Zero-hosts auto-pick keeps the first sync after pairing
	// silent; a genuinely divergent pair is the user's call.
	lh, rh := countHosts(payload), countHosts(remotePayload)
	if lh == 0 {
		return Result{Adopt: remotePayload, AdoptVersion: remote.Version}
	}
	if rh == 0 {
		return e.pushLocked(ctx, payload, fp, remote.Version, retryOn409)
	}
	e.pending = &pendingRemote{payload: remotePayload, version: remote.Version}
	return Result{Conflict: &Conflict{
		LocalHosts:      lh,
		RemoteHosts:     rh,
		RemoteVersion:   remote.Version,
		RemoteUpdatedAt: remote.UpdatedAt,
	}}
}

// pushLocked uploads the local vault blob with optimistic versioning.
func (e *Engine) pushLocked(ctx context.Context, payload []byte, fp string, expected int64, retryOn409 bool) Result {
	blob, err := e.cfg.ReadBlob()
	if err != nil {
		return Result{Err: err}
	}
	version, err := e.cfg.API.PutVault(ctx, blob, expected)
	if errors.Is(err, api.ErrVaultConflict) {
		if retryOn409 {
			// Someone pushed first: pull their state and re-evaluate once.
			return e.syncLocked(ctx, payload, false)
		}
		return Result{Err: err}
	}
	if err != nil {
		return e.failure(err)
	}
	if err := e.commit(version, fp); err != nil {
		return Result{Err: err}
	}
	e.pending = nil
	return Result{Pushed: true, Version: version}
}

// Resolve settles a pending conflict: keep local (overwrite remote) or take
// remote (discard local changes). payload is the current local payload (only
// used for keep-local).
func (e *Engine) Resolve(ctx context.Context, keepLocal bool, payload []byte) Result {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess == nil || e.closed {
		return Result{SignedOut: true}
	}
	if e.pending == nil {
		// The conflict evaporated (e.g. resolved elsewhere) — re-sync.
		res := e.syncLocked(ctx, payload, true)
		e.persistRotation()
		return res
	}
	var res Result
	if keepLocal {
		res = e.pushLocked(ctx, payload, fingerprint(payload), e.pending.version, false)
		if errors.Is(res.Err, api.ErrVaultConflict) {
			// The remote moved again mid-conflict; start over.
			e.pending = nil
			res = e.syncLocked(ctx, payload, true)
		}
	} else {
		res = Result{Adopt: e.pending.payload, AdoptVersion: e.pending.version}
	}
	e.persistRotation()
	return res
}

// CommitAdopt records that the caller wrote an adopted remote payload into
// the local vault, completing a pull.
func (e *Engine) CommitAdopt(version int64, payload []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess == nil {
		return nil
	}
	e.pending = nil
	return e.commit(version, fingerprint(payload))
}

// commit updates the bookkeeping and persists the session file.
func (e *Engine) commit(version int64, fp string) error {
	e.sess.LastSyncedVersion = version
	e.sess.LastSyncedFingerprint = fp
	return saveSession(e.cfg.SessionPath, e.cfg.Key, e.sess)
}

// failure maps an API error: a dead session signs the device out; anything
// else is a transient (offline) failure.
func (e *Engine) failure(err error) Result {
	if errors.Is(err, api.ErrSessionExpired) {
		os.Remove(e.cfg.SessionPath)
		e.sess = nil
		e.pending = nil
		return Result{SessionDead: true}
	}
	return Result{Err: err}
}

// persistRotation saves the session file when the backend rotated the
// refresh token during the last operation.
func (e *Engine) persistRotation() {
	if e.sess == nil {
		return
	}
	if rt := e.cfg.API.RefreshToken(); rt != "" && rt != e.sess.RefreshToken {
		e.sess.RefreshToken = rt
		_ = saveSession(e.cfg.SessionPath, e.cfg.Key, e.sess)
	}
}

// fingerprint is the content identity of a payload: SHA-256 hex of the
// canonical JSON bytes (store.Save marshals deterministically).
func fingerprint(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// countHosts parses just enough of a payload to count its hosts. An empty or
// unparsable payload counts as zero.
func countHosts(payload []byte) int {
	if len(payload) == 0 {
		return 0
	}
	var doc struct {
		Hosts []json.RawMessage `json:"hosts"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return 0
	}
	return len(doc.Hosts)
}

// zero scrubs a secret in place.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
