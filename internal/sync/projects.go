package sync

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Janne6565/wharf-tui/internal/api"
	"github.com/Janne6565/wharf-tui/internal/store"
)

// ErrNoProjectKey is returned when an operation needs a project's DEK but the
// project has not been synced (unwrapped) this session.
var ErrNoProjectKey = errors.New("sync: project key unavailable")

// ProjectView is a UI snapshot of one project after a sync pass. Payload is the
// decrypted project document (store.ProjectDoc JSON); it is nil when the project
// is awaiting a key or otherwise unreadable.
type ProjectView struct {
	ID                 string
	Name               string
	Description        string
	Role               string
	AwaitingKey        bool
	Version            int64
	MemberCount        int
	PendingInviteCount int
	Payload            []byte
}

// ProjectConflict describes a both-sides-changed project the user must resolve.
type ProjectConflict struct {
	ID              string
	Name            string
	LocalHosts      int
	RemoteHosts     int
	RemoteVersion   int64
	RemoteUpdatedAt time.Time
}

// ProjectsResult is the outcome of one SyncProjects pass.
type ProjectsResult struct {
	SignedOut   bool
	SessionDead bool
	NoIdentity  bool // identity not set — the UI must bootstrap it first
	Err         error
	Views       []ProjectView
	Removed     []string
	Conflicts   []ProjectConflict
}

// ProjectOpResult is the outcome of a single-project operation (push/resolve/
// rotate). Exactly one of Pushed/Adopted/Removed is set on success, or Conflict
// is non-nil when the caller should re-sync, or Err on failure.
type ProjectOpResult struct {
	Payload  []byte
	Version  int64
	Pushed   bool
	Adopted  bool
	Removed  bool
	Conflict *ProjectConflict
	Err      error
}

// SetIdentity installs the caller's X25519 keypair (from the personal vault
// payload). Passing nil clears it. The private key is copied and zeroed on
// Close/replace.
func (e *Engine) SetIdentity(pub, priv []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.identity != nil {
		zero(e.identity.priv)
	}
	if len(pub) == 0 || len(priv) == 0 {
		e.identity = nil
		return
	}
	e.identity = &identityKeys{
		pub:  append([]byte(nil), pub...),
		priv: append([]byte(nil), priv...),
	}
}

// HasIdentity reports whether an identity keypair is loaded.
func (e *Engine) HasIdentity() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.identity != nil
}

// ServerProfile fetches GET /users/me so the UI can check whether the account
// already published a public key during identity bootstrap.
func (e *Engine) ServerProfile(ctx context.Context) (api.Profile, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess == nil || e.closed {
		return api.Profile{}, ErrSignedOut
	}
	return e.cfg.API.Me(ctx)
}

// PublishIdentity publishes the caller's public key. rotate=true replaces an
// existing key and nulls all the caller's wrapped DEKs.
func (e *Engine) PublishIdentity(ctx context.Context, pub []byte, rotate bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess == nil || e.closed {
		return ErrSignedOut
	}
	return e.cfg.API.PublishPublicKey(ctx, pub, rotate)
}

// CreateProject seals an empty project document under a fresh DEK, wraps that
// DEK to the caller's own public key and creates the project. api.ErrNoPublicKey
// (412) propagates so the UI can bootstrap identity and retry.
func (e *Engine) CreateProject(ctx context.Context, name, description string) (ProjectView, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess == nil || e.closed {
		return ProjectView{}, ErrSignedOut
	}
	if e.cfg.ProjectCrypto == nil || e.identity == nil {
		return ProjectView{}, ErrNoIdentity
	}
	pc := e.cfg.ProjectCrypto
	dek, err := pc.NewDEK()
	if err != nil {
		return ProjectView{}, err
	}
	doc := &store.ProjectDoc{Schema: 1}
	payload, err := doc.Marshal()
	if err != nil {
		return ProjectView{}, err
	}
	blob, err := pc.Seal(dek, payload)
	if err != nil {
		return ProjectView{}, err
	}
	wrapped, err := pc.Wrap(dek, e.identity.pub)
	if err != nil {
		return ProjectView{}, err
	}
	detail, err := e.cfg.API.CreateProject(ctx, name, description, blob, wrapped)
	if err != nil {
		return ProjectView{}, err
	}
	e.ensureProjects()
	e.projectDEKs[detail.ID] = dek
	e.sess.Projects[detail.ID] = ProjectSyncState{
		Name:                  detail.Name,
		Role:                  detail.Role,
		LastSyncedVersion:     detail.VaultVersion,
		LastSyncedFingerprint: fingerprint(payload),
		WrappedDek:            base64.StdEncoding.EncodeToString(wrapped),
	}
	e.writeBlobCache(detail.ID, blob)
	_ = saveSession(e.cfg.SessionPath, e.cfg.Key, e.sess)
	return ProjectView{
		ID:          detail.ID,
		Name:        detail.Name,
		Description: detail.Description,
		Role:        detail.Role,
		Version:     detail.VaultVersion,
		MemberCount: len(detail.Members),
		Payload:     payload,
	}, nil
}

// ErrNoIdentity signals that an identity keypair is required but not loaded.
var ErrNoIdentity = errors.New("sync: no identity")

// SyncProjects runs one full projects pass: list projects, drop vanished ones,
// then per project unwrap the caller's DEK, decrypt the blob and run the same
// 2×2 (local-changed × remote-moved) state machine used for the personal vault.
// local maps project ID → the UI's current decrypted payload (absent = none).
func (e *Engine) SyncProjects(ctx context.Context, local map[string][]byte) ProjectsResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess == nil || e.closed {
		return ProjectsResult{SignedOut: true}
	}
	if e.cfg.ProjectCrypto == nil {
		return ProjectsResult{}
	}
	if e.identity == nil {
		return ProjectsResult{NoIdentity: true}
	}
	res := e.syncProjectsLocked(ctx, local)
	e.persistRotation()
	return res
}

func (e *Engine) syncProjectsLocked(ctx context.Context, local map[string][]byte) ProjectsResult {
	pc := e.cfg.ProjectCrypto
	list, err := e.cfg.API.ListProjects(ctx)
	if err != nil {
		if errors.Is(err, api.ErrSessionExpired) {
			e.deadLocked()
			return ProjectsResult{SessionDead: true}
		}
		return ProjectsResult{Err: err}
	}
	e.ensureProjects()

	live := make(map[string]bool, len(list))
	for _, s := range list {
		live[s.ID] = true
	}
	var res ProjectsResult
	for id := range e.sess.Projects {
		if !live[id] {
			e.dropProjectLocked(id)
			res.Removed = append(res.Removed, id)
		}
	}

	var firstErr error
	for _, sum := range list {
		st := e.sess.Projects[sum.ID]
		st.Name, st.Role = sum.Name, sum.Role
		view := ProjectView{
			ID: sum.ID, Name: sum.Name, Description: sum.Description, Role: sum.Role,
			Version: sum.VaultVersion, MemberCount: int(sum.MemberCount),
			PendingInviteCount: int(sum.PendingInviteCount),
		}

		if sum.AwaitingKey {
			e.markAwaiting(sum.ID, st, &view, &res)
			continue
		}

		v, verr := e.cfg.API.GetProjectVault(ctx, sum.ID)
		if errors.Is(verr, api.ErrProjectNotFound) {
			e.dropProjectLocked(sum.ID)
			res.Removed = append(res.Removed, sum.ID)
			continue
		}
		if verr != nil {
			if errors.Is(verr, api.ErrSessionExpired) {
				e.deadLocked()
				return ProjectsResult{SessionDead: true}
			}
			if firstErr == nil {
				firstErr = verr
			}
			continue
		}
		if v.WrappedDek == nil {
			e.markAwaiting(sum.ID, st, &view, &res)
			continue
		}
		dek, uerr := pc.Unwrap(v.WrappedDek, e.identity.pub, e.identity.priv)
		if uerr != nil {
			// The caller's wrapped DEK no longer opens (rotated or foreign key):
			// treat as awaiting until a fresh key is granted.
			e.markAwaiting(sum.ID, st, &view, &res)
			continue
		}
		e.projectDEKs[sum.ID] = dek
		st.WrappedDek = base64.StdEncoding.EncodeToString(v.WrappedDek)
		e.writeBlobCache(sum.ID, v.Blob)
		remotePayload, oerr := pc.Open(dek, v.Blob)
		if oerr != nil {
			e.markAwaiting(sum.ID, st, &view, &res)
			continue
		}

		localPayload := local[sum.ID]
		localChanged := localPayload != nil && fingerprint(localPayload) != st.LastSyncedFingerprint
		remoteMoved := v.Version != st.LastSyncedVersion

		switch {
		case localChanged && !remoteMoved:
			blob, serr := pc.Seal(dek, localPayload)
			if serr != nil {
				if firstErr == nil {
					firstErr = serr
				}
				view.Payload = localPayload
				break
			}
			nv, _, perr := e.cfg.API.PutProjectVault(ctx, sum.ID, blob, v.Version)
			if errors.Is(perr, api.ErrVaultConflict) {
				e.refetchProjectConflict(ctx, sum, dek, localPayload, &st, &view, &res)
				break
			}
			if perr != nil {
				if errors.Is(perr, api.ErrSessionExpired) {
					e.deadLocked()
					return ProjectsResult{SessionDead: true}
				}
				if firstErr == nil {
					firstErr = perr
				}
				view.Payload = localPayload
				break
			}
			e.writeBlobCache(sum.ID, blob)
			st.LastSyncedVersion = nv
			st.LastSyncedFingerprint = fingerprint(localPayload)
			view.Version = nv
			view.Payload = localPayload

		case !localChanged && (remoteMoved || localPayload == nil):
			// Fast-forward pull (also the first-sight case).
			st.LastSyncedVersion = v.Version
			st.LastSyncedFingerprint = fingerprint(remotePayload)
			view.Version = v.Version
			view.Payload = remotePayload

		case localChanged && remoteMoved:
			if fingerprint(localPayload) == fingerprint(remotePayload) {
				st.LastSyncedVersion = v.Version
				st.LastSyncedFingerprint = fingerprint(remotePayload)
				view.Version = v.Version
				view.Payload = remotePayload
			} else {
				e.pendingProjects[sum.ID] = &pendingRemote{payload: remotePayload, version: v.Version}
				res.Conflicts = append(res.Conflicts, ProjectConflict{
					ID: sum.ID, Name: sum.Name,
					LocalHosts: countHosts(localPayload), RemoteHosts: countHosts(remotePayload),
					RemoteVersion: v.Version, RemoteUpdatedAt: v.UpdatedAt,
				})
				view.Payload = localPayload
			}

		default: // in sync
			st.LastSyncedVersion = v.Version
			st.LastSyncedFingerprint = fingerprint(remotePayload)
			view.Version = v.Version
			view.Payload = remotePayload
		}

		e.sess.Projects[sum.ID] = st
		res.Views = append(res.Views, view)
	}

	_ = saveSession(e.cfg.SessionPath, e.cfg.Key, e.sess)
	if firstErr != nil {
		res.Err = firstErr
	}
	return res
}

// refetchProjectConflict handles a lost push race: it re-reads the remote,
// and either fast-forwards (identical content) or queues a conflict.
func (e *Engine) refetchProjectConflict(ctx context.Context, sum api.ProjectSummary, dek, localPayload []byte, st *ProjectSyncState, view *ProjectView, res *ProjectsResult) {
	view.Payload = localPayload
	v, err := e.cfg.API.GetProjectVault(ctx, sum.ID)
	if err != nil || v.WrappedDek == nil {
		return
	}
	remotePayload, oerr := e.cfg.ProjectCrypto.Open(dek, v.Blob)
	if oerr != nil {
		return
	}
	if fingerprint(localPayload) == fingerprint(remotePayload) {
		st.LastSyncedVersion = v.Version
		st.LastSyncedFingerprint = fingerprint(remotePayload)
		view.Version = v.Version
		view.Payload = remotePayload
		return
	}
	e.pendingProjects[sum.ID] = &pendingRemote{payload: remotePayload, version: v.Version}
	res.Conflicts = append(res.Conflicts, ProjectConflict{
		ID: sum.ID, Name: sum.Name,
		LocalHosts: countHosts(localPayload), RemoteHosts: countHosts(remotePayload),
		RemoteVersion: v.Version, RemoteUpdatedAt: v.UpdatedAt,
	})
}

// markAwaiting records a project the caller cannot currently read.
func (e *Engine) markAwaiting(id string, st ProjectSyncState, view *ProjectView, res *ProjectsResult) {
	view.AwaitingKey = true
	view.Payload = nil
	delete(e.projectDEKs, id)
	e.sess.Projects[id] = st
	res.Views = append(res.Views, *view)
}

// ResolveProject settles a pending per-project conflict: keep local (push over
// remote) or take remote (adopt).
func (e *Engine) ResolveProject(ctx context.Context, id string, keepLocal bool, localPayload []byte) ProjectOpResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess == nil || e.closed {
		return ProjectOpResult{Err: ErrSignedOut}
	}
	pend := e.pendingProjects[id]
	if pend == nil {
		return ProjectOpResult{} // conflict evaporated
	}
	st := e.sess.Projects[id]
	if !keepLocal {
		st.LastSyncedVersion = pend.version
		st.LastSyncedFingerprint = fingerprint(pend.payload)
		e.sess.Projects[id] = st
		payload := pend.payload
		delete(e.pendingProjects, id)
		_ = saveSession(e.cfg.SessionPath, e.cfg.Key, e.sess)
		return ProjectOpResult{Adopted: true, Version: st.LastSyncedVersion, Payload: payload}
	}
	dek := e.projectDEKs[id]
	if dek == nil {
		return ProjectOpResult{Err: ErrNoProjectKey}
	}
	blob, err := e.cfg.ProjectCrypto.Seal(dek, localPayload)
	if err != nil {
		return ProjectOpResult{Err: err}
	}
	nv, _, err := e.cfg.API.PutProjectVault(ctx, id, blob, pend.version)
	if errors.Is(err, api.ErrVaultConflict) {
		delete(e.pendingProjects, id)
		return ProjectOpResult{Conflict: &ProjectConflict{ID: id}}
	}
	if err != nil {
		return ProjectOpResult{Err: err}
	}
	e.writeBlobCache(id, blob)
	st.LastSyncedVersion = nv
	st.LastSyncedFingerprint = fingerprint(localPayload)
	e.sess.Projects[id] = st
	delete(e.pendingProjects, id)
	_ = saveSession(e.cfg.SessionPath, e.cfg.Key, e.sess)
	return ProjectOpResult{Pushed: true, Version: nv, Payload: localPayload}
}

// PushProject seals and uploads an edited project document with optimistic
// versioning. A 409 returns a Conflict marker (the UI re-runs SyncProjects to
// surface the resolve prompt).
func (e *Engine) PushProject(ctx context.Context, id string, payload []byte) ProjectOpResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess == nil || e.closed {
		return ProjectOpResult{Err: ErrSignedOut}
	}
	dek := e.projectDEKs[id]
	if dek == nil {
		return ProjectOpResult{Err: ErrNoProjectKey}
	}
	st := e.sess.Projects[id]
	blob, err := e.cfg.ProjectCrypto.Seal(dek, payload)
	if err != nil {
		return ProjectOpResult{Err: err}
	}
	nv, _, err := e.cfg.API.PutProjectVault(ctx, id, blob, st.LastSyncedVersion)
	if errors.Is(err, api.ErrVaultConflict) {
		return ProjectOpResult{Conflict: &ProjectConflict{ID: id}}
	}
	if errors.Is(err, api.ErrProjectNotFound) {
		e.dropProjectLocked(id)
		return ProjectOpResult{Removed: true}
	}
	if err != nil {
		return ProjectOpResult{Err: err}
	}
	e.writeBlobCache(id, blob)
	st.LastSyncedVersion = nv
	st.LastSyncedFingerprint = fingerprint(payload)
	e.sess.Projects[id] = st
	_ = saveSession(e.cfg.SessionPath, e.cfg.Key, e.sess)
	return ProjectOpResult{Pushed: true, Version: nv, Payload: payload}
}

// RemoveMember performs a client-side re-key: it draws a fresh DEK, re-seals the
// project document, re-wraps the DEK for every remaining recipient that has a
// published public key, and posts an atomic rotate that also removes removeUserID
// (pass "" to rotate the key without removing anyone). recipients is the set of
// members to keep keyed (userId + published pubkey). A 409 refetches and retries
// once.
func (e *Engine) RemoveMember(ctx context.Context, projectID, removeUserID string, payload []byte, recipients []api.PendingKey) ProjectOpResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess == nil || e.closed {
		return ProjectOpResult{Err: ErrSignedOut}
	}
	if e.cfg.ProjectCrypto == nil || e.identity == nil {
		return ProjectOpResult{Err: ErrNoIdentity}
	}
	pc := e.cfg.ProjectCrypto
	newDEK, err := pc.NewDEK()
	if err != nil {
		return ProjectOpResult{Err: err}
	}
	wraps, selfWrapped, err := e.wrapForRecipients(newDEK, recipients)
	if err != nil {
		return ProjectOpResult{Err: err}
	}
	st := e.sess.Projects[projectID]
	blob, err := pc.Seal(newDEK, payload)
	if err != nil {
		return ProjectOpResult{Err: err}
	}
	nv, _, err := e.cfg.API.RotateProject(ctx, projectID, api.RotateRequest{
		RemoveUserID: removeUserID, Blob: blob, ExpectedVersion: st.LastSyncedVersion, WrappedKeys: wraps,
	})
	if errors.Is(err, api.ErrVaultConflict) {
		// Refetch current remote and retry once with the fresh version/payload.
		if v, gerr := e.cfg.API.GetProjectVault(ctx, projectID); gerr == nil && v.WrappedDek != nil {
			if od, uerr := pc.Unwrap(v.WrappedDek, e.identity.pub, e.identity.priv); uerr == nil {
				if fresh, oerr := pc.Open(od, v.Blob); oerr == nil {
					payload = fresh
					if b2, serr := pc.Seal(newDEK, fresh); serr == nil {
						nv, _, err = e.cfg.API.RotateProject(ctx, projectID, api.RotateRequest{
							RemoveUserID: removeUserID, Blob: b2, ExpectedVersion: v.Version, WrappedKeys: wraps,
						})
						blob = b2
					}
				}
			}
		}
	}
	if err != nil {
		if errors.Is(err, api.ErrVaultConflict) {
			return ProjectOpResult{Conflict: &ProjectConflict{ID: projectID}}
		}
		return ProjectOpResult{Err: err}
	}
	e.projectDEKs[projectID] = newDEK
	e.writeBlobCache(projectID, blob)
	st.LastSyncedVersion = nv
	st.LastSyncedFingerprint = fingerprint(payload)
	if selfWrapped != nil {
		st.WrappedDek = base64.StdEncoding.EncodeToString(selfWrapped)
	}
	e.sess.Projects[projectID] = st
	_ = saveSession(e.cfg.SessionPath, e.cfg.Key, e.sess)
	return ProjectOpResult{Pushed: true, Version: nv, Payload: payload}
}

// wrapForRecipients seals dek to every recipient that has a public key, and
// returns the caller's own wrapped copy (nil if the caller was not listed).
func (e *Engine) wrapForRecipients(dek []byte, recipients []api.PendingKey) ([]api.WrappedKey, []byte, error) {
	var wraps []api.WrappedKey
	var self []byte
	for _, r := range recipients {
		if len(r.PublicKey) == 0 {
			continue
		}
		w, err := e.cfg.ProjectCrypto.Wrap(dek, r.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		wraps = append(wraps, api.WrappedKey{UserID: r.UserID, WrappedDek: w})
		if r.UserID == e.sess.UserID {
			self = w
		}
	}
	return wraps, self, nil
}

// FinalizeProjects is the admin/owner pass: for every keyed project the caller
// administers, seal the DEK to each pending member that has published a public
// key. A stale-version 409 is skipped silently (it resolves on the next pass).
// Returns the number of keys granted.
func (e *Engine) FinalizeProjects(ctx context.Context) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess == nil || e.closed || e.cfg.ProjectCrypto == nil || e.identity == nil {
		return 0
	}
	granted := 0
	for id, st := range e.sess.Projects {
		role := strings.ToUpper(st.Role)
		if role != "ADMIN" && role != "OWNER" {
			continue
		}
		dek := e.projectDEKs[id]
		if dek == nil {
			continue
		}
		pks, err := e.cfg.API.GetPendingKeys(ctx, id)
		if err != nil {
			continue
		}
		for _, pk := range pks {
			if len(pk.PublicKey) == 0 {
				continue
			}
			wrapped, werr := e.cfg.ProjectCrypto.Wrap(dek, pk.PublicKey)
			if werr != nil {
				continue
			}
			if serr := e.cfg.API.SubmitMemberKey(ctx, id, pk.UserID, wrapped, st.LastSyncedVersion); serr == nil {
				granted++
			}
		}
	}
	return granted
}

// FetchInvites returns the caller's pending received invites.
func (e *Engine) FetchInvites(ctx context.Context) ([]api.ReceivedInvite, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess == nil || e.closed {
		return nil, ErrSignedOut
	}
	return e.cfg.API.ListMyInvites(ctx)
}

// ProjectDetail fetches the full project detail (members + invites).
func (e *Engine) ProjectDetail(ctx context.Context, id string) (api.ProjectDetail, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess == nil || e.closed {
		return api.ProjectDetail{}, ErrSignedOut
	}
	return e.cfg.API.GetProject(ctx, id)
}

// CreateInvite invites an email to a project (admin+).
func (e *Engine) CreateInvite(ctx context.Context, projectID, email string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess == nil || e.closed {
		return ErrSignedOut
	}
	_, err := e.cfg.API.CreateInvite(ctx, projectID, email)
	return err
}

// RevokeInvite deletes a pending invite (admin+).
func (e *Engine) RevokeInvite(ctx context.Context, projectID, inviteID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess == nil || e.closed {
		return ErrSignedOut
	}
	return e.cfg.API.DeleteInvite(ctx, projectID, inviteID)
}

// AcceptInvite joins a project as an awaiting-key member.
func (e *Engine) AcceptInvite(ctx context.Context, inviteID string) (api.ProjectSummary, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess == nil || e.closed {
		return api.ProjectSummary{}, ErrSignedOut
	}
	return e.cfg.API.AcceptInvite(ctx, inviteID)
}

// DeclineInvite declines a received invite.
func (e *Engine) DeclineInvite(ctx context.Context, inviteID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess == nil || e.closed {
		return ErrSignedOut
	}
	return e.cfg.API.DeclineInvite(ctx, inviteID)
}

// LoadCachedProjects opens the on-disk project blob cache using the persisted
// wrapped DEKs, so an unlocked-but-offline client can render project hosts
// before (or without) a network sync.
func (e *Engine) LoadCachedProjects() []ProjectView {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess == nil || e.closed || e.cfg.ProjectCrypto == nil || e.identity == nil {
		return nil
	}
	pc := e.cfg.ProjectCrypto
	var out []ProjectView
	for id, st := range e.sess.Projects {
		view := ProjectView{ID: id, Name: st.Name, Role: st.Role, Version: st.LastSyncedVersion}
		wd, err := base64.StdEncoding.DecodeString(st.WrappedDek)
		if err != nil || len(wd) == 0 {
			view.AwaitingKey = true
			out = append(out, view)
			continue
		}
		dek, err := pc.Unwrap(wd, e.identity.pub, e.identity.priv)
		if err != nil {
			view.AwaitingKey = true
			out = append(out, view)
			continue
		}
		blob, err := os.ReadFile(e.blobCachePath(id))
		if err != nil {
			view.AwaitingKey = true
			out = append(out, view)
			continue
		}
		payload, err := pc.Open(dek, blob)
		if err != nil {
			view.AwaitingKey = true
			out = append(out, view)
			continue
		}
		e.projectDEKs[id] = dek
		view.Payload = payload
		out = append(out, view)
	}
	return out
}

// --- internals ----------------------------------------------------------------

func (e *Engine) ensureProjects() {
	if e.sess.Projects == nil {
		e.sess.Projects = map[string]ProjectSyncState{}
	}
	if e.projectDEKs == nil {
		e.projectDEKs = map[string][]byte{}
	}
	if e.pendingProjects == nil {
		e.pendingProjects = map[string]*pendingRemote{}
	}
}

// deadLocked signs the device out under an already-held lock.
func (e *Engine) deadLocked() {
	os.Remove(e.cfg.SessionPath)
	e.sess = nil
	e.pending = nil
	e.pendingProjects = map[string]*pendingRemote{}
}

// dropProjectLocked forgets a project whose membership vanished.
func (e *Engine) dropProjectLocked(id string) {
	if dek := e.projectDEKs[id]; dek != nil {
		zero(dek)
	}
	delete(e.projectDEKs, id)
	delete(e.pendingProjects, id)
	if e.sess != nil {
		delete(e.sess.Projects, id)
	}
	os.Remove(e.blobCachePath(id))
}

// projectsDir is the blob-cache directory next to the session file.
func (e *Engine) projectsDir() string {
	return filepath.Join(filepath.Dir(e.cfg.SessionPath), "projects")
}

func (e *Engine) blobCachePath(id string) string {
	return filepath.Join(e.projectsDir(), id+".blob")
}

// writeBlobCache persists a project's opaque blob for offline opens (best-effort).
func (e *Engine) writeBlobCache(id string, blob []byte) {
	if err := os.MkdirAll(e.projectsDir(), 0700); err != nil {
		return
	}
	_ = os.WriteFile(e.blobCachePath(id), blob, 0600)
}
