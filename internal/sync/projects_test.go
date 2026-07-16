package sync

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/Janne6565/wharf-tui/internal/api"
	"github.com/Janne6565/wharf-tui/internal/store"
)

// --- fake project crypto -------------------------------------------------------

// fakeCrypto is a deterministic, non-cryptographic stand-in for the vault
// project crypto so engine tests reason about bytes, not ciphertext:
//   - Seal(dek,payload)   = dek(32) ++ payload   (Open requires the same dek)
//   - Wrap(dek,pub)       = pub ++ dek           (Unwrap requires the same pub)
type fakeCrypto struct{}

func (fakeCrypto) NewDEK() ([]byte, error) {
	dek := make([]byte, 32)
	_, err := rand.Read(dek)
	return dek, err
}

func (fakeCrypto) Seal(dek, payload []byte) ([]byte, error) {
	if len(dek) != 32 {
		return nil, errors.New("fake: bad dek")
	}
	return append(append([]byte(nil), dek...), payload...), nil
}

func (fakeCrypto) Open(dek, blob []byte) ([]byte, error) {
	if len(blob) < 32 || !bytes.Equal(blob[:32], dek) {
		return nil, errors.New("fake: wrong dek")
	}
	return append([]byte(nil), blob[32:]...), nil
}

func (fakeCrypto) Wrap(dek, pub []byte) ([]byte, error) {
	return append(append([]byte(nil), pub...), dek...), nil
}

func (fakeCrypto) Unwrap(wrapped, pub, priv []byte) ([]byte, error) {
	if len(wrapped) < len(pub) || !bytes.Equal(wrapped[:len(pub)], pub) {
		return nil, errors.New("fake: wrong recipient")
	}
	return append([]byte(nil), wrapped[len(pub):]...), nil
}

// pub/priv for a given user id in the fake identity space.
func fakePub(uid string) []byte  { return []byte("PUB:" + uid) }
func fakePriv(uid string) []byte { return []byte("PRIV:" + uid) }

// --- fakeAPI project methods ---------------------------------------------------

func (f *fakeAPI) uid() string {
	if f.userID == "" {
		return "u1"
	}
	return f.userID
}

func (f *fakeAPI) Me(context.Context) (api.Profile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := api.Profile{ID: f.uid(), Email: "d@example.com"}
	if len(f.publicKey) > 0 {
		p.PublicKey = string(f.publicKey)
	}
	return p, nil
}

func (f *fakeAPI) PublishPublicKey(_ context.Context, pub []byte, rotate bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.publicKey) > 0 && !rotate {
		return api.ErrPublicKeyExists
	}
	f.publicKey = append([]byte(nil), pub...)
	return nil
}

func (f *fakeAPI) ListProjects(context.Context) ([]api.ProjectSummary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []api.ProjectSummary
	for _, p := range f.fakeProjs {
		_, keyed := p.wrapped[f.uid()]
		out = append(out, api.ProjectSummary{
			ID: p.id, Name: p.name, Description: p.desc, Role: p.role,
			MemberCount: int64(len(p.members)), PendingInviteCount: int64(len(p.invites)),
			VaultVersion: p.version, AwaitingKey: !keyed,
		})
	}
	return out, nil
}

func (f *fakeAPI) GetProject(_ context.Context, id string) (api.ProjectDetail, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.fakeProjs[id]
	if p == nil {
		return api.ProjectDetail{}, api.ErrProjectNotFound
	}
	return api.ProjectDetail{
		ID: p.id, Name: p.name, Description: p.desc, Role: p.role,
		VaultVersion: p.version, Members: p.members, Invites: p.invites,
	}, nil
}

func (f *fakeAPI) CreateProject(_ context.Context, name, description string, blob, wrappedDek []byte) (api.ProjectDetail, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.publicKey) == 0 {
		return api.ProjectDetail{}, api.ErrNoPublicKey
	}
	if f.fakeProjs == nil {
		f.fakeProjs = map[string]*fakeProject{}
	}
	id := "p" + itoaLen(len(f.fakeProjs)+1)
	p := &fakeProject{
		id: id, name: name, desc: description, role: "OWNER",
		vault: append([]byte(nil), blob...), version: 1,
		wrapped: map[string][]byte{f.uid(): append([]byte(nil), wrappedDek...)},
		members: []api.ProjectMember{{UserID: f.uid(), Email: "d@example.com", Role: "OWNER", Keyed: true, PublicKey: f.publicKey}},
	}
	f.fakeProjs[id] = p
	return api.ProjectDetail{ID: id, Name: name, Description: description, Role: "OWNER", VaultVersion: 1, Members: p.members}, nil
}

func (f *fakeAPI) GetProjectVault(_ context.Context, id string) (api.ProjectVaultResp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.fakeProjs[id]
	if p == nil {
		return api.ProjectVaultResp{}, api.ErrProjectNotFound
	}
	resp := api.ProjectVaultResp{Blob: append([]byte(nil), p.vault...), Version: p.version}
	if w, ok := p.wrapped[f.uid()]; ok {
		resp.WrappedDek = append([]byte(nil), w...)
	}
	return resp, nil
}

func (f *fakeAPI) PutProjectVault(_ context.Context, id string, blob []byte, expectedVersion int64) (int64, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.fakeProjs[id]
	if p == nil {
		return 0, time.Time{}, api.ErrProjectNotFound
	}
	if _, keyed := p.wrapped[f.uid()]; !keyed {
		return 0, time.Time{}, &api.Error{Status: 403, Detail: "no key"}
	}
	if expectedVersion != p.version {
		return 0, time.Time{}, api.ErrVaultConflict
	}
	p.vault = append([]byte(nil), blob...)
	p.version++
	return p.version, time.Time{}, nil
}

func (f *fakeAPI) RotateProject(_ context.Context, id string, req api.RotateRequest) (int64, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.fakeProjs[id]
	if p == nil {
		return 0, time.Time{}, api.ErrProjectNotFound
	}
	if req.ExpectedVersion != p.version {
		return 0, time.Time{}, api.ErrVaultConflict
	}
	if req.RemoveUserID != "" {
		var kept []api.ProjectMember
		for _, m := range p.members {
			if m.UserID != req.RemoveUserID {
				kept = append(kept, m)
			}
		}
		p.members = kept
	}
	p.vault = append([]byte(nil), req.Blob...)
	p.version++
	p.wrapped = map[string][]byte{}
	for _, wk := range req.WrappedKeys {
		p.wrapped[wk.UserID] = append([]byte(nil), wk.WrappedDek...)
	}
	return p.version, time.Time{}, nil
}

func (f *fakeAPI) CreateInvite(_ context.Context, id, email string) (api.ProjectInvite, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.fakeProjs[id]
	if p == nil {
		return api.ProjectInvite{}, api.ErrProjectNotFound
	}
	inv := api.ProjectInvite{ID: "inv" + itoaLen(len(p.invites)+1), Email: email}
	p.invites = append(p.invites, inv)
	return inv, nil
}

func (f *fakeAPI) DeleteInvite(_ context.Context, projectID, inviteID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.fakeProjs[projectID]
	if p == nil {
		return api.ErrProjectNotFound
	}
	var kept []api.ProjectInvite
	for _, inv := range p.invites {
		if inv.ID != inviteID {
			kept = append(kept, inv)
		}
	}
	p.invites = kept
	return nil
}

func (f *fakeAPI) ListMyInvites(context.Context) ([]api.ReceivedInvite, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]api.ReceivedInvite(nil), f.myInvites...), nil
}

func (f *fakeAPI) AcceptInvite(_ context.Context, inviteID string) (api.ProjectSummary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return api.ProjectSummary{ID: inviteID}, nil
}

func (f *fakeAPI) DeclineInvite(context.Context, string) error { return nil }

func (f *fakeAPI) GetPendingKeys(_ context.Context, id string) ([]api.PendingKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.fakeProjs[id]
	if p == nil {
		return nil, api.ErrProjectNotFound
	}
	return append([]api.PendingKey(nil), p.pending...), nil
}

func (f *fakeAPI) SubmitMemberKey(_ context.Context, projectID, userID string, wrappedDek []byte, vaultVersion int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.fakeProjs[projectID]
	if p == nil {
		return api.ErrProjectNotFound
	}
	if vaultVersion != p.version {
		return api.ErrVaultConflict
	}
	if p.wrapped == nil {
		p.wrapped = map[string][]byte{}
	}
	p.wrapped[userID] = append([]byte(nil), wrappedDek...)
	// clear the pending entry
	var kept []api.PendingKey
	for _, pk := range p.pending {
		if pk.UserID != userID {
			kept = append(kept, pk)
		}
	}
	p.pending = kept
	f.keySubmits++
	return nil
}

// --- engine project tests ------------------------------------------------------

func projectEngine(t *testing.T, f *fakeAPI) *Engine {
	t.Helper()
	var local []byte
	e := testEngine(t, f, &local)
	e.cfg.ProjectCrypto = fakeCrypto{}
	e.SetIdentity(fakePub("u1"), fakePriv("u1"))
	f.publicKey = fakePub("u1")
	return e
}

func TestCreateAndSyncProject(t *testing.T) {
	f := &fakeAPI{noVault: true}
	e := projectEngine(t, f)

	view, err := e.CreateProject(context.Background(), "atlas", "core")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if view.ID == "" || view.Role != "OWNER" {
		t.Fatalf("unexpected create view: %+v", view)
	}
	doc, err := store.OpenProjectDoc(view.Payload)
	if err != nil || len(doc.HostList()) != 0 {
		t.Fatalf("fresh project should open to an empty doc: %v", err)
	}

	// A follow-up sync with the same local payload must be a no-op (no conflict).
	res := e.SyncProjects(context.Background(), map[string][]byte{view.ID: view.Payload})
	if res.Err != nil || len(res.Conflicts) != 0 {
		t.Fatalf("resync should be clean, got err=%v conflicts=%d", res.Err, len(res.Conflicts))
	}
	if len(res.Views) != 1 || res.Views[0].AwaitingKey {
		t.Fatalf("owner should read its own project: %+v", res.Views)
	}
}

func TestSyncProjectPushesLocalEdit(t *testing.T) {
	f := &fakeAPI{noVault: true}
	e := projectEngine(t, f)
	view, _ := e.CreateProject(context.Background(), "atlas", "")

	// Edit the doc locally (add a host) and sync → engine should push.
	doc, _ := store.OpenProjectDoc(view.Payload)
	if _, err := doc.AddHost(store.Host{Name: "web", Addr: "a.com"}); err != nil {
		t.Fatalf("add host: %v", err)
	}
	edited, _ := doc.Marshal()

	res := e.SyncProjects(context.Background(), map[string][]byte{view.ID: edited})
	if res.Err != nil {
		t.Fatalf("sync err: %v", res.Err)
	}
	f.mu.Lock()
	stored := f.fakeProjs[view.ID].vault
	f.mu.Unlock()
	// The pushed blob (dek||payload) must contain the new host name.
	if !bytes.Contains(stored, []byte("web")) {
		t.Fatal("edited host should be pushed to the project vault")
	}
}

func TestSyncProjectConflict(t *testing.T) {
	f := &fakeAPI{noVault: true}
	e := projectEngine(t, f)
	view, _ := e.CreateProject(context.Background(), "atlas", "")

	// Local edit.
	ldoc, _ := store.OpenProjectDoc(view.Payload)
	ldoc.AddHost(store.Host{Name: "local", Addr: "l.com"})
	localPayload, _ := ldoc.Marshal()

	// Simulate a concurrent remote edit at a higher version, sealed under the
	// project's current DEK (the caller's cached one).
	dek := e.projectDEKs[view.ID]
	rdoc, _ := store.OpenProjectDoc(view.Payload)
	rdoc.AddHost(store.Host{Name: "remote", Addr: "r.com"})
	remotePayload, _ := rdoc.Marshal()
	rblob, _ := fakeCrypto{}.Seal(dek, remotePayload)
	f.mu.Lock()
	f.fakeProjs[view.ID].vault = rblob
	f.fakeProjs[view.ID].version = 5
	f.mu.Unlock()

	res := e.SyncProjects(context.Background(), map[string][]byte{view.ID: localPayload})
	if len(res.Conflicts) != 1 {
		t.Fatalf("both-changed should conflict, got %d conflicts (err=%v)", len(res.Conflicts), res.Err)
	}

	// Resolve keep-local → the local host wins on the server.
	op := e.ResolveProject(context.Background(), view.ID, true, localPayload)
	if op.Err != nil || !op.Pushed {
		t.Fatalf("keep-local resolve should push: %+v", op)
	}
	f.mu.Lock()
	stored := f.fakeProjs[view.ID].vault
	f.mu.Unlock()
	if !bytes.Contains(stored, []byte("local")) {
		t.Fatal("keep-local must overwrite the remote with the local doc")
	}
}

func TestFinalizeGrantsPendingKey(t *testing.T) {
	f := &fakeAPI{noVault: true}
	e := projectEngine(t, f)
	view, _ := e.CreateProject(context.Background(), "atlas", "")

	// A second member joined and published a key, awaiting finalize.
	f.mu.Lock()
	p := f.fakeProjs[view.ID]
	p.pending = []api.PendingKey{{UserID: "u2", Email: "b@example.com", PublicKey: fakePub("u2")}}
	f.mu.Unlock()

	// Ensure the DEK is cached (create already cached it). Finalize should wrap.
	if n := e.FinalizeProjects(context.Background()); n != 1 {
		t.Fatalf("finalize should grant 1 key, got %d", n)
	}
	f.mu.Lock()
	wrapped, ok := p.wrapped["u2"]
	f.mu.Unlock()
	if !ok {
		t.Fatal("finalize should have sealed the DEK for u2")
	}
	// u2 can unwrap with its own identity.
	if _, err := (fakeCrypto{}).Unwrap(wrapped, fakePub("u2"), fakePriv("u2")); err != nil {
		t.Fatalf("u2 should unwrap the granted key: %v", err)
	}
}

func TestRemoveMemberRotates(t *testing.T) {
	f := &fakeAPI{noVault: true}
	e := projectEngine(t, f)
	view, _ := e.CreateProject(context.Background(), "atlas", "")

	// Add u2 as a keyed member directly.
	f.mu.Lock()
	p := f.fakeProjs[view.ID]
	p.wrapped["u2"] = []byte("PUB:u2somekey")
	p.members = append(p.members, api.ProjectMember{UserID: "u2", Email: "b@example.com", Role: "MEMBER", Keyed: true, PublicKey: fakePub("u2")})
	f.mu.Unlock()

	// Remove u2: keep only the owner (u1).
	op := e.RemoveMember(context.Background(), view.ID, "u2", view.Payload,
		[]api.PendingKey{{UserID: "u1", PublicKey: fakePub("u1")}})
	if op.Err != nil || !op.Pushed {
		t.Fatalf("remove should rotate+push: %+v", op)
	}
	f.mu.Lock()
	_, u2Keyed := p.wrapped["u2"]
	_, u1Keyed := p.wrapped["u1"]
	memberCount := len(p.members)
	f.mu.Unlock()
	if u2Keyed {
		t.Fatal("removed member must lose its wrapped key")
	}
	if !u1Keyed {
		t.Fatal("owner must keep a wrapped key after rotation")
	}
	if memberCount != 1 {
		t.Fatalf("member should be removed, got %d members", memberCount)
	}
}

// itoaLen is a tiny int→string for fake IDs (avoids importing strconv here).
func itoaLen(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
