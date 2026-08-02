package ui

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Janne6565/wharf-tui/internal/api"
	"github.com/Janne6565/wharf-tui/internal/identity"
	"github.com/Janne6565/wharf-tui/internal/store"
	tea "github.com/charmbracelet/bubbletea"
)

// --- fake project crypto + identity (mirrors internal/sync test doubles) -------

type fakeProjCrypto struct{}

func (fakeProjCrypto) NewDEK() ([]byte, error) { return bytesFill("dek", 32), nil }
func (fakeProjCrypto) Seal(dek, payload []byte) ([]byte, error) {
	return append(append([]byte(nil), dek...), payload...), nil
}
func (fakeProjCrypto) Open(dek, blob []byte) ([]byte, error) {
	if len(blob) < 32 || !bytes.Equal(blob[:32], dek) {
		return nil, errors.New("fake: wrong dek")
	}
	return append([]byte(nil), blob[32:]...), nil
}
func (fakeProjCrypto) Wrap(dek, pub []byte) ([]byte, error) {
	return append(append([]byte(nil), pub...), dek...), nil
}
func (fakeProjCrypto) Unwrap(wrapped, pub, priv []byte) ([]byte, error) {
	if len(wrapped) < len(pub) || !bytes.Equal(wrapped[:len(pub)], pub) {
		return nil, errors.New("fake: wrong recipient")
	}
	return append([]byte(nil), wrapped[len(pub):]...), nil
}

func bytesFill(seed string, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed[i%len(seed)]
	}
	return b
}

func fakeIdentity() (pub, priv []byte, err error) {
	return bytesFill("u1pubkey", 32), bytesFill("u1privkey", 32), nil
}

func u2pub() []byte { return bytesFill("u2pubkey", 32) }

// --- fakeBackend project methods ----------------------------------------------

func (f *fakeBackend) uid() string {
	if f.userID == "" {
		return "u1"
	}
	return f.userID
}

func (f *fakeBackend) Me(context.Context) (api.Profile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.meErr != nil {
		return api.Profile{}, f.meErr
	}
	p := api.Profile{
		ID:          f.uid(),
		Email:       "deniz@example.com",
		HasVault:    !f.noVault,
		HasPassword: !f.noVault,
		HasRecovery: !f.noVault,
	}
	if len(f.publicKey) > 0 {
		// Base64 like the real backend: the published-key check compares against
		// exactly this encoding.
		p.PublicKey = base64.StdEncoding.EncodeToString(f.publicKey)
	}
	return p, nil
}

func (f *fakeBackend) PublishPublicKey(_ context.Context, pub []byte, rotate bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.publicKey) > 0 && !rotate {
		return api.ErrPublicKeyExists
	}
	f.publicKey = append([]byte(nil), pub...)
	return nil
}

func (f *fakeBackend) ListProjects(context.Context) ([]api.ProjectSummary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []api.ProjectSummary
	for _, p := range f.projs {
		_, keyed := p.wrapped[f.uid()]
		out = append(out, api.ProjectSummary{
			ID: p.id, Name: p.name, Description: p.desc, Role: p.role,
			MemberCount: int64(len(p.members)), PendingInviteCount: int64(len(p.invites)),
			VaultVersion: p.version, AwaitingKey: !keyed,
		})
	}
	return out, nil
}

func (f *fakeBackend) GetProject(_ context.Context, id string) (api.ProjectDetail, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.projs[id]
	if p == nil {
		return api.ProjectDetail{}, api.ErrProjectNotFound
	}
	return api.ProjectDetail{
		ID: p.id, Name: p.name, Description: p.desc, Role: p.role,
		VaultVersion: p.version, Members: p.members, Invites: p.invites,
	}, nil
}

func (f *fakeBackend) CreateProject(_ context.Context, name, description string, blob, wrappedDek []byte) (api.ProjectDetail, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.publicKey) == 0 {
		return api.ProjectDetail{}, api.ErrNoPublicKey
	}
	if f.projs == nil {
		f.projs = map[string]*fakeProjRow{}
	}
	id := "proj" + itoa(len(f.projs)+1)
	p := &fakeProjRow{
		id: id, name: name, desc: description, role: "OWNER",
		vault: append([]byte(nil), blob...), version: 1,
		wrapped: map[string][]byte{f.uid(): append([]byte(nil), wrappedDek...)},
		members: []api.ProjectMember{{UserID: f.uid(), Email: "deniz@example.com", Role: "OWNER", Keyed: true, PublicKey: f.publicKey}},
	}
	f.projs[id] = p
	return api.ProjectDetail{ID: id, Name: name, Description: description, Role: "OWNER", VaultVersion: 1, Members: p.members}, nil
}

func (f *fakeBackend) GetProjectVault(_ context.Context, id string) (api.ProjectVaultResp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.projs[id]
	if p == nil {
		return api.ProjectVaultResp{}, api.ErrProjectNotFound
	}
	resp := api.ProjectVaultResp{Blob: append([]byte(nil), p.vault...), Version: p.version}
	if w, ok := p.wrapped[f.uid()]; ok {
		resp.WrappedDek = append([]byte(nil), w...)
	}
	return resp, nil
}

func (f *fakeBackend) PutProjectVault(_ context.Context, id string, blob []byte, expectedVersion int64) (int64, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.projs[id]
	if p == nil {
		return 0, time.Time{}, api.ErrProjectNotFound
	}
	if expectedVersion != p.version {
		return 0, time.Time{}, api.ErrVaultConflict
	}
	p.vault = append([]byte(nil), blob...)
	p.version++
	return p.version, time.Time{}, nil
}

func (f *fakeBackend) RotateProject(_ context.Context, id string, req api.RotateRequest) (int64, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.projs[id]
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

func (f *fakeBackend) CreateInvite(_ context.Context, id, email string) (api.ProjectInvite, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.projs[id]
	if p == nil {
		return api.ProjectInvite{}, api.ErrProjectNotFound
	}
	inv := api.ProjectInvite{ID: "inv" + itoa(len(p.invites)+1), Email: email}
	p.invites = append(p.invites, inv)
	return inv, nil
}

func (f *fakeBackend) DeleteInvite(_ context.Context, projectID, inviteID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.projs[projectID]
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

func (f *fakeBackend) ListMyInvites(context.Context) ([]api.ReceivedInvite, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]api.ReceivedInvite(nil), f.myInvites...), nil
}

func (f *fakeBackend) AcceptInvite(_ context.Context, inviteID string) (api.ProjectSummary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// drop the invite
	var kept []api.ReceivedInvite
	for _, inv := range f.myInvites {
		if inv.ID != inviteID {
			kept = append(kept, inv)
		}
	}
	f.myInvites = kept
	return api.ProjectSummary{ID: inviteID}, nil
}

func (f *fakeBackend) DeclineInvite(_ context.Context, inviteID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var kept []api.ReceivedInvite
	for _, inv := range f.myInvites {
		if inv.ID != inviteID {
			kept = append(kept, inv)
		}
	}
	f.myInvites = kept
	return nil
}

func (f *fakeBackend) GetPendingKeys(_ context.Context, id string) ([]api.PendingKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.projs[id]
	if p == nil {
		return nil, api.ErrProjectNotFound
	}
	return append([]api.PendingKey(nil), p.pending...), nil
}

func (f *fakeBackend) SubmitMemberKey(_ context.Context, projectID, userID string, wrappedDek []byte, vaultVersion int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.projs[projectID]
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
	var kept []api.PendingKey
	for _, pk := range p.pending {
		if pk.UserID != userID {
			kept = append(kept, pk)
		}
	}
	p.pending = kept
	// mark the member keyed in the detail
	for i := range p.members {
		if p.members[i].UserID == userID {
			p.members[i].Keyed = true
		}
	}
	f.keySubmits++
	return nil
}

// --- projects flow test --------------------------------------------------------

// projectModel builds a real-mode model paired to a project-aware fake backend,
// wired with the fake project crypto + fake identity generator, signed in and on
// the dashboard.
func projectModel(t *testing.T) (tea.Model, *fakeVault, *fakeBackend) {
	t.Helper()
	fv := &fakeVault{}
	fb := &fakeBackend{vault: []byte(emptyAccountVault), version: 1}
	m := New(Config{
		VaultPath:    t.TempDir() + "/vault.enc",
		VaultExists:  func(string) bool { return true },
		OpenVault:    func(string, []byte) (vaultHandle, error) { return fv, nil },
		SyncAPI:      fb,
		SyncReadBlob: func() ([]byte, error) { return fv.Payload(), nil },
		SyncOpenBlob: func(blob, _ []byte) ([]byte, error) { return blob, nil },
		InstallVault: func(_ string, blob, _ []byte) (vaultHandle, error) {
			fv.payload = append([]byte(nil), blob...)
			fv.installs++
			fv.closed = false
			return fv, nil
		},
		SyncProjectCrypto: fakeProjCrypto{},
		GenIdentity:       fakeIdentity,
	})
	var tm tea.Model = m
	tm = send(tm, tea.WindowSizeMsg{Width: 100, Height: 34})
	tm = typeStr(tm, "pw")
	tm, cmd := step(tm, special(tea.KeyEnter))
	tm, _ = step(tm, cmd()) // vaultOpenedMsg → dashboard, engine built

	// Pair via the account row (settings tab).
	tm = gotoSettingRow(t, tm, "account")
	tm, _ = step(tm, special(tea.KeyEnter))
	tm, _ = step(tm, special(tea.KeyEnter)) // intro → code entry
	tm = typeStr(tm, "K7PQ-M2XR")
	tm, cmd = step(tm, special(tea.KeyEnter))
	tm, adoptCmd := step(tm, cmd())        // pairedMsg → fetch the account vault
	tm, installCmd := step(tm, adoptCmd()) // accountFetchedMsg → install it
	tm = drainCmd(t, tm, installCmd)
	if !tm.(Model).signedIn {
		t.Fatal("pairing should sign in")
	}
	return tm, fv, fb
}

// drain runs a command and feeds its message back, returning the model. Nil
// commands are ignored.
func drain(t *testing.T, tm tea.Model, cmd tea.Cmd) tea.Model {
	t.Helper()
	for i := 0; cmd != nil && i < 12; i++ {
		var msg tea.Msg
		msg = cmd()
		if batch, ok := msg.(tea.BatchMsg); ok {
			for _, c := range batch {
				tm = drain(t, tm, c)
			}
			return tm
		}
		tm, cmd = step(tm, msg)
	}
	return tm
}

func TestProjectsEndToEndFlow(t *testing.T) {
	tm, _, fb := projectModel(t)

	// Enter the projects tab: identity bootstrap → generate + publish → sync.
	tm, cmd := step(tm, runes("2"))
	tm = drain(t, tm, cmd)

	// Identity should now be published on the server.
	fb.mu.Lock()
	hasKey := len(fb.publicKey) > 0
	fb.mu.Unlock()
	if !hasKey {
		t.Fatal("entering projects should bootstrap + publish an identity")
	}
	if !tm.(Model).identityReady {
		t.Fatal("identity should be ready after bootstrap")
	}

	// Create a project via n → form → enter.
	tm = send(tm, runes("n"))
	if tm.(Model).modal != modalCreateProject {
		t.Fatalf("n should open the create-project form:\n%s", tm.View())
	}
	tm = typeStr(tm, "atlas")
	tm, cmd = step(tm, special(tea.KeyEnter))
	tm = drain(t, tm, cmd) // projectCreatedMsg → syncProjects → detail/finalize
	m := tm.(Model)
	if len(m.realProjects) != 1 || m.realProjects[0].Name != "atlas" {
		t.Fatalf("project should be created and listed: %+v", m.realProjects)
	}
	var projID string
	fb.mu.Lock()
	for id := range fb.projs {
		projID = id
	}
	fb.mu.Unlock()

	// A second account accepts the invite (simulate: add u2 as pending with a key).
	fb.mu.Lock()
	p := fb.projs[projID]
	p.members = append(p.members, api.ProjectMember{UserID: "u2", Email: "sam@example.com", Role: "MEMBER", PublicKey: u2pub()})
	p.pending = []api.PendingKey{{UserID: "u2", Email: "sam@example.com", PublicKey: u2pub()}}
	fb.mu.Unlock()

	// Sync projects → the admin finalize pass should grant u2 its key.
	tm = drain(t, tm, tm.(Model).syncProjectsCmd())
	fb.mu.Lock()
	_, u2keyed := fb.projs[projID].wrapped["u2"]
	fb.mu.Unlock()
	if !u2keyed {
		t.Fatal("finalize should seal the DEK for the accepted member u2")
	}

	// Add a host to the project doc (hosts tab, project selector).
	tm = send(tm, runes("1")) // hosts tab
	tm = send(tm, runes("a")) // add form
	tm = typeStr(tm, "proj-web")
	tm = send(tm, special(tea.KeyTab)) // user
	tm = send(tm, special(tea.KeyTab)) // addr
	tm = typeStr(tm, "p.example.com")
	// Navigate to the project selector (addr→port→tags→auth→key→project) and pick atlas.
	for i := 0; i < 4; i++ {
		tm = send(tm, special(tea.KeyTab))
	}
	// key field then project: cycle to atlas.
	tm = send(tm, special(tea.KeyTab)) // → project selector (key is visible in key mode)
	tm = send(tm, runes(" "))          // personal → atlas
	tm, cmd = step(tm, special(tea.KeyEnter))
	tm = drain(t, tm, cmd)
	m = tm.(Model)
	if doc := m.projectDocs[projID]; doc == nil || len(doc.HostList()) != 1 {
		t.Fatalf("host should be added to the project doc: %+v", m.projectDocs[projID])
	}

	// Debounced push uploads the edited project doc.
	gen := m.syncGen
	tm, cmd = step(tm, projPushTimerMsg{id: projID, gen: gen})
	tm = drain(t, tm, cmd)
	fb.mu.Lock()
	pushed := bytes.Contains(fb.projs[projID].vault, []byte("proj-web"))
	fb.mu.Unlock()
	if !pushed {
		t.Fatal("the debounced push should upload the edited project doc")
	}

	// Remove u2 → client-side rotation.
	tm = send(tm, runes("2"))                       // projects tab
	tm = drain(t, tm, tm.(Model).syncProjectsCmd()) // refresh + detail
	tm = drain(t, tm, tm.(Model).projectDetailCmd(projID))
	// tab rings through the detail pane: hosts first, then members.
	tm = send(tm, special(tea.KeyTab))
	tm = send(tm, special(tea.KeyTab))
	if tm.(Model).focus != pfMembers {
		t.Fatalf("two tabs should reach the member cursor, focus = %d", tm.(Model).focus)
	}
	// move cursor to u2 (index 1).
	tm = send(tm, runes("j"))
	tm, _ = step(tm, runes("d")) // open remove confirm
	if tm.(Model).modal != modalRemoveMember {
		t.Fatalf("d on a member should open the remove confirm:\n%s", tm.View())
	}
	tm, cmd = step(tm, runes("y"))
	tm = drain(t, tm, cmd)
	fb.mu.Lock()
	_, u2still := fb.projs[projID].wrapped["u2"]
	members := len(fb.projs[projID].members)
	fb.mu.Unlock()
	if u2still {
		t.Fatal("removed member must lose its wrapped key after rotation")
	}
	if members != 1 {
		t.Fatalf("member should be removed, got %d members", members)
	}

	// Server-side removal of the whole project drops it locally on the next sync.
	fb.mu.Lock()
	delete(fb.projs, projID)
	fb.mu.Unlock()
	tm = drain(t, tm, tm.(Model).syncProjectsCmd())
	if _, ok := tm.(Model).projectDocs[projID]; ok {
		t.Fatal("a vanished project should be dropped from local state")
	}
	if len(tm.(Model).realProjects) != 0 {
		t.Fatalf("removed project should leave the list empty: %+v", tm.(Model).realProjects)
	}
}

func TestProjectsInviteFlow(t *testing.T) {
	tm, _, fb := projectModel(t)
	tm, cmd := step(tm, runes("2"))
	tm = drain(t, tm, cmd)

	// Create a project.
	tm = send(tm, runes("n"))
	tm = typeStr(tm, "edge")
	tm, cmd = step(tm, special(tea.KeyEnter))
	tm = drain(t, tm, cmd)

	// Invite an email via i → modal → enter.
	tm = send(tm, runes("i"))
	if !tm.(Model).inviteOpen {
		t.Fatalf("i should open the invite modal:\n%s", tm.View())
	}
	tm = typeStr(tm, "sam@example.com")
	tm, cmd = step(tm, special(tea.KeyEnter))
	tm = drain(t, tm, cmd)

	var projID string
	fb.mu.Lock()
	for id, p := range fb.projs {
		projID = id
		_ = p
	}
	invites := len(fb.projs[projID].invites)
	fb.mu.Unlock()
	if invites != 1 {
		t.Fatalf("invite should be recorded on the server, got %d", invites)
	}
	if !strings.Contains(tm.View(), "invitation sent") {
		t.Fatalf("a confirming toast should show:\n%s", tm.View())
	}
}

func TestReceivedInviteAcceptFlow(t *testing.T) {
	tm, _, fb := projectModel(t)
	fb.mu.Lock()
	fb.myInvites = []api.ReceivedInvite{{ID: "inv9", ProjectID: "p9", ProjectName: "shared-infra", InvitedByEmail: "mara@example.com"}}
	fb.mu.Unlock()

	tm, cmd := step(tm, runes("2"))
	tm = drain(t, tm, cmd)
	if len(tm.(Model).receivedInvites) != 1 {
		t.Fatalf("received invites should be fetched: %+v", tm.(Model).receivedInvites)
	}
	if !strings.Contains(tm.View(), "shared-infra") {
		t.Fatalf("the pinned invite row should render:\n%s", tm.View())
	}

	// The pinned invite is the top row; enter opens the response modal.
	tm, _ = step(tm, special(tea.KeyEnter))
	if tm.(Model).modal != modalInviteResponse {
		t.Fatalf("enter on an invite should open the response modal:\n%s", tm.View())
	}
	tm, cmd = step(tm, runes("a")) // accept
	tm = drain(t, tm, cmd)
	fb.mu.Lock()
	remaining := len(fb.myInvites)
	fb.mu.Unlock()
	if remaining != 0 {
		t.Fatal("accepting should consume the invite")
	}
}

func TestProjectConflictResolve(t *testing.T) {
	tm, _, fb := projectModel(t)
	tm, cmd := step(tm, runes("2"))
	tm = drain(t, tm, cmd)
	tm = send(tm, runes("n"))
	tm = typeStr(tm, "atlas")
	tm, cmd = step(tm, special(tea.KeyEnter))
	tm = drain(t, tm, cmd)

	var projID string
	fb.mu.Lock()
	for id := range fb.projs {
		projID = id
	}
	fb.mu.Unlock()

	// Local edit (not yet pushed).
	m := tm.(Model)
	m.projectDocs[projID].AddHost(store.Host{Name: "local-h", Addr: "l.com"})
	tm = m

	// Concurrent remote edit at a higher version, sealed under the shared fake DEK.
	rdoc, _ := store.OpenProjectDoc(nil)
	rdoc.AddHost(store.Host{Name: "remote-h", Addr: "r.com"})
	rpay, _ := rdoc.Marshal()
	rblob, _ := fakeProjCrypto{}.Seal(bytesFill("dek", 32), rpay)
	fb.mu.Lock()
	fb.projs[projID].vault = rblob
	fb.projs[projID].version = 7
	fb.mu.Unlock()

	// Sync → both changed → conflict modal.
	tm = drain(t, tm, tm.(Model).syncProjectsCmd())
	if tm.(Model).modal != modalProjectConflict {
		t.Fatalf("both-changed should open the project conflict modal:\n%s", tm.View())
	}
	if !strings.Contains(tm.View(), "project conflict") {
		t.Fatalf("conflict prompt should render:\n%s", tm.View())
	}

	// Keep local → the local host wins on the server.
	tm, cmd = step(tm, runes("l"))
	tm = drain(t, tm, cmd)
	fb.mu.Lock()
	won := bytes.Contains(fb.projs[projID].vault, []byte("local-h"))
	fb.mu.Unlock()
	if !won {
		t.Fatal("keep-local must overwrite the project vault with the local doc")
	}
}

// needsSyncModel puts the model in the needs-sync identity state: the server
// already holds a public key this vault does not carry locally.
func needsSyncModel(t *testing.T) (tea.Model, *fakeVault, *fakeBackend) {
	t.Helper()
	tm, fv, fb := projectModel(t)
	fb.mu.Lock()
	fb.publicKey = bytesFill("oldkey", 32)
	fb.mu.Unlock()
	tm, cmd := step(tm, runes("2")) // enter projects → bootstrap sees the server key
	tm = drain(t, tm, cmd)
	return tm, fv, fb
}

func TestIdentityResetFlow(t *testing.T) {
	tm, fv, fb := needsSyncModel(t)

	m := tm.(Model)
	if !m.identityNeedsSync {
		t.Fatalf("a server key with no local identity should enter needs-sync:\n%s", tm.View())
	}
	if m.identityReady {
		t.Fatal("identity must not be ready in the needs-sync state")
	}
	if !strings.Contains(tm.View(), "R reset identity") {
		t.Fatalf("the needs-sync notice should advertise the reset keybinding:\n%s", tm.View())
	}

	// R opens the confirm modal spelling out the consequences.
	tm = send(tm, runes("R"))
	if tm.(Model).modal != modalResetIdentity {
		t.Fatalf("R should open the reset-identity confirm:\n%s", tm.View())
	}
	if !strings.Contains(tm.View(), "awaiting-access") || !strings.Contains(tm.View(), "unrecoverable") {
		t.Fatalf("the confirm should spell out the consequences:\n%s", tm.View())
	}

	// Confirm → generate + save + rotate the published key + resync.
	savesBefore := fv.saves
	tm, cmd := step(tm, runes("y"))
	tm = drain(t, tm, cmd)

	m = tm.(Model)
	if !m.identityReady || m.identityNeedsSync {
		t.Fatalf("reset should leave identity ready and out of needs-sync (ready=%v needsSync=%v)", m.identityReady, m.identityNeedsSync)
	}
	fb.mu.Lock()
	rotated := bytes.Equal(fb.publicKey, bytesFill("u1pubkey", 32))
	fb.mu.Unlock()
	if !rotated {
		t.Fatal("reset should rotate the published public key to the freshly minted one")
	}
	if fv.saves == savesBefore {
		t.Fatal("reset should persist the new identity into the local vault")
	}
	if id := m.st.Identity(); id == nil {
		t.Fatal("the store should carry the new identity after reset")
	}
}

func TestIdentityResetCancel(t *testing.T) {
	tm, _, fb := needsSyncModel(t)

	tm = send(tm, runes("R"))
	if tm.(Model).modal != modalResetIdentity {
		t.Fatalf("R should open the reset confirm:\n%s", tm.View())
	}
	tm = send(tm, special(tea.KeyEsc))
	m := tm.(Model)
	if m.modal != modalNone {
		t.Fatal("esc should dismiss the reset confirm")
	}
	if m.identityReady || !m.identityNeedsSync {
		t.Fatal("cancelling must not touch identity state")
	}
	fb.mu.Lock()
	untouched := bytes.Equal(fb.publicKey, bytesFill("oldkey", 32))
	fb.mu.Unlock()
	if !untouched {
		t.Fatal("cancelling must not rotate the published key")
	}
}

// --- published-key mismatch ------------------------------------------------------

// identityModel returns a signed-in model whose vault already carries the local
// identity, i.e. the path where ensureIdentity has a key to compare.
func identityModel(t *testing.T) (tea.Model, *fakeBackend) {
	t.Helper()
	tm, _, fb := projectModel(t)
	m := tm.(Model)
	pub, priv, _ := fakeIdentity()
	m.st.SetIdentity(&store.Identity{
		X25519Pub:  base64.StdEncoding.EncodeToString(pub),
		X25519Priv: base64.StdEncoding.EncodeToString(priv),
		CreatedAt:  time.Now().UTC(),
	})
	return m, fb
}

// enterProjects switches to the projects tab and settles the resulting commands.
func enterProjects(t *testing.T, tm tea.Model) tea.Model {
	t.Helper()
	tm, cmd := step(tm, runes("2"))
	return drain(t, tm, cmd)
}

func TestIdentityMismatchDetected(t *testing.T) {
	tm, fb := identityModel(t)
	attacker := bytesFill("attacker", 32)
	fb.mu.Lock()
	fb.publicKey = attacker
	fb.mu.Unlock()

	tm = enterProjects(t, tm)
	m := tm.(Model)
	if !m.identityMismatch {
		t.Fatalf("a differing published key must enter the mismatch state:\n%s", tm.View())
	}
	localPub, _, _ := fakeIdentity()
	if want := identity.Fingerprint(localPub); m.identityLocalFP != want {
		t.Fatalf("local fingerprint = %q, want %q", m.identityLocalFP, want)
	}
	if want := identity.Fingerprint(attacker); m.identityServerFP != want {
		t.Fatalf("server fingerprint = %q, want %q", m.identityServerFP, want)
	}
	// The engine's key-distribution gate must be armed, not just the UI state.
	if !m.eng.IdentityMismatch() {
		t.Fatal("the mismatch must reach the engine so finalize halts")
	}

	view := tm.View()
	if !strings.Contains(view, "public key mismatch") || !strings.Contains(view, "does not match") {
		t.Fatalf("the projects tab should warn about the mismatch:\n%s", view)
	}
	if !strings.Contains(view, "in this vault") || !strings.Contains(view, "published by the server") {
		t.Fatalf("both fingerprints should be labelled:\n%s", view)
	}
	if !strings.Contains(view, m.identityLocalFP) || !strings.Contains(view, m.identityServerFP) {
		t.Fatalf("both fingerprints should render:\n%s", view)
	}
	if !strings.Contains(view, "Do not accept invites") {
		t.Fatalf("the warning should tell the user not to accept invites:\n%s", view)
	}
}

func TestIdentityMatchIsNoMismatch(t *testing.T) {
	tm, fb := identityModel(t)
	pub, _, _ := fakeIdentity()
	fb.mu.Lock()
	fb.publicKey = pub // the server publishes exactly our key
	fb.mu.Unlock()

	tm = enterProjects(t, tm)
	m := tm.(Model)
	if m.identityMismatch {
		t.Fatalf("an identical published key must not raise a mismatch:\n%s", tm.View())
	}
	if m.eng.IdentityMismatch() {
		t.Fatal("the engine gate must stay open when the keys agree")
	}
	if strings.Contains(tm.View(), "public key mismatch") {
		t.Fatalf("no warning should render:\n%s", tm.View())
	}
}

func TestIdentityUnreachableServerIsNotMismatch(t *testing.T) {
	tm, fb := identityModel(t)
	fb.mu.Lock()
	fb.meErr = errors.New("dial tcp: connection refused")
	fb.publicKey = bytesFill("attacker", 32)
	fb.mu.Unlock()

	tm = enterProjects(t, tm)
	m := tm.(Model)
	if m.identityMismatch {
		t.Fatalf("an unreachable server is unknown, never a mismatch:\n%s", tm.View())
	}
	if m.eng.IdentityMismatch() {
		t.Fatal("a failed check must not arm the engine gate")
	}
}

func TestIdentityMismatchRepublish(t *testing.T) {
	tm, fb := identityModel(t)
	fb.mu.Lock()
	fb.publicKey = bytesFill("attacker", 32)
	fb.mu.Unlock()
	tm = enterProjects(t, tm)

	// p opens a confirm that spells out the cost of the rotate.
	tm = send(tm, runes("p"))
	if tm.(Model).modal != modalRepublishKey {
		t.Fatalf("p should open the republish confirm:\n%s", tm.View())
	}
	view := tm.View()
	if !strings.Contains(view, "awaiting-") || !strings.Contains(view, "wrapped project") {
		t.Fatalf("the confirm should state that rotate nulls the wrapped DEKs:\n%s", view)
	}
	if !strings.Contains(view, "no new keypair") {
		t.Fatalf("the confirm should make clear the local key is kept:\n%s", view)
	}

	tm, cmd := step(tm, runes("y"))
	tm = drain(t, tm, cmd)

	localPub, _, _ := fakeIdentity()
	fb.mu.Lock()
	published := append([]byte(nil), fb.publicKey...)
	fb.mu.Unlock()
	if !bytes.Equal(published, localPub) {
		t.Fatal("republish should put this vault's own key on the server")
	}
	m := tm.(Model)
	if id := m.st.Identity(); id == nil || id.X25519Pub != base64.StdEncoding.EncodeToString(localPub) {
		t.Fatal("republish must not mint a new local keypair")
	}
	if m.identityMismatch || m.eng.IdentityMismatch() {
		t.Fatalf("the re-check after republish should clear the mismatch:\n%s", tm.View())
	}
}

func TestIdentityMismatchRepublishCancel(t *testing.T) {
	tm, fb := identityModel(t)
	attacker := bytesFill("attacker", 32)
	fb.mu.Lock()
	fb.publicKey = attacker
	fb.mu.Unlock()
	tm = enterProjects(t, tm)

	tm = send(tm, runes("p"))
	tm = send(tm, special(tea.KeyEsc))
	m := tm.(Model)
	if m.modal != modalNone {
		t.Fatal("esc should dismiss the republish confirm")
	}
	if !m.identityMismatch {
		t.Fatal("cancelling must leave the mismatch standing")
	}
	fb.mu.Lock()
	untouched := bytes.Equal(fb.publicKey, attacker)
	fb.mu.Unlock()
	if !untouched {
		t.Fatal("cancelling must not touch the published key")
	}
}

func TestProjectHostLastSeenOnConnect(t *testing.T) {
	tm, _, fb := projectModel(t)
	tm, cmd := step(tm, runes("2"))
	tm = drain(t, tm, cmd)
	tm = send(tm, runes("n"))
	tm = typeStr(tm, "atlas")
	tm, cmd = step(tm, special(tea.KeyEnter))
	tm = drain(t, tm, cmd)

	var projID string
	fb.mu.Lock()
	for id := range fb.projs {
		projID = id
	}
	fb.mu.Unlock()

	// Add a host to the project doc directly.
	m := tm.(Model)
	stored, err := m.projectDocs[projID].AddHost(store.Host{Name: "proj-web", User: "deploy", Addr: "p.example.com", Port: 22})
	if err != nil {
		t.Fatalf("add project host: %v", err)
	}
	tm = m

	// A successful dial of the project host stamps LastSeen + arms the debounced push.
	before := tm.(Model).syncGen
	tm, _ = step(tm, dialDoneMsg{hostID: stored.ID})
	m = tm.(Model)
	h, ok := m.projectDocs[projID].HostByID(stored.ID)
	if !ok || h.LastSeen.IsZero() {
		t.Fatalf("connect should stamp LastSeen on the project host: %+v", h)
	}
	if m.syncGen == before {
		t.Fatal("connect to a project host should arm the debounced project push")
	}

	// Firing the debounce uploads the doc (now carrying the connect stamp). No
	// personal-vault push is scheduled for a project host.
	tm, cmd = step(tm, projPushTimerMsg{id: projID, gen: m.syncGen})
	tm = drain(t, tm, cmd)
	fb.mu.Lock()
	pushed := bytes.Contains(fb.projs[projID].vault, []byte("proj-web"))
	fb.mu.Unlock()
	if !pushed {
		t.Fatal("the debounced push should upload the project doc with the connect stamp")
	}
}

func TestProjectHostFilterByID(t *testing.T) {
	tm, _, fb := projectModel(t)
	tm, cmd := step(tm, runes("2"))
	tm = drain(t, tm, cmd)
	tm = send(tm, runes("n"))
	tm = typeStr(tm, "atlas")
	tm, cmd = step(tm, special(tea.KeyEnter))
	tm = drain(t, tm, cmd)

	var projID string
	fb.mu.Lock()
	for id := range fb.projs {
		projID = id
	}
	fb.mu.Unlock()

	// f shows the merged hosts tab filtered to this project by ID.
	m := tm.(Model)
	if _, ok := m.selectedProject(); !ok {
		// move onto the project row past any invites
		tm = send(tm, runes("j"))
	}
	tm, _ = step(tm, runes("f"))
	m = tm.(Model)
	if m.tab != 0 || m.projFilterID != projID {
		t.Fatalf("f on a project should filter the hosts tab by ID, got tab=%d filter=%q", m.tab, m.projFilterID)
	}
	if !strings.Contains(tm.View(), "⧉ atlas") {
		t.Fatalf("the filter chip should render:\n%s", tm.View())
	}
	// esc clears the filter.
	tm, _ = step(tm, special(tea.KeyEsc))
	if tm.(Model).projFilterID != "" {
		t.Fatal("esc should clear the project filter")
	}
}

// projectWithHost builds a signed-in model owning one project that already
// holds one host, and leaves the cursor on the projects tab.
func projectWithHost(t *testing.T, hostName string) (tea.Model, *fakeBackend, string) {
	t.Helper()
	tm, _, fb := projectModel(t)
	tm, cmd := step(tm, runes("2"))
	tm = drain(t, tm, cmd)
	tm = send(tm, runes("n"))
	tm = typeStr(tm, "atlas")
	tm, cmd = step(tm, special(tea.KeyEnter))
	tm = drain(t, tm, cmd)

	var projID string
	fb.mu.Lock()
	for id := range fb.projs {
		projID = id
	}
	fb.mu.Unlock()

	m, _, _, err := tm.(Model).addHostToProject(projID, store.Host{
		Name: hostName, User: "root", Addr: hostName + ".example.com", Port: 22, Source: "manual",
	})
	if err != nil {
		t.Fatalf("add project host: %v", err)
	}
	// Fire the debounced push so the host actually reaches the backend — a doc
	// that only exists locally would vanish on the next sync.
	tm = m
	tm, cmd = step(tm, projPushTimerMsg{id: projID, gen: m.syncGen})
	tm = drain(t, tm, cmd)
	return tm, fb, projID
}

// Opening a project keeps you on the projects tab: the cursor drops into that
// project's own host list instead of teleporting to the hosts tab.
func TestProjectEnterOpensHostsInPane(t *testing.T) {
	tm, _, _ := projectWithHost(t, "proj-web")
	m := tm.(Model)
	if _, ok := m.selectedProject(); !ok {
		tm = send(tm, runes("j"))
	}
	tm, _ = step(tm, special(tea.KeyEnter))

	m = tm.(Model)
	if m.tab != 1 {
		t.Fatalf("enter on a project must not switch tabs, tab = %d", m.tab)
	}
	if m.focus != pfHosts {
		t.Fatalf("enter should focus the project's hosts, focus = %d", m.focus)
	}
	if m.projFilterID != "" {
		t.Fatalf("enter should no longer set the hosts-tab filter, got %q", m.projFilterID)
	}
	v := tm.View()
	if !strings.Contains(v, "proj-web") {
		t.Fatalf("the project's hosts should render in the detail pane:\n%s", v)
	}
	if !strings.Contains(v, "enter connect") {
		t.Fatalf("the hints should say what enter does here:\n%s", v)
	}

	// esc steps back to the project list rather than off the tab.
	tm, _ = step(tm, special(tea.KeyEsc))
	m = tm.(Model)
	if m.tab != 1 || m.focus != pfList {
		t.Fatalf("esc should return to the project list, tab=%d focus=%d", m.tab, m.focus)
	}
}

// A project with no readable hosts has nothing to open, and says so instead of
// dropping the cursor into an empty list.
func TestProjectEnterWithNoHosts(t *testing.T) {
	tm, _, fb := projectModel(t)
	tm, cmd := step(tm, runes("2"))
	tm = drain(t, tm, cmd)
	tm = send(tm, runes("n"))
	tm = typeStr(tm, "atlas")
	tm, cmd = step(tm, special(tea.KeyEnter))
	tm = drain(t, tm, cmd)
	_ = fb

	if _, ok := tm.(Model).selectedProject(); !ok {
		tm = send(tm, runes("j"))
	}
	tm, _ = step(tm, special(tea.KeyEnter))
	m := tm.(Model)
	if m.focus != pfList {
		t.Fatalf("an empty project should leave the cursor on the list, focus = %d", m.focus)
	}
	if !strings.Contains(tm.View(), "no hosts in atlas yet") {
		t.Fatalf("the empty project should explain itself:\n%s", tm.View())
	}
}

// p on a host moves it into a project: it leaves the personal vault and lands
// in the project doc, which is then pushed.
func TestMoveHostIntoProject(t *testing.T) {
	tm, _, fb := projectModel(t)
	tm, cmd := step(tm, runes("2"))
	tm = drain(t, tm, cmd)
	tm = send(tm, runes("n"))
	tm = typeStr(tm, "atlas")
	tm, cmd = step(tm, special(tea.KeyEnter))
	tm = drain(t, tm, cmd)

	var projID string
	fb.mu.Lock()
	for id := range fb.projs {
		projID = id
	}
	fb.mu.Unlock()

	// A personal host, then p → picker → the project.
	tm = addHost(t, tm, "homelab", "10.0.0.5")
	tm, _ = step(tm, runes("p"))
	if tm.(Model).modal != modalMoveProject {
		t.Fatalf("p should open the move picker, modal = %d", tm.(Model).modal)
	}
	v := tm.View()
	if !strings.Contains(v, "Move ") || !strings.Contains(v, "where it is now") {
		t.Fatalf("the picker should name the host and its current home:\n%s", v)
	}
	tm = send(tm, runes("j")) // personal → atlas
	tm, cmd = step(tm, special(tea.KeyEnter))
	// Checked before draining: the project push that follows raises its own
	// toast over this one.
	if !strings.Contains(tm.View(), "moved homelab to atlas") {
		t.Fatalf("the move should be confirmed:\n%s", tm.View())
	}
	tm = drain(t, tm, cmd)

	m := tm.(Model)
	for _, h := range m.storeHosts() {
		if h.Name == "homelab" {
			t.Fatal("the host should have left the personal vault")
		}
	}
	doc := m.projectDocs[projID]
	if doc == nil {
		t.Fatal("project doc missing")
	}
	var found bool
	for _, h := range doc.HostList() {
		if h.Name == "homelab" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the host should now be in the project, got %+v", doc.HostList())
	}
}

// A move is remove-then-add across two separate encrypted documents, so a name
// already taken at the destination is refused *before* the source is touched —
// otherwise the host would end up in neither.
func TestMoveHostRejectsNameClashWithoutLosingIt(t *testing.T) {
	tm, _, projID := projectWithHost(t, "homelab")
	tm = addHost(t, tm, "homelab", "10.0.0.5")

	tm, _ = step(tm, runes("p"))
	tm = send(tm, runes("j")) // personal → atlas
	tm, _ = step(tm, special(tea.KeyEnter))

	m := tm.(Model)
	if m.modal != modalMoveProject {
		t.Fatal("a rejected move should keep the picker open")
	}
	if !strings.Contains(tm.View(), "already has a host named") {
		t.Fatalf("the clash should be explained:\n%s", tm.View())
	}
	var stillPersonal bool
	for _, h := range m.storeHosts() {
		if h.Name == "homelab" {
			stillPersonal = true
		}
	}
	if !stillPersonal {
		t.Fatal("a refused move must leave the host where it was")
	}
	if n := len(m.projectDocs[projID].HostList()); n != 1 {
		t.Fatalf("the project should be unchanged, has %d hosts", n)
	}
}

// Projects load when the session comes up, not when the projects tab is first
// opened: the hosts tab merges project hosts in, and "move to project" needs
// the list. Pressing p on a host used to report "no projects yet" for an
// account that had several, purely because the tab had not been visited.
func TestProjectsLoadWithoutVisitingTheTab(t *testing.T) {
	tm, _, _ := projectWithHost(t, "proj-web")
	tm = addHost(t, tm, "homelab", "10.0.0.5") // a personal host to press p on

	// Simulate a fresh run over the same vault: the identity is in the vault
	// (so initSync marks it ready), but no project state has been fetched yet.
	m := tm.(Model)
	if !m.identityReady {
		t.Fatal("the vault should carry an identity by now")
	}
	m.realProjects = nil
	m.projectDocs = map[string]*store.ProjectDoc{}
	m.projectsLoaded = false
	m.tab, m.focus = 0, 0
	tm = m

	// p before anything has loaded must not claim the account has no projects.
	tmp, _ := step(tm, runes("p"))
	if !strings.Contains(tmp.View(), "still loading") {
		t.Fatalf("an unloaded list must not be reported as empty:\n%s", tmp.View())
	}

	// The resumed session loads them, with no visit to the projects tab.
	tm, cmd := step(tm, sessionResumedMsg{email: "deniz@example.com", ok: true})
	if cmd == nil {
		t.Fatal("a resumed session should load projects")
	}
	tm = drain(t, tm, cmd)

	m = tm.(Model)
	if m.tab != 0 {
		t.Fatalf("loading projects must not move the user off their tab, tab = %d", m.tab)
	}
	if len(m.realProjects) == 0 {
		t.Fatal("the project list should be populated after a resume")
	}
	if !m.projectsLoaded {
		t.Fatal("a landed projects sync should mark the list loaded")
	}

	// And p now offers the project as a destination.
	tm, _ = step(tm, runes("p"))
	if tm.(Model).modal != modalMoveProject {
		t.Fatalf("p should open the picker once projects are loaded:\n%s", tm.View())
	}
	if !strings.Contains(tm.View(), "atlas") {
		t.Fatalf("the loaded project should be a destination:\n%s", tm.View())
	}
}

// Signing in must not mint a project identity for someone who never opens
// projects: generating one writes an X25519 keypair into the vault, publishes
// it, and bumps the payload to a schema older builds refuse to open.
func TestSignInDoesNotCreateProjectIdentity(t *testing.T) {
	tm, fv, fb := projectModel(t)

	m := tm.(Model)
	if m.identityReady || m.identityBooting {
		t.Fatal("a vault with no identity should not have one after signing in")
	}
	if id := m.st.Identity(); id != nil {
		t.Fatalf("signing in wrote a project identity into the vault: %+v", id)
	}
	if bytes.Contains(fv.Payload(), []byte("x25519Priv")) {
		t.Fatal("the vault payload must not carry an identity yet")
	}
	fb.mu.Lock()
	published := len(fb.publicKey)
	fb.mu.Unlock()
	if published != 0 {
		t.Fatal("signing in must not publish a public key")
	}

	// Opening the projects tab still bootstraps one on demand.
	tm, cmd := step(tm, runes("2"))
	tm = drain(t, tm, cmd)
	if !tm.(Model).identityReady {
		t.Fatal("opening the projects tab should create the identity")
	}
}

// An account whose hosts all live in projects used to see the fresh-install
// "No hosts yet" panel for as long as the project sync took — a claim about
// the account made before the data that would contradict it had arrived.
func TestHostsTabShowsLoadingBeforeProjectsLand(t *testing.T) {
	tm, _, _ := projectWithHost(t, "proj-web")

	// A fresh run over the same vault: identity present, nothing fetched yet.
	m := tm.(Model)
	m.realProjects = nil
	m.projectDocs = map[string]*store.ProjectDoc{}
	m.projectsLoaded = false
	m.tab, m.focus = 0, 0
	tm = m

	if !m.projectsPending() {
		t.Fatal("projects should count as pending before the first sync lands")
	}
	v := tm.View()
	if strings.Contains(v, "No hosts yet") {
		t.Fatalf("an unloaded hosts tab must not claim to be empty:\n%s", v)
	}
	if !strings.Contains(v, "loading your hosts") {
		t.Fatalf("the hosts tab should show a loading state:\n%s", v)
	}

	// The projects tab is in the same position.
	tm, cmd := step(tm, runes("2"))
	if !strings.Contains(tm.View(), "loading your projects") &&
		!strings.Contains(tm.View(), "setting up project encryption") {
		t.Fatalf("the projects tab should show a loading state:\n%s", tm.View())
	}
	tm = drain(t, tm, cmd)

	// Once the sync lands the real content replaces it, and never the empty state.
	v = tm.View()
	if strings.Contains(v, "loading your projects") {
		t.Fatalf("the placeholder should give way to the project list:\n%s", v)
	}
	if !strings.Contains(v, "atlas") {
		t.Fatalf("the loaded project should render:\n%s", v)
	}
	tm = send(tm, runes("1"))
	if v := tm.View(); !strings.Contains(v, "proj-web") || strings.Contains(v, "loading your hosts") {
		t.Fatalf("the project host should appear on the hosts tab:\n%s", v)
	}
}

// A failed projects sync must resolve the placeholder rather than spin
// forever: an empty list is a worse answer than nothing at all only while an
// answer is still coming.
func TestLoadingResolvesWhenProjectsSyncFails(t *testing.T) {
	tm, fb, _ := projectWithHost(t, "proj-web")
	m := tm.(Model)
	m.realProjects = nil
	m.projectDocs = map[string]*store.ProjectDoc{}
	m.projectsLoaded = false
	m.tab, m.focus = 0, 0
	tm = m

	fb.mu.Lock()
	fb.meErr = errors.New("offline")
	fb.mu.Unlock()

	tm, cmd := step(tm, sessionResumedMsg{email: "deniz@example.com", ok: true})
	tm = drain(t, tm, cmd)

	if tm.(Model).projectsPending() {
		t.Fatal("a finished attempt must clear the pending state, even on failure")
	}
	if v := tm.View(); strings.Contains(v, "loading your hosts") {
		t.Fatalf("the placeholder must not outlive the attempt:\n%s", v)
	}
}
