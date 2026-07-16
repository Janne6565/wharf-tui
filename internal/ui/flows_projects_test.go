package ui

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Janne6565/wharf-tui/internal/api"
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
	p := api.Profile{ID: f.uid(), Email: "deniz@example.com"}
	if len(f.publicKey) > 0 {
		p.PublicKey = string(f.publicKey)
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
	fb := &fakeBackend{noVault: true}
	m := New(Config{
		VaultPath:         t.TempDir() + "/vault.enc",
		VaultExists:       func(string) bool { return true },
		OpenVault:         func(string, []byte) (vaultHandle, error) { return fv, nil },
		SyncAPI:           fb,
		SyncReadBlob:      func() ([]byte, error) { return fv.Payload(), nil },
		SyncOpenBlob:      func(blob, _ []byte) ([]byte, error) { return blob, nil },
		SyncProjectCrypto: fakeProjCrypto{},
		GenIdentity:       fakeIdentity,
	})
	var tm tea.Model = m
	tm = send(tm, tea.WindowSizeMsg{Width: 100, Height: 34})
	tm = typeStr(tm, "pw")
	tm, cmd := step(tm, special(tea.KeyEnter))
	tm, _ = step(tm, cmd()) // vaultOpenedMsg → dashboard, engine built

	// Pair via the account row (settings tab).
	tm = send(tm, runes("4"))
	tm = send(tm, runes("j"))
	tm = send(tm, runes("j"))
	tm = send(tm, runes("j")) // Account row
	tm, _ = step(tm, special(tea.KeyEnter))
	tm, _ = step(tm, special(tea.KeyEnter)) // intro → code entry
	tm = typeStr(tm, "K7PQ-M2XR")
	tm, cmd = step(tm, special(tea.KeyEnter))
	tm, syncCmd := step(tm, cmd()) // pairedMsg → signed in
	tm, _ = step(tm, syncCmd())    // initial personal sync
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
	tm = send(tm, special(tea.KeyTab)) // focus detail pane (member cursor)
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

	// Select the project and press enter → hosts tab filtered by project ID.
	m := tm.(Model)
	if _, ok := m.selectedProject(); !ok {
		// move onto the project row past any invites
		tm = send(tm, runes("j"))
	}
	tm, _ = step(tm, special(tea.KeyEnter))
	m = tm.(Model)
	if m.tab != 0 || m.projFilterID != projID {
		t.Fatalf("enter on a project should filter the hosts tab by ID, got tab=%d filter=%q", m.tab, m.projFilterID)
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
