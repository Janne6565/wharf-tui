package ui

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/Janne6565/wharf-tui/internal/api"
	"github.com/Janne6565/wharf-tui/internal/store"
	syncx "github.com/Janne6565/wharf-tui/internal/sync"
	tea "github.com/charmbracelet/bubbletea"
)

// projTimeout bounds one projects network operation.
const projTimeout = 60 * time.Second

// --- messages -----------------------------------------------------------------

type projectsSyncedMsg struct{ res syncx.ProjectsResult }
type invitesFetchedMsg struct {
	invites []api.ReceivedInvite
	err     error
}
type projectDetailMsg struct {
	detail api.ProjectDetail
	err    error
}
type projectCreatedMsg struct {
	view syncx.ProjectView
	err  error
}
type projectOpMsg struct {
	kind string // "push" | "resolve" | "rotate"
	id   string // the project the op targeted
	res  syncx.ProjectOpResult
}
type inviteSentMsg struct{ err error }
type inviteRevokedMsg struct{ err error }
type inviteRespondedMsg struct {
	accepted bool
	err      error
}
type finalizeDoneMsg struct{ granted int }

// identityReadyMsg reports the outcome of the lazy identity bootstrap. needSync
// asks the UI to pull the personal vault first (the account has a server key we
// lack locally); notice is a user-facing message when bootstrap can't proceed.
type identityReadyMsg struct {
	ready    bool
	needSync bool
	notice   string
	err      error
}

// projPushTimerMsg fires after the per-project push debounce.
type projPushTimerMsg struct {
	id  string
	gen int
}

// --- identity bootstrap -------------------------------------------------------

// ensureIdentity lazily prepares the account's X25519 identity for projects. It
// runs on the first real Projects entry / create / accept. Cheap when the
// identity is already loaded.
func (m Model) ensureIdentity() (Model, tea.Cmd) {
	if m.identityReady || m.identityBooting || m.eng == nil || !m.realMode() {
		return m, nil
	}
	if pub, priv, ok := m.loadIdentity(); ok {
		// Have a local identity: hand it to the engine and idempotently publish.
		m.eng.SetIdentity(pub, priv)
		m.identityReady = true
		return m, m.publishIdentityCmd(pub)
	}
	// No local identity — a network check decides whether to generate one.
	m.identityBooting = true
	return m, m.bootstrapIdentityCmd()
}

// loadIdentity decodes the personal vault's stored identity keypair.
func (m Model) loadIdentity() (pub, priv []byte, ok bool) {
	if m.st == nil {
		return nil, nil, false
	}
	id := m.st.Identity()
	if id == nil {
		return nil, nil, false
	}
	pub, e1 := base64.StdEncoding.DecodeString(id.X25519Pub)
	priv, e2 := base64.StdEncoding.DecodeString(id.X25519Priv)
	if e1 != nil || e2 != nil || len(pub) != 32 || len(priv) != 32 {
		return nil, nil, false
	}
	return pub, priv, true
}

// publishIdentityCmd publishes an existing public key; a 409 (already set) is a
// success.
func (m Model) publishIdentityCmd(pub []byte) tea.Cmd {
	eng := m.eng
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), projTimeout)
		defer cancel()
		err := eng.PublishIdentity(ctx, pub, false)
		if err != nil && !errors.Is(err, api.ErrPublicKeyExists) {
			return identityReadyMsg{err: err}
		}
		return identityReadyMsg{ready: true}
	}
}

// publishIdentityRotateCmd rotates the account's published public key. Unlike a
// plain publish, rotate=true replaces any existing key AND nulls every wrapped
// project DEK server-side, so all the caller's projects re-enter awaiting-access.
// Success reuses identityReadyMsg{ready} so the ready handler triggers a resync.
func (m Model) publishIdentityRotateCmd(pub []byte) tea.Cmd {
	eng := m.eng
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), projTimeout)
		defer cancel()
		if err := eng.PublishIdentity(ctx, pub, true); err != nil {
			return identityReadyMsg{err: err}
		}
		return identityReadyMsg{ready: true}
	}
}

// bootstrapIdentityCmd checks the server for an existing public key. If the
// account already published one we lack locally, it asks the UI to sync the
// personal vault first; otherwise it signals "generate a fresh keypair".
func (m Model) bootstrapIdentityCmd() tea.Cmd {
	eng := m.eng
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), projTimeout)
		defer cancel()
		p, err := eng.ServerProfile(ctx)
		if err != nil {
			return identityReadyMsg{err: err}
		}
		if p.PublicKey != "" {
			return identityReadyMsg{needSync: true}
		}
		return identityReadyMsg{} // neither side has a key → generate
	}
}

func (m Model) handleIdentityReady(msg identityReadyMsg) (tea.Model, tea.Cmd) {
	m.identityBooting = false
	switch {
	case msg.err != nil:
		return m.setToast("could not set up project encryption: "+msg.err.Error(), "err"), nil
	case msg.ready:
		m.identityReady = true
		m.identityNotice = ""
		m.identityNeedsSync = false
		// Kick off the first projects sync now that identity is live.
		return m, m.syncProjectsCmd()
	case msg.needSync:
		// The server has a key we don't hold locally — pull the personal vault on
		// the device that created the identity, then the user retries. If that
		// device is gone for good, "R" resets the identity (the view appends the
		// reset keybinding when identityNeedsSync).
		m.identityNotice = "sync this vault on the device that created your identity first"
		m.identityNeedsSync = true
		mm, cmd := m.startSync()
		return mm, cmd
	default:
		// Neither side has a key: generate one, persist it, publish it.
		pub, priv, err := m.genIdentity()
		if err != nil || len(pub) != 32 || len(priv) != 32 {
			return m.setToast("could not generate an identity key", "err"), nil
		}
		m.st.SetIdentity(&store.Identity{
			X25519Pub:  base64.StdEncoding.EncodeToString(pub),
			X25519Priv: base64.StdEncoding.EncodeToString(priv),
			CreatedAt:  time.Now().UTC(),
		})
		if err := m.st.Save(); err != nil {
			return m.setToast("could not save identity: "+err.Error(), "err"), nil
		}
		m.eng.SetIdentity(pub, priv)
		m.identityReady = true
		m.identityNotice = ""
		m.identityNeedsSync = false
		// Persisting to the synced payload also schedules a personal push.
		mm, pushCmd := m.schedulePush()
		return mm, tea.Batch(pushCmd, mm.publishIdentityCmd(pub))
	}
}

// --- commands -----------------------------------------------------------------

func (m Model) syncProjectsCmd() tea.Cmd {
	if m.eng == nil || !m.realMode() {
		return nil
	}
	eng, local := m.eng, m.projectHostsPayloads()
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), projTimeout)
		defer cancel()
		return projectsSyncedMsg{res: eng.SyncProjects(ctx, local)}
	}
}

func (m Model) fetchInvitesCmd() tea.Cmd {
	if m.eng == nil || !m.realMode() {
		return nil
	}
	eng := m.eng
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), projTimeout)
		defer cancel()
		inv, err := eng.FetchInvites(ctx)
		return invitesFetchedMsg{invites: inv, err: err}
	}
}

func (m Model) finalizeCmd() tea.Cmd {
	if m.eng == nil || !m.realMode() {
		return nil
	}
	eng := m.eng
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), projTimeout)
		defer cancel()
		return finalizeDoneMsg{granted: eng.FinalizeProjects(ctx)}
	}
}

func (m Model) projectDetailCmd(id string) tea.Cmd {
	if m.eng == nil || id == "" {
		return nil
	}
	eng := m.eng
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), projTimeout)
		defer cancel()
		d, err := eng.ProjectDetail(ctx, id)
		return projectDetailMsg{detail: d, err: err}
	}
}

func (m Model) createProjectCmd(name, desc string) tea.Cmd {
	eng := m.eng
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), projTimeout)
		defer cancel()
		v, err := eng.CreateProject(ctx, name, desc)
		return projectCreatedMsg{view: v, err: err}
	}
}

func (m Model) pushProjectCmd(id string) tea.Cmd {
	eng := m.eng
	doc := m.projectDocs[id]
	if eng == nil || doc == nil {
		return nil
	}
	payload, err := doc.Marshal()
	if err != nil {
		return nil
	}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), projTimeout)
		defer cancel()
		return projectOpMsg{kind: "push", id: id, res: eng.PushProject(ctx, id, payload)}
	}
}

func (m Model) resolveProjectCmd(id string, keepLocal bool) tea.Cmd {
	eng := m.eng
	doc := m.projectDocs[id]
	var payload []byte
	if doc != nil {
		payload, _ = doc.Marshal()
	}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), projTimeout)
		defer cancel()
		return projectOpMsg{kind: "resolve", id: id, res: eng.ResolveProject(ctx, id, keepLocal, payload)}
	}
}

func (m Model) inviteCmd(projectID, email string) tea.Cmd {
	eng := m.eng
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), projTimeout)
		defer cancel()
		return inviteSentMsg{err: eng.CreateInvite(ctx, projectID, email)}
	}
}

func (m Model) revokeInviteCmd(projectID, inviteID string) tea.Cmd {
	eng := m.eng
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), projTimeout)
		defer cancel()
		return inviteRevokedMsg{err: eng.RevokeInvite(ctx, projectID, inviteID)}
	}
}

func (m Model) respondInviteCmd(inviteID string, accept bool) tea.Cmd {
	eng := m.eng
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), projTimeout)
		defer cancel()
		if accept {
			_, err := eng.AcceptInvite(ctx, inviteID)
			return inviteRespondedMsg{accepted: true, err: err}
		}
		return inviteRespondedMsg{accepted: false, err: eng.DeclineInvite(ctx, inviteID)}
	}
}

// removeMemberCmd runs the client-side rotation-with-removal. recipients is the
// set of members to keep keyed (published pubkey), captured on the UI goroutine.
func (m Model) removeMemberCmd(projectID, removeUserID string, payload []byte, recipients []api.PendingKey) tea.Cmd {
	eng := m.eng
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), projTimeout)
		defer cancel()
		return projectOpMsg{kind: "rotate", id: projectID, res: eng.RemoveMember(ctx, projectID, removeUserID, payload, recipients)}
	}
}

// scheduleProjectPush arms a per-project push debounce after an edit.
func (m Model) scheduleProjectPush(id string) (Model, tea.Cmd) {
	if m.eng == nil || !m.realMode() {
		return m, nil
	}
	m.syncGen++
	gen := m.syncGen
	return m, tea.Tick(pushDebounce, func(time.Time) tea.Msg { return projPushTimerMsg{id: id, gen: gen} })
}

// --- message handlers ---------------------------------------------------------

func (m Model) handleProjectsSynced(msg projectsSyncedMsg) (tea.Model, tea.Cmd) {
	res := msg.res
	switch {
	case res.SignedOut:
		return m, nil
	case res.SessionDead:
		return m.signOut(), nil
	case res.NoIdentity:
		return m.ensureIdentity()
	}
	// Drop removed projects.
	for _, id := range res.Removed {
		delete(m.projectDocs, id)
	}
	// Rebuild the project list from the snapshot, adopting decrypted payloads.
	items := make([]projectItem, 0, len(res.Views))
	for _, v := range res.Views {
		it := projectItem{
			ID: v.ID, Name: v.Name, Description: v.Description, Role: v.Role,
			AwaitingKey: v.AwaitingKey, Version: v.Version, MemberCount: v.MemberCount,
		}
		if v.Payload != nil {
			if doc, err := store.OpenProjectDoc(v.Payload); err == nil {
				m.projectDocs[v.ID] = doc
				it.HostCount = len(doc.HostList())
			}
		}
		items = append(items, it)
	}
	m.realProjects = items
	// Queue new conflicts, skipping any already queued or being resolved (the
	// engine re-reports an unresolved conflict on every pass).
	for _, c := range res.Conflicts {
		if m.projConflict != nil && m.projConflict.ID == c.ID {
			continue
		}
		dup := false
		for _, q := range m.projConflicts {
			if q.ID == c.ID {
				dup = true
				break
			}
		}
		if !dup {
			m.projConflicts = append(m.projConflicts, c)
		}
	}
	m.projIdx = clampIdx(m.projIdx, m.projectRowCount())
	if res.Err != nil {
		m.syncSt = ssOffline
	}
	var cmds []tea.Cmd
	// Surface the first queued conflict.
	if mm, c := m.maybeOpenProjectConflict(); c != nil || mm.modal == modalProjectConflict {
		m = mm
		if c != nil {
			cmds = append(cmds, c)
		}
	}
	// Admin/owner finalize pass grants keys to freshly joined members.
	cmds = append(cmds, m.finalizeCmd(), m.refreshDetailCmd())
	return m, tea.Batch(cmds...)
}

// refreshDetailCmd re-fetches the selected project's detail (members/invites).
func (m Model) refreshDetailCmd() tea.Cmd {
	if p, ok := m.selectedProject(); ok && !p.AwaitingKey {
		return m.projectDetailCmd(p.ID)
	}
	return nil
}

func (m Model) handleInvitesFetched(msg invitesFetchedMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		return m, nil
	}
	m.receivedInvites = msg.invites
	m.projIdx = clampIdx(m.projIdx, m.projectRowCount())
	return m, nil
}

func (m Model) handleProjectDetail(msg projectDetailMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		if errors.Is(msg.err, api.ErrProjectNotFound) {
			// Vanished — refresh the list.
			return m, m.syncProjectsCmd()
		}
		return m, nil
	}
	d := msg.detail
	m.projDetail = &d
	m.memberIdx = clampIdx(m.memberIdx, len(d.Members)+len(d.Invites))
	return m, nil
}

func (m Model) handleProjectCreated(msg projectCreatedMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		if errors.Is(msg.err, api.ErrNoPublicKey) {
			// Identity not published yet — bootstrap, then the user retries.
			m.cpjErr = "setting up encryption — try again in a moment"
			mm, cmd := m.ensureIdentity()
			return mm, cmd
		}
		m.cpjErr = cleanErr(msg.err)
		return m, nil
	}
	m.modal = modalNone
	v := msg.view
	if v.Payload != nil {
		if doc, err := store.OpenProjectDoc(v.Payload); err == nil {
			m.projectDocs[v.ID] = doc
		}
	}
	m = m.setToast("created project "+v.Name, "ok")
	return m, m.syncProjectsCmd()
}

func (m Model) handleProjectOp(msg projectOpMsg) (tea.Model, tea.Cmd) {
	res := msg.res
	if res.Err != nil {
		if errors.Is(res.Err, syncx.ErrSignedOut) {
			return m, nil
		}
		return m.setToast("project sync failed: "+cleanErr(res.Err), "err"), nil
	}
	if res.Removed {
		return m, m.syncProjectsCmd()
	}
	if res.Conflict != nil {
		// Re-run the projects pass to surface the resolve prompt.
		return m, m.syncProjectsCmd()
	}
	switch msg.kind {
	case "rotate":
		m = m.setToast("member removed — project re-keyed", "ok")
	case "resolve":
		if res.Pushed {
			m = m.setToast("project synced — changes kept", "ok")
		} else if res.Adopted {
			m = m.setToast("project synced — took remote", "ok")
		}
	case "push":
		if res.Pushed {
			m = m.setToast("project synced", "ok")
		}
	}
	// Adopt the payload the engine committed into the cached doc so the next
	// sync sees no spurious local change (critical for resolve take-remote).
	if res.Payload != nil && msg.id != "" {
		if doc, err := store.OpenProjectDoc(res.Payload); err == nil {
			m.projectDocs[msg.id] = doc
		}
	}
	return m, m.syncProjectsCmd()
}

func (m Model) handleInviteSent(msg inviteSentMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		if errors.Is(msg.err, api.ErrInviteConflict) {
			return m.setToast("already a member or already invited", "err"), nil
		}
		return m.setToast("invite failed: "+cleanErr(msg.err), "err"), nil
	}
	m = m.setToast("invitation sent", "ok")
	return m, tea.Batch(m.refreshDetailCmd(), m.syncProjectsCmd())
}

func (m Model) handleInviteRevoked(msg inviteRevokedMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		return m.setToast("could not revoke invite: "+cleanErr(msg.err), "err"), nil
	}
	m = m.setToast("invite revoked", "ok")
	return m, tea.Batch(m.refreshDetailCmd(), m.syncProjectsCmd())
}

func (m Model) handleInviteResponded(msg inviteRespondedMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		if errors.Is(msg.err, api.ErrInviteExpired) {
			return m.setToast("that invite has expired", "err"), m.fetchInvitesCmd()
		}
		return m.setToast("could not respond to invite: "+cleanErr(msg.err), "err"), nil
	}
	if msg.accepted {
		m = m.setToast("joined project — awaiting access key", "ok")
		return m, tea.Batch(m.fetchInvitesCmd(), m.ensureAndSyncProjects())
	}
	m = m.setToast("invite declined", "ok")
	return m, m.fetchInvitesCmd()
}

func (m Model) handleFinalizeDone(msg finalizeDoneMsg) (tea.Model, tea.Cmd) {
	if msg.granted > 0 {
		return m.setToast("granted access to "+itoa(msg.granted)+" member(s)", "ok"), nil
	}
	return m, nil
}

func (m Model) handleProjPushTimer(msg projPushTimerMsg) (tea.Model, tea.Cmd) {
	if msg.gen != m.syncGen || m.eng == nil || !m.realMode() {
		return m, nil
	}
	return m, m.pushProjectCmd(msg.id)
}

// ensureAndSyncProjects makes sure identity is ready, then syncs projects.
func (m Model) ensureAndSyncProjects() tea.Cmd {
	if !m.identityReady {
		return nil // ensureIdentity's success handler triggers the sync
	}
	return m.syncProjectsCmd()
}

// --- projects tab entry -------------------------------------------------------

// enterProjectsTab is called when the user switches to the projects tab in real
// mode: bootstrap identity (once), fetch invites, and run a projects sync.
func (m Model) enterProjectsTab() (Model, tea.Cmd) {
	m.tab, m.focus = 1, 0
	if !m.realMode() {
		return m, nil
	}
	if !m.identityReady && !m.identityBooting {
		mm, cmd := m.ensureIdentity()
		return mm, tea.Batch(cmd, mm.fetchInvitesCmd())
	}
	return m, tea.Batch(m.syncProjectsCmd(), m.fetchInvitesCmd())
}

// --- projects tab key handling (real mode) ------------------------------------

func (m Model) projectsKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "j", "down":
		m.projectsMove(1)
		return m, m.onProjectSelectionChanged()
	case "k", "up":
		m.projectsMove(-1)
		return m, m.onProjectSelectionChanged()
	case "tab":
		if m.focus == 0 {
			m.focus = 1
		} else {
			m.focus = 0
		}
		return m, nil
	case "enter", " ":
		return m.projectsEnter()
	case "i":
		if p, ok := m.selectedProject(); ok && !p.AwaitingKey && isAdmin(p.Role) {
			m.inviteOpen = true
			m.inviteEmail = ""
		}
		return m, nil
	case "n":
		return m.openCreateProject(), nil
	case "x":
		return m.revokeSelectedInvite()
	case "d":
		return m.removeSelectedMember()
	case "r", "R":
		// "I lost my old vault" — only offered in the needs-sync state.
		if m.identityNeedsSync {
			m.modal = modalResetIdentity
		}
		return m, nil
	}
	return m, nil
}

// projectsMove moves the active cursor: the project/invite list (focus 0) or the
// member cursor (focus 1).
func (m *Model) projectsMove(d int) {
	if m.focus == 1 && m.projDetail != nil {
		n := len(m.projDetail.Members) + len(m.projDetail.Invites)
		m.memberIdx = clampIdx(m.memberIdx+d, n)
		return
	}
	m.projIdx = clampIdx(m.projIdx+d, m.projectRowCount())
}

// onProjectSelectionChanged fetches detail for a newly selected project.
func (m Model) onProjectSelectionChanged() tea.Cmd {
	if m.focus == 1 {
		return nil
	}
	m.projDetail = nil
	m.memberIdx = 0
	return m.refreshDetailCmd()
}

func (m Model) projectsEnter() (tea.Model, tea.Cmd) {
	if inv, ok := m.selectedInvite(); ok {
		m.invRespID = inv.ID
		m.invRespName = inv.ProjectName
		m.modal = modalInviteResponse
		return m, nil
	}
	if p, ok := m.selectedProject(); ok {
		if p.AwaitingKey {
			return m.setToast("awaiting access — an admin needs to grant your key", "err"), nil
		}
		// Filter the hosts tab to this project by ID.
		m.projFilterID = p.ID
		m.projFilterName = p.Name
		m.tab, m.focus = 0, 0
		m.query = ""
		m.hostIdx = 0
		return m, nil
	}
	return m, nil
}

// --- create-project form ------------------------------------------------------

func (m Model) openCreateProject() Model {
	m.modal = modalCreateProject
	m.cpjVals = [2]string{}
	m.cpjFocus = 0
	m.cpjErr = ""
	return m
}

func (m Model) createProjectKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.modal = modalNone
		return m, nil
	case "tab", "down":
		m.cpjFocus = (m.cpjFocus + 1) % 2
		return m, nil
	case "shift+tab", "up":
		m.cpjFocus = (m.cpjFocus + 1) % 2
		return m, nil
	case "enter":
		name := strings.TrimSpace(m.cpjVals[0])
		if name == "" {
			m.cpjErr = "project name is required"
			return m, nil
		}
		if !m.identityReady {
			m.cpjErr = "setting up encryption — try again in a moment"
			return m.ensureIdentity()
		}
		m.cpjErr = ""
		return m, m.createProjectCmd(name, strings.TrimSpace(m.cpjVals[1]))
	case "backspace":
		if v := m.cpjVals[m.cpjFocus]; len(v) > 0 {
			m.cpjVals[m.cpjFocus] = v[:len(v)-1]
		}
		return m, nil
	default:
		if isPrintable(key) {
			m.cpjVals[m.cpjFocus] += key
		}
		return m, nil
	}
}

// --- invite response modal ----------------------------------------------------

func (m Model) inviteResponseKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "a", "A", "enter":
		id := m.invRespID
		m.modal = modalNone
		return m, m.respondInviteCmd(id, true)
	case "d", "D":
		id := m.invRespID
		m.modal = modalNone
		return m, m.respondInviteCmd(id, false)
	case "esc", "n", "N":
		m.modal = modalNone
	}
	return m, nil
}

// --- identity reset (pubkey rotate) -------------------------------------------

// resetIdentityConfirmKey handles the "I lost my old vault" confirm: mint a fresh
// keypair, persist it into the personal vault, hand it to the engine, then rotate
// the published public key. The rotate nulls all our wrapped project DEKs, so the
// follow-up resync (driven by identityReadyMsg{ready}) marks every project
// awaiting-access until an admin re-grants.
func (m Model) resetIdentityConfirmKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "y", "Y", "enter":
		m.modal = modalNone
		if m.st == nil || m.eng == nil {
			return m.setToast("cannot reset identity right now", "err"), nil
		}
		pub, priv, err := m.genIdentity()
		if err != nil || len(pub) != 32 || len(priv) != 32 {
			return m.setToast("could not generate an identity key", "err"), nil
		}
		m.st.SetIdentity(&store.Identity{
			X25519Pub:  base64.StdEncoding.EncodeToString(pub),
			X25519Priv: base64.StdEncoding.EncodeToString(priv),
			CreatedAt:  time.Now().UTC(),
		})
		if err := m.st.Save(); err != nil {
			return m.setToast("could not save identity: "+err.Error(), "err"), nil
		}
		m.eng.SetIdentity(pub, priv)
		m.identityReady = true
		m.identityNeedsSync = false
		m.identityNotice = ""
		m = m.setToast("identity reset — projects await re-grant", "ok")
		// Persist the new identity to the synced payload, then rotate the pubkey.
		mm, pushCmd := m.schedulePush()
		return mm, tea.Batch(pushCmd, mm.publishIdentityRotateCmd(pub))
	case "n", "N", "esc":
		m.modal = modalNone
	}
	return m, nil
}

// --- revoke invite / remove member --------------------------------------------

func (m Model) revokeSelectedInvite() (tea.Model, tea.Cmd) {
	p, ok := m.selectedProject()
	if !ok || m.projDetail == nil || !isAdmin(p.Role) {
		return m, nil
	}
	// Only the detail-pane invites are revocable; use the member cursor when it
	// is over an invite row.
	invIdx := m.memberIdx - len(m.projDetail.Members)
	if m.focus != 1 || invIdx < 0 || invIdx >= len(m.projDetail.Invites) {
		return m.setToast("select a pending invite (tab to the detail pane)", "err"), nil
	}
	inv := m.projDetail.Invites[invIdx]
	return m, m.revokeInviteCmd(p.ID, inv.ID)
}

func (m Model) removeSelectedMember() (tea.Model, tea.Cmd) {
	p, ok := m.selectedProject()
	if !ok || m.projDetail == nil || !isAdmin(p.Role) {
		return m, nil
	}
	if m.focus != 1 || m.memberIdx >= len(m.projDetail.Members) {
		return m.setToast("select a member in the detail pane to remove", "err"), nil
	}
	target := m.projDetail.Members[m.memberIdx]
	if strings.EqualFold(target.Role, "OWNER") {
		return m.setToast("the owner cannot be removed", "err"), nil
	}
	if m.eng != nil && target.UserID == m.myUserID() {
		return m.setToast("use leave to remove yourself (not in v1)", "err"), nil
	}
	m.rmUserID = target.UserID
	m.rmName = target.Email
	m.rmProjID = p.ID
	m.modal = modalRemoveMember
	return m, nil
}

func (m Model) removeMemberConfirmKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "y", "Y", "enter":
		m.modal = modalNone
		doc := m.projectDocs[m.rmProjID]
		if doc == nil || m.projDetail == nil {
			return m.setToast("project not ready — sync first", "err"), nil
		}
		payload, err := doc.Marshal()
		if err != nil {
			return m.setToast("could not read project doc", "err"), nil
		}
		recipients := m.keepRecipients(m.rmUserID)
		return m.setToast("re-keying project…", "ok"), m.removeMemberCmd(m.rmProjID, m.rmUserID, payload, recipients)
	case "n", "N", "esc":
		m.modal = modalNone
	}
	return m, nil
}

// keepRecipients builds the list of members to keep keyed after removing
// removeUserID: everyone else who has published a public key.
func (m Model) keepRecipients(removeUserID string) []api.PendingKey {
	if m.projDetail == nil {
		return nil
	}
	var out []api.PendingKey
	for _, mem := range m.projDetail.Members {
		if mem.UserID == removeUserID || len(mem.PublicKey) == 0 {
			continue
		}
		out = append(out, api.PendingKey{UserID: mem.UserID, PublicKey: mem.PublicKey})
	}
	return out
}

// myUserID returns the account's user ID (from the engine's session), best
// effort; "" when unavailable.
func (m Model) myUserID() string {
	// The engine does not expose the user ID directly; matching by email against
	// the member list is the practical proxy here.
	if m.projDetail != nil {
		for _, mem := range m.projDetail.Members {
			if mem.Email == m.email {
				return mem.UserID
			}
		}
	}
	return ""
}

// --- per-project conflict -----------------------------------------------------

// maybeOpenProjectConflict opens the conflict modal for the next queued project
// conflict, if any and no modal is up.
func (m Model) maybeOpenProjectConflict() (Model, tea.Cmd) {
	if len(m.projConflicts) == 0 || m.modal != modalNone {
		return m, nil
	}
	c := m.projConflicts[0]
	m.projConflict = &c
	m.modal = modalProjectConflict
	return m, nil
}

func (m Model) projectConflictKey(key string) (tea.Model, tea.Cmd) {
	if m.projConflict == nil {
		m.modal = modalNone
		return m, nil
	}
	id := m.projConflict.ID
	switch key {
	case "l", "L":
		m.modal = modalNone
		m = m.popProjectConflict()
		return m, m.resolveProjectCmd(id, true)
	case "r", "R":
		m.modal = modalNone
		m = m.popProjectConflict()
		return m, m.resolveProjectCmd(id, false)
	case "esc":
		// Decide later: leave it queued, close the modal.
		m.modal = modalNone
		m.projConflict = nil
	}
	return m, nil
}

// popProjectConflict removes the head conflict and clears the active one.
func (m Model) popProjectConflict() Model {
	if len(m.projConflicts) > 0 {
		m.projConflicts = m.projConflicts[1:]
	}
	m.projConflict = nil
	return m
}

// --- helpers ------------------------------------------------------------------

// isAdmin reports whether a role grants admin privileges (admin or owner).
func isAdmin(role string) bool {
	r := strings.ToUpper(role)
	return r == "ADMIN" || r == "OWNER"
}
