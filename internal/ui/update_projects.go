package ui

import (
	"context"
	"encoding/base64"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/Janne6565/wharf-tui/internal/api"
	"github.com/Janne6565/wharf-tui/internal/identity"
	"github.com/Janne6565/wharf-tui/internal/store"
	syncx "github.com/Janne6565/wharf-tui/internal/sync"
	"github.com/Janne6565/wharf-tui/internal/vault"
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

// identityCheckedMsg reports the outcome of comparing the public key the server
// publishes for this account against the local one. checked is false when the
// profile could not be fetched at all: an unreachable server is *unknown*, never
// a mismatch, so that state leaves the current verdict untouched.
type identityCheckedMsg struct {
	checked  bool
	mismatch bool
	localFP  string
	serverFP string
}

// identityRepublishedMsg reports the outcome of the mismatch remediation: a
// rotate-publish of the local (correct) public key over the server's copy.
type identityRepublishedMsg struct{ err error }

// projPushTimerMsg fires after the per-project push debounce.
type projPushTimerMsg struct {
	id  string
	gen int
}

// --- identity bootstrap -------------------------------------------------------

// ensureIdentity lazily prepares the account's identity for projects. It runs
// on the first real Projects entry / create / accept. Cheap when the identity is
// already loaded.
func (m Model) ensureIdentity() (Model, tea.Cmd) {
	if m.identityReady || m.identityBooting || m.eng == nil || !m.realMode() {
		return m, nil
	}
	if pub, priv, ok := m.loadIdentity(); ok {
		// Have a local identity: hand it to the engine and idempotently publish.
		// The publish is a no-op against an already-set key, which is precisely why
		// it can never notice a *substituted* one — so the check runs alongside it
		// and reads back what the server actually hands out for this account.
		m.eng.SetIdentity(pub, priv)
		m.identityReady = true
		// The hybrid upgrade deliberately does NOT happen here: it replaces the
		// server's copy of the key, which would paper over a substituted one
		// before the check below ever saw it. It runs from handleIdentityChecked
		// instead, once the published key is confirmed to be ours.
		return m, tea.Batch(m.publishIdentityCmd(pub, api.PublishNew), m.identityCheckCmd())
	}
	// No local identity — a network check decides whether to generate one.
	m.identityBooting = true
	return m, m.bootstrapIdentityCmd()
}

// identityNeedsHybridUpgrade reports whether the vault holds a classical (v1)
// identity that has not yet grown its ML-KEM half.
func (m Model) identityNeedsHybridUpgrade() bool {
	if m.st == nil {
		return false
	}
	id := m.st.Identity()
	return id != nil && id.X25519Pub != "" && id.MLKEMSeed == ""
}

// upgradeIdentityToHybrid mints the ML-KEM-768 half of an existing identity and
// persists it. The X25519 keypair is kept, so every DEK already sealed to this
// account still opens and no project drops into awaiting-access; the publish
// that follows therefore uses PublishUpgrade rather than PublishRotate.
//
// A failure here is deliberately silent: the account simply stays on the
// classical identity, which still works. Nothing is lost, and shouting about it
// mid-flow would only block the user from reaching their projects.
func (m Model) upgradeIdentityToHybrid() (Model, bool) {
	id := m.st.Identity()
	seed, err := vault.NewMLKEMSeed()
	if err != nil {
		return m, false
	}
	upgraded := *id
	upgraded.MLKEMSeed = base64.StdEncoding.EncodeToString(seed)
	m.st.SetIdentity(&upgraded)
	if err := m.st.Save(); err != nil {
		m.st.SetIdentity(id)
		return m, false
	}
	m.identityHybridUpgraded = true
	// Persist to the synced payload too, so the other clients pick up the seed.
	mm, _ := m.schedulePush()
	return mm, true
}

// loadIdentity decodes the personal vault's stored identity keypair into the
// wire forms the engine and server use: the bare X25519 keys for a pre-hybrid
// identity, the versioned hybrid blobs once an ML-KEM seed is present.
func (m Model) loadIdentity() (pub, priv []byte, ok bool) {
	if m.st == nil {
		return nil, nil, false
	}
	id := m.st.Identity()
	if id == nil {
		return nil, nil, false
	}
	xPub, e1 := base64.StdEncoding.DecodeString(id.X25519Pub)
	xPriv, e2 := base64.StdEncoding.DecodeString(id.X25519Priv)
	if e1 != nil || e2 != nil || len(xPub) != 32 || len(xPriv) != 32 {
		return nil, nil, false
	}
	var seed []byte
	if id.MLKEMSeed != "" {
		s, err := base64.StdEncoding.DecodeString(id.MLKEMSeed)
		if err != nil {
			return nil, nil, false
		}
		seed = s
	}
	pub, priv, err := vault.EncodeIdentity(xPub, xPriv, seed)
	if err != nil {
		return nil, nil, false
	}
	return pub, priv, true
}

// publishIdentityCmd publishes an existing public key; a 409 (already set) is a
// success.
func (m Model) publishIdentityCmd(pub []byte, mode api.PublishMode) tea.Cmd {
	eng := m.eng
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), projTimeout)
		defer cancel()
		err := eng.PublishIdentity(ctx, pub, mode)
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
		if err := eng.PublishIdentity(ctx, pub, api.PublishRotate); err != nil {
			return identityReadyMsg{err: err}
		}
		return identityReadyMsg{ready: true}
	}
}

// identityCheckCmd compares the public key the server publishes for this
// account against the one in this vault, off the UI goroutine.
//
// This is the only place a substituted key can be caught: project DEKs are
// sealed to whatever public key the server hands out per member, so a server
// that quietly replaces *our* key receives every DEK anyone seals "to us". The
// symptom alone (projects stuck awaiting-access) is indistinguishable from the
// benign case, so we verify the one key we can: our own.
//
// Failure to reach the server is deliberately not a verdict — only a key that
// actually differs counts as a mismatch.
func (m Model) identityCheckCmd() tea.Cmd {
	if m.eng == nil || !m.realMode() {
		return nil
	}
	pub, _, ok := m.loadIdentity()
	if !ok {
		return nil
	}
	eng := m.eng
	localB64 := base64.StdEncoding.EncodeToString(pub)
	localFP := identity.Fingerprint(pub)
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), projTimeout)
		defer cancel()
		p, err := eng.ServerProfile(ctx)
		if err != nil {
			return identityCheckedMsg{} // unreachable → unknown, not a mismatch
		}
		if p.PublicKey == "" || p.PublicKey == localB64 {
			// No key published yet, or the expected one. Base64 of a 32-byte key is
			// canonical, so equal strings mean equal keys.
			return identityCheckedMsg{checked: true, localFP: localFP}
		}
		return identityCheckedMsg{
			checked: true, mismatch: true,
			localFP: localFP, serverFP: serverFingerprint(p.PublicKey),
		}
	}
}

// serverFingerprint renders the fingerprint of a base64 public key as published
// by the server. Anything that is not a well-formed identity key — of either
// version — is reported as such rather than fingerprinted: it is still not our
// key, and pretending to fingerprint garbage would give the user something
// meaningless to compare.
func serverFingerprint(b64 string) string {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || !vault.IsIdentityPub(raw) {
		return "(malformed key)"
	}
	return identity.Fingerprint(raw)
}

// republishIdentityCmd re-publishes the *local* public key over the server's
// copy with rotate=true. No new keypair is minted: the local key is the correct
// one, only the server's copy is wrong.
func (m Model) republishIdentityCmd(pub []byte) tea.Cmd {
	eng := m.eng
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), projTimeout)
		defer cancel()
		return identityRepublishedMsg{err: eng.PublishIdentity(ctx, pub, api.PublishRotate)}
	}
}

// handleIdentityChecked records the verdict of the published-key comparison and
// keeps the engine's key-distribution gate in step with it.
func (m Model) handleIdentityChecked(msg identityCheckedMsg) (tea.Model, tea.Cmd) {
	if !msg.checked {
		return m, nil // unknown — leave the previous verdict alone
	}
	m.identityMismatch = msg.mismatch
	m.identityLocalFP = msg.localFP
	m.identityServerFP = msg.serverFP
	if m.eng != nil {
		m.eng.SetIdentityMismatch(msg.mismatch)
	}
	if msg.mismatch {
		return m.setToast("published key mismatch — see the projects tab", "err"), nil
	}
	// The published key is ours, so it is safe to replace it with the hybrid
	// form: any substitution would have surfaced above. PublishUpgrade keeps the
	// wrapped DEKs, which stay openable because the X25519 half is unchanged.
	if m.identityNeedsHybridUpgrade() {
		mm, ok := m.upgradeIdentityToHybrid()
		if !ok {
			return m, nil
		}
		m = mm
		pub, priv, ok := m.loadIdentity()
		if !ok {
			return m, nil
		}
		m.eng.SetIdentity(pub, priv)
		return m, m.publishIdentityCmd(pub, api.PublishUpgrade)
	}
	return m, nil
}

// handleIdentityRepublished completes the remediation: on success the server's
// copy is ours again, so re-verify (rather than assume) and resync.
func (m Model) handleIdentityRepublished(msg identityRepublishedMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		return m.setToast("could not republish your key: "+cleanErr(msg.err), "err"), nil
	}
	m = m.setToast("key republished — projects await re-grant", "ok")
	return m, tea.Batch(m.identityCheckCmd(), m.syncProjectsCmd())
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
		xPub, xPriv, err := m.genIdentity()
		if err != nil || len(xPub) != 32 || len(xPriv) != 32 {
			return m.setToast("could not generate an identity key", "err"), nil
		}
		// A fresh identity is always hybrid: the X25519 keypair plus the ML-KEM
		// half that makes DEKs sealed to it quantum-safe.
		seed, err := vault.NewMLKEMSeed()
		if err != nil {
			return m.setToast("could not generate an identity key", "err"), nil
		}
		pub, priv, err := vault.EncodeIdentity(xPub, xPriv, seed)
		if err != nil {
			return m.setToast("could not generate an identity key", "err"), nil
		}
		m.st.SetIdentity(&store.Identity{
			X25519Pub:  base64.StdEncoding.EncodeToString(xPub),
			X25519Priv: base64.StdEncoding.EncodeToString(xPriv),
			MLKEMSeed:  base64.StdEncoding.EncodeToString(seed),
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
		return mm, tea.Batch(pushCmd, mm.publishIdentityCmd(pub, api.PublishNew))
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
	m.projectsLoaded = true
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

// bootstrapProjects loads the project list and received invites for a signed-in
// session, without waiting for the projects tab to be opened. Projects are not
// a feature of that one tab: the hosts tab merges project hosts into its list,
// and "move to project" needs to know which projects exist — deferring the load
// left both quietly wrong, a hosts list missing rows and a move that reported
// "no projects yet" for an account that had several.
//
// It deliberately does NOT create a project identity. Identity generation
// writes an X25519 keypair into the vault, pushes it and publishes the public
// key, and it bumps the payload to a schema older builds refuse to open — none
// of which should happen to someone who signs in and never touches projects.
// A vault that already carries an identity has it loaded by initSync, and a
// vault that does not has no keyed projects to show anyway; opening the tab
// still bootstraps one on demand.
func (m Model) bootstrapProjects() (Model, tea.Cmd) {
	if !m.realMode() || m.eng == nil || !m.identityReady {
		return m, nil
	}
	return m, tea.Batch(m.syncProjectsCmd(), m.fetchInvitesCmd())
}

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
	// Re-verify the published key on every entry: the substitution can happen at
	// any time, not just on the session's first visit.
	return m, tea.Batch(m.syncProjectsCmd(), m.fetchInvitesCmd(), m.identityCheckCmd())
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
		return m.projectsCycleFocus(1), nil
	case "shift+tab":
		return m.projectsCycleFocus(-1), nil
	case "esc":
		// Step back out of the detail pane rather than off the tab.
		if m.focus != pfList {
			m.focus = pfList
			return m, nil
		}
		return m, nil
	case "enter", " ":
		return m.projectsEnter()
	case "f":
		// The merged hosts tab, filtered to this project — the old behaviour of
		// enter, now an explicit choice instead of a surprise tab switch.
		return m.filterHostsByProject()
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
	case "p", "P":
		// Remediation for a published-key mismatch — only offered while one stands.
		if m.identityMismatch {
			m.modal = modalRepublishKey
		}
		return m, nil
	}
	return m, nil
}

// projectsMove moves the active cursor: the project/invite list (focus 0) or the
// member cursor (focus 1).
func (m *Model) projectsMove(d int) {
	switch {
	case m.focus == pfHosts:
		m.projHostIdx = clampIdx(m.projHostIdx+d, len(m.selectedProjectHosts()))
	case m.focus == pfMembers && m.projDetail != nil:
		n := len(m.projDetail.Members) + len(m.projDetail.Invites)
		m.memberIdx = clampIdx(m.memberIdx+d, n)
	default:
		m.projIdx = clampIdx(m.projIdx+d, m.projectRowCount())
	}
}

// projectsCycleFocus advances the detail-pane focus ring, skipping rings that
// have nothing in them (an invite row has neither hosts nor members, and an
// awaiting-access project has no readable hosts).
func (m Model) projectsCycleFocus(d int) Model {
	p, isProject := m.selectedProject()
	if !isProject || p.AwaitingKey {
		m.focus = pfList
		return m
	}
	for i := 0; i < pfCount; i++ {
		m.focus = (m.focus + d + pfCount) % pfCount
		switch m.focus {
		case pfList:
			return m
		case pfHosts:
			if len(m.selectedProjectHosts()) > 0 {
				m.projHostIdx = clampIdx(m.projHostIdx, len(m.selectedProjectHosts()))
				return m
			}
		case pfMembers:
			if m.projDetail != nil && len(m.projDetail.Members)+len(m.projDetail.Invites) > 0 {
				return m
			}
		}
	}
	m.focus = pfList
	return m
}

// selectedProjectHosts returns the hosts of the project under the cursor,
// stable-sorted the way the hosts tab sorts them. Empty unless a keyed project
// row is selected.
func (m Model) selectedProjectHosts() []store.Host {
	p, ok := m.selectedProject()
	if !ok || p.AwaitingKey {
		return nil
	}
	doc := m.projectDocs[p.ID]
	if doc == nil {
		return nil
	}
	hosts := doc.HostList()
	sort.SliceStable(hosts, func(i, j int) bool {
		return strings.ToLower(hosts[i].Name) < strings.ToLower(hosts[j].Name)
	})
	return hosts
}

// selectedProjectHost returns the host under the detail-pane host cursor.
func (m Model) selectedProjectHost() (store.Host, bool) {
	hosts := m.selectedProjectHosts()
	if len(hosts) == 0 {
		return store.Host{}, false
	}
	return hosts[clampIdx(m.projHostIdx, len(hosts))], true
}

// onProjectSelectionChanged fetches detail for a newly selected project.
func (m Model) onProjectSelectionChanged() tea.Cmd {
	if m.focus != pfList {
		return nil
	}
	m.projDetail = nil
	m.memberIdx = 0
	m.projHostIdx = 0
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
		// Opening a project stays on this tab: the cursor drops into the
		// project's own host list in the detail pane. Switching tabs out from
		// under the user was disorienting — the hosts tab looked like it had
		// silently lost most of its rows.
		if m.focus == pfList {
			if len(m.selectedProjectHosts()) == 0 {
				return m.setToast("no hosts in "+p.Name+" yet — p on a host moves one in", "err"), nil
			}
			m.focus = pfHosts
			m.projHostIdx = 0
			return m, nil
		}
		if m.focus == pfHosts {
			if h, ok := m.selectedProjectHost(); ok {
				return m.startConnect(h)
			}
		}
		return m, nil
	}
	return m, nil
}

// filterHostsByProject shows the merged hosts tab narrowed to the selected
// project (the filter chip clears with esc).
func (m Model) filterHostsByProject() (tea.Model, tea.Cmd) {
	p, ok := m.selectedProject()
	if !ok || p.AwaitingKey {
		return m, nil
	}
	m.projFilterID = p.ID
	m.projFilterName = p.Name
	m.tab, m.focus = 0, 0
	m.query = ""
	m.hostIdx = 0
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
		xPub, xPriv, err := m.genIdentity()
		if err != nil || len(xPub) != 32 || len(xPriv) != 32 {
			return m.setToast("could not generate an identity key", "err"), nil
		}
		// A fresh identity is always hybrid: the X25519 keypair plus the ML-KEM
		// half that makes DEKs sealed to it quantum-safe.
		seed, err := vault.NewMLKEMSeed()
		if err != nil {
			return m.setToast("could not generate an identity key", "err"), nil
		}
		pub, priv, err := vault.EncodeIdentity(xPub, xPriv, seed)
		if err != nil {
			return m.setToast("could not generate an identity key", "err"), nil
		}
		m.st.SetIdentity(&store.Identity{
			X25519Pub:  base64.StdEncoding.EncodeToString(xPub),
			X25519Priv: base64.StdEncoding.EncodeToString(xPriv),
			MLKEMSeed:  base64.StdEncoding.EncodeToString(seed),
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

// --- republish key (mismatch remediation) -------------------------------------

// republishKeyConfirmKey handles the "the server has the wrong key for me"
// confirm. It deliberately does *not* mint a new keypair: the local key is the
// correct one and stays put; only the server's copy is overwritten, with
// rotate=true because that is the only way to replace an already-set key.
func (m Model) republishKeyConfirmKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "y", "Y", "enter":
		m.modal = modalNone
		if m.eng == nil {
			return m.setToast("cannot republish right now", "err"), nil
		}
		pub, _, ok := m.loadIdentity()
		if !ok {
			return m.setToast("no local identity to republish", "err"), nil
		}
		return m.setToast("republishing your key…", "ok"), m.republishIdentityCmd(pub)
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
	if m.focus != pfMembers || invIdx < 0 || invIdx >= len(m.projDetail.Invites) {
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
	if m.focus != pfMembers || m.memberIdx >= len(m.projDetail.Members) {
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
