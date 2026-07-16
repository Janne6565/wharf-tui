package ui

import (
	"strings"
	"testing"

	"github.com/Janne6565/wharf-tui/internal/api"
	"github.com/Janne6565/wharf-tui/internal/store"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

func runes(s string) tea.KeyMsg        { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }
func special(k tea.KeyType) tea.KeyMsg { return tea.KeyMsg{Type: k} }

func send(m tea.Model, msg tea.Msg) tea.Model {
	nm, _ := m.Update(msg)
	return nm
}

// dump renders a frame to stdout with a caption (colors stripped).
func dump(t *testing.T, m tea.Model, caption string) {
	t.Logf("\n===== %s =====\n%s", caption, m.View())
}

func TestDumpFrames(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii) // strip ANSI so frames are readable text

	var m tea.Model = New(Config{Demo: true})
	m = send(m, tea.WindowSizeMsg{Width: 108, Height: 34})

	dump(t, m, "01 login (entry)")

	// Skip login → local dashboard (hosts tab).
	m = send(m, runes("l"))
	dump(t, m, "02 local dashboard · hosts")

	// Move selection down twice, open a session.
	m = send(m, runes("j"))
	m = send(m, runes("j"))
	m = send(m, special(tea.KeyEnter))
	dump(t, m, "03 session (db-primary)")

	// Type a command.
	for _, r := range "uptime" {
		m = send(m, runes(string(r)))
	}
	m = send(m, special(tea.KeyEnter))
	dump(t, m, "04 session after `uptime`")

	// Detach, go to projects tab → gate (signed out).
	m = send(m, special(tea.KeyEsc))
	m = send(m, runes("2"))
	dump(t, m, "05 projects gate (signed out)")

	// Enter → sign-in flow, type a code, verify.
	m = send(m, special(tea.KeyEnter)) // gate → auth
	m = send(m, special(tea.KeyEnter)) // intro → code entry
	for _, r := range "K7PQM2XR" {
		m = send(m, runes(string(r)))
	}
	dump(t, m, "06 device code entry")
	m = send(m, special(tea.KeyEnter)) // submit code → verifying
	m = send(m, authDoneMsg{})         // simulate verification complete
	dump(t, m, "07 signed in · dashboard")

	// Projects tab now unlocked.
	m = send(m, runes("2"))
	dump(t, m, "08 projects (signed in)")

	// Keys tab.
	m = send(m, runes("3"))
	dump(t, m, "09 identities")

	// Settings tab, cycle theme.
	m = send(m, runes("4"))
	m = send(m, runes("j"))
	m = send(m, runes("j"))
	m = send(m, runes("j"))
	m = send(m, runes("j")) // land on Theme row
	m = send(m, special(tea.KeyEnter))
	dump(t, m, "10 settings (phosphor)")

	// Help overlay.
	m = send(m, runes("?"))
	dump(t, m, "11 help")
}

// TestDumpFrames (real mode): the device pairing + sync states, driven over
// fake vault/backend hooks.
func TestDumpSyncFrames(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)

	tm, _, fb := pairModelForDump(t)
	dump(t, tm, "s1 signed in · ● synced header")

	// Conflict: local add + remote change, then manual sync.
	tm = send(tm, runes("1"))
	tm = send(tm, runes("a"))
	tm = typeStr(tm, "local-host")
	tm = send(tm, special(tea.KeyTab))
	tm = send(tm, special(tea.KeyTab))
	tm = typeStr(tm, "l.example.com")
	tm, _ = step(tm, special(tea.KeyEnter))
	fb.mu.Lock()
	fb.noVault = false
	fb.vault = []byte(`{"schema":1,"hosts":[{"id":"eeeeffff00001111","name":"remote-host","addr":"r.example.com","port":22,"source":"manual"}],"settings":{"theme":"abyss"}}`)
	fb.version++
	fb.mu.Unlock()
	tm = send(tm, runes("4"))
	tm, cmd := step(tm, runes("s"))
	tm, _ = step(tm, cmd())
	dump(t, tm, "s2 sync conflict prompt")
}

// pairModelForDump mirrors pairModel but dumps the sign-in frames on the way.
func pairModelForDump(t *testing.T) (tea.Model, *fakeVault, *fakeBackend) {
	t.Helper()
	tm, fv, fb := syncedModel(t)
	tm = send(tm, runes("2"))               // projects gate
	tm, _ = step(tm, special(tea.KeyEnter)) // → sign-in intro
	dump(t, tm, "s0a real sign-in (intro)")
	tm, _ = step(tm, special(tea.KeyEnter)) // → code entry
	tm = typeStr(tm, "K7PQ-M2XR")
	dump(t, tm, "s0b device code entry")
	tm, cmd := step(tm, special(tea.KeyEnter))
	tm, syncCmd := step(tm, cmd())
	tm, _ = step(tm, syncCmd())
	return tm, fv, fb
}

// TestDumpProjectFrames (real mode): the live Projects tab, forms and modals,
// driven over the project-aware fake backend + fake crypto.
func TestDumpProjectFrames(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)

	tm, _, fb := projectModel(t)

	// Enter the projects tab: bootstrap identity, then sync.
	tm, cmd := step(tm, runes("2"))
	tm = drain(t, tm, cmd)

	// Create form.
	tm = send(tm, runes("n"))
	tm = typeStr(tm, "atlas-platform")
	tm = send(tm, special(tea.KeyTab))
	tm = typeStr(tm, "core API + data plane")
	dump(t, tm, "p1 create-project form")
	tm, cmd = step(tm, special(tea.KeyEnter))
	tm = drain(t, tm, cmd)

	var projID string
	fb.mu.Lock()
	for id := range fb.projs {
		projID = id
	}
	// Add a pending member + an awaiting-key second project for richer frames.
	fb.projs[projID].members = append(fb.projs[projID].members,
		api.ProjectMember{UserID: "u2", Email: "sam@example.com", Role: "MEMBER", PublicKey: u2pub(), Keyed: true})
	fb.projs[projID].invites = []api.ProjectInvite{{ID: "inv1", Email: "priya@example.com"}}
	fb.projs["awaiting"] = &fakeProjRow{id: "awaiting", name: "edge-infra", desc: "CDN edge", role: "MEMBER", version: 3}
	fb.mu.Unlock()

	tm = drain(t, tm, tm.(Model).syncProjectsCmd())
	tm = drain(t, tm, tm.(Model).projectDetailCmd(projID))
	dump(t, tm, "p2 projects list + detail (members/invites)")

	// Awaiting-access project: move the cursor to it and dump.
	tm = send(tm, runes("j"))
	dump(t, tm, "p3 awaiting-access placeholder")

	// Received invite row + response modal.
	fb.mu.Lock()
	fb.myInvites = []api.ReceivedInvite{{ID: "inv9", ProjectID: "px", ProjectName: "shared-infra", InvitedByEmail: "mara@example.com"}}
	fb.mu.Unlock()
	tm = drain(t, tm, tm.(Model).fetchInvitesCmd())
	// cursor back to the top (the pinned invite).
	tm = send(tm, runes("k"))
	tm = send(tm, runes("k"))
	dump(t, tm, "p4 received-invite pinned row")
	tm, _ = step(tm, special(tea.KeyEnter))
	dump(t, tm, "p5 invite response modal")
	tm, _ = step(tm, special(tea.KeyEsc))

	// Invite modal (on the first project).
	tm = send(tm, runes("j")) // onto a real project (past the invite)
	tm = drain(t, tm, tm.(Model).onProjectSelectionChanged())
	tm = send(tm, runes("i"))
	tm = typeStr(tm, "newhire@example.com")
	dump(t, tm, "p6 invite member modal")
	tm, _ = step(tm, special(tea.KeyEsc))

	// Remove-member confirm: focus the detail pane, land on the member, press d.
	tm = send(tm, special(tea.KeyTab)) // detail pane
	tm = send(tm, runes("j"))          // onto u2 (index 1)
	tm, _ = step(tm, runes("d"))
	dump(t, tm, "p7 remove-member confirm")
	tm, _ = step(tm, special(tea.KeyEsc))

	// Hosts tab with a project host tag.
	fb.mu.Lock()
	// Add a host to the project doc directly via the UI form path is heavy; add
	// through the doc and refresh so the tag renders.
	fb.mu.Unlock()
	mm := tm.(Model)
	if doc := mm.projectDocs[projID]; doc != nil {
		doc.AddHost(store.Host{Name: "proj-web-01", User: "deploy", Addr: "10.0.4.12", Port: 22})
	}
	tm = mm
	tm = send(tm, runes("1"))
	dump(t, tm, "p8 hosts tab with project tag")
}

// TestDumpIdentityResetFrames (real mode): the needs-sync notice and the
// "I lost my old vault" identity-reset confirm.
func TestDumpIdentityResetFrames(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)

	tm, _, _ := needsSyncModel(t)
	dump(t, tm, "r1 needs-sync notice (R reset identity)")

	tm = send(tm, runes("R"))
	dump(t, tm, "r2 reset-identity confirm")
}

// assertions on structure.
func TestLocalFlow(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)
	var m tea.Model = New(Config{Demo: true})
	m = send(m, tea.WindowSizeMsg{Width: 100, Height: 30})

	if !strings.Contains(m.View(), "sign in") {
		t.Fatal("login screen should show sign in")
	}
	if !strings.Contains(m.View(), "skip") {
		t.Fatal("login screen should offer skip/local option")
	}
	m = send(m, runes("l"))
	v := m.View()
	if !strings.Contains(v, "prod-api-01") {
		t.Fatal("local dashboard should list hosts without an account")
	}
	if !strings.Contains(v, "local vault") {
		t.Fatal("header should indicate local (signed-out) state")
	}
	// projects gated
	m = send(m, runes("2"))
	if !strings.Contains(m.View(), "team feature") {
		t.Fatal("projects should be gated when signed out")
	}
}
