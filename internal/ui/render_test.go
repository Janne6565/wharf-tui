package ui

import (
	"strings"
	"testing"

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

	var m tea.Model = New()
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

// assertions on structure.
func TestLocalFlow(t *testing.T) {
	lipgloss.SetColorProfile(termenv.Ascii)
	var m tea.Model = New()
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
