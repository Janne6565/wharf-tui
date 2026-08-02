package ui

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// browserModel is a first-run model whose browser opener records the URL it was
// handed instead of launching anything.
func browserModel(t *testing.T, opened *[]string, openErr error) tea.Model {
	t.Helper()
	m := New(Config{
		VaultPath:   filepath.Join(t.TempDir(), "vault.enc"),
		VaultExists: func(string) bool { return false },
		OpenBrowser: func(url string) error {
			*opened = append(*opened, url)
			return openErr
		},
	})
	return send(m, tea.WindowSizeMsg{Width: 100, Height: 32})
}

func TestSignInAtGateOpensThePairingPage(t *testing.T) {
	var opened []string
	tm := browserModel(t, &opened, nil)

	tm, cmd := step(tm, runes("2")) // sign in to an account
	if cmd == nil {
		t.Fatal("choosing an account should emit a command to open the browser")
	}
	// The command is what Bubble Tea would run; running it here is what
	// actually reaches the opener.
	msg := cmd()
	if _, ok := msg.(browserOpenedMsg); !ok {
		t.Fatalf("command returned %T, want browserOpenedMsg", msg)
	}
	if len(opened) != 1 {
		t.Fatalf("opened %d URLs, want 1", len(opened))
	}
	if !strings.HasSuffix(opened[0], "/device") {
		t.Errorf("opened %q, want the /device pairing page", opened[0])
	}
	// The URL stays on screen regardless — the browser is a shortcut, not a
	// replacement for the instructions.
	if !strings.Contains(tm.View(), "pairing code") {
		t.Errorf("code entry should still be shown:\n%s", tm.View())
	}
}

func TestPairingScreenSaysWhenTheBrowserOpened(t *testing.T) {
	var opened []string
	tm := browserModel(t, &opened, nil)
	tm, cmd := step(tm, runes("2"))
	if cmd == nil {
		t.Fatal("want a browser command")
	}
	if got := tm.View(); !strings.Contains(got, "In your browser, open") {
		t.Errorf("before the open resolves the screen should still instruct:\n%s", got)
	}

	tm = send(tm, cmd())
	if got := tm.View(); !strings.Contains(got, "Opened in your browser") {
		t.Errorf("after a successful open the screen should say so:\n%s", got)
	}
}

func TestPairingScreenKeepsInstructingWhenTheOpenFails(t *testing.T) {
	var opened []string
	tm := browserModel(t, &opened, errors.New("no handler"))
	tm, cmd := step(tm, runes("2"))
	if cmd == nil {
		t.Fatal("want a browser command")
	}

	tm = send(tm, cmd())
	// Claiming a browser opened when it did not leaves the user waiting for a
	// window that is never coming.
	got := tm.View()
	if strings.Contains(got, "Opened in your browser") {
		t.Errorf("a failed open must not claim success:\n%s", got)
	}
	if !strings.Contains(got, "In your browser, open") {
		t.Errorf("a failed open should keep the manual instruction:\n%s", got)
	}
}

func TestNoBrowserOpenerMeansNoCommand(t *testing.T) {
	// What a headless box, an SSH session, or WHARF_NO_BROWSER produces: no
	// opener is wired and the flow is exactly as it was before.
	t.Setenv("WHARF_NO_BROWSER", "1")
	m := New(Config{
		VaultPath:   filepath.Join(t.TempDir(), "vault.enc"),
		VaultExists: func(string) bool { return false },
		OpenBrowser: nil,
	})
	var tm tea.Model = m
	tm = send(tm, tea.WindowSizeMsg{Width: 100, Height: 32})

	tm, cmd := step(tm, runes("2"))
	if cmd != nil {
		t.Errorf("no opener should emit no command, got %T", cmd())
	}
	if !strings.Contains(tm.View(), "In your browser, open") {
		t.Errorf("manual instructions should stand:\n%s", tm.View())
	}
}

func TestDemoModeNeverOpensABrowser(t *testing.T) {
	var tm tea.Model = New(Config{Demo: true})
	tm = send(tm, tea.WindowSizeMsg{Width: 100, Height: 32})
	// Demo mode simulates the whole exchange; opening a real pairing page from
	// a demo would be a surprise.
	tm = send(tm, runes("s")) // account screen
	_, cmd := step(tm, special(tea.KeyEnter))
	if cmd != nil {
		if _, ok := cmd().(browserOpenedMsg); ok {
			t.Error("demo mode must not open a browser")
		}
	}
}
