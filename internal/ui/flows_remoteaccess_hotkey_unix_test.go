//go:build !windows

package ui

import (
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// The in-session hotkey is exercised by calling the callback the attach loop
// would call, rather than by faking a terminal. That is the honest seam: what
// internal/sessd promises is "this function is called, on its own goroutine,
// and whatever it returns is printed raw", and internal/sessd's own tests hold
// it to that. What is left to prove here is that the callback mints the right
// thing through the Holder and says so in text a raw terminal can show.

// hotkeyModel returns an unlocked real-mode model and the callback bound to
// hostID/hostName, plus the clipboard recorder the callback writes through.
func hotkeyModel(t *testing.T, hostID, hostName string) (Model, func() string, *[]string) {
	t.Helper()
	tm, _ := openedModel(t)
	m := tm.(Model)
	var copies []string
	m.copyToClipboard = func(s string) error {
		copies = append(copies, s)
		return nil
	}
	t.Cleanup(m.ra.Revoke)
	return m, remoteAccessHotkey(m.ra, m.raCopy, m.copyToClipboard, hostID, hostName, stubExec{}), &copies
}

// Every line the callback returns is printed into a terminal that is still in
// raw mode, so a bare \n would leave the second line indented under the end of
// the first.
func assertRawModeLines(t *testing.T, text string) {
	t.Helper()
	for _, l := range strings.Split(strings.TrimSuffix(text, "\r\n"), "\r\n") {
		if strings.Contains(l, "\n") {
			t.Fatalf("every line break must be \\r\\n in raw mode, got %q", text)
		}
	}
}

func TestTheInSessionHotkeyMintsAGrantAndPrintsTheCommandLine(t *testing.T) {
	m, hotkey, copies := hotkeyModel(t, "h1", "web1")

	text := hotkey()
	assertRawModeLines(t, text)

	g := m.raGrant()
	if g == nil {
		t.Fatalf("the hotkey must mint a grant, printed:\n%s", text)
	}
	if !strings.Contains(text, g.CommandLine()) {
		t.Fatalf("the printed text must carry the whole command line — OSC 52 reaches nobody in some terminals:\n%s", text)
	}
	for _, want := range []string{"remote access ON for web1", "expires ", "copied to clipboard"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the status line should contain %q:\n%s", want, text)
		}
	}
	if len(*copies) != 1 || (*copies)[0] != g.CommandLine() {
		t.Fatalf("the hotkey should copy exactly the command line it printed, copies = %v", *copies)
	}
	if ok, _ := m.raCopy.forGrant(g); !ok {
		t.Fatal("a clipboard hook that returned nil should be recorded as copied, so the overlay agrees with the print")
	}
}

func TestPressingTheInSessionHotkeyAgainRevokesAndSaysSo(t *testing.T) {
	m, hotkey, _ := hotkeyModel(t, "h1", "web1")

	hotkey()
	sock := m.raGrant().SocketPath()

	text := hotkey()
	assertRawModeLines(t, text)
	if m.raGrant() != nil {
		t.Fatal("a second press on the same host must revoke")
	}
	if !strings.Contains(text, "revoked for web1") {
		t.Fatalf("the revocation must name the host it took the capability from:\n%s", text)
	}
	if strings.Contains(text, sock) || strings.Contains(text, "wharf --remote") {
		t.Fatalf("a revocation has no command line to print:\n%s", text)
	}
	if n := strings.Count(strings.TrimSpace(text), "\r\n"); n != 0 {
		t.Fatalf("a revocation is one line, got %d breaks in %q", n, text)
	}
}

// Silently moving a capability from one host to another is not acceptable: the
// printed line has to name the host that just lost it.
func TestTheInSessionHotkeyOnAnotherHostReplacesAndNamesTheDisplacedHost(t *testing.T) {
	m, onWeb1, _ := hotkeyModel(t, "h1", "web1")
	onDB1 := remoteAccessHotkey(m.ra, m.raCopy, m.copyToClipboard, "h2", "db1", stubExec{})

	onWeb1()
	first := m.raGrant()

	text := onDB1()
	assertRawModeLines(t, text)
	g := m.raGrant()
	if g == nil || g.HostID() != "h2" {
		t.Fatalf("the grant should have moved to db1, got %v", g)
	}
	if !strings.Contains(text, "db1") || !strings.Contains(text, "web1 lost it") {
		t.Fatalf("a replacement must name both hosts:\n%s", text)
	}
	if !strings.Contains(text, g.CommandLine()) {
		t.Fatalf("the new grant's command line must be printed:\n%s", text)
	}
	if strings.Contains(text, first.Token()) {
		t.Fatalf("the displaced grant's token must not be printed:\n%s", text)
	}
	// The copy record moved with the grant, so the overlay cannot claim the old
	// grant's successful copy for the new one.
	if ok, _ := m.raCopy.forGrant(first); ok {
		t.Fatal("the copy record must follow the live grant, not the displaced one")
	}
}

// This is the property the Holder exists for: the dashboard reflects a grant
// minted while Bubble Tea was suspended, with nothing to deliver and nothing to
// synchronise.
func TestAGrantMintedInSessionIsOnTheDashboardAfterDetachWithNoExtraStep(t *testing.T) {
	m, hotkey, _ := hotkeyModel(t, "h1", "web1")
	m.attaching = true

	hotkey() // pressed while the terminal belongs to the session

	tm := send(m, tea.WindowSizeMsg{Width: 140, Height: 32})
	tm, _ = step(tm, detachedMsg{sessionID: "s1"})
	got := tm.(Model)
	if got.raGrant() == nil {
		t.Fatal("the grant minted in-session must be the one the dashboard sees")
	}
	if !strings.Contains(got.View(), "remote web1") {
		t.Fatalf("the header badge must show it with no synchronisation step:\n%s", got.View())
	}
	// And the overlay opens on it, command line and all.
	if v := send(got, runes("A")).View(); !strings.Contains(v, got.raGrant().CommandLine()) {
		t.Fatalf("the overlay must show the in-session grant's command line:\n%s", v)
	}
}

// lock() is the revocation a user walking away relies on, and it has to reach a
// grant the reducer never minted.
func TestLockingTheVaultRevokesAGrantMintedInSession(t *testing.T) {
	m, hotkey, _ := hotkeyModel(t, "h1", "web1")
	hotkey()
	g := m.raGrant()

	tm, _ := step(send(m, tea.WindowSizeMsg{Width: 140, Height: 32}), detachedMsg{sessionID: "s1"})
	tm = send(tm, runes("q")) // q on the dashboard locks the vault

	got := tm.(Model)
	if got.screen != scUnlock {
		t.Fatalf("q should lock the vault, screen = %v", got.screen)
	}
	if got.raGrant() != nil {
		t.Fatal("locking must revoke a grant minted in-session too")
	}
	if _, err := os.Stat(g.SocketPath()); !os.IsNotExist(err) {
		t.Fatalf("revocation is synchronous: the socket must be gone, stat err = %v", err)
	}
}

// The quit confirmation is driven by the same Holder read, so a grant minted
// in-session still stops ctrl+q from quitting silently.
func TestQuitStillConfirmsWhenAGrantWasMintedInSession(t *testing.T) {
	m, hotkey, _ := hotkeyModel(t, "h1", "web1")
	hotkey()

	next, cmd := m.requestQuit()
	got := next.(Model)
	if got.modal != modalQuitConfirm {
		t.Fatalf("a live grant must make quit confirm first, modal = %v", got.modal)
	}
	if cmd != nil {
		t.Fatal("requestQuit must not quit while it is asking")
	}
	if v := send(got, tea.WindowSizeMsg{Width: 140, Height: 32}).View(); !strings.Contains(v, "remote access on web1 will be revoked") {
		t.Fatalf("the confirmation should name what quitting takes away:\n%s", v)
	}
	// Confirming it revokes.
	after, _ := got.doQuit()
	if after.(Model).raGrant() != nil {
		t.Fatal("quitting must revoke the grant rather than leave it to the process exit")
	}
}

// A grant that exists must never be reported as a failure. The clipboard hook
// is somebody else's code running after the grant is already live; a panic
// there used to unwind into the attach loop's recover, which prints "remote
// access failed" — leaving a capability open on a real host that the user
// believes was never granted, with the command line never printed and no way to
// reach it from inside the session.
func TestAPanickingClipboardHookStillReportsTheGrantItAlreadyMinted(t *testing.T) {
	tm, _ := openedModel(t)
	m := tm.(Model)
	t.Cleanup(m.ra.Revoke)
	m.copyToClipboard = func(string) error { panic("the terminal went away") }

	text := remoteAccessHotkey(m.ra, m.raCopy, m.copyToClipboard, "h1", "web1", stubExec{})()

	g := m.raGrant()
	if g == nil {
		t.Fatalf("the grant was minted before the copy was attempted, so it must survive it:\n%s", text)
	}
	if !strings.Contains(text, g.CommandLine()) {
		t.Fatalf("the command line is the only way back to a live grant from inside a session:\n%s", text)
	}
	if !strings.Contains(text, "remote access ON for web1") {
		t.Fatalf("a live grant must be reported as one:\n%s", text)
	}
	if !strings.Contains(text, "not copied") {
		t.Fatalf("the copy did not happen and must not be claimed:\n%s", text)
	}
	// And the overlay agrees with the print.
	if ok, _ := m.raCopy.forGrant(g); ok {
		t.Fatal("a panicking hook must never be recorded as a successful copy")
	}
}

// The same containment on the dashboard path, where the panic would otherwise
// unwind through Update and take the whole program down with a live grant.
func TestAPanickingClipboardHookDoesNotTakeTheDashboardGrantWithIt(t *testing.T) {
	tm, _ := openedModel(t)
	m := tm.(Model)
	t.Cleanup(m.ra.Revoke)
	m.copyToClipboard = func(string) error { panic("the terminal went away") }

	next, _ := m.grantRemoteAccess("h1", "web1", stubExec{})
	got := next.(Model)
	if got.raGrant() == nil {
		t.Fatal("the grant must survive a panicking clipboard hook")
	}
	if v := got.View(); !strings.Contains(v, got.raGrant().CommandLine()) {
		t.Fatalf("the overlay must still show the command line:\n%s", v)
	}
	if !strings.Contains(got.View(), "not copied") {
		t.Fatalf("the overlay must not claim a copy that panicked:\n%s", got.View())
	}
}
