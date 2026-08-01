//go:build !windows

package ui

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Janne6565/wharf-tui/internal/sessd"
	"github.com/Janne6565/wharf-tui/internal/sshx"
	"github.com/Janne6565/wharf-tui/internal/store"
	tea "github.com/charmbracelet/bubbletea"
)

// pickerModel unlocks a model wired to a real pool, whose sessions are dialed
// against the package's fake session hosts (see picker_host_test.go).
func pickerModel(t *testing.T, sessions int) (Model, store.Host) {
	t.Helper()
	tm, _ := openedModel(t)
	m := tm.(Model)
	h, err := m.st.AddHost(store.Host{Name: "web1", User: "deploy", Addr: "127.0.0.1", Port: 22})
	if err != nil {
		t.Fatalf("add host: %v", err)
	}
	m.pool = fakePool(t, h.ID, sessions)
	return m, h
}

func TestConnectWithNoSessionsDialsDirectly(t *testing.T) {
	m, h := pickerModel(t, 0)

	next, _ := m.startConnect(h)
	got := next.(Model)
	if got.modal != modalConnecting {
		t.Fatalf("a host with no sessions should dial straight away, modal = %v", got.modal)
	}
}

func TestConnectWithSessionsOpensPicker(t *testing.T) {
	m, h := pickerModel(t, 2)

	next, _ := m.startConnect(h)
	got := next.(Model)
	if got.modal != modalSessionPicker {
		t.Fatalf("a host with sessions should offer the picker, modal = %v", got.modal)
	}

	view := got.View()
	for _, want := range []string{"sessions · web1", "session 1", "session 2", "+ new session", "x x"} {
		if !strings.Contains(view, want) {
			t.Errorf("the picker should show %q:\n%s", want, view)
		}
	}
}

func TestPickerNewSessionRowDials(t *testing.T) {
	m, h := pickerModel(t, 2)
	next, _ := m.startConnect(h)
	got := next.(Model)

	// Move past both sessions onto "+ new session" and take it.
	got = send(got, runes("j")).(Model)
	got = send(got, runes("j")).(Model)
	if got.pickIdx != 2 {
		t.Fatalf("j should reach the new-session row, pickIdx = %d", got.pickIdx)
	}
	after, _ := step(got, special(tea.KeyEnter))
	final := after.(Model)
	if final.modal != modalConnecting {
		t.Fatalf("choosing new session should dial, modal = %v", final.modal)
	}
}

func TestPickerNKeyDialsWithoutMoving(t *testing.T) {
	m, h := pickerModel(t, 2)
	next, _ := m.startConnect(h)

	after := send(next.(Model), runes("n")).(Model)
	if after.modal != modalConnecting {
		t.Fatalf("n should dial a new session, modal = %v", after.modal)
	}
}

func TestPickerKillNeedsTwoPresses(t *testing.T) {
	m, h := pickerModel(t, 2)
	next, _ := m.startConnect(h)
	got := next.(Model)

	before := len(got.hostSessions(h.ID))
	got = send(got, runes("x")).(Model)
	if got.pickKill != got.pickerSessions()[0].ID() {
		t.Fatal("the first x should only arm the selected session")
	}
	if len(got.hostSessions(h.ID)) != before {
		t.Fatal("the first x must not kill anything")
	}
	if !strings.Contains(got.View(), "press x again to kill") {
		t.Fatalf("an armed row should say so:\n%s", got.View())
	}

	// Moving away disarms, so a stray x elsewhere cannot finish the kill.
	got = send(got, runes("j")).(Model)
	if got.pickKill != noKillArmed {
		t.Fatal("moving the cursor should disarm the kill")
	}
}

func TestPickerEscLeavesEverythingRunning(t *testing.T) {
	m, h := pickerModel(t, 2)
	next, _ := m.startConnect(h)

	after := send(next.(Model), special(tea.KeyEsc)).(Model)
	if after.modal != modalNone {
		t.Fatalf("esc should close the picker, modal = %v", after.modal)
	}
	if len(after.hostSessions(h.ID)) != 2 {
		t.Fatal("esc must not touch the sessions")
	}
	if after.attaching {
		t.Fatal("esc must not attach")
	}
}

func TestGlobalSessionOverlayHasNoNewRow(t *testing.T) {
	m, _ := pickerModel(t, 2)

	next, _ := m.openAllSessions()
	got := next.(Model)
	if got.modal != modalSessionPicker {
		t.Fatalf("S should open the picker, modal = %v", got.modal)
	}
	if got.pickerHasNewRow() {
		t.Fatal("the global overlay has no host in context, so no new-session row")
	}
	view := got.View()
	if !strings.Contains(view, "live sessions") {
		t.Fatalf("the overlay should be titled for all sessions:\n%s", view)
	}
	if strings.Contains(view, "+ new session") {
		t.Fatalf("the overlay must not offer a new session:\n%s", view)
	}
	if !strings.Contains(view, "web1") {
		t.Fatalf("the overlay should name each session's host:\n%s", view)
	}
}

func TestGlobalOverlayWithNoSessionsJustToasts(t *testing.T) {
	m, _ := pickerModel(t, 0)

	next, _ := m.openAllSessions()
	got := next.(Model)
	if got.modal != modalNone {
		t.Fatalf("with nothing running the overlay should not open, modal = %v", got.modal)
	}
	if !strings.Contains(got.toast, "no live sessions") {
		t.Fatalf("expected an explanatory toast, got %q", got.toast)
	}
}

func TestHostDetailReportsSessionCount(t *testing.T) {
	m, _ := pickerModel(t, 2)
	if !strings.Contains(m.View(), "2 live sessions") {
		t.Fatalf("the detail pane should count the sessions:\n%s", m.View())
	}
}

// fakePool builds a pool holding n real sessions for hostID, each backed by a
// stub session host in its own process (the package test binary re-execs).
func fakePool(t *testing.T, hostID string, n int) *sessd.Pool {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "wh-ui")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	srv := startStubSSHD(t)
	pool := sessd.NewPool(dir, srv.knownHosts, false)
	pool.SetExecutable(os.Args[0])
	pool.SetNotify(func(msg tea.Msg) {
		// Auto-accept TOFU / auth so the fixture dials without a UI.
		switch p := msg.(type) {
		case sshx.HostKeyPromptMsg:
			p.Reply <- true
		case sshx.SecretPromptMsg:
			p.Reply <- []byte(stubPassword)
		}
	})
	for range n {
		spec := sshx.HostSpec{
			ID: hostID, Name: "web1", User: "tester",
			Addr: srv.host, Port: srv.port,
			AuthMethod: sshx.AuthPassword, Password: stubPassword,
		}
		if _, err := pool.Dial(context.Background(), spec, 80, 24); err != nil {
			t.Fatalf("seeding session: %v", err)
		}
	}
	t.Cleanup(pool.CloseAll)
	return pool
}

// Arming a kill follows the session, not the row. Sessions end on their own
// while the picker is open, so if the list shifts between the two presses, an
// index-based arm would silently point at a different shell — and the second x
// would kill it with no arming step at all.
func TestPickerKillArmsTheSessionNotTheRow(t *testing.T) {
	m, h := pickerModel(t, 3)
	next, _ := m.startConnect(h)
	got := next.(Model)

	// Arm the second session, then let the first one end underneath the cursor.
	got = send(got, runes("j")).(Model)
	armed := got.pickerSessions()[1]
	got = send(got, runes("x")).(Model)
	if got.pickKill != armed.ID() {
		t.Fatalf("x should arm session %s, armed %q", armed.ID(), got.pickKill)
	}

	first := got.pickerSessions()[0]
	_ = first.Close()
	waitPicker(t, &got, func(m Model) bool { return len(m.pickerSessions()) == 2 })

	// Row 1 is now a different session; the armed one moved to row 0.
	if now := got.pickerSessions()[1]; now.ID() == armed.ID() {
		t.Skip("the list did not shift; nothing to assert")
	}
	before := len(got.pickerSessions())
	got = send(got, runes("x")).(Model)
	if len(got.pickerSessions()) != before {
		t.Fatal("x on a row that is no longer the armed session must re-arm, not kill")
	}
	if got.pickKill != got.pickerSessions()[got.pickIdx].ID() {
		t.Fatal("the press should have armed whatever now sits under the cursor")
	}
}

// waitPicker polls until cond holds against the live pool behind the model.
func waitPicker(t *testing.T, m *Model, cond func(Model) bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond(*m) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the session list to shrink")
}
