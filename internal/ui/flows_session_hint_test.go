package ui

import (
	"strings"
	"testing"

	"github.com/Janne6565/wharf-tui/internal/store"
	tea "github.com/charmbracelet/bubbletea"
)

// hintModel returns an unlocked model with one host, parked on the
// first-connect session hint as a successful dial would leave it.
func hintModel(t *testing.T) (Model, store.Host) {
	t.Helper()
	tm, _ := openedModel(t)
	m := tm.(Model)
	h, err := m.st.AddHost(store.Host{Name: "web1", User: "deploy", Addr: "w.example.com", Port: 22})
	if err != nil {
		t.Fatalf("add host: %v", err)
	}
	m.sessionHintSeen = true
	m.pendingAttachID = h.ID
	m.modal = modalSessionHint
	return m, h
}

func TestSessionHintShowsDetachAndReattachKeys(t *testing.T) {
	m, _ := hintModel(t)
	view := m.View()

	for _, want := range []string{"web1", `ctrl+\`, "alt+1..9", "detach", "reattach"} {
		if !strings.Contains(view, want) {
			t.Errorf("the session hint should mention %q:\n%s", want, view)
		}
	}
}

func TestSessionHintEscStaysOnDashboard(t *testing.T) {
	m, _ := hintModel(t)

	tm, cmd := step(m, special(tea.KeyEsc))
	got := tm.(Model)
	if got.modal != modalNone {
		t.Fatalf("esc should dismiss the hint, modal = %v", got.modal)
	}
	if got.attaching {
		t.Fatal("esc must not hand over the terminal")
	}
	if got.pendingAttachID != "" {
		t.Fatal("esc should clear the pending attach")
	}
	if cmd != nil {
		t.Fatal("esc should not emit an attach command")
	}
	if !strings.Contains(got.toast, "background") {
		t.Fatalf("esc should explain the session kept running, toast = %q", got.toast)
	}
}

// With no engine (or a session that died between dial and keypress) enter must
// close the hint rather than drive a nil attach.
func TestSessionHintEnterWithoutLiveSession(t *testing.T) {
	m, _ := hintModel(t)
	m.mgr = nil

	tm, cmd := step(m, special(tea.KeyEnter))
	got := tm.(Model)
	if got.modal != modalNone {
		t.Fatalf("enter should dismiss the hint, modal = %v", got.modal)
	}
	if got.attaching {
		t.Fatal("there is no live session to attach to")
	}
	if cmd != nil {
		t.Fatal("enter must not emit an attach command without a session")
	}
}

// The hint is a once-per-run primer: a later dial goes straight to the takeover.
func TestSessionHintOnlyOncePerRun(t *testing.T) {
	m, h := hintModel(t)
	tm, _ := step(m, special(tea.KeyEsc))
	m = tm.(Model)

	// A second successful dial with no live session behind it: the degenerate
	// path returns early, but the flag must already be set either way.
	if !m.sessionHintSeen {
		t.Fatal("the hint should be marked seen after the first connect")
	}
	tm, _ = step(m, dialDoneMsg{hostID: h.ID})
	if tm.(Model).modal == modalSessionHint {
		t.Fatal("the hint must not reappear on a later connect")
	}
}

// The first-connect primer is where most users learn how to get back to a
// session, so it has to name the route that always works. alt+1..9 only
// reaches wharf when the terminal maps Option to Meta — which macOS does not
// do by default — so S must be listed, and listed before it.
func TestSessionHintNamesTheSessionsOverlay(t *testing.T) {
	m, _ := hintModel(t)
	view := m.View()

	if !strings.Contains(view, "S ") || !strings.Contains(view, "list live sessions") {
		t.Fatalf("the session hint should name S:\n%s", view)
	}
	sIdx := strings.Index(view, "list live sessions")
	altIdx := strings.Index(view, "alt+1..9")
	if sIdx < 0 || altIdx < 0 || sIdx > altIdx {
		t.Fatalf("S should come before the alt+# route (S at %d, alt at %d):\n%s", sIdx, altIdx, view)
	}
	if !strings.Contains(view, "needs Option-as-Meta") {
		t.Fatalf("the alt+# caveat should be stated where it is offered:\n%s", view)
	}
}

// The help overlay is the fallback place to look one up.
func TestHelpListsTheSessionsOverlay(t *testing.T) {
	tm, _ := openedModel(t)
	m := tm.(Model)
	m.helpOpen = true
	if !strings.Contains(m.View(), "live sessions") {
		t.Fatalf("the help overlay should list S:\n%s", m.View())
	}
}
