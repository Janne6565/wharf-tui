package ui

import (
	"errors"
	"strings"
	"testing"

	"github.com/Janne6565/wharf-tui/internal/sshx"
	tea "github.com/charmbracelet/bubbletea"
)

// forwardModelWithHost returns an unlocked real-mode model wired to a real
// (network-free until StartForward) manager, with one personal host "web1"
// selected. Returns the model and the host's ID.
func forwardModelWithHost(t *testing.T) (tea.Model, string) {
	t.Helper()
	tm, _ := openedModel(t)
	mm := tm.(Model)
	mm.mgr = sshx.NewManager("/tmp/wharf-test-known-hosts", false)
	tm = mm

	tm = send(tm, runes("a"))
	tm = typeStr(tm, "web1")
	tm = send(tm, special(tea.KeyTab)) // → user
	tm = typeStr(tm, "deploy")
	tm = send(tm, special(tea.KeyTab)) // → address
	tm = typeStr(tm, "example.com")
	tm, _ = step(tm, special(tea.KeyEnter))
	return tm, hostByName(t, tm, "web1").ID
}

func TestForwardFormDefaults(t *testing.T) {
	tm, _ := forwardModelWithHost(t)
	tm = send(tm, runes("f"))
	v := tm.View()
	if !strings.Contains(v, "forward for") || !strings.Contains(v, "web1") {
		t.Fatalf("f should open the forward form for the selected host:\n%s", v)
	}
	if !strings.Contains(v, "local (-L)") {
		t.Fatalf("kind should default to local (-L):\n%s", v)
	}
	if !strings.Contains(v, "127.0.0.1") {
		t.Fatalf("bind/target address should prefill 127.0.0.1:\n%s", v)
	}
}

func TestForwardFormDynamicHidesTargets(t *testing.T) {
	tm, _ := forwardModelWithHost(t)
	tm = send(tm, runes("f"))
	// On the kind selector: local → remote → dynamic.
	tm = send(tm, runes(" "))
	tm = send(tm, runes(" "))
	v := tm.View()
	if !strings.Contains(v, "dynamic socks5 (-D)") {
		t.Fatalf("cycling should reach the dynamic kind:\n%s", v)
	}
	if strings.Contains(v, "target addr") || strings.Contains(v, "target port") {
		t.Fatalf("dynamic forward should hide the target fields:\n%s", v)
	}

	// Navigation must skip the hidden target fields: from kind, one tab lands on
	// bind addr, then bind port, then wraps back to kind (never a target field).
	tm = send(tm, special(tea.KeyTab)) // → bind addr
	tm = send(tm, special(tea.KeyTab)) // → bind port
	tm = send(tm, special(tea.KeyTab)) // wraps → kind
	tm, cmd := step(tm, special(tea.KeyEnter))
	// Kind is a selector; enter submits. A dynamic forward needs no target, so
	// this should start (produce a command), not error.
	if cmd == nil {
		t.Fatalf("submitting a valid dynamic forward should start it:\n%s", tm.View())
	}
}

func TestForwardFormBadTargetPort(t *testing.T) {
	tm, _ := forwardModelWithHost(t)
	tm = send(tm, runes("f"))
	// kind → bind addr → bind port → target addr → target port
	for i := 0; i < 4; i++ {
		tm = send(tm, special(tea.KeyTab))
	}
	tm = typeStr(tm, "70000") // out of range
	tm, _ = step(tm, special(tea.KeyEnter))
	if !strings.Contains(tm.View(), "target port must be 1-65535") {
		t.Fatalf("an out-of-range target port should surface an inline error:\n%s", tm.View())
	}
}

func TestForwardSubmitStartsForward(t *testing.T) {
	tm, _ := forwardModelWithHost(t)
	tm = send(tm, runes("f"))
	for i := 0; i < 4; i++ {
		tm = send(tm, special(tea.KeyTab)) // → target port
	}
	tm = typeStr(tm, "5432")
	tm, cmd := step(tm, special(tea.KeyEnter))
	if cmd == nil {
		t.Fatal("submitting a valid forward should produce a startForwardCmd")
	}
	if !strings.Contains(tm.View(), "starting forward") {
		t.Fatalf("the connecting modal should announce a forward start:\n%s", tm.View())
	}
}

func TestForwardDoneError(t *testing.T) {
	tm, id := forwardModelWithHost(t)
	tm, _ = step(tm, forwardDoneMsg{hostID: id, err: sshx.ErrAuthFailed})
	if !strings.Contains(tm.View(), "authentication failed") {
		t.Fatalf("a failed forward should route through the dial error taxonomy:\n%s", tm.View())
	}
}

func TestForwardEndedToast(t *testing.T) {
	tm, id := forwardModelWithHost(t)

	closed, _ := step(tm, sshx.ForwardEndedMsg{ForwardID: "fa", HostID: id, Err: nil})
	if !strings.Contains(closed.View(), "forward to web1 closed") {
		t.Fatalf("a deliberate close should toast closed:\n%s", closed.View())
	}

	ended, _ := step(tm, sshx.ForwardEndedMsg{ForwardID: "fb", HostID: id, Err: errors.New("boom")})
	if !strings.Contains(ended.View(), "ended: boom") {
		t.Fatalf("a failed end should toast the error:\n%s", ended.View())
	}
}

func TestForwardsOverlayEmpty(t *testing.T) {
	tm, _ := forwardModelWithHost(t)
	tm = send(tm, runes("F"))
	if !strings.Contains(tm.View(), "no active forwards") {
		t.Fatalf("F with no forwards should show the empty overlay:\n%s", tm.View())
	}
	// F again closes.
	tm = send(tm, runes("F"))
	if strings.Contains(tm.View(), "no active forwards") {
		t.Fatalf("F should toggle the overlay closed:\n%s", tm.View())
	}
}

func TestForwardDemoInert(t *testing.T) {
	var m tea.Model = New(Config{Demo: true})
	m = send(m, tea.WindowSizeMsg{Width: 100, Height: 32})
	m = send(m, runes("l")) // skip login → local dashboard (hosts tab)
	m = send(m, runes("f"))
	if strings.Contains(m.View(), "forward for") {
		t.Fatalf("f must be inert in demo mode:\n%s", m.View())
	}
}

func TestForwardSpecLabelResolvesAutoPort(t *testing.T) {
	cases := []struct {
		name      string
		spec      sshx.ForwardSpec
		boundAddr string
		want      string
	}{
		{
			name:      "auto-picked local bind port substituted",
			spec:      sshx.ForwardSpec{Kind: sshx.ForwardLocal, BindAddr: "127.0.0.1", BindPort: 0, TargetAddr: "db", TargetPort: 5432},
			boundAddr: "127.0.0.1:54321",
			want:      "L 127.0.0.1:54321 → db:5432",
		},
		{
			name:      "explicit bind port kept as typed",
			spec:      sshx.ForwardSpec{Kind: sshx.ForwardLocal, BindAddr: "127.0.0.1", BindPort: 8080, TargetAddr: "db", TargetPort: 5432},
			boundAddr: "127.0.0.1:8080",
			want:      "L 127.0.0.1:8080 → db:5432",
		},
		{
			name:      "dynamic auto port substituted",
			spec:      sshx.ForwardSpec{Kind: sshx.ForwardDynamic, BindAddr: "127.0.0.1", BindPort: 0},
			boundAddr: "127.0.0.1:1080",
			want:      "D socks5 127.0.0.1:1080",
		},
	}
	for _, c := range cases {
		if got := forwardSpecLabel(c.spec, c.boundAddr); got != c.want {
			t.Errorf("%s: forwardSpecLabel = %q, want %q", c.name, got, c.want)
		}
	}
}
