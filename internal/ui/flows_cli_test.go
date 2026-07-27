package ui

import (
	"strings"
	"testing"

	"github.com/Janne6565/wharf-tui/internal/store"
	tea "github.com/charmbracelet/bubbletea"
)

// cliHosts is a small personal host set for resolving command-line arguments.
func cliHosts() []store.Host {
	return []store.Host{
		{Name: "prod-api-01", User: "deploy", Addr: "10.0.0.1", Port: 22, Source: "manual"},
		{Name: "prod-api-02", User: "deploy", Addr: "10.0.0.2", Port: 22, Source: "manual"},
		{Name: "homelab", User: "janne", Addr: "10.0.0.9", Port: 22, Source: "manual"},
	}
}

func TestHostByName(t *testing.T) {
	m := Model{st: store.NewMemory(cliHosts(), store.DefaultSettings())}

	for _, tc := range []struct{ arg, want string }{
		{"homelab", "homelab"},         // exact
		{"HomeLab", "homelab"},         // case-insensitive
		{"home", "homelab"},            // unique prefix
		{"prod-api-01", "prod-api-01"}, // exact wins even though it is also a prefix
	} {
		h, err := m.hostByName(tc.arg)
		if err != nil {
			t.Fatalf("hostByName(%q): unexpected error: %v", tc.arg, err)
		}
		if h.Name != tc.want {
			t.Fatalf("hostByName(%q) = %q, want %q", tc.arg, h.Name, tc.want)
		}
	}

	if _, err := m.hostByName("prod"); err == nil {
		t.Fatal("an ambiguous prefix must not resolve")
	} else if !strings.Contains(err.Error(), "prod-api-01") || !strings.Contains(err.Error(), "prod-api-02") {
		t.Fatalf("ambiguity error should name the candidates, got: %v", err)
	}

	if _, err := m.hostByName("nope"); err == nil {
		t.Fatal("an unknown name must not resolve")
	}

	if _, err := m.hostByName(""); err == nil {
		t.Fatal("an empty name must not resolve")
	}
}

// connectArgModel unlocks a vault seeded with cliHosts, with host given as the
// command-line argument. The manager is nil, so a resolved host reaches the
// dial path and stops there — enough to observe which branch ran.
func connectArgModel(t *testing.T, host string) tea.Model {
	t.Helper()
	payload := []byte(`{"schema":1,"hosts":[` +
		`{"id":"aaaabbbbccccdd01","name":"prod-api-01","user":"deploy","addr":"10.0.0.1","port":22,"source":"manual"},` +
		`{"id":"aaaabbbbccccdd02","name":"prod-api-02","user":"deploy","addr":"10.0.0.2","port":22,"source":"manual"}],` +
		`"settings":{"theme":"abyss","agent":true,"keepalive":true,"telemetry":false}}`)
	fv := &fakeVault{payload: payload}
	m := New(Config{
		VaultPath:   "/tmp/none",
		ConnectHost: host,
		VaultExists: func(string) bool { return true },
		OpenVault:   func(string, []byte) (vaultHandle, error) { return fv, nil },
	})
	var tm tea.Model = m
	tm = send(tm, tea.WindowSizeMsg{Width: 100, Height: 32})
	tm = typeStr(tm, "pw")
	tm, cmd := step(tm, special(tea.KeyEnter))
	if cmd == nil {
		t.Fatal("unlock submit produced no command")
	}
	tm, _ = step(tm, cmd()) // vaultOpenedMsg → scMain (+ auto-connect)
	return tm
}

func TestConnectHostArgDialsResolvedHost(t *testing.T) {
	tm := connectArgModel(t, "prod-api-02")
	m := tm.(Model)
	if m.connectTo != "" {
		t.Fatal("the command-line host must be consumed once the vault opens")
	}
	// With no SSH engine the dial path bails with its own toast; reaching it at
	// all proves the argument resolved and connect was attempted.
	if m.toast != "no ssh engine available" {
		t.Fatalf("expected the dial path to run, got toast %q", m.toast)
	}
}

func TestConnectHostArgUnknownStaysOnHosts(t *testing.T) {
	tm := connectArgModel(t, "nope")
	m := tm.(Model)
	if !strings.Contains(m.toast, "no saved host") {
		t.Fatalf("an unknown host argument should toast, got %q", m.toast)
	}
	if m.screen != scMain || m.tab != 0 {
		t.Fatalf("an unknown host argument must still land on the hosts tab (screen=%v tab=%d)", m.screen, m.tab)
	}
	if !strings.Contains(tm.View(), "prod-api-01") {
		t.Fatalf("the hosts list should be visible:\n%s", tm.View())
	}
}
