package sshx

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// agentSocket starts a listening unix socket and points SSH_AUTH_SOCK at it.
// The path deliberately avoids t.TempDir(): macOS caps sockaddr_un at ~104
// bytes and the per-test temp path overflows it.
func agentSocket(t *testing.T) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "wh")
	if err != nil {
		t.Skipf("no short temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, "a.sock"))
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(dir, "a.sock"))
}

// The "Use SSH agent keys" setting has to reach the auth chain: it used to be
// stored and never read, so key-mode auth always offered $SSH_AUTH_SOCK.
func TestUseAgentGatesAgentAuthMethod(t *testing.T) {
	// A listening socket is enough — authMethods only needs the dial to
	// succeed to add the agent method; nothing speaks the protocol here.
	agentSocket(t)

	mgr := NewManager(filepath.Join(t.TempDir(), "known_hosts"), true)
	if !mgr.UseAgent() {
		t.Fatal("the agent should be used by default (matches DefaultSettings)")
	}
	hs := HostSpec{ID: "h1", AuthMethod: AuthKey}

	withAgent := len(mgr.authMethods(context.Background(), hs))
	mgr.SetUseAgent(false)
	without := len(mgr.authMethods(context.Background(), hs))

	if withAgent != without+1 {
		t.Fatalf("turning the agent off should drop exactly one auth method, got %d then %d",
			withAgent, without)
	}
}

// Password mode never offered agent keys; the new gate must not change that.
func TestUseAgentIrrelevantInPasswordMode(t *testing.T) {
	agentSocket(t)

	mgr := NewManager(filepath.Join(t.TempDir(), "known_hosts"), true)
	hs := HostSpec{ID: "h1", AuthMethod: AuthPassword}
	on := len(mgr.authMethods(context.Background(), hs))
	mgr.SetUseAgent(false)
	if off := len(mgr.authMethods(context.Background(), hs)); off != on {
		t.Fatalf("password mode should be unaffected by the agent setting: %d vs %d", on, off)
	}
}
