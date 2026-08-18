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
//
// The assertion is on the signers the public-key method actually collects, not
// on how many ssh.AuthMethod values the chain holds: every key source now feeds
// one merged publickey method (see publicKeySigners), so the count is constant.
func TestUseAgentGatesAgentAuthMethod(t *testing.T) {
	serveAgent(t, mustEd25519(t))

	mgr := NewManager(filepath.Join(t.TempDir(), "known_hosts"), true)
	if !mgr.UseAgent() {
		t.Fatal("the agent should be used by default (matches DefaultSettings)")
	}
	hs := HostSpec{ID: "h1", AuthMethod: AuthKey}

	withAgent, err := mgr.publicKeySigners(context.Background(), hs, &keyRing{})()
	if err != nil {
		t.Fatalf("collect signers with the agent on: %v", err)
	}
	if len(withAgent) != 1 {
		t.Fatalf("agent on should offer the agent's 1 key, got %d", len(withAgent))
	}

	mgr.SetUseAgent(false)
	without, err := mgr.publicKeySigners(context.Background(), hs, &keyRing{})()
	if err != nil {
		t.Fatalf("collect signers with the agent off: %v", err)
	}
	if len(without) != 0 {
		t.Fatalf("agent off should offer nothing, got %d signers", len(without))
	}
}

// Password mode never offered agent keys; the new gate must not change that.
func TestUseAgentIrrelevantInPasswordMode(t *testing.T) {
	agentSocket(t)

	mgr := NewManager(filepath.Join(t.TempDir(), "known_hosts"), true)
	hs := HostSpec{ID: "h1", AuthMethod: AuthPassword}
	on := len(mgr.authMethods(context.Background(), hs, &keyRing{}))
	mgr.SetUseAgent(false)
	if off := len(mgr.authMethods(context.Background(), hs, &keyRing{})); off != on {
		t.Fatalf("password mode should be unaffected by the agent setting: %d vs %d", on, off)
	}
}
