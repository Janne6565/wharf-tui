package sshx

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	gliderssh "github.com/gliderlabs/ssh"
)

// Key mode feeds the agent, the key file and the vault keys into ONE
// public-key method. Three separate ssh.PublicKeysCallback entries looked
// equivalent but were not: x/crypto/ssh tracks tried methods by name, so the
// first "publickey" entry to fail retired the method for the whole handshake
// and every later source was silently skipped. The tests below pin each source
// behind another failing one — they fail on any regression back to a chain of
// separate publickey methods.

// serveAgent runs an in-process SSH agent holding key over a unix socket and
// points SSH_AUTH_SOCK at it.
//
// The socket lives under /tmp rather than t.TempDir(): macOS caps sockaddr_un
// at ~104 bytes and per-test temp paths overflow it.
func serveAgent(t *testing.T, key any) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "wh")
	if err != nil {
		t.Skipf("no short temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	sock := filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	ring := agent.NewKeyring()
	if err := ring.Add(agent.AddedKey{PrivateKey: key}); err != nil {
		t.Fatalf("agent add: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(ring, conn) }()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)
}

// A key file the server does not know must not stop the vault key that it does
// know from being offered.
func TestKeyFileDoesNotHideVaultKeys(t *testing.T) {
	pemBytes, pub := newVaultKeyPEM(t, "")
	ts := startServerWithAuthorizedKeys(t, pub)

	t.Setenv("SSH_AUTH_SOCK", "")
	m := NewManager(filepath.Join(t.TempDir(), "known_hosts"), false)
	m.SetNotify(newRecorder().notify)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hs := ts.hostSpec()
	hs.KeyPath = writeTestKey(t) // a valid key the server will reject
	hs.VaultKeys = []VaultKeySpec{{Name: "vault", PEM: pemBytes}}

	sess, err := m.Dial(ctx, hs, 80, 24)
	if err != nil {
		t.Fatalf("dial: the vault key was never offered after the key file: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
}

// An unreadable key file must not sink the vault keys either: a stale KeyPath
// on one host is a misconfiguration, not a reason to skip working credentials.
func TestMissingKeyFileDoesNotHideVaultKeys(t *testing.T) {
	pemBytes, pub := newVaultKeyPEM(t, "")
	ts := startServerWithAuthorizedKeys(t, pub)

	t.Setenv("SSH_AUTH_SOCK", "")
	m := NewManager(filepath.Join(t.TempDir(), "known_hosts"), false)
	m.SetNotify(newRecorder().notify)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hs := ts.hostSpec()
	hs.KeyPath = filepath.Join(t.TempDir(), "does-not-exist")
	hs.VaultKeys = []VaultKeySpec{{Name: "vault", PEM: pemBytes}}

	sess, err := m.Dial(ctx, hs, 80, 24)
	if err != nil {
		t.Fatalf("dial: a missing key file hid the vault key: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
}

// The reachable agent is the common case of this bug: it holds keys for other
// fleets, fails first, and used to retire the publickey method before the
// vault keys (or the host's own key file) were ever tried.
func TestAgentDoesNotHideVaultKeys(t *testing.T) {
	agentKey := mustEd25519(t)
	serveAgent(t, agentKey)

	pemBytes, pub := newVaultKeyPEM(t, "")
	ts := startServerWithAuthorizedKeys(t, pub)

	m := NewManager(filepath.Join(t.TempDir(), "known_hosts"), false)
	m.SetNotify(newRecorder().notify)
	if !m.UseAgent() {
		t.Fatal("the agent should be on by default")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hs := ts.hostSpec()
	hs.VaultKeys = []VaultKeySpec{{Name: "vault", PEM: pemBytes}}

	sess, err := m.Dial(ctx, hs, 80, 24)
	if err != nil {
		t.Fatalf("dial: the agent swallowed the vault key: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
}

// Every offer costs one of the server's MaxAuthTries, so a key held by both the
// agent and the vault must be offered once, not twice.
func TestDuplicateKeyIsOfferedOnce(t *testing.T) {
	shared := mustEd25519(t)
	serveAgent(t, shared)

	signer, err := gossh.NewSignerFromKey(shared)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	pemBytes := marshalPEM(t, shared)

	var offers offerLog
	ts := startCountingKeyServer(t, signer.PublicKey(), &offers)

	m := NewManager(filepath.Join(t.TempDir(), "known_hosts"), false)
	m.SetNotify(newRecorder().notify)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hs := ts.hostSpec()
	hs.VaultKeys = []VaultKeySpec{{Name: "same key", PEM: pemBytes}}

	sess, err := m.Dial(ctx, hs, 80, 24)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	// x/crypto probes a key before signing for it, so the accepted key is seen
	// twice; a second copy of the same key would push this to four.
	if n := offers.count(); n > 2 {
		t.Fatalf("the shared key was offered %d times, want it deduplicated", n)
	}
}

// mustEd25519 generates a raw ed25519 private key usable as both an agent key
// and vault PEM material.
func mustEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

// marshalPEM encodes an in-memory key as unencrypted OpenSSH PEM.
func marshalPEM(t *testing.T, key ed25519.PrivateKey) []byte {
	t.Helper()
	block, err := gossh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(block)
}

// offerLog records every public key a client offers, so a test can assert both
// on which keys reached the server and on how much of its MaxAuthTries budget
// the chain spent.
type offerLog struct {
	mu   sync.Mutex
	keys [][]byte
}

func (l *offerLog) add(key gossh.PublicKey) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keys = append(l.keys, key.Marshal())
}

func (l *offerLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.keys)
}

// has reports whether key was offered at all (a key is offered twice when the
// server accepts it: once probed, once signed).
func (l *offerLog) has(key gossh.PublicKey) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	want := key.Marshal()
	for _, got := range l.keys {
		if bytes.Equal(want, got) {
			return true
		}
	}
	return false
}

// startCountingKeyServer accepts only authorized and logs every public key the
// client offers.
func startCountingKeyServer(t *testing.T, authorized gossh.PublicKey, log *offerLog) *testServer {
	t.Helper()
	signer := newHostSigner(t)
	want := authorized.Marshal()

	srv := &gliderssh.Server{
		Handler: echoHandler(nil, nil),
		PublicKeyHandler: func(ctx gliderssh.Context, key gliderssh.PublicKey) bool {
			log.add(key)
			return bytes.Equal(want, key.Marshal())
		},
	}
	srv.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})

	tcp := ln.Addr().(*net.TCPAddr)
	return &testServer{host: "127.0.0.1", port: tcp.Port, hostPub: signer.PublicKey()}
}

// A vault with more keys than the server's MaxAuthTries (6 by default, and the
// opening "none" probe already spends one) cannot offer them all on a single
// connection: the server hangs up partway through with "Too many
// authentication failures". connect works through the list in batches instead,
// so the key a host wants is found wherever it sits in the vault.
func TestKeysBeyondMaxAuthTriesAreReachedInLaterBatches(t *testing.T) {
	const total = 20

	var vaultKeys []VaultKeySpec
	var authorized gossh.PublicKey
	for i := 0; i < total; i++ {
		pemBytes, pub := newVaultKeyPEM(t, "")
		vaultKeys = append(vaultKeys, VaultKeySpec{Name: "k", PEM: pemBytes})
		authorized = pub // the LAST key is the one the server accepts
	}

	var offers offerLog
	ts := startCountingKeyServer(t, authorized, &offers)

	t.Setenv("SSH_AUTH_SOCK", "")
	m := NewManager(filepath.Join(t.TempDir(), "known_hosts"), false)
	m.SetNotify(newRecorder().notify)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	hs := ts.hostSpec()
	hs.VaultKeys = vaultKeys

	sess, err := m.Dial(ctx, hs, 80, 24)
	if err != nil {
		t.Fatalf("dial: the %dth vault key was never reached: %v", total, err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	// Every key had to be offered to reach the last one; the point of the test
	// is that this happened across connections instead of dying on the first.
	if n := offers.count(); n < total {
		t.Fatalf("only %d keys were offered, want all %d", n, total)
	}
}

// The batching must not turn a host that simply rejects us into a redial storm:
// once the keys run out, the failure is reported.
func TestKeyBatchingStopsWhenKeysRunOut(t *testing.T) {
	var vaultKeys []VaultKeySpec
	for i := 0; i < 8; i++ {
		pemBytes, _ := newVaultKeyPEM(t, "")
		vaultKeys = append(vaultKeys, VaultKeySpec{Name: "k", PEM: pemBytes})
	}
	_, unrelated := newVaultKeyPEM(t, "")

	var offers offerLog
	ts := startCountingKeyServer(t, unrelated, &offers)

	t.Setenv("SSH_AUTH_SOCK", "")
	m := NewManager(filepath.Join(t.TempDir(), "known_hosts"), false)
	m.SetNotify(newRecorder().notify)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	hs := ts.hostSpec()
	hs.VaultKeys = vaultKeys

	if _, err := m.Dial(ctx, hs, 80, 24); err == nil {
		t.Fatal("dial should have failed: no offered key is authorized")
	}
	if n := offers.count(); int(n) > len(vaultKeys) {
		t.Fatalf("%d offers for %d keys: a key was retried across rounds", n, len(vaultKeys))
	}
}

// The MaxAuthTries disconnect reads like a network fault; it must reach the UI
// as its own typed error instead.
func TestTooManyAuthFailuresIsTyped(t *testing.T) {
	for _, msg := range []string{
		`ssh: handshake failed: ssh: disconnect, reason 2: "Too many authentication failures"`,
		`ssh: handshake failed: ssh: disconnect, reason 2: "too many authentication failures"`,
	} {
		if err := classifyHandshakeErr(errors.New(msg)); !errors.Is(err, ErrTooManyAuthAttempts) {
			t.Fatalf("classify(%q) = %v, want ErrTooManyAuthAttempts", msg, err)
		}
	}
}

// A host bound to one vault key offers that key alone. The agent is skipped on
// purpose: binding exists so the server's small try budget is spent on the one
// key that can work, and an agent holding a fleet's worth of keys would eat it.
func TestBoundHostSkipsTheAgent(t *testing.T) {
	agentKey := mustEd25519(t)
	serveAgent(t, agentKey)
	agentPub, err := gossh.NewSignerFromKey(agentKey)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	pemBytes, pub := newVaultKeyPEM(t, "")
	var offers offerLog
	ts := startCountingKeyServer(t, pub, &offers)

	m := NewManager(filepath.Join(t.TempDir(), "known_hosts"), false)
	m.SetNotify(newRecorder().notify)
	if !m.UseAgent() {
		t.Fatal("the agent should be on by default")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hs := ts.hostSpec()
	hs.VaultKeys = []VaultKeySpec{{Name: "bound", PEM: pemBytes}}
	hs.KeyBound = true

	sess, err := m.Dial(ctx, hs, 80, 24)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	if offers.has(agentPub.PublicKey()) {
		t.Fatal("the agent's key was offered to a host bound to a vault key")
	}
	if !offers.has(pub) {
		t.Fatal("the bound key was never offered")
	}
}

// Without the binding the agent is still offered first — an unbound host has no
// reason to ignore it.
func TestUnboundHostStillOffersTheAgent(t *testing.T) {
	agentKey := mustEd25519(t)
	serveAgent(t, agentKey)
	agentPub, err := gossh.NewSignerFromKey(agentKey)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	pemBytes, pub := newVaultKeyPEM(t, "")
	var offers offerLog
	ts := startCountingKeyServer(t, pub, &offers)

	m := NewManager(filepath.Join(t.TempDir(), "known_hosts"), false)
	m.SetNotify(newRecorder().notify)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hs := ts.hostSpec()
	hs.VaultKeys = []VaultKeySpec{{Name: "vault", PEM: pemBytes}}

	sess, err := m.Dial(ctx, hs, 80, 24)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	if !offers.has(agentPub.PublicKey()) {
		t.Fatal("an unbound host must still offer the agent's keys")
	}
}
