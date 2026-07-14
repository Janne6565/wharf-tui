package sshx

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	gliderssh "github.com/gliderlabs/ssh"
	"github.com/skeema/knownhosts"
	gossh "golang.org/x/crypto/ssh"
)

const testPassword = "hunter2"

// safeBuffer is a mutex-guarded bytes.Buffer: the server handler writes from
// its own goroutine while the test reads.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// testServer is an in-process sshd for exercising the engine.
type testServer struct {
	host    string
	port    int
	hostPub gossh.PublicKey
}

func (ts *testServer) addr() string { return net.JoinHostPort(ts.host, strconv.Itoa(ts.port)) }

func (ts *testServer) hostSpec() HostSpec {
	return HostSpec{ID: "h1", Name: "test", User: "tester", Addr: ts.host, Port: ts.port}
}

func newHostSigner(t *testing.T) gossh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer from key: %v", err)
	}
	return signer
}

// startServer runs a password-authenticating sshd on 127.0.0.1:0. If password
// is empty, all password attempts are rejected (for the auth-failure test).
func startServer(t *testing.T, password string, handler gliderssh.Handler) *testServer {
	t.Helper()
	signer := newHostSigner(t)

	srv := &gliderssh.Server{
		Handler: handler,
		PasswordHandler: func(ctx gliderssh.Context, pass string) bool {
			return password != "" && pass == password
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
	return &testServer{
		host:    "127.0.0.1",
		port:    tcp.Port,
		hostPub: signer.PublicKey(),
	}
}

// startServerWithPubKeyCounter is like startServer but also installs a
// PublicKeyHandler that rejects every key while counting the attempts, so a
// test can assert the client never even offered a public key.
func startServerWithPubKeyCounter(t *testing.T, password string, pubKeyAttempts *int32) *testServer {
	t.Helper()
	signer := newHostSigner(t)

	srv := &gliderssh.Server{
		Handler: echoHandler(nil, nil),
		PasswordHandler: func(ctx gliderssh.Context, pass string) bool {
			return password != "" && pass == password
		},
		PublicKeyHandler: func(ctx gliderssh.Context, key gliderssh.PublicKey) bool {
			atomic.AddInt32(pubKeyAttempts, 1)
			return false
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
	return &testServer{
		host:    "127.0.0.1",
		port:    tcp.Port,
		hostPub: signer.PublicKey(),
	}
}

// writeTestKey generates an ed25519 private key and writes it, unencrypted in
// OpenSSH PEM form, into a temp file — a real on-disk identity for exercising
// the key-file leg of the auth chain.
func writeTestKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

// echoHandler copies stdin back to stdout (and into capture, if non-nil),
// keeping the session alive until the client closes stdin. It drains the
// window-change channel (gliderlabs' winch buffer is size 1 and pre-filled,
// so an undrained channel would block the server's request loop on a second
// WindowChange). ready, if non-nil, is closed once the single Pty() read has
// returned — callers that later send window changes (attach) must wait on it
// so their WindowChange can't race the server's Pty() bookkeeping.
func echoHandler(capture *safeBuffer, ready chan<- struct{}) gliderssh.Handler {
	return func(s gliderssh.Session) {
		_, winCh, isPty := s.Pty()
		if isPty {
			go func() {
				for range winCh {
				}
			}()
		}
		if ready != nil {
			close(ready)
		}
		var dst io.Writer = s
		if capture != nil {
			dst = io.MultiWriter(s, capture)
		}
		_, _ = io.Copy(dst, s)
	}
}

// recorder auto-answers prompts and records lifecycle messages, standing in
// for the UI's tea.Program.Send.
type recorder struct {
	mu           sync.Mutex
	hostKey      []HostKeyPromptMsg
	secret       []SecretPromptMsg
	hostKeyReply bool
	secretReply  func(SecretPromptMsg) []byte
	endedCh      chan SessionEndedMsg
}

func newRecorder() *recorder {
	return &recorder{
		hostKeyReply: true,
		secretReply:  func(SecretPromptMsg) []byte { return []byte(testPassword) },
		endedCh:      make(chan SessionEndedMsg, 8),
	}
}

func (r *recorder) notify(msg tea.Msg) {
	switch m := msg.(type) {
	case HostKeyPromptMsg:
		r.mu.Lock()
		r.hostKey = append(r.hostKey, m)
		reply := r.hostKeyReply
		r.mu.Unlock()
		m.Reply <- reply
	case SecretPromptMsg:
		r.mu.Lock()
		r.secret = append(r.secret, m)
		fn := r.secretReply
		r.mu.Unlock()
		var ans []byte
		if fn != nil {
			ans = fn(m)
		}
		m.Reply <- ans
	case SessionEndedMsg:
		r.mu.Lock()
		ch := r.endedCh
		r.mu.Unlock()
		select {
		case ch <- m:
		default:
		}
	}
}

func (r *recorder) hostKeyCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.hostKey)
}

func (r *recorder) secretCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.secret)
}

func waitFor(t *testing.T, d time.Duration, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for: %s", msg)
}

func TestDialPasswordAuth(t *testing.T) {
	rec := newRecorder()
	ts := startServer(t, testPassword, echoHandler(nil, nil))

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	t.Setenv("SSH_AUTH_SOCK", "")
	m := NewManager(khPath, false)
	m.SetNotify(rec.notify)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sess, err := m.Dial(ctx, ts.hostSpec(), 80, 24)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	if !sess.Alive() {
		t.Fatal("session not alive after dial")
	}
	if rec.secretCount() == 0 {
		t.Fatal("expected a SecretPromptMsg for the password")
	}
}

func TestTOFUAcceptAndPersist(t *testing.T) {
	rec := newRecorder()
	ts := startServer(t, testPassword, echoHandler(nil, nil))

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	t.Setenv("SSH_AUTH_SOCK", "")
	m := NewManager(khPath, false)
	m.SetNotify(rec.notify)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sess, err := m.Dial(ctx, ts.hostSpec(), 80, 24)
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	if rec.hostKeyCount() != 1 {
		t.Fatalf("expected 1 host-key prompt, got %d", rec.hostKeyCount())
	}
	rec.mu.Lock()
	fp := rec.hostKey[0].Fingerprint
	rec.mu.Unlock()
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Fatalf("fingerprint %q lacks SHA256 prefix", fp)
	}

	// known_hosts must now be parseable by x/crypto and cover this host.
	data, err := os.ReadFile(khPath)
	if err != nil || len(data) == 0 {
		t.Fatalf("known_hosts not written: err=%v len=%d", err, len(data))
	}
	if _, err := knownhosts.New(khPath); err != nil {
		t.Fatalf("known_hosts not parseable: %v", err)
	}

	// Second dial must NOT prompt again.
	before := rec.hostKeyCount()
	sess2, err := m.Dial(ctx, ts.hostSpec(), 80, 24)
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	t.Cleanup(func() { _ = sess2.Close() })
	if rec.hostKeyCount() != before {
		t.Fatalf("second dial prompted again: before=%d after=%d", before, rec.hostKeyCount())
	}
}

func TestTOFURejectFails(t *testing.T) {
	rec := newRecorder()
	rec.hostKeyReply = false
	ts := startServer(t, testPassword, echoHandler(nil, nil))

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	t.Setenv("SSH_AUTH_SOCK", "")
	m := NewManager(khPath, false)
	m.SetNotify(rec.notify)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sess, err := m.Dial(ctx, ts.hostSpec(), 80, 24)
	if err == nil {
		_ = sess.Close()
		t.Fatal("expected dial to fail on rejected host key")
	}
	if !errors.Is(err, ErrHostKeyRejected) {
		t.Fatalf("expected ErrHostKeyRejected, got %v", err)
	}
}

func TestChangedHostKeyHardFails(t *testing.T) {
	rec := newRecorder()
	ts := startServer(t, testPassword, echoHandler(nil, nil))

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	t.Setenv("SSH_AUTH_SOCK", "")

	// Pre-populate known_hosts with a DIFFERENT key for this host:port.
	other := newHostSigner(t)
	line := knownhosts.Line([]string{knownhosts.Normalize(ts.addr())}, other.PublicKey())
	if err := os.WriteFile(khPath, []byte(line+"\n"), 0600); err != nil {
		t.Fatalf("seed known_hosts: %v", err)
	}

	m := NewManager(khPath, false)
	m.SetNotify(rec.notify)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sess, err := m.Dial(ctx, ts.hostSpec(), 80, 24)
	if err == nil {
		_ = sess.Close()
		t.Fatal("expected dial to fail on changed host key")
	}
	if !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("expected ErrHostKeyChanged, got %v", err)
	}
	if rec.hostKeyCount() != 0 {
		t.Fatalf("changed key must not prompt, got %d prompts", rec.hostKeyCount())
	}
}

func TestRingRecordsWhileDetached(t *testing.T) {
	rec := newRecorder()
	const marker = "ring-data-marker-123"
	handler := func(s gliderssh.Session) {
		_, _, _ = s.Pty()
		_, _ = io.WriteString(s, marker)
		_, _ = io.Copy(io.Discard, s) // keep the session open
	}
	ts := startServer(t, testPassword, handler)

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	t.Setenv("SSH_AUTH_SOCK", "")
	m := NewManager(khPath, false)
	m.SetNotify(rec.notify)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sess, err := m.Dial(ctx, ts.hostSpec(), 80, 24)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	waitFor(t, 5*time.Second, "ring to contain server output", func() bool {
		return strings.Contains(string(sess.ring.Snapshot()), marker)
	})
}

func TestSessionEndedDelivered(t *testing.T) {
	rec := newRecorder()
	handler := func(s gliderssh.Session) {
		_, _, _ = s.Pty()
		_, _ = io.WriteString(s, "bye")
		// returning closes the session
	}
	ts := startServer(t, testPassword, handler)

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	t.Setenv("SSH_AUTH_SOCK", "")
	m := NewManager(khPath, false)
	m.SetNotify(rec.notify)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sess, err := m.Dial(ctx, ts.hostSpec(), 80, 24)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	select {
	case msg := <-rec.endedCh:
		if msg.HostID != sess.Host().ID {
			t.Fatalf("SessionEndedMsg host = %q, want %q", msg.HostID, sess.Host().ID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no SessionEndedMsg delivered")
	}

	waitFor(t, 5*time.Second, "session to be marked dead", func() bool { return !sess.Alive() })

	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Done() not closed")
	}

	if m.Get(sess.Host().ID) != nil {
		t.Fatal("ended session still registered in manager")
	}
}

func TestAttachDetachByte(t *testing.T) {
	rec := newRecorder()
	capture := &safeBuffer{}
	ready := make(chan struct{})
	ts := startServer(t, testPassword, echoHandler(capture, ready))

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	t.Setenv("SSH_AUTH_SOCK", "")
	m := NewManager(khPath, false)
	m.SetNotify(rec.notify)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sess, err := m.Dial(ctx, ts.hostSpec(), 80, 24)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	// Wait until the server handler has read its PTY info before attaching, so
	// attach's WindowChange can't race the server's Pty() bookkeeping.
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("server handler did not become ready")
	}

	// stdin: a pipe delivering "abc" then the detach byte (0x1C).
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { _ = pr.Close(); _ = pw.Close() })
	go func() { _, _ = pw.Write([]byte("abc\x1c")) }()

	var out bytes.Buffer // not an *os.File => no raw mode
	cmd := sess.Attach()
	cmd.SetStdin(pr)
	cmd.SetStdout(&out)

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case rerr := <-done:
		if rerr != nil {
			t.Fatalf("attach Run returned error: %v", rerr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("attach Run did not return after detach byte")
	}

	if !sess.Alive() {
		t.Fatal("session should still be alive after detach")
	}

	waitFor(t, 5*time.Second, "remote to receive 'abc'", func() bool {
		return strings.Contains(capture.String(), "abc")
	})

	// Live writer must be cleared on return: subsequent output goes to ring only.
	sess.tee.mu.Lock()
	live := sess.tee.live
	sess.tee.mu.Unlock()
	if live != nil {
		t.Fatal("live writer not cleared after detach")
	}
}

func TestWrongPasswordFailsCleanly(t *testing.T) {
	rec := newRecorder()
	rec.secretReply = func(SecretPromptMsg) []byte { return []byte("wrong-password") }
	ts := startServer(t, testPassword, echoHandler(nil, nil)) // server rejects wrong password

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	t.Setenv("SSH_AUTH_SOCK", "")
	m := NewManager(khPath, false)
	m.SetNotify(rec.notify)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sess, err := m.Dial(ctx, ts.hostSpec(), 80, 24)
	if err == nil {
		_ = sess.Close()
		t.Fatal("expected auth to fail with wrong password")
	}
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed, got %v", err)
	}
	if len(m.List()) != 0 {
		t.Fatalf("failed dial left %d sessions registered", len(m.List()))
	}
}

func TestStoredPasswordSucceedsWithoutPrompt(t *testing.T) {
	rec := newRecorder()
	ts := startServer(t, testPassword, echoHandler(nil, nil))

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	t.Setenv("SSH_AUTH_SOCK", "")
	m := NewManager(khPath, false)
	m.SetNotify(rec.notify)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hs := ts.hostSpec()
	hs.Password = testPassword // correct stored password
	sess, err := m.Dial(ctx, hs, 80, 24)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	if !sess.Alive() {
		t.Fatal("session not alive after dial")
	}
	if rec.secretCount() != 0 {
		t.Fatalf("stored password must not prompt, got %d prompts", rec.secretCount())
	}
}

func TestStoredPasswordRejectedThenPrompts(t *testing.T) {
	rec := newRecorder() // default secretReply returns the correct testPassword
	ts := startServer(t, testPassword, echoHandler(nil, nil))

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	t.Setenv("SSH_AUTH_SOCK", "")
	m := NewManager(khPath, false)
	m.SetNotify(rec.notify)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hs := ts.hostSpec()
	hs.Password = "wrong-stored" // rejected → must fall through to a prompt
	sess, err := m.Dial(ctx, hs, 80, 24)
	if err != nil {
		t.Fatalf("dial after prompt fallback: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	if rec.secretCount() == 0 {
		t.Fatal("expected a prompt after the stored password was rejected")
	}
	rec.mu.Lock()
	got := rec.secret[0]
	rec.mu.Unlock()
	if got.Title != "password" {
		t.Fatalf("prompt Title = %q, want exactly \"password\"", got.Title)
	}
	if !strings.Contains(got.Detail, "reject") {
		t.Fatalf("prompt Detail = %q, want it to mention the rejection", got.Detail)
	}
}

func TestAuthPasswordNeverOffersPublicKey(t *testing.T) {
	rec := newRecorder()
	var pubKeyAttempts int32
	ts := startServerWithPubKeyCounter(t, testPassword, &pubKeyAttempts)

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	t.Setenv("SSH_AUTH_SOCK", "")
	m := NewManager(khPath, false)
	m.SetNotify(rec.notify)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hs := ts.hostSpec()
	hs.AuthMethod = AuthPassword
	hs.KeyPath = writeTestKey(t) // present, but AuthPassword must ignore it
	sess, err := m.Dial(ctx, hs, 80, 24)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	if n := atomic.LoadInt32(&pubKeyAttempts); n != 0 {
		t.Fatalf("AuthPassword offered %d public keys, want 0", n)
	}
}

func TestAuthKeyAgainstPasswordServerFailsWithoutPrompt(t *testing.T) {
	rec := newRecorder()
	ts := startServer(t, testPassword, echoHandler(nil, nil)) // password-only server

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	t.Setenv("SSH_AUTH_SOCK", "")
	m := NewManager(khPath, false)
	m.SetNotify(rec.notify)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hs := ts.hostSpec()
	hs.AuthMethod = AuthKey
	hs.KeyPath = writeTestKey(t) // key the server won't accept
	sess, err := m.Dial(ctx, hs, 80, 24)
	if err == nil {
		_ = sess.Close()
		t.Fatal("expected AuthKey to fail against a password-only server")
	}
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed, got %v", err)
	}
	if rec.secretCount() != 0 {
		t.Fatalf("AuthKey must not deliver a password prompt, got %d", rec.secretCount())
	}
}
