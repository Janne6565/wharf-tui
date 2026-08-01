//go:build !windows

package sessd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Janne6565/wharf-tui/internal/sshx"
	tea "github.com/charmbracelet/bubbletea"
	gliderssh "github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

const testPassword = "hunter2"

// TestMain doubles as the session-host binary: the pool re-executes the test
// binary with --session-host, which is exactly how the real TUI re-executes
// wharf. That means these tests exercise the true process boundary, not an
// in-process stand-in.
func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == SessionHostFlag {
		f := os.NewFile(3, "listener")
		if f == nil {
			os.Exit(1)
		}
		ln, err := net.FileListener(f)
		if err != nil {
			os.Exit(1)
		}
		_ = Serve(ln, os.Args[2])
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// --- harness ----------------------------------------------------------------

type testServer struct {
	host string
	port int
}

func (ts *testServer) spec() sshx.HostSpec {
	return sshx.HostSpec{
		ID: "h1", Name: "test", User: "tester",
		Addr: ts.host, Port: ts.port,
		AuthMethod: sshx.AuthPassword, Password: testPassword,
	}
}

// startServer runs an echoing, password-authenticating sshd on 127.0.0.1:0.
func startServer(t *testing.T) *testServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	srv := &gliderssh.Server{
		Handler: func(s gliderssh.Session) {
			_, winCh, isPty := s.Pty()
			if isPty {
				go func() {
					for range winCh {
					}
				}()
			}
			_, _ = io.Copy(s, s)
		},
		PasswordHandler: func(_ gliderssh.Context, pass string) bool { return pass == testPassword },
	}
	srv.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close(); _ = ln.Close() })

	return &testServer{host: "127.0.0.1", port: ln.Addr().(*net.TCPAddr).Port}
}

// recorder stands in for the UI's tea.Program.Send: it auto-accepts TOFU and
// records session-ended messages.
type recorder struct {
	mu      sync.Mutex
	hostKey int
	secrets int
	ended   chan sshx.SessionEndedMsg
}

func newRecorder() *recorder {
	return &recorder{ended: make(chan sshx.SessionEndedMsg, 8)}
}

func (r *recorder) notify(msg tea.Msg) {
	switch m := msg.(type) {
	case sshx.HostKeyPromptMsg:
		r.mu.Lock()
		r.hostKey++
		r.mu.Unlock()
		m.Reply <- true
	case sshx.SecretPromptMsg:
		r.mu.Lock()
		r.secrets++
		r.mu.Unlock()
		m.Reply <- []byte(testPassword)
	case sshx.SessionEndedMsg:
		select {
		case r.ended <- m:
		default:
		}
	}
}

func (r *recorder) hostKeyPrompts() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hostKey
}

// newPool builds a pool re-executing the test binary, with its own socket
// directory and a scratch known_hosts so TOFU is exercised for real.
func newPool(t *testing.T, dir, knownHosts string) (*Pool, *recorder) {
	t.Helper()
	p := NewPool(dir, knownHosts, false)
	// Normally the test binary re-executes itself (TestMain serves the
	// --session-host branch). Setting WHARF_TEST_BINARY to a built wharf runs
	// the same tests against the real binary's fd-3 wiring.
	exe := os.Args[0]
	if real := os.Getenv("WHARF_TEST_BINARY"); real != "" {
		exe = real
	}
	p.SetExecutable(exe)
	rec := newRecorder()
	p.SetNotify(rec.notify)
	return p, rec
}

func tempDirs(t *testing.T) (sockDir, knownHosts string) {
	t.Helper()
	// Socket paths are length-capped, and macOS hands tests a very long
	// TMPDIR, so the socket directory lives under a short /tmp path.
	sockDir, err := os.MkdirTemp("/tmp", "wh-t")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	return sockDir, filepath.Join(t.TempDir(), "known_hosts")
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// --- tests ------------------------------------------------------------------

func TestDialRunsSessionInChildProcess(t *testing.T) {
	ts := startServer(t)
	sockDir, knownHosts := tempDirs(t)
	pool, rec := newPool(t, sockDir, knownHosts)

	r, err := pool.Dial(context.Background(), ts.spec(), 80, 24)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })

	if !r.Alive() {
		t.Fatal("a freshly dialed session should be alive")
	}
	if rec.hostKeyPrompts() != 1 {
		t.Fatalf("an unknown host key should prompt exactly once, got %d", rec.hostKeyPrompts())
	}
	if got := pool.Get(r.ID()); got != r {
		t.Fatal("the session should be registered under its session ID")
	}
	if hs := pool.ForHost(ts.spec().ID); len(hs) != 1 || hs[0] != r {
		t.Fatalf("ForHost should find the session, got %d", len(hs))
	}

	info, err := r.requestInfo(dialTimeout)
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	if info.PID == os.Getpid() {
		t.Fatal("the session must run in a child process, not in the TUI")
	}
	if !info.Alive || info.HostName != "test" {
		t.Fatalf("unexpected info: %+v", info)
	}
	// TOFU should have been recorded by the child, in the file we handed it.
	if _, err := os.Stat(knownHosts); err != nil {
		t.Fatalf("the child should have written known_hosts: %v", err)
	}
}

// Detach has to leave the remote reporting dead the moment it returns, not
// whenever readLoop next gets scheduled. closeConn nils the connection, so
// readLoop can take its `c == nil` exit and return without touching the alive
// flag — the flag has to be cleared on the teardown path itself.
//
// Asserting immediately after Detach, with no waitFor, is the point: a poll
// would pass on the readLoop's error path too and hide exactly this bug.
func TestDetachMarksSessionDeadSynchronously(t *testing.T) {
	ts := startServer(t)
	sockDir, knownHosts := tempDirs(t)

	pool, _ := newPool(t, sockDir, knownHosts)
	r, err := pool.Dial(context.Background(), ts.spec(), 80, 24)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })

	pool.Detach()

	if r.Alive() {
		t.Error("Alive() must report false as soon as Detach returns")
	}
	select {
	case <-r.Done():
	default:
		t.Error("Done() must be closed as soon as Detach returns")
	}
	if pool.Get(r.ID()) != nil {
		t.Error("a detached session must no longer be in the pool")
	}
}

func TestSessionSurvivesPoolShutdown(t *testing.T) {
	ts := startServer(t)
	sockDir, knownHosts := tempDirs(t)

	pool, _ := newPool(t, sockDir, knownHosts)
	r, err := pool.Dial(context.Background(), ts.spec(), 80, 24)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	pid := mustInfo(t, r).PID

	// Quitting wharf: control connections drop, sessions are left alone.
	pool.Detach()
	waitFor(t, "the control connection to close", func() bool { return !r.Alive() })

	// A new run adopts what is still out there.
	next, _ := newPool(t, sockDir, knownHosts)
	n, err := next.Adopt()
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected to adopt 1 session, got %d", n)
	}
	adopted := next.Get(r.ID())
	if adopted == nil {
		t.Fatal("adoption should preserve the session ID, which is derived from the socket")
	}
	if hs := next.ForHost(ts.spec().ID); len(hs) != 1 {
		t.Fatalf("ForHost should find the adopted session, got %d", len(hs))
	}
	t.Cleanup(func() { _ = adopted.Close() })

	if !adopted.Alive() {
		t.Fatal("the adopted session should still be alive")
	}
	info := mustInfo(t, adopted)
	if info.PID != pid {
		t.Fatalf("adoption should reattach to the same child (%d), got %d", pid, info.PID)
	}
	if info.HostName != "test" || info.Addr != ts.host {
		t.Fatalf("adopted info should describe the host: %+v", info)
	}
}

func TestAdoptUnlinksStaleSockets(t *testing.T) {
	sockDir, knownHosts := tempDirs(t)
	stale := filepath.Join(sockDir, "dead-abc123.sock")
	if err := os.WriteFile(stale, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	pool, _ := newPool(t, sockDir, knownHosts)
	n, err := pool.Adopt()
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if n != 0 {
		t.Fatalf("a stale socket must not be adopted, got %d", n)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("adoption should unlink a socket with no listener")
	}
}

func TestCloseTerminatesChildAndRemovesSocket(t *testing.T) {
	ts := startServer(t)
	sockDir, knownHosts := tempDirs(t)
	pool, rec := newPool(t, sockDir, knownHosts)

	r, err := pool.Dial(context.Background(), ts.spec(), 80, 24)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	sock := r.sock

	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	waitFor(t, "the socket to be unlinked", func() bool {
		_, statErr := os.Stat(sock)
		return os.IsNotExist(statErr)
	})
	if len(pool.List()) != 0 {
		t.Fatal("a closed session should leave the pool")
	}
	select {
	case <-rec.ended:
	case <-time.After(5 * time.Second):
		t.Fatal("closing should deliver SessionEndedMsg to the UI")
	}
}

func TestAttachStreamsThroughTheChild(t *testing.T) {
	ts := startServer(t)
	sockDir, knownHosts := tempDirs(t)
	pool, _ := newPool(t, sockDir, knownHosts)

	r, err := pool.Dial(context.Background(), ts.spec(), 80, 24)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })

	// The echo server mirrors stdin, so what we type comes back over the
	// socket. ctrl+\ ends the attach with the session still running.
	in := io.MultiReader(strings.NewReader("hello over the socket\n"), blockUntil(r.Done()))
	out := &safeBuffer{}
	cmd := r.Attach()
	cmd.SetStdin(in)
	cmd.SetStdout(out)

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	waitFor(t, "the echoed bytes to arrive", func() bool {
		return strings.Contains(out.String(), "hello over the socket")
	})

	// Detaching leaves the session alive.
	_ = r.writeFrame(kindDetach, nil)
	if !r.Alive() {
		t.Fatal("detaching must not end the session")
	}

	// Reattaching replays the ring the child kept while we were away.
	out2 := &safeBuffer{}
	cmd2 := r.Attach()
	cmd2.SetStdin(blockUntil(r.Done()))
	cmd2.SetStdout(out2)
	go func() { _ = cmd2.Run() }()
	waitFor(t, "the replay of earlier output", func() bool {
		return strings.Contains(out2.String(), "hello over the socket")
	})
}

func TestDialFailureReportsAndCleansUp(t *testing.T) {
	sockDir, knownHosts := tempDirs(t)
	pool, _ := newPool(t, sockDir, knownHosts)

	// Nothing is listening on this port.
	spec := sshx.HostSpec{ID: "dead", Name: "dead", User: "u", Addr: "127.0.0.1", Port: 1}
	_, err := pool.Dial(context.Background(), spec, 80, 24)
	if err == nil {
		t.Fatal("dialing a closed port should fail")
	}
	if len(pool.List()) != 0 {
		t.Fatal("a failed dial must not register a session")
	}
	waitFor(t, "the child to clean up its socket", func() bool {
		socks, _ := listSockets(sockDir)
		return len(socks) == 0
	})
}

func TestRuntimeDirIsPrivate(t *testing.T) {
	t.Setenv("WHARF_RUNTIME_DIR", filepath.Join(t.TempDir(), "rt"))
	dir, err := RuntimeDir()
	if err != nil {
		t.Fatalf("runtime dir: %v", err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Fatalf("the socket directory must be 0700, got %o", perm)
	}
}

func TestSocketPathsAreUniquePerSession(t *testing.T) {
	dir, _ := tempDirs(t)
	seen := map[string]bool{}
	for range 20 {
		p, err := socketPath(dir, "aaaabbbbccccdddd")
		if err != nil {
			t.Fatal(err)
		}
		if seen[p] {
			t.Fatalf("socket paths must not repeat: %s", p)
		}
		seen[p] = true
		if !strings.HasSuffix(p, sockSuffix) {
			t.Fatalf("unexpected socket name: %s", p)
		}
	}
}

func TestSanitizeKeepsPathsInsideTheDirectory(t *testing.T) {
	for _, in := range []string{"../escape", "a/b", "", strings.Repeat("x", 100)} {
		got := sanitize(in)
		if strings.ContainsAny(got, "/.") {
			t.Errorf("sanitize(%q) = %q, which is not a safe filename component", in, got)
		}
		if len(got) > 12 {
			t.Errorf("sanitize(%q) = %q, longer than the 12-char cap", in, got)
		}
	}
}

func TestFrameRoundTrip(t *testing.T) {
	var buf safeBuffer
	payload := []byte("some bytes")
	if err := writeFrame(&buf, kindData, payload); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(&buf, kindDetach, nil); err != nil {
		t.Fatal(err)
	}

	rd := strings.NewReader(buf.String())
	kind, got, err := readFrame(rd)
	if err != nil {
		t.Fatal(err)
	}
	if kind != kindData || string(got) != "some bytes" {
		t.Fatalf("round trip = %d/%q", kind, got)
	}
	kind, got, err = readFrame(rd)
	if err != nil {
		t.Fatal(err)
	}
	if kind != kindDetach || len(got) != 0 {
		t.Fatalf("empty frame round trip = %d/%q", kind, got)
	}
	if _, _, err := readFrame(rd); !errors.Is(err, ErrClosed) {
		t.Fatalf("a clean hangup should report ErrClosed, got %v", err)
	}
}

func TestReadFrameRejectsOversizedLength(t *testing.T) {
	// kind + a length beyond maxFrame must be refused before allocating.
	head := []byte{byte(kindData), 0xff, 0xff, 0xff, 0xff}
	if _, _, err := readFrame(strings.NewReader(string(head))); err == nil {
		t.Fatal("an oversized frame length must be rejected")
	}
}

// --- helpers ----------------------------------------------------------------

func mustInfo(t *testing.T, r *Remote) infoResponse {
	t.Helper()
	info, err := r.requestInfo(dialTimeout)
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	return info
}

// blockUntil returns a reader that blocks until ch closes, then reports EOF. It
// keeps an attach's stdin open the way a real terminal would.
func blockUntil(ch <-chan struct{}) io.Reader { return &blockReader{ch: ch} }

type blockReader struct{ ch <-chan struct{} }

func (b *blockReader) Read([]byte) (int, error) {
	<-b.ch
	return 0, io.EOF
}

type safeBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
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

var _ = strconv.Itoa

func TestManySessionsPerHost(t *testing.T) {
	ts := startServer(t)
	sockDir, knownHosts := tempDirs(t)
	pool, _ := newPool(t, sockDir, knownHosts)

	var ids []string
	for range 3 {
		r, err := pool.Dial(context.Background(), ts.spec(), 80, 24)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = r.Close() })
		ids = append(ids, r.ID())
	}

	for i, id := range ids {
		for j, other := range ids {
			if i != j && id == other {
				t.Fatalf("session IDs must be unique, %d and %d are both %q", i, j, id)
			}
		}
	}
	if got := pool.ForHost(ts.spec().ID); len(got) != 3 {
		t.Fatalf("one host should carry all 3 sessions, got %d", len(got))
	}
	if got := pool.List(); len(got) != 3 {
		t.Fatalf("the pool should list all 3 sessions, got %d", len(got))
	}

	// Killing the middle one leaves the others untouched.
	mid := pool.Get(ids[1])
	if mid == nil {
		t.Fatal("the middle session should be addressable by ID")
	}
	_ = mid.Close()
	waitFor(t, "the killed session to leave the pool", func() bool {
		return len(pool.ForHost(ts.spec().ID)) == 2
	})
	if pool.Get(ids[0]) == nil || pool.Get(ids[2]) == nil {
		t.Fatal("killing one session must not disturb the others")
	}
}
