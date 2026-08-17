//go:build !windows

package remoteaccess

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- helpers ----------------------------------------------------------------

// runtimeDir points the grant machinery at a private directory for the length
// of one test. It deliberately avoids t.TempDir(): socket paths are capped at
// 100 bytes and macOS hands tests a very long TMPDIR, so a grant socket under
// it would not fit.
func runtimeDir(t *testing.T) {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "wh-ra")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	t.Setenv("WHARF_RUNTIME_DIR", base)
}

// waitFor polls cond until it holds or the deadline passes. Tests synchronise
// with this rather than with a sleep, so a slow machine costs patience instead
// of a flake.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// fakeExec stands in for *sessd.Remote. Everything it records is guarded,
// because the server calls it from one goroutine per in-flight command.
type fakeExec struct {
	mu       sync.Mutex
	commands []string
	running  int

	stdout string
	stderr string
	code   int
	err    error

	// block, when non-nil, holds Exec until it is closed or ctx is cancelled.
	// It is how the concurrency and revocation tests pin a command in flight.
	block chan struct{}
}

func (f *fakeExec) Exec(ctx context.Context, req ExecRequest, stdout, stderr io.Writer) (int, error) {
	f.mu.Lock()
	f.commands = append(f.commands, req.Command)
	f.running++
	out, errOut, code, execErr, block := f.stdout, f.stderr, f.code, f.err, f.block
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.running--
		f.mu.Unlock()
	}()

	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	if out != "" {
		if _, err := io.WriteString(stdout, out); err != nil {
			return 0, err
		}
	}
	if errOut != "" {
		if _, err := io.WriteString(stderr, errOut); err != nil {
			return 0, err
		}
	}
	return code, execErr
}

func (f *fakeExec) inFlight() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}

func (f *fakeExec) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.commands...)
}

// recorder collects audit events from the arbitrary goroutines Notify is
// called on.
type recorder struct {
	mu     sync.Mutex
	events []Event
}

func (r *recorder) add(ev Event) {
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
}

func (r *recorder) all() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.events...)
}

// openGrant opens a grant in a private runtime directory and closes it at the
// end of the test.
func openGrant(t *testing.T, opts Options) *Grant {
	t.Helper()
	runtimeDir(t)
	g, err := Open(opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

// --- tests ------------------------------------------------------------------

func TestAWrongTokenIsRejectedAndRevealsNothing(t *testing.T) {
	exec := &fakeExec{}
	g := openGrant(t, Options{Exec: exec, HostName: "prod"})

	var out, errBuf bytes.Buffer
	code, err := Dial(context.Background(), "not-the-token", Request{Command: "id"}, &out, &errBuf)
	if !errors.Is(err, ErrNoGrant) {
		t.Fatalf("wrong token: got (%d, %v), want ErrNoGrant", code, err)
	}
	// The failure must not name the grant, the host or the token. Anything more
	// specific than "no" is an oracle for whether a grant exists at all.
	msg := err.Error()
	for _, leak := range []string{g.Token(), g.SocketPath(), "prod"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("error %q leaks %q", msg, leak)
		}
	}
	if got := exec.seen(); len(got) != 0 {
		t.Fatalf("a rejected caller ran commands: %v", got)
	}
	if g.Count() != 0 {
		t.Fatalf("Count = %d after a rejected token, want 0", g.Count())
	}

	// The right token still works, which is what proves the rejection was about
	// the token and not about a grant that was never serving.
	if _, err := Dial(context.Background(), g.Token(), Request{Command: "id"}, &out, &errBuf); err != nil {
		t.Fatalf("valid token: %v", err)
	}
}

func TestTheTokenIsNeverPartOfTheSocketPath(t *testing.T) {
	g := openGrant(t, Options{Exec: &fakeExec{}})
	if strings.Contains(g.SocketPath(), g.Token()) {
		t.Fatal("the socket path contains the token")
	}
	// A filename is world-readable metadata; a directory listing must not be a
	// place to find the secret.
	entries, err := os.ReadDir(filepathDirOf(g.SocketPath()))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), g.Token()) {
			t.Fatalf("directory entry %q contains the token", e.Name())
		}
	}
}

func TestTheTokenIsAlphanumericAndCarriesFullEntropy(t *testing.T) {
	alnum := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	// Many grants, because the hazard is probabilistic: a base64url token
	// starts with '-' or '_' about one time in 32, so a single sample would
	// have passed the encoding this test exists to rule out.
	runtimeDir(t)
	for i := 0; i < 200; i++ {
		g, err := Open(Options{Exec: &fakeExec{}})
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		tok := g.Token()
		if !alnum.MatchString(tok) {
			t.Fatalf("token %q is not alphanumeric — it needs quoting, and a leading dash reads as a flag", tok)
		}
		// tokenBytes of entropy, base32-encoded: 8 characters per 5 bytes,
		// rounded up. Asserting the length is how a well-meaning shortening of
		// the token gets caught.
		if want := (tokenBytes*8 + 4) / 5; len(tok) != want {
			t.Fatalf("token is %d characters, want %d (%d bytes of entropy)", len(tok), want, tokenBytes)
		}
		_ = g.Close()
	}
	if tokenBytes < 32 {
		t.Fatalf("tokenBytes = %d, want at least 32", tokenBytes)
	}
}

func TestARevokedGrantRefusesCommandsAndItsSocketIsGone(t *testing.T) {
	exec := &fakeExec{block: make(chan struct{})}
	rec := &recorder{}
	runtimeDir(t)
	g, err := Open(Options{Exec: exec, Notify: rec.add})
	if err != nil {
		t.Fatal(err)
	}
	token, sock := g.Token(), g.SocketPath()

	// Pin one command in flight so Close has something to cancel.
	go func() {
		_, _ = Dial(context.Background(), token, Request{Command: "sleep"}, io.Discard, io.Discard)
	}()
	waitFor(t, "the first command to start", func() bool { return exec.inFlight() == 1 })

	if err := g.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Synchronous revocation: by the time Close returned, the socket file is
	// already gone. No polling here on purpose — polling would hide exactly the
	// bug this asserts.
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket still present after Close: %v", err)
	}
	if _, err := Dial(context.Background(), token, Request{Command: "id"}, io.Discard, io.Discard); !errors.Is(err, ErrNoGrant) {
		t.Fatalf("after revocation: got %v, want ErrNoGrant", err)
	}
	// The in-flight command was cancelled rather than left running.
	waitFor(t, "the in-flight command to be cancelled", func() bool { return exec.inFlight() == 0 })
	if got := exec.seen(); len(got) != 1 {
		t.Fatalf("commands run = %v, want only the one started before revocation", got)
	}
	// Close is idempotent: the UI revokes on several triggers at once (key,
	// lock, session end, quit) and they can race.
	if err := g.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestAnExpiredGrantRefusesACommand(t *testing.T) {
	exec := &fakeExec{}
	g := openGrant(t, Options{Exec: exec, TTL: time.Millisecond})
	waitFor(t, "the TTL to lapse", g.Expired)

	_, err := Dial(context.Background(), g.Token(), Request{Command: "id"}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired grant: got %v, want an expiry error", err)
	}
	if got := exec.seen(); len(got) != 0 {
		t.Fatalf("an expired grant ran %v", got)
	}
	// The check is per request, not per connect: the socket is still there and
	// the token is still accepted, and the command is still refused.
	if _, statErr := os.Stat(g.SocketPath()); statErr != nil {
		t.Fatalf("the socket should outlive the TTL until Close: %v", statErr)
	}
}

func TestAuditEventsFireOnStartAndFinish(t *testing.T) {
	exec := &fakeExec{code: 3}
	rec := &recorder{}
	g := openGrant(t, Options{Exec: exec, Notify: rec.add})

	code, err := Dial(context.Background(), g.Token(), Request{Command: "uname -a"}, io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
	waitFor(t, "both audit events", func() bool { return len(rec.all()) == 2 })

	evs := rec.all()
	start, end := evs[0], evs[1]
	if start.Finished {
		t.Fatal("the first event must be the start event")
	}
	if start.Command != "uname -a" {
		t.Fatalf("start command = %q", start.Command)
	}
	if start.At.IsZero() {
		t.Fatal("the start event has no timestamp")
	}
	if !end.Finished {
		t.Fatal("the second event must be terminal")
	}
	if end.Code != 3 || end.Err != nil {
		t.Fatalf("finish event = (%d, %v), want (3, nil)", end.Code, end.Err)
	}
	if g.Count() != 1 {
		t.Fatalf("Count = %d, want 1", g.Count())
	}
}

func TestOutputAndExitCodeStreamThroughToTheClient(t *testing.T) {
	exec := &fakeExec{stdout: "hello\n", stderr: "warned\n", code: 42}
	g := openGrant(t, Options{Exec: exec})

	var out, errBuf bytes.Buffer
	code, err := Dial(context.Background(), g.Token(), Request{
		Command: "echo hello",
		Stdin:   []byte("piped"),
		Timeout: 30 * time.Second,
	}, &out, &errBuf)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if code != 42 {
		t.Fatalf("exit code = %d, want 42 — a non-zero remote exit is not a Go error", code)
	}
	if out.String() != "hello\n" {
		t.Fatalf("stdout = %q", out.String())
	}
	if errBuf.String() != "warned\n" {
		t.Fatalf("stderr = %q", errBuf.String())
	}
	if got := exec.seen(); len(got) != 1 || got[0] != "echo hello" {
		t.Fatalf("executor saw %v", got)
	}
}

func TestMaxInFlightIsEnforced(t *testing.T) {
	exec := &fakeExec{block: make(chan struct{})}
	g := openGrant(t, Options{Exec: exec, MaxInFlight: 1})

	go func() {
		_, _ = Dial(context.Background(), g.Token(), Request{Command: "first"}, io.Discard, io.Discard)
	}()
	waitFor(t, "the first command to occupy the only slot", func() bool { return exec.inFlight() == 1 })

	_, err := Dial(context.Background(), g.Token(), Request{Command: "second"}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("over the limit: got %v, want a refusal", err)
	}
	if exec.inFlight() != 1 {
		t.Fatalf("the refused command still reached the executor (%d in flight)", exec.inFlight())
	}

	close(exec.block)
	waitFor(t, "the first command to finish", func() bool { return exec.inFlight() == 0 })
	// The slot is released, not leaked: the next command runs.
	if _, err := Dial(context.Background(), g.Token(), Request{Command: "third"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("after the slot freed: %v", err)
	}
}

func TestAnOversizedFrameLengthIsRejectedWithoutAllocating(t *testing.T) {
	// The unit check: a header claiming 4 GiB must be refused on the length,
	// before any buffer exists. Reading it must not grow the heap.
	var before, after runtime.MemStats
	hostile := []byte{byte(kindAuth), 0xff, 0xff, 0xff, 0xff}
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, _, err := readFrame(bytes.NewReader(hostile))
	runtime.ReadMemStats(&after)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("hostile length: got %v, want a limit error", err)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
		t.Fatalf("reading a 4 GiB length allocated %d bytes", grew)
	}

	// And end to end: the server hangs up on it instead of dying, and the grant
	// keeps serving afterwards.
	exec := &fakeExec{}
	g := openGrant(t, Options{Exec: exec})
	c, err := net.Dial("unix", g.SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	var head [5]byte
	head[0] = byte(kindAuth)
	binary.BigEndian.PutUint32(head[1:], 0xffffffff)
	if _, err := c.Write(head[:]); err != nil {
		t.Fatal(err)
	}
	// The server must close the connection rather than wait for four gigabytes.
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadAll(c); err != nil {
		t.Fatalf("reading after a hostile frame: %v", err)
	}
	_ = c.Close()

	if _, err := Dial(context.Background(), g.Token(), Request{Command: "id"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("the grant stopped serving after a hostile frame: %v", err)
	}
}

func TestAConnectionThatSkipsTheTokenFrameIsClosed(t *testing.T) {
	exec := &fakeExec{}
	g := openGrant(t, Options{Exec: exec})

	c, err := net.Dial("unix", g.SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// The server opens with its challenge, unconditionally and before it knows
	// anything about the peer, so that frame is expected and carries no
	// information about whether the peer will be accepted.
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	kind, nonce, err := readFrameLimit(c, maxHandshakeFrame)
	if err != nil || kind != kindChallenge || len(nonce) != nonceLen {
		t.Fatalf("challenge: got kind %d, %d bytes, err %v", kind, len(nonce), err)
	}
	// A command frame where the proof belongs: the handshake is mandatory, so
	// this gets no further reply at all, not even a rejection to time against.
	if err := writeJSON(c, kindRun, runRequest{Command: "id"}); err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("reading after an unauthenticated request: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("the server answered an unauthenticated request with %q", rest)
	}
	if got := exec.seen(); len(got) != 0 {
		t.Fatalf("an unauthenticated request ran %v", got)
	}
}

func TestOpenRejectsAGrantWithNoExecutor(t *testing.T) {
	runtimeDir(t)
	if _, err := Open(Options{}); err == nil {
		t.Fatal("a grant with no executor must not open")
	}
}

func TestTheCommandLineCarriesTheTokenAndNotThePath(t *testing.T) {
	g := openGrant(t, Options{Exec: &fakeExec{}})
	line := g.CommandLine()
	if !strings.Contains(line, g.Token()) {
		t.Fatalf("CommandLine %q does not carry the token", line)
	}
	if strings.Contains(line, g.SocketPath()) {
		t.Fatalf("CommandLine %q exposes the socket path", line)
	}
	if !strings.HasPrefix(line, "wharf --remote ") {
		t.Fatalf("CommandLine %q does not spell the verb as a flag", line)
	}
}

func TestDefaultsApplyWhenOptionsAreZero(t *testing.T) {
	g := openGrant(t, Options{Exec: &fakeExec{}})
	want := time.Now().Add(DefaultTTL)
	if d := g.ExpiresAt().Sub(want); d > time.Minute || d < -time.Minute {
		t.Fatalf("ExpiresAt = %v, want about %v", g.ExpiresAt(), want)
	}
}

// --- finding 3: the token never goes on the wire ----------------------------

// rogueListener is a socket planted in the grants directory by a process
// running as the same uid — in practice the very agent a grant is meant to
// constrain. It records everything a client says to it, which is the whole
// question: what does a planted socket learn?
type rogueListener struct {
	ln net.Listener

	mu       sync.Mutex
	captured []byte
	conns    int
}

// plantRogue binds name inside dir and serves it with reply, which is handed
// each accepted connection. The name is chosen by the caller so it sorts before
// any real grant socket — os.ReadDir returns entries in name order, so a rogue
// named grant-0000000000.sock is the first thing Dial ever talks to.
func plantRogue(t *testing.T, dir, name string, reply func(*rogueListener, net.Conn)) *rogueListener {
	t.Helper()
	ln, err := net.Listen("unix", filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	r := &rogueListener{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			r.mu.Lock()
			r.conns++
			r.mu.Unlock()
			go func() {
				defer c.Close()
				reply(r, c)
			}()
		}
	}()
	return r
}

// record appends everything readable from c until the client gives up on it.
func (r *rogueListener) record(c net.Conn) {
	buf := make([]byte, 4096)
	for {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := c.Read(buf)
		if n > 0 {
			r.mu.Lock()
			r.captured = append(r.captured, buf[:n]...)
			r.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

func (r *rogueListener) loot() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.captured...)
}

func (r *rogueListener) connections() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.conns
}

func TestASocketPlantedInTheGrantsDirectoryLearnsNothingUsable(t *testing.T) {
	exec := &fakeExec{}
	g := openGrant(t, Options{Exec: exec, HostName: "prod"})
	dir := filepathDirOf(g.SocketPath())

	// The rogue plays a plausible server: it challenges like a real grant, takes
	// whatever the client offers and claims success. Everything it can do without
	// the token, it does.
	rogue := plantRogue(t, dir, "grant-0000000000.sock", func(r *rogueListener, c net.Conn) {
		var nonce [nonceLen]byte
		_ = writeFrame(c, kindChallenge, nonce[:])
		go r.record(c)
		time.Sleep(300 * time.Millisecond)
		_ = writeFrame(c, kindAuthOK, make([]byte, macLen))
		time.Sleep(300 * time.Millisecond)
	})

	var out bytes.Buffer
	code, dialErr := Dial(context.Background(), g.Token(), Request{Command: "curl -sS localhost:9000/health"}, &out, io.Discard)
	if rogue.connections() == 0 {
		t.Fatal("the rogue was never dialled — the test is not exercising what it claims to")
	}

	// What the rogue captured is checked before Dial's own outcome, so a
	// regression is reported as the leak it is rather than as whatever the client
	// happened to do afterwards.
	loot := rogue.loot()
	// The point of the fix: the secret is not in there. A planted socket used to
	// receive the token verbatim in the first frame.
	if bytes.Contains(loot, []byte(g.Token())) {
		t.Fatalf("the planted socket captured the token: %q", loot)
	}
	// Nor the command. The client verifies the server's proof before it sends
	// anything, so a rogue never learns what the agent was trying to run.
	if bytes.Contains(loot, []byte("curl")) {
		t.Fatalf("the planted socket captured the command: %q", loot)
	}
	// Only now: the honest client must have walked past the rogue to the real
	// grant and run there.
	if dialErr != nil {
		t.Fatalf("Dial past a planted socket: %v", dialErr)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	// And what it did capture is not a bearer credential: replaying the client's
	// proof against the real grant fails, because that proof is bound to a nonce
	// the real grant did not issue and to the rogue's own socket name.
	c, err := net.Dial("unix", g.SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, _, err := readFrameLimit(c, maxHandshakeFrame); err != nil {
		t.Fatalf("challenge from the real grant: %v", err)
	}
	if len(loot) < 5 {
		t.Fatalf("the rogue captured %d bytes, expected at least a frame header", len(loot))
	}
	if _, err := c.Write(loot); err != nil {
		t.Fatalf("replaying the captured bytes: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	kind, payload, err := readFrame(c)
	if err == nil && kind == kindAuthOK {
		t.Fatal("the real grant accepted a replay of what the planted socket captured")
	}
	if err == nil && kind == kindError && !bytes.Contains(payload, []byte("rejected")) {
		t.Fatalf("replay was answered with %q, want the opaque rejection", payload)
	}
	// The honest command still ran exactly once, on the real grant.
	if got := exec.seen(); len(got) != 1 || got[0] != "curl -sS localhost:9000/health" {
		t.Fatalf("executor saw %v", got)
	}
}

func TestARogueRelayingTheRealChallengeStillNeverSeesTheCommand(t *testing.T) {
	exec := &fakeExec{}
	g := openGrant(t, Options{Exec: exec})
	dir := filepathDirOf(g.SocketPath())
	real := g.SocketPath()

	// The strongest thing a planted socket can do without the token: forward the
	// real grant's challenge, hoping the client's proof is a credential it can
	// pass on. It is not — the proof is bound to the socket name the client
	// dialled, so the real grant refuses it.
	relayed := make(chan bool, 4)
	plantRogue(t, dir, "grant-0000000000.sock", func(r *rogueListener, c net.Conn) {
		up, err := net.Dial("unix", real)
		if err != nil {
			relayed <- false
			return
		}
		defer up.Close()
		_ = up.SetDeadline(time.Now().Add(5 * time.Second))
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		kind, nonce, err := readFrameLimit(up, maxHandshakeFrame)
		if err != nil || kind != kindChallenge {
			relayed <- false
			return
		}
		if err := writeFrame(c, kindChallenge, nonce); err != nil {
			relayed <- false
			return
		}
		kind, proof, err := readFrameLimit(c, maxHandshakeFrame)
		if err != nil || kind != kindAuth {
			relayed <- false
			return
		}
		if err := writeFrame(up, kindAuth, proof); err != nil {
			relayed <- false
			return
		}
		kind, payload, err := readFrame(up)
		accepted := err == nil && kind == kindAuthOK
		relayed <- accepted
		if err == nil {
			_ = writeFrame(c, kind, payload)
		}
		r.record(c)
	})

	if _, err := Dial(context.Background(), g.Token(), Request{Command: "secret-argv"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("Dial past a relaying socket: %v", err)
	}
	select {
	case accepted := <-relayed:
		if accepted {
			t.Fatal("the real grant authenticated a relayed proof")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the relay never completed — the test is not exercising what it claims to")
	}
	if got := exec.seen(); len(got) != 1 || got[0] != "secret-argv" {
		t.Fatalf("executor saw %v, want the one honest command", got)
	}
}

// --- finding 4: an unauthenticated peer costs a bounded amount --------------

func TestAnAuthFrameIsCappedAtTheHandshakeSizeNotTheGenericLimit(t *testing.T) {
	// The unit check first: a megabyte is fine for a command frame and must not
	// be for a handshake frame, which is 64 bytes at most.
	head := []byte{byte(kindAuth), 0, 0x10, 0, 0}
	if _, _, err := readFrameLimit(bytes.NewReader(head), maxHandshakeFrame); err == nil {
		t.Fatal("a 1 MiB handshake frame was accepted")
	}
	if maxHandshakeFrame != nonceLen+macLen {
		t.Fatalf("maxHandshakeFrame = %d, want the exact size of the largest handshake frame", maxHandshakeFrame)
	}

	// End to end: the server hangs up on the declaration instead of allocating
	// for it, and keeps serving afterwards.
	exec := &fakeExec{}
	g := openGrant(t, Options{Exec: exec})
	c, err := net.Dial("unix", g.SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := readFrameLimit(c, maxHandshakeFrame); err != nil {
		t.Fatalf("challenge: %v", err)
	}
	if _, err := c.Write(head); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	rest, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("the server did not hang up on an oversized auth frame: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("the server answered an oversized auth frame with %q", rest)
	}
	_ = c.Close()

	if _, err := Dial(context.Background(), g.Token(), Request{Command: "id"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("the grant stopped serving after an oversized auth frame: %v", err)
	}
}

func TestUnauthenticatedConnectionsCannotPileUpWithoutBound(t *testing.T) {
	exec := &fakeExec{}
	g := openGrant(t, Options{Exec: exec})

	// Fill every handshake slot with a connection that says nothing. Receiving
	// the challenge is the proof that a slot is held: the server only writes it
	// after taking one.
	var silent []net.Conn
	for i := 0; i < maxPendingConns; i++ {
		c, err := net.Dial("unix", g.SocketPath())
		if err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		silent = append(silent, c)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if kind, _, err := readFrameLimit(c, maxHandshakeFrame); err != nil || kind != kindChallenge {
			t.Fatalf("connection %d got kind %d, err %v", i, kind, err)
		}
	}

	// One more. Without the semaphore this would be served immediately, and so
	// would the three hundred after it — which is how 300 connections became
	// 189 MiB of heap. With it, the accept loop is parked and this connection
	// hears nothing until a slot frees.
	over, err := net.Dial("unix", g.SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	_ = over.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, _, err := readFrameLimit(over, maxHandshakeFrame); err == nil {
		t.Fatal("a connection past the handshake bound was served anyway")
	}

	// The bound is backpressure, not a refusal: freeing the slots lets the queued
	// work through, and the grant is still perfectly usable.
	for _, c := range silent {
		_ = c.Close()
	}
	_ = over.SetReadDeadline(time.Now().Add(10 * time.Second))
	if kind, _, err := readFrameLimit(over, maxHandshakeFrame); err != nil || kind != kindChallenge {
		t.Fatalf("after the slots freed: kind %d, err %v", kind, err)
	}
	_ = over.Close()

	if _, err := Dial(context.Background(), g.Token(), Request{Command: "id"}, io.Discard, io.Discard); err != nil {
		t.Fatalf("the grant stopped serving after a pile-up: %v", err)
	}
}

// --- finding 7: Close means no command starts -------------------------------

// dispatchWatcher fails the test if a command is ever handed a live context
// after Close has already returned. That is exactly what Close promises, and it
// is the assertion that a widened window between the revocation check and the
// dispatch would break.
type dispatchWatcher struct {
	closed     atomic.Bool
	violations atomic.Int64
	dispatched atomic.Int64
}

func (d *dispatchWatcher) Exec(ctx context.Context, req ExecRequest, stdout, stderr io.Writer) (int, error) {
	d.dispatched.Add(1)
	if d.closed.Load() && ctx.Err() == nil {
		d.violations.Add(1)
	}
	return 0, nil
}

func TestCloseNeverLetsACommandStartOnALiveContextAfterItReturns(t *testing.T) {
	runtimeDir(t)
	watch := &dispatchWatcher{}
	for i := 0; i < 200; i++ {
		g, err := Open(Options{Exec: watch})
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		watch.closed.Store(false)
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = Dial(context.Background(), g.Token(), Request{Command: "race"}, io.Discard, io.Discard)
		}()
		// Land Close somewhere around the dispatch. The interval is jittered
		// because a fixed one lands in the same place every iteration and would
		// only ever probe a single instant of the window.
		time.Sleep(time.Duration(i%40) * 50 * time.Microsecond)
		if err := g.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		watch.closed.Store(true)
		<-done
		if watch.violations.Load() != 0 {
			t.Fatalf("a command was dispatched on a live context after Close returned (iteration %d)", i)
		}
	}
	if watch.dispatched.Load() == 0 {
		t.Fatal("no command was ever dispatched — the race was never exercised")
	}
}

func TestACloseLandingInTheDispatchWindowStopsTheCommand(t *testing.T) {
	runtimeDir(t)
	exec := &fakeExec{}

	// The probe fires inside the window between the revocation check and the
	// dispatch, and revokes there. Close's doc comment and
	// docs/REMOTE-ACCESS.md both promise that a command cannot start once it has
	// returned; this is that promise, tested at the one instant where it used to
	// be false.
	var holder atomic.Pointer[Grant]
	var once sync.Once
	probe := func() {
		once.Do(func() {
			if g := holder.Load(); g != nil {
				_ = g.Close()
			}
		})
	}
	dispatchProbe.Store(&probe)
	t.Cleanup(func() { dispatchProbe.Store(nil) })

	g, err := Open(Options{Exec: exec})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = g.Close() })
	holder.Store(g)

	if _, err := Dial(context.Background(), g.Token(), Request{Command: "must not run"}, io.Discard, io.Discard); err == nil {
		t.Fatal("a command revoked mid-dispatch reported success")
	}
	if got := exec.seen(); len(got) != 0 {
		t.Fatalf("Close returned and the command ran anyway: %v", got)
	}
	if g.Count() != 0 {
		t.Fatalf("Count = %d, want 0 — a command that never started must not be counted", g.Count())
	}
}

// --- the audit log records what was attempted, not only what ran ------------

func TestARefusedCommandIsAudited(t *testing.T) {
	exec := &fakeExec{}
	rec := &recorder{}
	g := openGrant(t, Options{Exec: exec, Notify: rec.add, TTL: time.Millisecond})
	waitFor(t, "the TTL to lapse", g.Expired)

	if _, err := Dial(context.Background(), g.Token(), Request{Command: "rm -rf /"}, io.Discard, io.Discard); err == nil {
		t.Fatal("an expired grant ran a command")
	}
	waitFor(t, "the refusal to be audited", func() bool { return len(rec.all()) == 1 })

	ev := rec.all()[0]
	if !ev.Refused {
		t.Fatal("the refusal event is not marked Refused — a burst of refusals would read as a burst of commands")
	}
	if !ev.Finished {
		t.Fatal("a refusal is terminal: there is no start event to pair it with")
	}
	if ev.Command != "rm -rf /" {
		t.Fatalf("refusal command = %q — the log must show what was attempted", ev.Command)
	}
	if ev.Err == nil || !strings.HasPrefix(ev.Err.Error(), "refused: ") {
		t.Fatalf("refusal error = %v, want text a consumer that ignores Refused still reads as a refusal", ev.Err)
	}
	if ev.At.IsZero() {
		t.Fatal("the refusal event has no timestamp")
	}
	if got := exec.seen(); len(got) != 0 {
		t.Fatalf("a refused command reached the executor: %v", got)
	}
	// A refusal is an attempt, not a run: Count is what the UI shows as commands
	// run and must not move.
	if g.Count() != 0 {
		t.Fatalf("Count = %d after a refusal, want 0", g.Count())
	}
}

func TestACommandRefusedForConcurrencyIsAuditedToo(t *testing.T) {
	exec := &fakeExec{block: make(chan struct{})}
	rec := &recorder{}
	g := openGrant(t, Options{Exec: exec, Notify: rec.add, MaxInFlight: 1})

	go func() {
		_, _ = Dial(context.Background(), g.Token(), Request{Command: "first"}, io.Discard, io.Discard)
	}()
	waitFor(t, "the first command to occupy the only slot", func() bool { return exec.inFlight() == 1 })

	if _, err := Dial(context.Background(), g.Token(), Request{Command: "second"}, io.Discard, io.Discard); err == nil {
		t.Fatal("the second command was not refused")
	}
	waitFor(t, "a refusal event", func() bool {
		for _, ev := range rec.all() {
			if ev.Refused {
				return true
			}
		}
		return false
	})
	for _, ev := range rec.all() {
		if ev.Refused && ev.Command != "second" {
			t.Fatalf("refusal event names %q, want the command that was turned away", ev.Command)
		}
	}
	close(exec.block)
}

// filepathDirOf keeps the token test readable without importing path/filepath
// for one call.
func filepathDirOf(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i]
	}
	return "."
}
