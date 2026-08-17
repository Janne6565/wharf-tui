//go:build !windows

package sessd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// execRemote dials a session in a real child process and returns it, which is
// what makes these tests exercise the framing and the process boundary rather
// than an in-process stand-in.
func execRemote(t *testing.T) (*testServer, *Remote) {
	t.Helper()
	ts := startServer(t)
	sockDir, knownHosts := tempDirs(t)
	pool, _ := newPool(t, sockDir, knownHosts)
	r, err := pool.Dial(context.Background(), ts.spec(), 80, 24)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return ts, r
}

func TestExecStreamsStdoutStderrAndTheRemoteExitCode(t *testing.T) {
	_, r := execRemote(t)

	var out, errb safeBuffer
	code, err := r.Exec(context.Background(),
		ExecRequest{Command: "out on-stdout; err on-stderr; exit 42"}, &out, &errb)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	// A command that ran and failed is a code, not a Go error: a grant proxies
	// this straight back to somebody's shell, and reporting wharf's own
	// failures in the same channel would make the two indistinguishable.
	if code != 42 {
		t.Errorf("exit code = %d, want the remote's 42", code)
	}
	if out.String() != "on-stdout" {
		t.Errorf("stdout = %q, want %q", out.String(), "on-stdout")
	}
	if errb.String() != "on-stderr" {
		t.Errorf("stderr = %q, want %q", errb.String(), "on-stderr")
	}
}

// The load-bearing test for correlation. Every exec writes a marker unique to
// itself and exits with a status unique to itself, and they all overlap in
// time. Route the replies through r.ctl — depth-4 and unkeyed — and one
// caller's stdout lands in another's writer and one caller's exit code is
// reported to another's shell, which is a wrong answer presented as a right
// one. Exact-equality assertions are deliberate: a substring check would pass
// on a writer that also received a stranger's output.
func TestConcurrentExecsNeverCrossDeliverTheirOutput(t *testing.T) {
	_, r := execRemote(t)

	const n = 8
	type result struct {
		code   int
		err    error
		out    string
		errOut string
	}
	results := make([]result, n)

	// A barrier rather than staggered starts: the whole point is that all of
	// them are in flight on the same socket at the same time, and the sleep in
	// the middle of each command keeps them overlapping while output is being
	// delivered, not just while requests are being sent.
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var out, errb safeBuffer
			cmd := fmt.Sprintf("out stdout-%d; sleep 80; err stderr-%d; exit %d", i, i, i+1)
			<-start
			code, err := r.Exec(context.Background(), ExecRequest{Command: cmd}, &out, &errb)
			results[i] = result{code: code, err: err, out: out.String(), errOut: errb.String()}
		}()
	}
	close(start)
	wg.Wait()

	for i, got := range results {
		if got.err != nil {
			t.Fatalf("exec %d: %v", i, got.err)
		}
		if want := fmt.Sprintf("stdout-%d", i); got.out != want {
			t.Errorf("exec %d stdout = %q, want exactly %q", i, got.out, want)
		}
		if want := fmt.Sprintf("stderr-%d", i); got.errOut != want {
			t.Errorf("exec %d stderr = %q, want exactly %q", i, got.errOut, want)
		}
		if got.code != i+1 {
			t.Errorf("exec %d exit code = %d, want %d", i, got.code, i+1)
		}
	}

	// Nothing may be left behind: an entry per call would keep the caller's
	// writers reachable from the read loop for the rest of the session.
	r.execMu.Lock()
	left := len(r.execs)
	r.execMu.Unlock()
	if left != 0 {
		t.Errorf("%d exec registry entries leaked", left)
	}
}

// Output larger than one frame has to be chunked and reassembled in order.
// maxFrame is 1 MiB and the payload is base64 in JSON, so a command that emits
// a megabyte is not an exotic case — it is `cat` on a log file.
func TestExecOutputLargerThanOneFrameArrivesIntact(t *testing.T) {
	_, r := execRemote(t)

	const size = 10*execChunk + 517 // deliberately not a chunk multiple
	var out safeBuffer
	code, err := r.Exec(context.Background(),
		ExecRequest{Command: fmt.Sprintf("big %d", size)}, &out, nil)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	got := out.String()
	if len(got) != size {
		t.Fatalf("got %d bytes, want %d", len(got), size)
	}
	for i := range size {
		if got[i] != byte('a'+i%26) {
			t.Fatalf("byte %d = %q, want %q — chunks were reordered or dropped",
				i, got[i], byte('a'+i%26))
		}
	}
}

// A dead session must fail an exec, not park it. A grant holding a reference to
// a session whose child has gone would otherwise block a caller's shell
// forever, and the bound below is what makes a regression fail loudly in CI
// instead of hanging the run until the test timeout kills everything.
func TestExecAgainstAnEndedSessionFailsInsteadOfHanging(t *testing.T) {
	ts := startServer(t)
	sockDir, knownHosts := tempDirs(t)
	pool, _ := newPool(t, sockDir, knownHosts)
	r, err := pool.Dial(context.Background(), ts.spec(), 80, 24)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	waitFor(t, "the session to end", func() bool { return !r.Alive() })

	done := make(chan error, 1)
	go func() {
		_, execErr := r.Exec(context.Background(),
			ExecRequest{Command: "out never"}, io.Discard, io.Discard)
		done <- execErr
	}()
	select {
	case execErr := <-done:
		if execErr == nil {
			t.Fatal("exec on an ended session must report an error, not a zero exit code")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("exec on an ended session must fail, not block")
	}
}

// Cancelling has to reach the host, not just release the caller. A command left
// running after the grant that authorised it was revoked is precisely the
// authority the design promises can be withdrawn, so the assertion is on the
// server's own count of live exec channels — the client returning is not
// evidence that anything stopped.
func TestCancellingTheContextStopsTheCommandOnTheHost(t *testing.T) {
	ts, r := execRemote(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := r.Exec(ctx, ExecRequest{Command: "tick 600 50"}, io.Discard, io.Discard)
		done <- err
	}()
	waitFor(t, "the command to start on the server", func() bool { return ts.execsRunning() > 0 })

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("exec error = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancelling ctx must stop Exec waiting")
	}
	waitFor(t, "the host to abandon the command", func() bool { return ts.execsRunning() == 0 })

	// The session itself is untouched: a cancelled exec must not cost the user
	// the shell that is sharing the connection.
	if !r.Alive() {
		t.Fatal("cancelling an exec must not end the session")
	}
	var out safeBuffer
	if _, err := r.Exec(context.Background(), ExecRequest{Command: "out still-here"}, &out, nil); err != nil {
		t.Fatalf("exec after a cancellation: %v", err)
	}
	if out.String() != "still-here" {
		t.Errorf("stdout after a cancellation = %q, want %q", out.String(), "still-here")
	}
}

// serveLegacyHost listens on sock and behaves exactly as a session host from
// before exec existed: it answers kindInfo with the protocol it was given, and
// every other frame — kindExec included — falls off the end of its switch and
// is silently dropped, with no reply and no error frame. That silence is the
// failure mode being tested.
func serveLegacyHost(t *testing.T, sock string, proto int) {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close(); _ = os.Remove(sock) })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				for {
					kind, _, err := readFrame(c)
					if err != nil {
						return
					}
					if kind == kindInfo {
						_ = writeJSON(c, kindInfoOK, infoResponse{
							Protocol: proto, PID: os.Getpid() + 1,
							HostID: "h1", HostName: "legacy", User: "tester",
							Addr: "127.0.0.1", Port: 22,
							StartedAt: time.Now().Unix(), Alive: true,
						})
					}
					// Anything else, kindExec above all, is dropped.
				}
			}()
		}
	}()
}

// Sessions outlive the TUI on purpose, so the minutes after an upgrade are
// exactly when a new wharf meets old hosts. Two things must hold at once, and
// they pull in opposite directions: those sessions must still be adopted — an
// upgrade that silently orphans every running shell is a worse bug than the one
// being fixed — and exec against them must fail immediately with an
// explanation, because a host that predates kindExec drops the frame without a
// reply and Exec would otherwise wait out the caller's entire timeout, or
// forever when the timeout is zero.
//
// The bound is what makes a regression fail loudly instead of hanging CI.
func TestASessionFromAnOlderWharfIsStillAdoptedButRefusesExec(t *testing.T) {
	sockDir, knownHosts := tempDirs(t)
	sock, err := socketPath(sockDir, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	serveLegacyHost(t, sock, execProtocol-1)

	pool, _ := newPool(t, sockDir, knownHosts)
	n, err := pool.Adopt()
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if n != 1 {
		t.Fatalf("adopted %d sessions, want 1 — an older host's shell must not be orphaned", n)
	}
	r := pool.Get(sessionIDFor(sock))
	if r == nil {
		t.Fatal("the adopted session should be addressable by its ID")
	}
	if got := r.hostProtocol(); got != execProtocol-1 {
		t.Fatalf("adoption recorded protocol %d, want the host's own %d", got, execProtocol-1)
	}

	done := make(chan error, 1)
	go func() {
		_, execErr := r.Exec(context.Background(),
			ExecRequest{Command: "out hi"}, io.Discard, io.Discard)
		done <- execErr
	}()
	select {
	case execErr := <-done:
		if !errors.Is(execErr, ErrExecUnsupported) {
			t.Fatalf("exec error = %v, want ErrExecUnsupported", execErr)
		}
		// The remedy has to be in the message: "it did not work" is not
		// actionable, "reconnect to the host" is.
		if !strings.Contains(execErr.Error(), "older wharf") ||
			!strings.Contains(execErr.Error(), "reconnect") {
			t.Errorf("the error should name the cause and the remedy, got: %v", execErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("exec against a host that cannot run it must fail fast, not block " +
			"waiting for a reply that host will never send")
	}

	// The session itself is untouched: it is an ordinary shell, and only the
	// new feature is unavailable on it.
	if !r.Alive() {
		t.Error("refusing an exec must not end the session")
	}
}

// A host newer than this build is still refused, because its frames could land
// in ctl and be mistaken for a dial or info reply. Only the older direction was
// relaxed.
func TestAdoptStillRefusesAHostNewerThanThisBuild(t *testing.T) {
	sockDir, knownHosts := tempDirs(t)
	sock, err := socketPath(sockDir, "future")
	if err != nil {
		t.Fatal(err)
	}
	serveLegacyHost(t, sock, protocolVersion+1)

	pool, _ := newPool(t, sockDir, knownHosts)
	n, err := pool.Adopt()
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if n != 0 {
		t.Fatalf("adopted %d sessions, want 0 — a newer host cannot be framed by this build", n)
	}
	// The socket stays: that session is real, and a later wharf can claim it.
	if _, err := os.Stat(sock); err != nil {
		t.Errorf("a newer host's socket must not be unlinked: %v", err)
	}
}

// The JSON tags are part of the contract, not an implementation detail: the two
// sides of this socket may be different wharf builds, so a renamed field is a
// silent protocol break rather than a compile error.
func TestExecFrameRoundTrip(t *testing.T) {
	var buf safeBuffer
	req := execRequest{ID: "c0ffee", Command: "out hi", Stdin: []byte("input"), Timeout: 1500}
	if err := writeJSON(&buf, kindExec, req); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(&buf, kindExecOut, execOutput{
		ID: "c0ffee", Stream: execStreamErr, Data: []byte{0x00, 0x01, 0xff, '\n'},
	}); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(&buf, kindExecEnd, execEnd{ID: "c0ffee", Code: 7, Err: "boom"}); err != nil {
		t.Fatal(err)
	}

	rd := strings.NewReader(buf.String())

	kind, payload, err := readFrame(rd)
	if err != nil {
		t.Fatal(err)
	}
	if kind != kindExec {
		t.Fatalf("first frame kind = %d, want kindExec (%d)", kind, kindExec)
	}
	var wire map[string]any
	if err := json.Unmarshal(payload, &wire); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"id", "command", "stdin", "timeoutMs"} {
		if _, ok := wire[key]; !ok {
			t.Errorf("execRequest is missing the %q field the contract names; got %v", key, wire)
		}
	}
	var gotReq execRequest
	if err := json.Unmarshal(payload, &gotReq); err != nil {
		t.Fatal(err)
	}
	if gotReq.ID != req.ID || gotReq.Command != req.Command ||
		string(gotReq.Stdin) != string(req.Stdin) || gotReq.Timeout != req.Timeout {
		t.Errorf("execRequest round trip = %+v, want %+v", gotReq, req)
	}

	kind, payload, err = readFrame(rd)
	if err != nil {
		t.Fatal(err)
	}
	if kind != kindExecOut {
		t.Fatalf("second frame kind = %d, want kindExecOut (%d)", kind, kindExecOut)
	}
	var gotOut execOutput
	if err := json.Unmarshal(payload, &gotOut); err != nil {
		t.Fatal(err)
	}
	// Binary-safe is the point of base64: output is arbitrary bytes, not text.
	if gotOut.ID != "c0ffee" || gotOut.Stream != execStreamErr ||
		string(gotOut.Data) != string([]byte{0x00, 0x01, 0xff, '\n'}) {
		t.Errorf("execOutput round trip = %+v", gotOut)
	}

	kind, payload, err = readFrame(rd)
	if err != nil {
		t.Fatal(err)
	}
	if kind != kindExecEnd {
		t.Fatalf("third frame kind = %d, want kindExecEnd (%d)", kind, kindExecEnd)
	}
	var gotEnd execEnd
	if err := json.Unmarshal(payload, &gotEnd); err != nil {
		t.Fatal(err)
	}
	if gotEnd.ID != "c0ffee" || gotEnd.Code != 7 || gotEnd.Err != "boom" {
		t.Errorf("execEnd round trip = %+v", gotEnd)
	}

	if _, _, err := readFrame(rd); !errors.Is(err, ErrClosed) {
		t.Fatalf("a clean hangup should report ErrClosed, got %v", err)
	}
}

// A cancel frame carries no command, so it must not be mistaken for one — the
// two travel as the same kind, and a host that ran it would spawn a shell doing
// nothing every time a caller gave up.
func TestExecCancelFrameIsDistinguishableFromARequest(t *testing.T) {
	var buf safeBuffer
	if err := writeJSON(&buf, kindExec, execRequest{ID: "abc", Cancel: true}); err != nil {
		t.Fatal(err)
	}
	_, payload, err := readFrame(strings.NewReader(buf.String()))
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeExecRequest(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Cancel || got.ID != "abc" || got.Command != "" {
		t.Fatalf("cancel frame decoded as %+v", got)
	}
}
