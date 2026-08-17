package sshx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gliderssh "github.com/gliderlabs/ssh"
)

// execHooks lets a test observe the fake remote command from the server side:
// when it was dispatched, which signals it received, when it returned, and —
// for the command that outlives its channel — that it is demonstrably still
// running. Every channel is buffered, because gliderlabs delivers signals from
// its request loop and a blocking send there would wedge the server.
type execHooks struct {
	started   chan struct{}         // one token per fake command dispatched
	signaled  chan gliderssh.Signal // signals the fake command received
	finished  chan struct{}         // one token when the fake command returns
	heartbeat chan struct{}         // one token per tick of the heartbeat command
}

func newExecHooks() *execHooks {
	return &execHooks{
		started:   make(chan struct{}, 8),
		signaled:  make(chan gliderssh.Signal, 8),
		finished:  make(chan struct{}, 8),
		heartbeat: make(chan struct{}, 64),
	}
}

// send delivers one token without ever blocking the server's goroutine.
func send[T any](ch chan T, v T) {
	if ch == nil {
		return
	}
	select {
	case ch <- v:
	default:
	}
}

// execOrEchoHandler serves both halves of an exec test on one sshd. The two
// cases are told apart the way a real server tells them apart: an interactive
// shell asks for a PTY and carries no command, an exec channel does neither.
// marker, when non-empty, is written to the interactive session so a test has
// something to assert the ring buffer on.
func execOrEchoHandler(marker string, h *execHooks) gliderssh.Handler {
	return func(s gliderssh.Session) {
		_, winCh, isPty := s.Pty()
		if !isPty && len(s.Command()) > 0 {
			serveFakeCommand(s, h)
			return
		}
		go func() {
			for range winCh {
			}
		}()
		if marker != "" {
			_, _ = io.WriteString(s, marker)
		}
		_, _ = io.Copy(io.Discard, s) // keep the interactive session open
	}
}

// serveFakeCommand is a tiny command vocabulary standing in for a real shell,
// so the exec tests exercise stdout, stderr, exit codes, stdin, a command that
// obeys a signal and one that does not, without depending on anything
// installed on the machine running the tests.
func serveFakeCommand(s gliderssh.Session, h *execHooks) {
	if h != nil {
		send(h.started, struct{}{})
		defer send(h.finished, struct{}{})
	}
	argv := s.Command()
	switch argv[0] {
	case "out":
		_, _ = io.WriteString(s, strings.Join(argv[1:], " "))
		_ = s.Exit(0)
	case "err":
		_, _ = io.WriteString(s.Stderr(), strings.Join(argv[1:], " "))
		_ = s.Exit(0)
	case "both":
		_, _ = io.WriteString(s, "on-stdout")
		_, _ = io.WriteString(s.Stderr(), "on-stderr")
		_ = s.Exit(0)
	case "cat":
		_, _ = io.Copy(s, s)
		_ = s.Exit(0)
	case "fail":
		code, err := strconv.Atoi(argv[1])
		if err != nil {
			code = 1
		}
		_ = s.Exit(code)
	case "block":
		<-s.Context().Done() // ends when the connection goes away
		_ = s.Exit(0)
	case "signal-block":
		// The well-behaved long-running command: it dies on the first signal.
		sigCh := make(chan gliderssh.Signal, 4)
		s.Signals(sigCh)
		select {
		case sig := <-sigCh:
			if h != nil {
				send(h.signaled, sig)
			}
		case <-s.Context().Done():
		}
		_ = s.Exit(0)
	case "heartbeat":
		// The badly-behaved one: it ignores signals and keeps working, so a
		// test can observe that it survives its channel being closed.
		t := time.NewTicker(10 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-s.Context().Done():
				_ = s.Exit(0)
				return
			case <-t.C:
				// Writing every tick as well: a write to a torn-down channel
				// just errors, and the test uses it to prove no late output
				// reaches the caller's writer.
				_, _ = io.WriteString(s, "tick")
				if h != nil {
					send(h.heartbeat, struct{}{})
				}
			}
		}
	default:
		_ = s.Exit(127)
	}
}

// dialExecSession brings up an sshd running execOrEchoHandler and returns a
// live interactive session against it, closed by cleanup.
func dialExecSession(t *testing.T, marker string, h *execHooks) *Session {
	t.Helper()
	ts := startServer(t, testPassword, execOrEchoHandler(marker, h))

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	t.Setenv("SSH_AUTH_SOCK", "")
	m := NewManager(khPath, false)
	m.SetNotify(newRecorder().notify)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sess, err := m.Dial(ctx, ts.passwordSpec(), 80, 24)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

func TestExecStreamsStdoutToTheGivenWriter(t *testing.T) {
	sess := dialExecSession(t, "", nil)

	var out, errBuf safeBuffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := sess.Exec(ctx, ExecRequest{Command: "out hello-stdout"}, &out, &errBuf)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if res.Code != 0 {
		t.Fatalf("exit code = %d, want 0", res.Code)
	}
	if got := out.String(); got != "hello-stdout" {
		t.Fatalf("stdout = %q, want %q", got, "hello-stdout")
	}
	if got := errBuf.String(); got != "" {
		t.Fatalf("stderr = %q, want empty", got)
	}
}

func TestExecStreamsStderrSeparatelyFromStdout(t *testing.T) {
	sess := dialExecSession(t, "", nil)

	var out, errBuf safeBuffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := sess.Exec(ctx, ExecRequest{Command: "both"}, &out, &errBuf)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if res.Code != 0 {
		t.Fatalf("exit code = %d, want 0", res.Code)
	}
	if got := out.String(); got != "on-stdout" {
		t.Fatalf("stdout = %q, want %q", got, "on-stdout")
	}
	if got := errBuf.String(); got != "on-stderr" {
		t.Fatalf("stderr = %q, want %q", got, "on-stderr")
	}
}

// A command that fails is a result, not a Go error: the exit code has to reach
// the caller's shell verbatim, and an error return would make it indisguishable
// from wharf failing to run the command at all.
func TestExecReportsANonZeroExitWithoutAGoError(t *testing.T) {
	sess := dialExecSession(t, "", nil)

	var out, errBuf safeBuffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := sess.Exec(ctx, ExecRequest{Command: "fail 42"}, &out, &errBuf)
	if err != nil {
		t.Fatalf("a non-zero remote exit must not be a Go error, got %v", err)
	}
	if res.Code != 42 {
		t.Fatalf("exit code = %d, want 42", res.Code)
	}
}

func TestExecSendsStdinAndClosesIt(t *testing.T) {
	sess := dialExecSession(t, "", nil)

	var out, errBuf safeBuffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// cat copies stdin to stdout and only returns at EOF, so this also proves
	// stdin is closed rather than left open forever.
	res, err := sess.Exec(ctx, ExecRequest{Command: "cat", Stdin: []byte("piped-payload")}, &out, &errBuf)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if res.Code != 0 {
		t.Fatalf("exit code = %d, want 0", res.Code)
	}
	if got := out.String(); got != "piped-payload" {
		t.Fatalf("stdout = %q, want %q", got, "piped-payload")
	}
}

func TestExecAbortsOnContextCancellation(t *testing.T) {
	hooks := newExecHooks()
	sess := dialExecSession(t, "", hooks)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type outcome struct {
		res ExecResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		var out, errBuf safeBuffer
		res, err := sess.Exec(ctx, ExecRequest{Command: "block"}, &out, &errBuf)
		done <- outcome{res, err}
	}()

	select {
	case <-hooks.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the remote command never started")
	}
	cancel()

	select {
	case got := <-done:
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Exec did not return after the context was canceled")
	}

	// Cancelling one exec must not take the interactive session with it.
	if !sess.Alive() {
		t.Fatal("session died when an exec was canceled")
	}
}

func TestExecHonoursItsOwnTimeout(t *testing.T) {
	sess := dialExecSession(t, "", newExecHooks())

	var out, errBuf safeBuffer
	// No deadline on ctx: the timeout under test is the one in the request.
	req := ExecRequest{Command: "block", Timeout: 150 * time.Millisecond}
	_, err := sess.Exec(context.Background(), req, &out, &errBuf)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if !sess.Alive() {
		t.Fatal("session died when an exec timed out")
	}
}

func TestExecOnAClosedSessionReturnsErrSessionClosed(t *testing.T) {
	sess := dialExecSession(t, "", nil)

	_ = sess.Close()
	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("session did not end after Close")
	}

	var out, errBuf safeBuffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := sess.Exec(ctx, ExecRequest{Command: "out never-runs"}, &out, &errBuf)
	if !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("err = %v, want ErrSessionClosed", err)
	}
	if got := out.String(); got != "" {
		t.Fatalf("a closed session wrote %q to stdout, want nothing", got)
	}
}

// Several grants (or one agent running commands in parallel) share one client.
// Each exec must land in its own writers: cross-delivery here would mean one
// agent reading another's output.
func TestExecConcurrentCallsKeepTheirOutputSeparate(t *testing.T) {
	sess := dialExecSession(t, "", nil)

	const n = 8
	outs := make([]*safeBuffer, n)
	errs := make([]error, n)
	codes := make([]int, n)

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		outs[i] = &safeBuffer{}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			res, err := sess.Exec(ctx, ExecRequest{Command: "out tag-" + strconv.Itoa(i)}, outs[i], io.Discard)
			errs[i], codes[i] = err, res.Code
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("exec %d: %v", i, errs[i])
		}
		if codes[i] != 0 {
			t.Fatalf("exec %d exit code = %d, want 0", i, codes[i])
		}
		want := "tag-" + strconv.Itoa(i)
		if got := outs[i].String(); got != want {
			t.Fatalf("exec %d stdout = %q, want %q", i, got, want)
		}
	}

	if !sess.Alive() {
		t.Fatal("session died under concurrent execs")
	}
}

// A writer handed to Exec must be safe to read the moment Exec returns. The
// abort paths are where that is hard: x/crypto's copier goroutines outlive the
// command, so closing the channel alone leaves them free to write into the
// caller's buffer after the caller has moved on.
//
// This test deliberately breaks the package's safeBuffer convention and uses a
// plain, unsynchronised bytes.Buffer. That is the entire point: a mutex-guarded
// buffer makes the unsynchronised write legal, so the race detector stays quiet
// and the bug survives. Every other test in this package uses safeBuffer, which
// is exactly why none of them could catch this. Do not "fix" this one by
// switching it to safeBuffer — that would silently delete the assertion. The
// assertion here is the -race detector itself; the string comparisons are a
// bonus that catches the same thing when the race happens to be observable.
func TestExecWritersAreSafeToReadOnceExecReturns(t *testing.T) {
	hooks := newExecHooks()
	sess := dialExecSession(t, "", hooks)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var buf bytes.Buffer // unsynchronised on purpose — see above
	done := make(chan error, 1)
	go func() {
		_, err := sess.Exec(ctx, ExecRequest{Command: "heartbeat"}, &buf, io.Discard)
		done <- err
	}()

	select {
	case <-hooks.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the remote command never started")
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Exec did not return after the context was canceled")
	}

	// Read immediately and unguarded. The remote is still ticking (and still
	// trying to write) for a good while yet, so a copier that has not been cut
	// loose will be caught racing this read.
	settled := buf.String()
	for i := 0; i < 5; i++ {
		select {
		case <-hooks.heartbeat:
		case <-time.After(5 * time.Second):
			t.Fatal("the remote command stopped producing output before the test could observe it")
		}
		if got := buf.String(); got != settled {
			t.Fatalf("Exec wrote to the caller's buffer after returning: %q -> %q", settled, got)
		}
	}
}

// The same guarantee on the other abort path: the session dying under a
// running command. Its writers must be cut too, and the assertion is again the
// race detector reading an unsynchronised buffer straight after Exec returns.
func TestExecWritersAreSafeToReadWhenTheSessionDiesMidCommand(t *testing.T) {
	hooks := newExecHooks()
	sess := dialExecSession(t, "", hooks)

	var buf bytes.Buffer // unsynchronised on purpose, as above
	done := make(chan error, 1)
	go func() {
		_, err := sess.Exec(context.Background(), ExecRequest{Command: "heartbeat"}, &buf, io.Discard)
		done <- err
	}()

	select {
	case <-hooks.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the remote command never started")
	}
	_ = sess.Close()

	select {
	case err := <-done:
		// Which arm of Exec's select wins here is genuinely racy and both are
		// correct: killing the session races the remote's own exit-status, so
		// Exec may report ErrSessionClosed or may report the command having
		// finished first. Asserting one of them would just be flaky. What must
		// hold either way — and what this test is actually for — is the read
		// below.
		if err != nil && !errors.Is(err, ErrSessionClosed) {
			t.Fatalf("err = %v, want nil or ErrSessionClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Exec did not return after the session died")
	}
	_ = buf.String() // unguarded read of the caller's buffer, under -race
}

// Cancellation asks the remote to stop before it closes the channel. Against a
// server that implements signal requests, that ask is honoured: the command
// receives SIGTERM and returns. This proves the mechanism is wired correctly —
// it does not prove anything about servers that ignore signal requests, which
// is the case the next test covers.
func TestExecCancellationSignalsTheRemoteCommand(t *testing.T) {
	hooks := newExecHooks()
	sess := dialExecSession(t, "", hooks)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := sess.Exec(ctx, ExecRequest{Command: "signal-block"}, io.Discard, io.Discard)
		done <- err
	}()

	select {
	case <-hooks.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the remote command never started")
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Exec did not return after the context was canceled")
	}

	select {
	case sig := <-hooks.signaled:
		if sig != gliderssh.SIGTERM {
			t.Fatalf("remote received %v, want SIGTERM", sig)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the remote command was never signaled")
	}
	select {
	case <-hooks.finished:
	case <-time.After(5 * time.Second):
		t.Fatal("the signaled remote command never returned")
	}
	if !sess.Alive() {
		t.Fatal("signaling an exec must not disturb the interactive session")
	}
}

// This is the documented limitation, asserted rather than assumed: closing the
// exec channel is not by itself a kill. A remote command that ignores signals
// keeps running after Exec has reported the cancellation, so the test requires
// it to still be observably alive afterwards. If a future change ever makes
// cancellation genuinely terminate such a command, this test fails loudly and
// the doc comment on Exec must be corrected — that is the point of it.
func TestExecCancellationDoesNotStopACommandThatIgnoresSignals(t *testing.T) {
	hooks := newExecHooks()
	sess := dialExecSession(t, "", hooks)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var out safeBuffer
	done := make(chan error, 1)
	go func() {
		_, err := sess.Exec(ctx, ExecRequest{Command: "heartbeat"}, &out, io.Discard)
		done <- err
	}()

	select {
	case <-hooks.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the remote command never started")
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Exec did not return after the context was canceled")
	}

	// Discard every tick produced before the channel was torn down, so what
	// follows can only have been produced afterwards.
	for draining := true; draining; {
		select {
		case <-hooks.heartbeat:
		default:
			draining = false
		}
	}
	afterCancel := out.String()
	for i := 0; i < 3; i++ {
		select {
		case <-hooks.heartbeat:
		case <-time.After(5 * time.Second):
			t.Fatal("expected the remote command to outlive its channel; if it no longer does, fix Exec's doc comment")
		}
	}

	// The command lives on, but nothing it produces may reach the caller once
	// Exec has returned: the ticks above are the time base that makes this a
	// real assertion rather than a sleep.
	if got := out.String(); got != afterCancel {
		t.Fatalf("late output reached the caller after cancellation: %q -> %q", afterCancel, got)
	}
}

// The load-bearing test for the whole feature: an exec rides its own channel on
// the live client, so nothing it runs may reach the interactive session's ring
// buffer. If this ever fails, an agent's commands are showing up in the user's
// scrollback and the isolation claim in the design contract is false.
func TestExecDoesNotDisturbTheInteractiveRing(t *testing.T) {
	const marker = "interactive-marker-42"
	sess := dialExecSession(t, marker, nil)

	waitFor(t, 5*time.Second, "ring to contain the interactive output", func() bool {
		return strings.Contains(string(sess.ring.Snapshot()), marker)
	})
	before := string(sess.ring.Snapshot())

	var out, errBuf safeBuffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := sess.Exec(ctx, ExecRequest{Command: "both"}, &out, &errBuf)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if res.Code != 0 {
		t.Fatalf("exit code = %d, want 0", res.Code)
	}
	if out.String() == "" || errBuf.String() == "" {
		t.Fatalf("exec produced no output to compare against: out=%q err=%q", out.String(), errBuf.String())
	}

	if after := string(sess.ring.Snapshot()); after != before {
		t.Fatalf("exec changed the interactive ring:\nbefore = %q\nafter  = %q", before, after)
	}
	// Nothing from the exec may be in the scrollback under any framing.
	if strings.Contains(string(sess.ring.Snapshot()), "on-stdout") ||
		strings.Contains(string(sess.ring.Snapshot()), "on-stderr") {
		t.Fatal("exec output leaked into the interactive ring")
	}
	if !sess.Alive() {
		t.Fatal("the interactive session must survive an exec")
	}
}
