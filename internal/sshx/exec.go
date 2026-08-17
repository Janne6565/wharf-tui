package sshx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// ExecRequest is one non-interactive command on an already-connected host.
type ExecRequest struct {
	Command string        // the command line, already assembled by the caller
	Stdin   []byte        // optional; nil sends an immediately-closed stdin
	Timeout time.Duration // zero means no deadline beyond ctx
}

// ExecResult reports how a command finished. Code is the remote exit status;
// it is meaningful only when Err is nil.
type ExecResult struct {
	Code int
}

// execKillGrace is how long an abandoned command has to die of its SIGTERM
// before it is sent SIGKILL. It is short because the caller has already been
// told the command was cancelled; this is cleanup, and nothing waits on it.
const execKillGrace = 2 * time.Second

// Exec runs cmd on the session's existing SSH connection in its own channel,
// streaming output to stdout and stderr as it arrives.
//
// It does not request a PTY and does not touch the session's ring buffer, so
// nothing it runs appears in the user's scrollback. It cannot prompt: the
// connection is already authenticated.
//
// The rejected alternative was dialling a second connection per exec, the way
// StartForward does. A forward has to — it must outlive detach — but an exec
// does not, and re-dialling would re-run the auth chain, which can prompt for a
// passphrase or a TOFU decision. A capability handed to an agent must never be
// able to raise a modal in the user's face, so this rides the live client and
// costs exactly one channel open.
//
// # The writer guarantee
//
// stdout and stderr are written only while Exec is running. Once Exec has
// returned — for any reason, including cancellation, timeout and session death
// — nothing will write to them again, so the caller may read them without
// synchronisation of its own. This is a promise the layers above rely on
// (sessd's execCall.seal is written against it), and it is not free: on the
// abort paths x/crypto's copier goroutines outlive the command, so the writers
// are cut before Exec returns rather than merely closing the channel and hoping
// the copiers stop in time. A test in this package hands Exec a plain,
// unsynchronised bytes.Buffer specifically to keep this honest.
//
// # What cancellation guarantees, and what it does not
//
// On ctx cancellation, Timeout, or the session dying, Exec returns promptly and
// stops writing to stdout and stderr: from the caller's side the command is
// over, and no late output can reach a revoked grant. That much is guaranteed.
//
// Whether the *remote process* dies is not guaranteed. This is an accepted
// limitation, not an oversight. Exec does ask — it sends an SSH "signal"
// request (SIGTERM, then SIGKILL after execKillGrace) before closing the
// channel — but that request is advisory: a server may refuse it, and OpenSSH's
// sshd has long been reported not to act on signal requests at all. Closing the
// channel is no substitute either: without a PTY there is no controlling
// terminal to hang up, so sshd has nothing to send SIGHUP to. This is the same
// reason `ssh host 'sleep 3600'` leaves a sleep behind when the client is
// killed, while `ssh -t` does not.
//
// So: a cancelled command that writes output usually dies of SIGPIPE on its
// next write, and one that writes nothing may run to completion on the host.
// Callers must phrase revocation as *the capability is withdrawn — no further
// command can be started*, never as *the running command was killed*. The
// behaviour is pinned by a test in this package so the claim cannot drift.
func (s *Session) Exec(ctx context.Context, req ExecRequest, stdout, stderr io.Writer) (ExecResult, error) {
	// A dead session is reported as such rather than as whatever "use of closed
	// network connection" the transport happens to raise: the caller (a grant)
	// has to distinguish "your host went away" from "your command failed".
	select {
	case <-s.done:
		return ExecResult{}, ErrSessionClosed
	default:
	}

	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	ch, err := s.client.NewSession()
	if err != nil {
		// The waiter closes s.client when the shell dies, so a NewSession that
		// fails right after that is the session ending, not a channel problem.
		select {
		case <-s.done:
			return ExecResult{}, ErrSessionClosed
		default:
		}
		return ExecResult{}, err
	}
	// Both writers are wrapped so an abandoned command cannot keep writing into
	// the caller's buffers after Exec has returned. Without this, a cancelled
	// exec could still deliver output to a grant that has already been revoked —
	// precisely the thing revocation is supposed to stop.
	out := &cutoffWriter{w: stdout}
	errw := &cutoffWriter{w: stderr}
	ch.Stdout = out
	ch.Stderr = errw
	// A nil Stdin still gets a reader: x/crypto closes the remote's stdin once
	// the reader is drained, so the command sees EOF immediately instead of
	// hanging forever waiting for input nobody is going to send.
	ch.Stdin = bytes.NewReader(req.Stdin)

	// ssh.Session has no ctx support, so the wait happens on its own goroutine
	// and the select below is what actually enforces ctx and session death.
	// Closing the channel is the only way to unblock a remote that is ignoring
	// us; a remote that never answers the close would otherwise pin Exec open
	// for as long as it liked, which is not acceptable for a revocable grant.
	runDone := make(chan error, 1)
	go func() { runDone <- ch.Run(req.Command) }()

	// abandon disowns the command. The cuts happen HERE, on this goroutine,
	// before Exec returns — not inside abandonExec. Cutting from the spawned
	// goroutine would leave a window between the `go` statement and that
	// goroutine being scheduled in which a copier could still write into the
	// caller's writer after Exec had already returned, which is the exact race
	// this is meant to close.
	abandon := func() {
		out.cut()
		errw.cut()
		go abandonExec(ch, runDone)
	}

	select {
	case err := <-runDone:
		// Run has returned, so x/crypto has already joined its copier
		// goroutines: nothing can touch the caller's writers any more.
		_ = ch.Close()
		return classifyExecErr(err)
	case <-ctx.Done():
		abandon()
		return ExecResult{}, ctx.Err()
	case <-s.done:
		abandon()
		return ExecResult{}, ErrSessionClosed
	}
}

// abandonExec finishes tearing down a command whose caller has already gone
// away: SIGTERM, a grace period, SIGKILL, close. Its writers must already have
// been cut by the caller — see abandon in Exec.
//
// It runs on its own goroutine deliberately. Waiting for the grace period
// inline would make cancellation take seconds to return, and a remote that
// simply ignores the close would pin a revoked grant open for as long as it
// liked — unacceptable for a capability whose whole point is being revocable.
func abandonExec(ch *ssh.Session, runDone <-chan error) {
	// Requests are ordered ahead of the close on the same channel, so a server
	// that implements signal requests sees SIGTERM before the teardown. Errors
	// are ignored throughout: this path runs precisely when the channel, or the
	// whole connection, is expected to be falling apart.
	_ = ch.Signal(ssh.SIGTERM)
	select {
	case <-runDone:
	case <-time.After(execKillGrace):
		_ = ch.Signal(ssh.SIGKILL)
	}
	_ = ch.Close()
}

// cutoffWriter forwards to an underlying writer until it is cut, after which it
// swallows everything. Cut writes report success rather than an error, because
// the goroutine still copying into it is x/crypto's and an error there would
// only surface as noise on a command nobody is listening to any more. A nil
// underlying writer is a valid "discard everything" writer.
type cutoffWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (c *cutoffWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.w == nil {
		return len(p), nil
	}
	return c.w.Write(p)
}

func (c *cutoffWriter) cut() {
	c.mu.Lock()
	c.w = nil
	c.mu.Unlock()
}

// classifyExecErr turns what ssh.Session.Run returns into the exec contract: a
// command that ran and failed is a result, not a Go error. Only a transport or
// protocol failure — the command never ran, or its outcome is unknowable — is
// an error, because a caller proxying an exit code back to a shell must not
// report wharf's own failures in the same channel as the remote's.
func classifyExecErr(err error) (ExecResult, error) {
	var exitErr *ssh.ExitError
	var missing *ssh.ExitMissingError
	switch {
	case err == nil:
		return ExecResult{}, nil
	case errors.As(err, &exitErr):
		return ExecResult{Code: exitErr.ExitStatus()}, nil
	case errors.As(err, &missing):
		// The remote closed the channel without an exit-status. OpenSSH reports
		// 255 for this and so do we, rather than inventing a Go error for a
		// command that did in fact run.
		return ExecResult{Code: 255}, nil
	default:
		return ExecResult{}, err
	}
}
