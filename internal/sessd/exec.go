//go:build !windows

package sessd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/Janne6565/wharf-tui/internal/sshx"
)

// execChunk caps the payload of one kindExecOut frame. It matches outChunk
// rather than maxFrame because the bytes are base64-encoded into JSON on the
// way out: 32 KiB of output becomes ~44 KiB of frame, which leaves the 1 MiB
// maxFrame ceiling an order of magnitude of headroom. Sizing the chunk at the
// ceiling instead would put the protocol one encoding overhead away from
// writeFrame refusing to send a legitimate command's output.
const execChunk = outChunk

// ErrExecUnsupported reports that this session's host cannot run commands at
// all — it was left running by a wharf from before exec existed, and sessions
// outliving the TUI is the whole point of sessd, so the first minutes after an
// upgrade are full of them.
//
// It is a sentinel because the UI has to tell it apart from a command that
// failed: the remedy is "reconnect to the host", which is worth saying, and
// nothing about the grant or the command is wrong.
var ErrExecUnsupported = errors.New("sessd: this session's host cannot run commands")

// --- client side --------------------------------------------------------

// execCall is one in-flight Exec waiting on its correlation id. It owns the
// caller's writers for the duration: readLoop writes output straight into them
// as frames land, and over is what guarantees it stops the instant Exec
// returns — a writer handed to Exec must be safe to read from once Exec is
// done, and the read loop is a different goroutine that may still be holding a
// frame for a call that just gave up.
type execCall struct {
	mu     sync.Mutex
	over   bool
	stdout io.Writer
	stderr io.Writer

	// done is buffered so the read loop never blocks delivering a terminal
	// frame, even to a caller that has already abandoned the call.
	done chan execEnd
}

func (e *execCall) write(stream string, data []byte) {
	if len(data) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.over {
		return
	}
	w := e.stdout
	if stream == execStreamErr {
		w = e.stderr
	}
	// A writer that errors is not worth failing the command over: the command
	// itself ran, and the caller's own sink breaking is the caller's problem to
	// notice. Dropping the chunk keeps the exit code honest.
	_, _ = w.Write(data)
}

func (e *execCall) finish(end execEnd) {
	select {
	case e.done <- end:
	default: // already terminated; the first answer is the one that counts
	}
}

// seal stops any further writing into the caller's writers. It is separate from
// finish because the two happen at different moments: finish is the host
// telling us the command is over, seal is Exec returning, and ctx cancellation
// makes the second happen without the first.
func (e *execCall) seal() {
	e.mu.Lock()
	e.over = true
	e.mu.Unlock()
}

// Exec runs a command on the session's host and streams its output, returning
// the remote exit code. A command that ran and failed is a non-zero code with a
// nil error; an error means wharf never learned an outcome — the session died,
// the socket broke, ctx was canceled. A caller proxying a status back to
// somebody's shell has to be able to tell those apart, which is why they are
// two return values and not one.
//
// Several Exec calls may be in flight at once on the same session, alongside
// the interactive shell. Nothing an exec runs reaches the session's scrollback:
// it gets its own SSH channel in the child (see sshx.Session.Exec).
//
// Canceling ctx both stops waiting and tells the host to abandon the command.
// Only doing the former would leave the command running on a real host after
// the grant that authorised it was revoked, which is the one thing a revocable
// capability may not do.
//
// A session adopted from a wharf older than execProtocol returns
// ErrExecUnsupported immediately. That check is not a nicety: such a host has
// no case for kindExec, so it drops the frame without even an error reply, and
// waiting for an answer that cannot arrive would burn the caller's whole
// timeout — or hang forever, since a zero Timeout is documented as "as long as
// the grant lives".
func (r *Remote) Exec(ctx context.Context, req ExecRequest, stdout, stderr io.Writer) (int, error) {
	if p := r.hostProtocol(); p < execProtocol {
		return 0, fmt.Errorf("%w: this session was started by an older wharf "+
			"(protocol %d, remote access needs %d) — reconnect to the host to use it",
			ErrExecUnsupported, p, execProtocol)
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}

	id, err := newExecID()
	if err != nil {
		return 0, err
	}
	call := &execCall{stdout: stdout, stderr: stderr, done: make(chan execEnd, 1)}

	r.execMu.Lock()
	if r.execs == nil {
		r.execs = map[string]*execCall{}
	}
	r.execs[id] = call
	r.execMu.Unlock()
	// Every exit below goes through here, cancellation included: an entry left
	// in the registry is a leak that also keeps the caller's writers reachable
	// from the read loop for the rest of the session's life.
	defer func() {
		call.seal()
		r.execMu.Lock()
		delete(r.execs, id)
		r.execMu.Unlock()
	}()

	wire := execRequest{
		ID:      id,
		Command: req.Command,
		Stdin:   req.Stdin,
		Timeout: int(req.Timeout.Milliseconds()),
	}
	if err := r.writeJSON(kindExec, wire); err != nil {
		return 0, err
	}

	select {
	case end := <-call.done:
		if end.Err != "" {
			return end.Code, errors.New(end.Err)
		}
		return end.Code, nil
	case <-r.done:
		// The session ended — or the control connection did — while the command
		// was running. Reporting it rather than waiting is what keeps a dead
		// session from hanging a grant forever.
		return 0, errNoSession
	case <-ctx.Done():
		// Best-effort: if the socket is already gone the host is gone with it.
		_ = r.writeJSON(kindExec, execRequest{ID: id, Cancel: true})
		return 0, ctx.Err()
	}
}

// hostProtocol reports the version the host on the other end speaks. It is read
// without a lock because the field is written exactly once — by Adopt, before
// the Remote is published through the pool's mutex, or not at all for a session
// we spawned ourselves.
func (r *Remote) hostProtocol() int { return r.protocol }

func (r *Remote) lookupExec(id string) *execCall {
	r.execMu.Lock()
	defer r.execMu.Unlock()
	return r.execs[id]
}

// newExecID mints a correlation id. It is random rather than a counter because
// the ids only have to be unique among this client's in-flight calls and random
// needs no shared state to stay that way; 8 bytes makes a collision between the
// handful of commands a grant runs at once not worth reasoning about.
func newExecID() (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

// --- host side ----------------------------------------------------------

// registerExec records a running exec so a later cancel frame can find it.
func (h *Host) registerExec(id string, cancel context.CancelFunc) {
	h.mu.Lock()
	if h.execs == nil {
		h.execs = map[string]context.CancelFunc{}
	}
	h.execs[id] = cancel
	h.mu.Unlock()
}

func (h *Host) forgetExec(id string) {
	h.mu.Lock()
	delete(h.execs, id)
	h.mu.Unlock()
}

// cancelExec aborts the exec with this id, if it is still running. An id that
// is unknown is not an error: the command may simply have finished between the
// client giving up and the frame arriving.
func (h *Host) cancelExec(id string) {
	h.mu.Lock()
	cancel := h.execs[id]
	h.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// exec runs one command for a client and streams the result back. It runs on
// its own goroutine — never on the connection's read loop — because the cancel
// frame that stops it arrives on that very connection, and a blocked reader
// could never deliver it. This is the same rule kindDial follows, and for the
// same reason.
func (c *conn) exec(req execRequest) {
	h := c.host

	h.mu.Lock()
	sess := h.sess
	h.mu.Unlock()
	if sess == nil {
		// Terminal, not silent: a client whose exec produced no answer at all
		// would wait for the session to end to find out it never started.
		_ = c.writeJSON(kindExecEnd, execEnd{ID: req.ID, Err: "sessd: no session to exec on"})
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.registerExec(req.ID, cancel)
	defer h.forgetExec(req.ID)

	// A client that vanishes mid-command cancels it, exactly as it cancels a
	// dial. Nobody is left to receive the output, and the command is running
	// with authority that client no longer has.
	go func() {
		select {
		case <-c.closed:
			cancel()
		case <-h.done:
			cancel()
		case <-ctx.Done():
		}
	}()

	res, err := sess.Exec(ctx, sshx.ExecRequest{
		Command: req.Command,
		Stdin:   req.Stdin,
		Timeout: time.Duration(req.Timeout) * time.Millisecond,
	}, c.execWriter(req.ID, execStreamOut), c.execWriter(req.ID, execStreamErr))

	end := execEnd{ID: req.ID, Code: res.Code}
	if err != nil {
		end.Code = 0
		end.Err = err.Error()
	}
	_ = c.writeJSON(kindExecEnd, end)
}

// execWriter returns the io.Writer that ships one stream of one exec back to
// the client.
func (c *conn) execWriter(id, stream string) io.Writer {
	return &execWriter{c: c, id: id, stream: stream}
}

type execWriter struct {
	c      *conn
	id     string
	stream string
}

// Write chunks p into frames that stay well under maxFrame. Like connOut it
// counts bytes as frames land rather than returning len(p) at the end: this
// writer is handed to x/crypto's channel copy, which treats a short write with
// no error as ErrShortWrite and truncates the stream.
func (w *execWriter) Write(p []byte) (int, error) {
	var written int
	for len(p) > 0 {
		n := len(p)
		if n > execChunk {
			n = execChunk
		}
		if err := w.c.writeJSON(kindExecOut, execOutput{
			ID:     w.id,
			Stream: w.stream,
			Data:   p[:n],
		}); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// decodeExecRequest is split out so handle stays a dispatch table: a malformed
// exec frame must not tear the connection down, because the connection is also
// carrying an interactive session.
func decodeExecRequest(payload []byte) (execRequest, error) {
	var req execRequest
	err := json.Unmarshal(payload, &req)
	return req, err
}
