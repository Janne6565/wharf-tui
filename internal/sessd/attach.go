//go:build !windows

package sessd

import (
	"bytes"
	"io"
	"os"
	"time"

	"github.com/Janne6565/wharf-tui/internal/detachkey"
	"github.com/Janne6565/wharf-tui/internal/termsig"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/muesli/cancelreader"
	"golang.org/x/term"
)

// remoteAccessTimeout bounds how long the stdin loop waits for OnRemoteAccess
// before giving up on it. The callback mints a unix socket, so it can block for
// a moment; ten seconds is far longer than that can honestly take, and past it
// the user is better served by a session that keeps forwarding keys than by one
// that looks hung with no way out.
const remoteAccessTimeout = 10 * time.Second

// Attach returns the tea.ExecCommand that hands this terminal to the remote
// session. It is the socket-backed twin of sshx.Session.Attach: raw mode,
// replay, bidirectional copy and WINCH forwarding, except the bytes travel over
// the unix socket to the child process that owns the SSH connection.
//
// detach is the byte that ends the takeover, the same contract as
// sshx.Session.Attach: zero falls back to the default (ctrl+\). The key is
// watched here rather than in the session host, so it applies from the moment
// it is changed — including to sessions an earlier wharf left running.
//
// It is the no-hotkeys shorthand for AttachWith, kept because most callers
// (and every test that predates the remote-access key) want nothing else.
func (r *Remote) Attach(detach byte) tea.ExecCommand {
	return r.AttachWith(AttachOptions{Detach: detach})
}

// AttachWith is Attach with the full option set. See AttachOptions.
func (r *Remote) AttachWith(opts AttachOptions) tea.ExecCommand {
	if opts.Detach == 0 {
		opts.Detach = detachkey.DefaultByte
	}
	// The detach byte wins a collision. internal/detachkey refuses to bind the
	// two keys to the same byte, so this should be unreachable — but if that
	// validation is ever bypassed (a hand-edited config, a future caller that
	// builds options itself), the failure mode has to be a session you can
	// still leave, not one whose only exit is a hotkey.
	if opts.RemoteAccess == opts.Detach {
		opts.RemoteAccess = 0
	}
	return &attachCmd{r: r, opts: opts}
}

type attachCmd struct {
	r      *Remote
	opts   AttachOptions
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer

	// out is stdout resolved once by Run: the terminal the session is attached
	// to, and therefore where hotkey feedback has to be written.
	out io.Writer
}

func (a *attachCmd) SetStdin(rd io.Reader) { a.stdin = rd }
func (a *attachCmd) SetStdout(w io.Writer) { a.stdout = w }
func (a *attachCmd) SetStderr(w io.Writer) { a.stderr = w }

// Run streams until the user detaches or the session dies. It always
// leaves the terminal restored and tells the host to stop streaming.
func (a *attachCmd) Run() error {
	r := a.r

	stdin := a.stdin
	if stdin == nil {
		stdin = os.Stdin
	}
	stdout := a.stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	a.out = stdout

	if f, ok := stdout.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fd := int(f.Fd())
		if st, err := term.MakeRaw(fd); err == nil {
			defer func() { _ = term.Restore(fd, st) }()
		}
	}

	// In raw mode ctrl+\ arrives as a byte; guard against the quit signal in
	// case raw mode ever fails to engage. This holds whether or not ctrl+\ is
	// still the detach key: unbound, it is a byte for the remote, not a signal.
	defer termsig.IgnoreQuit()()

	cols, rows := terminalSize(stdout)
	stopWindow := a.syncWindow(stdout)
	defer stopWindow()

	// Clear locally before the host replays its ring, so a full-screen app
	// repaints from a clean slate exactly as the in-process attach does.
	_, _ = io.WriteString(stdout, "\x1b[2J\x1b[H")

	r.setLive(stdout)
	defer r.unsetLive(stdout)

	if err := r.writeJSON(kindAttach, attachRequest{Cols: cols, Rows: rows}); err != nil {
		return nil // the session is gone; SessionEndedMsg reports it
	}
	defer func() { _ = r.writeFrame(kindDetach, nil) }()

	return a.stdinLoop(stdin)
}

// terminalSize reports the current size of w, or zeroes when it is not a tty.
func terminalSize(w io.Writer) (cols, rows int) {
	f, ok := w.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return 0, 0
	}
	c, rws, err := term.GetSize(int(f.Fd()))
	if err != nil {
		return 0, 0
	}
	return c, rws
}

// syncWindow forwards terminal resizes to the host for the attach lifetime. The
// returned func stops the watcher and its goroutine.
func (a *attachCmd) syncWindow(stdout io.Writer) func() {
	f, ok := stdout.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return func() {}
	}
	r := a.r

	return termsig.WatchResize(int(f.Fd()), func(cols, rows int) {
		_ = r.writeJSON(kindResize, resizeRequest{Cols: cols, Rows: rows})
	})
}

// stdinLoop forwards local input to the host until detach or session death.
func (a *attachCmd) stdinLoop(stdin io.Reader) error {
	r := a.r

	cr, err := cancelreader.NewReader(stdin)
	if err != nil {
		return a.forward(stdin)
	}
	defer cr.Cancel()

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-r.done:
			cr.Cancel()
		case <-stop:
		}
	}()

	return a.forward(cr)
}

// forward copies input to the host, watching for the bytes dispatch acts on. It
// returns nil on detach, EOF or session death — never an error, because the UI
// distinguishes the two through SessionEndedMsg, exactly as in-process attach
// does.
func (a *attachCmd) forward(rd io.Reader) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := rd.Read(buf)
		if n > 0 && !a.dispatch(buf[:n]) {
			return nil
		}
		if err != nil {
			return nil
		}
	}
}

// dispatch consumes one read, forwarding the runs between watched bytes and
// acting on the bytes themselves. It reports whether the takeover continues.
//
// It loops rather than handling a single hit because a read is up to 32 KiB of
// whatever the terminal had buffered: a hotkey can sit in the middle of it,
// twice, or at either end, and the runs on both sides still belong to the
// remote in their original order. Slicing past the byte and going round again
// is what keeps that true. The watched byte itself is always dropped — neither
// key is the remote's business.
//
// Each run goes out as its own data frame. Frames are already a stream the host
// re-concatenates onto the remote's stdin, so splitting one read into two
// frames changes nothing the remote can observe except that the hotkey byte is
// missing from between them.
func (a *attachCmd) dispatch(chunk []byte) bool {
	for len(chunk) > 0 {
		i, isDetach := a.scan(chunk)
		if i < 0 {
			return a.r.writeFrame(kindData, chunk) == nil
		}
		if i > 0 {
			if werr := a.r.writeFrame(kindData, chunk[:i]); werr != nil {
				return false
			}
		}
		if isDetach {
			return false
		}
		a.fireRemoteAccess()
		chunk = chunk[i+1:]
	}
	return true
}

// scan finds the first watched byte in chunk and says which one it is. A
// negative index means neither is present.
//
// When both are in the chunk the earlier one wins, and a tie goes to detach —
// see AttachWith on why a collision must never leave the session inescapable.
func (a *attachCmd) scan(chunk []byte) (idx int, isDetach bool) {
	d := bytes.IndexByte(chunk, a.opts.Detach)
	if a.opts.RemoteAccess == 0 || a.opts.OnRemoteAccess == nil {
		return d, true
	}
	h := bytes.IndexByte(chunk, a.opts.RemoteAccess)
	if h < 0 || (d >= 0 && d <= h) {
		return d, true
	}
	return h, false
}

// fireRemoteAccess runs the hotkey callback and prints what it returns to the
// terminal the session is attached to. It never fails the attach: the hotkey is
// a client-side convenience, and nothing about it is worth ending the session
// the user is working in.
//
// The callback runs on its own goroutine rather than inline, for two reasons it
// has to survive. It reaches into UI-owned code, and a panic there would
// otherwise unwind through Run — past the deferred term.Restore only by luck,
// and taking the session with it. And it can block: a bound wait means a
// callback that never returns costs the user one pause, not a stdin loop wedged
// forever with no key that still works. Rejected: inline with only a recover,
// which covers the panic but leaves the hang, and a wedged loop is
// indistinguishable from a dead session.
//
// A result that arrives after the timeout is dropped rather than printed. By
// then the user has typed on, and text landing in the middle of their input is
// worse than text that never came — the timeout line already said what
// happened.
//
// Nothing is held while it runs. It writes to the local terminal, not over the
// socket, so the host keeps streaming output through the whole call.
func (a *attachCmd) fireRemoteAccess() {
	fn := a.opts.OnRemoteAccess

	// Buffered, so the goroutine can always finish and be collected even when
	// nobody is left waiting for it.
	res := make(chan string, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				res <- "\r\nwharf: remote access failed\r\n"
			}
		}()
		res <- fn()
	}()

	var text string
	select {
	case text = <-res:
	case <-time.After(remoteAccessTimeout):
		text = "\r\nwharf: remote access is not responding\r\n"
	}
	if text == "" || a.out == nil {
		return
	}
	_, _ = io.WriteString(a.out, text)
}
