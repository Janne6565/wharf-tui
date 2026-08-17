package sshx

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

// AttachOptions is everything the attach loop has to know about the keys it
// watches. It is a struct rather than more parameters because the set is going
// to keep growing — the takeover is the only place a keystroke can be seen
// while the Bubble Tea program is suspended, so every in-session hotkey wharf
// ever grows lands here.
type AttachOptions struct {
	// Detach ends the takeover. Zero falls back to the default (ctrl+\).
	Detach byte

	// RemoteAccess toggles the remote-access grant without leaving the session.
	// Zero disables the hotkey, as does a nil OnRemoteAccess: the byte is then
	// ordinary input on its way to the remote, exactly as before this existed.
	RemoteAccess byte

	// OnRemoteAccess is called when RemoteAccess is typed, and returns the text
	// to print on the local terminal. The terminal is raw, so the text has to
	// use \r\n itself; the attach loop prints it verbatim and adds nothing.
	OnRemoteAccess func() string
}

// remoteAccessTimeout bounds how long the stdin loop waits for OnRemoteAccess
// before giving up on it. The callback mints a unix socket, so it can block for
// a moment; ten seconds is far longer than that can honestly take, and past it
// the user is better served by a session that keeps forwarding keys than by one
// that looks hung with no way out.
const remoteAccessTimeout = 10 * time.Second

// Attach returns the tea.ExecCommand that performs the full-screen terminal
// takeover: raw mode, replay of the ring buffer, bidirectional copy, WINCH
// forwarding. Typing detach (the configured key, ctrl+\ by default) returns
// from the takeover — Run returns with the session still alive.
//
// detach is a byte rather than a key name because that is all the attach loop
// sees: the terminal is raw and input is a stream on its way to the remote. A
// zero byte means "unset" and falls back to the default.
//
// It is the no-hotkeys shorthand for AttachWith, kept because most callers
// (and every test that predates the remote-access key) want nothing else.
func (s *Session) Attach(detach byte) tea.ExecCommand {
	return s.AttachWith(AttachOptions{Detach: detach})
}

// AttachWith is Attach with the full option set. See AttachOptions.
func (s *Session) AttachWith(opts AttachOptions) tea.ExecCommand {
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
	return &attachCmd{s: s, opts: opts}
}

// attachCmd implements tea.ExecCommand for a single attach lifetime.
type attachCmd struct {
	s      *Session
	opts   AttachOptions
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer

	// out is stdout resolved once by Run: the terminal the session is attached
	// to, and therefore where hotkey feedback has to be written.
	out io.Writer
}

func (a *attachCmd) SetStdin(r io.Reader)  { a.stdin = r }
func (a *attachCmd) SetStdout(w io.Writer) { a.stdout = w }
func (a *attachCmd) SetStderr(w io.Writer) { a.stderr = w }

// Run takes over the terminal until the user detaches or the session
// dies. It always leaves the terminal restored and the session's live writer
// cleared on return.
func (a *attachCmd) Run() error {
	s := a.s

	stdin := a.stdin
	if stdin == nil {
		stdin = os.Stdin
	}
	stdout := a.stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	a.out = stdout

	// Raw mode only when stdout is a real terminal (skipped under tests).
	if f, ok := stdout.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fd := int(f.Fd())
		if st, err := term.MakeRaw(fd); err == nil {
			defer func() { _ = term.Restore(fd, st) }()
		}
	}

	// In raw mode ctrl+\ reaches us as a byte; guard against the quit signal in
	// case raw mode ever fails to engage. This holds whether or not ctrl+\ is
	// still the detach key: unbound, it belongs to the remote as a byte, not to
	// us as a signal.
	defer termsig.IgnoreQuit()()

	stopWindow := a.syncWindow(stdout)
	defer stopWindow()

	// Replay: clear the screen, dump the ring, then jiggle the window so
	// full-screen (curses) apps repaint from a clean slate. Replay and handover
	// are one step: anything the remote emits meanwhile lands after the replay
	// instead of being dropped in the gap between them.
	_, _ = io.WriteString(stdout, "\x1b[2J\x1b[H")
	_ = s.tee.goLive(stdout, func(snap []byte) error {
		_, _ = stdout.Write(snap)
		return nil
	})
	defer s.tee.unsetLive(stdout)
	s.mu.Lock()
	rows, cols := s.rows, s.cols
	s.mu.Unlock()
	if rows > 1 {
		_ = s.sess.WindowChange(rows-1, cols)
		_ = s.sess.WindowChange(rows, cols)
	}

	return a.stdinLoop(stdin)
}

// syncWindow reports the current terminal size to the remote and keeps it in
// sync via SIGWINCH for the attach lifetime. It returns a cleanup func the
// caller must defer (stops the handler and the watcher goroutine). It is a
// no-op when stdout is not a real terminal (tests).
func (a *attachCmd) syncWindow(stdout io.Writer) func() {
	f, ok := stdout.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return func() {}
	}
	s := a.s
	fd := int(f.Fd())

	resize := func(w, h int) {
		s.mu.Lock()
		s.cols, s.rows = w, h
		s.mu.Unlock()
		_ = s.sess.WindowChange(h, w)
	}

	// The initial size is pushed here rather than by the watcher, which only
	// reports changes.
	if w, h, err := term.GetSize(fd); err == nil {
		resize(w, h)
	}
	return termsig.WatchResize(fd, resize)
}

// stdinLoop forwards local input to the remote until detach or session death.
func (a *attachCmd) stdinLoop(stdin io.Reader) error {
	s := a.s

	cr, err := cancelreader.NewReader(stdin)
	if err != nil {
		// Reader can't be canceled (e.g. a plain in-memory reader); forward
		// directly. It still terminates on EOF or a detach byte.
		return a.forward(stdin)
	}
	defer cr.Cancel()

	// Cancel the blocked read when the session dies; stop the watcher when we
	// return (detach) so it doesn't leak until the session ends.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-s.done:
			cr.Cancel()
		case <-stop:
		}
	}()

	return a.forward(cr)
}

// forward copies input chunks to the remote stdin, watching for the bytes
// dispatch acts on. It returns nil on detach, EOF, or session death — the
// session is never closed here; SessionEndedMsg tells the UI if the remote is
// gone.
func (a *attachCmd) forward(r io.Reader) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
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
func (a *attachCmd) dispatch(chunk []byte) bool {
	for len(chunk) > 0 {
		i, isDetach := a.scan(chunk)
		if i < 0 {
			_, werr := a.s.stdin.Write(chunk)
			return werr == nil
		}
		if i > 0 {
			if _, werr := a.s.stdin.Write(chunk[:i]); werr != nil {
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
