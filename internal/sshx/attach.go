package sshx

import (
	"bytes"
	"io"
	"os"

	"github.com/Janne6565/wharf-tui/internal/detachkey"
	"github.com/Janne6565/wharf-tui/internal/termsig"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/muesli/cancelreader"
	"golang.org/x/term"
)

// Attach returns the tea.ExecCommand that performs the full-screen terminal
// takeover: raw mode, replay of the ring buffer, bidirectional copy, WINCH
// forwarding. Typing detach (the configured key, ctrl+\ by default) returns
// from the takeover — Run returns with the session still alive.
//
// detach is a byte rather than a key name because that is all the attach loop
// sees: the terminal is raw and input is a stream on its way to the remote. A
// zero byte means "unset" and falls back to the default.
func (s *Session) Attach(detach byte) tea.ExecCommand {
	if detach == 0 {
		detach = detachkey.DefaultByte
	}
	return &attachCmd{s: s, detach: detach}
}

// attachCmd implements tea.ExecCommand for a single attach lifetime.
type attachCmd struct {
	s      *Session
	detach byte
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
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
		return a.forward(stdin, s)
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

	return a.forward(cr, s)
}

// forward copies input chunks to the remote stdin, watching for the detach
// byte. It returns nil on detach, EOF, or session death — the session is
// never closed here; SessionEndedMsg tells the UI if the remote is gone.
func (a *attachCmd) forward(r io.Reader, s *Session) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if i := bytes.IndexByte(chunk, a.detach); i >= 0 {
				if i > 0 {
					_, _ = s.stdin.Write(chunk[:i])
				}
				return nil
			}
			if _, werr := s.stdin.Write(chunk); werr != nil {
				return nil
			}
		}
		if err != nil {
			return nil
		}
	}
}
