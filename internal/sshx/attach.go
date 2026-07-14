package sshx

import (
	"bytes"
	"io"
	"os"
	"os/signal"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/muesli/cancelreader"
	"golang.org/x/term"
)

// detachByte is ctrl+\ (0x1C): typing it while attached returns from the
// takeover with the session still alive.
const detachByte = 0x1C

// Attach returns the tea.ExecCommand that performs the full-screen terminal
// takeover: raw mode, replay of the ring buffer, bidirectional copy, WINCH
// forwarding. Typing ctrl+\ (0x1C) detaches — Run returns with the session
// still alive.
func (s *Session) Attach() tea.ExecCommand {
	return &attachCmd{s: s}
}

// attachCmd implements tea.ExecCommand for a single attach lifetime.
type attachCmd struct {
	s      *Session
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

func (a *attachCmd) SetStdin(r io.Reader)  { a.stdin = r }
func (a *attachCmd) SetStdout(w io.Writer) { a.stdout = w }
func (a *attachCmd) SetStderr(w io.Writer) { a.stderr = w }

// Run takes over the terminal until the user detaches (ctrl+\) or the session
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

	// In raw mode ctrl+\ reaches us as a byte; guard against SIGQUIT in case
	// raw mode ever fails to engage.
	signal.Ignore(syscall.SIGQUIT)
	defer signal.Reset(syscall.SIGQUIT)

	stopWindow := a.syncWindow(stdout)
	defer stopWindow()

	// Replay: clear the screen, dump the ring, then jiggle the window so
	// full-screen (curses) apps repaint from a clean slate.
	_, _ = io.WriteString(stdout, "\x1b[2J\x1b[H")
	_, _ = stdout.Write(s.ring.Snapshot())
	s.mu.Lock()
	rows, cols := s.rows, s.cols
	s.mu.Unlock()
	if rows > 1 {
		_ = s.sess.WindowChange(rows-1, cols)
		_ = s.sess.WindowChange(rows, cols)
	}

	// Route remote output to this terminal for the attach lifetime.
	s.tee.setLive(stdout)
	defer s.tee.unsetLive(stdout)

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
	if w, h, err := term.GetSize(fd); err == nil {
		s.mu.Lock()
		s.cols, s.rows = w, h
		s.mu.Unlock()
		_ = s.sess.WindowChange(h, w)
	}

	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-winch:
				if w, h, err := term.GetSize(fd); err == nil {
					s.mu.Lock()
					s.cols, s.rows = w, h
					s.mu.Unlock()
					_ = s.sess.WindowChange(h, w)
				}
			}
		}
	}()
	return func() {
		signal.Stop(winch)
		close(stop)
	}
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
			if i := bytes.IndexByte(chunk, detachByte); i >= 0 {
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
