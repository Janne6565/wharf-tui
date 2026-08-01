//go:build !windows

package sessd

import (
	"bytes"
	"io"
	"os"

	"github.com/Janne6565/wharf-tui/internal/termsig"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/muesli/cancelreader"
	"golang.org/x/term"
)

// detachByte is ctrl+\ (0x1C), the same key the in-process attach uses: typing
// it returns from the takeover with the remote session still running.
const detachByte = 0x1C

// Attach returns the tea.ExecCommand that hands this terminal to the remote
// session. It is the socket-backed twin of sshx.Session.Attach: raw mode,
// replay, bidirectional copy and WINCH forwarding, except the bytes travel over
// the unix socket to the child process that owns the SSH connection.
func (r *Remote) Attach() tea.ExecCommand { return &attachCmd{r: r} }

type attachCmd struct {
	r      *Remote
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

func (a *attachCmd) SetStdin(rd io.Reader) { a.stdin = rd }
func (a *attachCmd) SetStdout(w io.Writer) { a.stdout = w }
func (a *attachCmd) SetStderr(w io.Writer) { a.stderr = w }

// Run streams until the user detaches (ctrl+\) or the session dies. It always
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

	if f, ok := stdout.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fd := int(f.Fd())
		if st, err := term.MakeRaw(fd); err == nil {
			defer func() { _ = term.Restore(fd, st) }()
		}
	}

	// In raw mode ctrl+\ arrives as a byte; guard against the quit signal in
	// case raw mode ever fails to engage.
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

// forward copies input to the host, watching for the detach byte. It returns
// nil on detach, EOF or session death — never an error, because the UI
// distinguishes the two through SessionEndedMsg, exactly as in-process attach
// does.
func (a *attachCmd) forward(rd io.Reader) error {
	r := a.r
	buf := make([]byte, 32*1024)
	for {
		n, err := rd.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if i := bytes.IndexByte(chunk, detachByte); i >= 0 {
				if i > 0 {
					_ = r.writeFrame(kindData, chunk[:i])
				}
				return nil
			}
			if werr := r.writeFrame(kindData, chunk); werr != nil {
				return nil
			}
		}
		if err != nil {
			return nil
		}
	}
}
