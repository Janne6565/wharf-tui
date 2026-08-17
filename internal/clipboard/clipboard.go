// Package clipboard copies text into the clipboard of the terminal the TUI is
// attached to, using OSC 52.
//
// OSC 52 is the only mechanism that works over SSH: it asks the *terminal
// emulator* on the user's desk to hold the text, so it needs no pbcopy, no
// xclip, no X11 forwarding and no local clipboard daemon. The price is that
// support is not universal — Terminal.app on macOS silently drops the sequence
// — so callers must treat a successful write as "the request was sent", keep
// showing the text as selectable, and never claim a copy that a nil error does
// not actually prove.
package clipboard

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aymanbagabas/go-osc52/v2"
	"golang.org/x/term"
)

// ErrNoTerminal reports that nothing was written because the output is not a
// terminal.
//
// This is a refusal, not a failure: the sequence carries a base64-encoded
// remote-access token, and `wharf 2>debug.log` — or script(1), a systemd unit,
// tmux logging, a CI harness — would turn a redirected stderr into that token
// sitting in a file. The feature's hard rule is that the token never touches
// disk, so when the far end is not a terminal the only correct move is to
// write nothing at all. It is a distinct sentinel from a write failure so the
// UI can tell "there is no clipboard here" apart from "the clipboard write
// broke"; both mean the same thing to the user (not copied), and neither may
// be reported as success.
var ErrNoTerminal = errors.New("clipboard: output is not a terminal")

// out is the seam the tests write through. It defaults to stderr rather than
// stdout because the TUI's stdout may be piped or redirected while stderr is
// still the terminal — an escape sequence that lands in a pipe reaches nobody's
// clipboard and corrupts the piped data.
var out io.Writer = os.Stderr

// isTerminal is the second half of that seam. It is a variable, and takes the
// writer rather than reading os.Stderr directly, so a test can exercise the
// terminal path against a buffer without owning a real tty — otherwise the
// only testable path would be the refusal, and the sequence itself would go
// unverified in CI.
var isTerminal = writerIsTerminal

// writerIsTerminal reports whether w is an actual terminal. Anything that is
// not an *os.File — a buffer, a pipe wrapper, a log multiplexer — cannot be
// one, and a plain file on disk is exactly the case this guards against.
func writerIsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// Copy writes s to the terminal's clipboard using OSC 52.
//
// The sequence is built by github.com/aymanbagabas/go-osc52 rather than
// hand-rolled, because the raw `ESC ] 52 ; c ; <base64> BEL` has to be wrapped
// again when a multiplexer sits in between — tmux needs its passthrough
// envelope, GNU screen needs a DCS split — and getting that wrapping subtly
// wrong is the classic way this feature "works on my machine" and silently
// fails everywhere else.
//
// It returns ErrNoTerminal, having written nothing, when the output is
// redirected; see that error for why. Any other non-nil error means the bytes
// did not reach the terminal at all. A nil error does not — and cannot — mean
// the terminal honoured them; there is no reply to a set request. Callers must
// not report success in stronger terms than that.
func Copy(s string) error {
	if !isTerminal(out) {
		return ErrNoTerminal
	}
	seq := osc52.New(s).Mode(mode())
	if _, err := seq.WriteTo(out); err != nil {
		return fmt.Errorf("write OSC 52 clipboard sequence: %w", err)
	}
	return nil
}

// mode picks the passthrough wrapping the sequence needs to survive the
// multiplexer, if any, between this process and the real terminal. The
// environment is the only signal available: a multiplexer does not announce
// itself over the tty. $TMUX is set inside a tmux pane; screen only marks
// itself in $TERM.
func mode() osc52.Mode {
	if os.Getenv("TMUX") != "" {
		return osc52.TmuxMode
	}
	if strings.HasPrefix(os.Getenv("TERM"), "screen") {
		return osc52.ScreenMode
	}
	return osc52.DefaultMode
}
