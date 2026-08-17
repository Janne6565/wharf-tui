package clipboard

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// capture redirects the package's output writer at a buffer for the duration
// of one test, and fakes the tty predicate so the terminal path is reachable
// without a real tty — a buffer is never a terminal, and CI has no tty at all,
// so without the fake only the refusal path could be tested.
//
// Every test must go through capture: one that let Copy reach the real stderr
// would spray an escape sequence at the developer's terminal and quietly
// overwrite their clipboard while `go test` ran.
func capture(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	setOutput(t, &buf, true)
	return &buf
}

// setOutput points the package at w, declares whether w counts as a terminal,
// and restores both seams afterwards.
func setOutput(t *testing.T, w io.Writer, tty bool) {
	t.Helper()
	prevOut, prevIsTerminal := out, isTerminal
	out, isTerminal = w, func(io.Writer) bool { return tty }
	t.Cleanup(func() { out, isTerminal = prevOut, prevIsTerminal })
}

func TestCopyEmitsTheOSC52IntroducerAndTheBase64Payload(t *testing.T) {
	t.Setenv("TMUX", "")
	t.Setenv("TERM", "xterm-256color")
	buf := capture(t)

	const payload = "wharf --remote 0123456789abcdef -- echo hi"
	if err := Copy(payload); err != nil {
		t.Fatalf("Copy() = %v, want nil", err)
	}

	got := buf.String()
	if !strings.Contains(got, "\x1b]52;c;") {
		t.Errorf("output %q lacks the OSC 52 introducer", got)
	}
	enc := base64.StdEncoding.EncodeToString([]byte(payload))
	if !strings.Contains(got, enc) {
		t.Errorf("output %q lacks the base64 payload %q", got, enc)
	}
}

func TestCopyWrapsTheSequenceForTmux(t *testing.T) {
	// Without the passthrough envelope tmux eats the sequence, which is the
	// failure mode the library dependency exists to prevent.
	t.Setenv("TMUX", "/private/tmp/tmux-501/default,1234,0")
	buf := capture(t)

	if err := Copy("hello"); err != nil {
		t.Fatalf("Copy() = %v, want nil", err)
	}
	if got := buf.String(); !strings.HasPrefix(got, "\x1bPtmux;\x1b") {
		t.Errorf("output %q is not wrapped in the tmux passthrough envelope", got)
	}
}

func TestCopyWrapsTheSequenceForScreen(t *testing.T) {
	t.Setenv("TMUX", "")
	t.Setenv("TERM", "screen.xterm-256color")
	buf := capture(t)

	if err := Copy("hello"); err != nil {
		t.Fatalf("Copy() = %v, want nil", err)
	}
	if got := buf.String(); !strings.HasPrefix(got, "\x1bP") {
		t.Errorf("output %q is not wrapped in a screen DCS sequence", got)
	}
}

func TestCopyWritesNothingWhenTheOutputIsNotATerminal(t *testing.T) {
	// `wharf 2>debug.log` must not deposit the base64 of a remote-access
	// token in debug.log. Refusing is the whole point; a partial write would
	// still be a leak.
	var buf bytes.Buffer
	setOutput(t, &buf, false)

	err := Copy("wharf --remote 0123456789abcdef -- echo hi")
	if !errors.Is(err, ErrNoTerminal) {
		t.Fatalf("Copy() = %v, want ErrNoTerminal", err)
	}
	if buf.Len() != 0 {
		t.Errorf("wrote %q to a non-terminal, want nothing", buf.String())
	}
}

// failingWriter stands in for a terminal whose fd has been closed underneath us.
type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestCopyReportsAFailedWriteSoTheUICanNotClaimSuccess(t *testing.T) {
	boom := errors.New("stderr is closed")
	setOutput(t, failingWriter{err: boom}, true)

	err := Copy("hello")
	if err == nil {
		t.Fatal("Copy() = nil, want an error when the write fails")
	}
	if !errors.Is(err, boom) {
		t.Errorf("Copy() = %v, want it to wrap %v", err, boom)
	}
	// A broken write is not the same condition as a redirected stream, and
	// the UI is entitled to tell them apart.
	if errors.Is(err, ErrNoTerminal) {
		t.Errorf("Copy() = %v, want it distinguishable from ErrNoTerminal", err)
	}
}

func TestWriterIsTerminalRejectsAnythingThatIsNotAFile(t *testing.T) {
	// The real predicate, unfaked: a buffer or a pipe can never be a tty, and
	// a file on disk is the leak this guards against.
	if writerIsTerminal(&bytes.Buffer{}) {
		t.Error("writerIsTerminal(buffer) = true, want false")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	if writerIsTerminal(w) {
		t.Error("writerIsTerminal(pipe) = true, want false")
	}
}
