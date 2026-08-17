//go:build !windows

package sessd

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// The remote-access hotkey under test. ctrl+] is the default binding; ctrl+\
// (0x1C) stays the detach byte throughout this file.
const (
	hotkeyByte = 0x1D
	detachByte = 0x1C
)

// scriptedReader hands the attach loop exactly the chunks a test names, one per
// Read, and then blocks until the test releases it.
//
// The chunk boundaries are the whole point of these tests: a pipe splits where
// the kernel feels like it, so a test written on os.Pipe would assert on the
// split it happened to get rather than the one it means to cover — and a hotkey
// sitting in the middle of one full 32 KiB read is exactly what a pipe is least
// likely to reproduce on demand. Each chunk must fit a single read (32 KiB);
// anything longer would be silently truncated here rather than in the code
// under test.
type scriptedReader struct {
	chunks chan []byte
	done   chan struct{}
}

func newScriptedReader(chunks ...[]byte) *scriptedReader {
	s := &scriptedReader{chunks: make(chan []byte, len(chunks)+4), done: make(chan struct{})}
	for _, c := range chunks {
		s.chunks <- c
	}
	return s
}

// send queues one more chunk, which becomes one more Read.
func (s *scriptedReader) send(b []byte) { s.chunks <- b }

// release makes the next Read report EOF, ending the attach.
func (s *scriptedReader) release() { close(s.done) }

func (s *scriptedReader) Read(p []byte) (int, error) {
	select {
	case c := <-s.chunks:
		return copy(p, c), nil
	case <-s.done:
		return 0, io.EOF
	}
}

// hotkeyRecorder is the callback internal/ui will supply, reduced to what these
// tests assert on: how often it fired and what it printed. block and panics
// stand in for a callback that misbehaves.
type hotkeyRecorder struct {
	mu     sync.Mutex
	calls  int
	text   string
	block  chan struct{}
	panics bool
}

func (h *hotkeyRecorder) fn() string {
	h.mu.Lock()
	h.calls++
	block, panics, text := h.block, h.panics, h.text
	h.mu.Unlock()
	if block != nil {
		<-block
	}
	if panics {
		panic("the callback blew up")
	}
	return text
}

func (h *hotkeyRecorder) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}

// hotkeyFixture dials a session in a real child process and returns it
// alongside the buffer recording what the *server* received. Asserting on that
// buffer, rather than on the local terminal, is what proves a byte was withheld:
// the client cannot tell a byte it never sent from one nobody echoed back. It
// also means the assertion covers the whole path — scanner, socket frames,
// child, ssh — not just the scanner.
func hotkeyFixture(t *testing.T) (*Remote, *safeBuffer) {
	t.Helper()
	t.Setenv("SSH_AUTH_SOCK", "")
	ts := startServer(t)
	sockDir, knownHosts := tempDirs(t)
	pool, _ := newPool(t, sockDir, knownHosts)

	r, err := pool.Dial(context.Background(), ts.spec(), 80, 24)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, ts.recv
}

// startAttach runs the attach in the background and returns a func that waits
// for it to come back.
func startAttach(t *testing.T, cmd interface{ Run() error }) func() {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	return func() {
		t.Helper()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("attach Run returned error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("attach Run did not return")
		}
	}
}

func TestTheRemoteAccessHotkeyFiresAndItsTextReachesTheLocalTerminal(t *testing.T) {
	r, recv := hotkeyFixture(t)
	hk := &hotkeyRecorder{text: "\r\nwharf: remote access ON for web1\r\n"}

	in := newScriptedReader([]byte{hotkeyByte})
	out := &safeBuffer{}
	cmd := r.AttachWith(AttachOptions{RemoteAccess: hotkeyByte, OnRemoteAccess: hk.fn})
	cmd.SetStdin(in)
	cmd.SetStdout(out)
	wait := startAttach(t, cmd)

	waitFor(t, "the callback to fire", func() bool { return hk.count() == 1 })
	waitFor(t, "its text on the local terminal", func() bool {
		return strings.Contains(out.String(), "remote access ON for web1")
	})

	in.release()
	wait()

	if strings.ContainsRune(recv.String(), hotkeyByte) {
		t.Fatal("the hotkey byte must never reach the remote")
	}
	if !r.Alive() {
		t.Fatal("the hotkey must not end the session")
	}
}

// The case this breaks on if it breaks: one full 32 KiB read carrying a run of
// bytes, the hotkey, and another run. Both runs belong to the remote, in order;
// the byte between them does not.
func TestASingleLargeReadSplitByTheHotkeyReachesTheRemoteIntact(t *testing.T) {
	r, recv := hotkeyFixture(t)
	hk := &hotkeyRecorder{text: "\r\nON\r\n"}

	before := bytes.Repeat([]byte("a"), 16*1024)
	after := bytes.Repeat([]byte("b"), 16*1024-1)
	chunk := make([]byte, 0, 32*1024)
	chunk = append(chunk, before...)
	chunk = append(chunk, hotkeyByte)
	chunk = append(chunk, after...)
	if len(chunk) != 32*1024 {
		t.Fatalf("the chunk must be exactly one full read, got %d", len(chunk))
	}

	in := newScriptedReader(chunk)
	cmd := r.AttachWith(AttachOptions{RemoteAccess: hotkeyByte, OnRemoteAccess: hk.fn})
	cmd.SetStdin(in)
	cmd.SetStdout(&safeBuffer{})
	wait := startAttach(t, cmd)

	want := string(before) + string(after)
	waitFor(t, "both runs to reach the remote, in order", func() bool {
		return recv.String() == want
	})
	if hk.count() != 1 {
		t.Fatalf("the callback should have fired once, got %d", hk.count())
	}

	in.release()
	wait()
}

func TestTwoHotkeysInOneChunkFireTwiceAndNeitherByteIsForwarded(t *testing.T) {
	r, recv := hotkeyFixture(t)
	hk := &hotkeyRecorder{text: "\r\ntoggled\r\n"}

	in := newScriptedReader([]byte{'o', 'n', 'e', hotkeyByte, 't', 'w', 'o', hotkeyByte, 't', 'h', 'r', 'e', 'e'})
	out := &safeBuffer{}
	cmd := r.AttachWith(AttachOptions{RemoteAccess: hotkeyByte, OnRemoteAccess: hk.fn})
	cmd.SetStdin(in)
	cmd.SetStdout(out)
	wait := startAttach(t, cmd)

	waitFor(t, "all three runs to reach the remote", func() bool {
		return recv.String() == "onetwothree"
	})
	if hk.count() != 2 {
		t.Fatalf("two hotkeys in one chunk should fire twice, got %d", hk.count())
	}
	waitFor(t, "both callbacks to print", func() bool {
		return strings.Count(out.String(), "toggled") == 2
	})

	in.release()
	wait()
}

func TestAHotkeyAtEitherEndOfAChunkIsWithheldAndTheSessionContinues(t *testing.T) {
	r, recv := hotkeyFixture(t)
	hk := &hotkeyRecorder{text: "\r\ntoggled\r\n"}

	// First byte of one read, last byte of the next.
	in := newScriptedReader(
		[]byte{hotkeyByte, 'l', 'e', 'a', 'd'},
		[]byte{'t', 'a', 'i', 'l', hotkeyByte},
	)
	cmd := r.AttachWith(AttachOptions{RemoteAccess: hotkeyByte, OnRemoteAccess: hk.fn})
	cmd.SetStdin(in)
	cmd.SetStdout(&safeBuffer{})
	wait := startAttach(t, cmd)

	waitFor(t, "both runs to reach the remote", func() bool {
		return recv.String() == "leadtail"
	})
	waitFor(t, "both callbacks to fire", func() bool { return hk.count() == 2 })

	// The session is still usable afterwards: more input, more output.
	in.send([]byte("still here"))
	waitFor(t, "input typed after the hotkey to reach the remote", func() bool {
		return recv.String() == "leadtailstill here"
	})

	in.release()
	wait()
	if !r.Alive() {
		t.Fatal("the session must survive the hotkey")
	}
}

// With the hotkey disabled the byte is nothing special: it belongs to the
// remote like any other keystroke, exactly as before the key existed.
func TestADisabledRemoteAccessKeyIsForwardedLikeAnyOtherByte(t *testing.T) {
	t.Run("zero byte", func(t *testing.T) {
		r, recv := hotkeyFixture(t)
		hk := &hotkeyRecorder{text: "\r\nnever\r\n"}

		in := newScriptedReader([]byte{'a', hotkeyByte, 'b'})
		out := &safeBuffer{}
		cmd := r.AttachWith(AttachOptions{RemoteAccess: 0, OnRemoteAccess: hk.fn})
		cmd.SetStdin(in)
		cmd.SetStdout(out)
		wait := startAttach(t, cmd)

		waitFor(t, "the whole chunk to reach the remote", func() bool {
			return recv.String() == string([]byte{'a', hotkeyByte, 'b'})
		})
		if hk.count() != 0 {
			t.Fatalf("a zero RemoteAccess byte must never call the callback, got %d", hk.count())
		}
		if strings.Contains(out.String(), "never") {
			t.Fatal("a disabled hotkey must print nothing locally")
		}

		in.release()
		wait()
	})

	t.Run("nil callback", func(t *testing.T) {
		r, recv := hotkeyFixture(t)

		in := newScriptedReader([]byte{'a', hotkeyByte, 'b'})
		cmd := r.AttachWith(AttachOptions{RemoteAccess: hotkeyByte})
		cmd.SetStdin(in)
		cmd.SetStdout(&safeBuffer{})
		wait := startAttach(t, cmd)

		waitFor(t, "the whole chunk to reach the remote", func() bool {
			return recv.String() == string([]byte{'a', hotkeyByte, 'b'})
		})

		in.release()
		wait()
	})
}

// Detach keeps its meaning: it ends the takeover even when a hotkey precedes it
// in the same read, and everything before it still reaches the remote.
func TestDetachStillEndsTheTakeoverWhenBothBytesShareAChunk(t *testing.T) {
	r, recv := hotkeyFixture(t)
	hk := &hotkeyRecorder{text: "\r\ntoggled\r\n"}

	in := newScriptedReader([]byte{'a', 'b', hotkeyByte, 'c', 'd', detachByte, 'e', 'f'})
	cmd := r.AttachWith(AttachOptions{RemoteAccess: hotkeyByte, OnRemoteAccess: hk.fn})
	cmd.SetStdin(in)
	cmd.SetStdout(&safeBuffer{})
	wait := startAttach(t, cmd)

	wait() // the detach byte returns from the takeover on its own

	waitFor(t, "the bytes before detach to reach the remote", func() bool {
		return recv.String() == "abcd"
	})
	if hk.count() != 1 {
		t.Fatalf("the hotkey before the detach byte should still have fired, got %d", hk.count())
	}
	if strings.Contains(recv.String(), "ef") {
		t.Fatal("bytes after the detach byte must not be forwarded")
	}
	if !r.Alive() {
		t.Fatal("detaching must not end the session")
	}
}

// Defence in depth: internal/detachkey refuses to bind both keys to one byte,
// but if that validation is ever bypassed the session must still be one you can
// leave.
func TestWhenBothKeysAreTheSameByteDetachWins(t *testing.T) {
	r, _ := hotkeyFixture(t)
	hk := &hotkeyRecorder{text: "\r\ntoggled\r\n"}

	in := newScriptedReader([]byte{detachByte})
	cmd := r.AttachWith(AttachOptions{Detach: detachByte, RemoteAccess: detachByte, OnRemoteAccess: hk.fn})
	cmd.SetStdin(in)
	cmd.SetStdout(&safeBuffer{})
	wait := startAttach(t, cmd)
	wait()

	if hk.count() != 0 {
		t.Fatalf("a colliding byte must detach, not toggle; the callback fired %d times", hk.count())
	}
	if !r.Alive() {
		t.Fatal("detaching must not end the session")
	}
}

// A callback that panics is the UI's bug, not the session's: the takeover keeps
// running, the surrounding bytes still travel, and the user is told.
func TestAPanickingCallbackDoesNotKillTheAttach(t *testing.T) {
	r, recv := hotkeyFixture(t)
	hk := &hotkeyRecorder{panics: true}

	in := newScriptedReader([]byte{'a', hotkeyByte, 'b'})
	out := &safeBuffer{}
	cmd := r.AttachWith(AttachOptions{RemoteAccess: hotkeyByte, OnRemoteAccess: hk.fn})
	cmd.SetStdin(in)
	cmd.SetStdout(out)
	wait := startAttach(t, cmd)

	waitFor(t, "the surrounding bytes to reach the remote anyway", func() bool {
		return recv.String() == "ab"
	})
	waitFor(t, "the failure to be reported locally", func() bool {
		return strings.Contains(out.String(), "remote access failed")
	})

	in.release()
	wait()
	if !r.Alive() {
		t.Fatal("a panicking callback must not take the session down")
	}
}

// A callback that blocks does not freeze what was already typed: the bytes
// before the hotkey are on their way to the remote before it is ever called,
// and the session is still alive while it hangs. (That it eventually gives up
// is the remoteAccessTimeout constant's job; waiting it out here would cost
// every run ten seconds.)
func TestABlockedCallbackDoesNotWedgeTheSession(t *testing.T) {
	r, recv := hotkeyFixture(t)
	block := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(block) })
	t.Cleanup(unblock)
	hk := &hotkeyRecorder{block: block}

	in := newScriptedReader([]byte{'a', hotkeyByte, 'b'})
	cmd := r.AttachWith(AttachOptions{RemoteAccess: hotkeyByte, OnRemoteAccess: hk.fn})
	cmd.SetStdin(in)
	cmd.SetStdout(&safeBuffer{})
	wait := startAttach(t, cmd)

	waitFor(t, "the bytes before the hotkey to reach the remote", func() bool {
		return recv.String() == "a"
	})
	if !r.Alive() {
		t.Fatal("a blocked callback must not take the session down")
	}

	// Once it returns, the rest of the chunk goes on as if nothing happened.
	unblock()
	waitFor(t, "the rest of the chunk to follow", func() bool {
		return recv.String() == "ab"
	})

	in.release()
	wait()
}
