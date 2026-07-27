package sshx

import (
	"bytes"
	"strconv"
	"sync"
	"testing"
	"time"
)

// syncBuf is an io.Writer safe to hand to the tee while a pump is running.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// Attaching while the remote is producing output must lose nothing and repeat
// nothing: replay and handover happen together, so every chunk is either in the
// scrollback the client replays or delivered live after it.
func TestGoLiveHandsOverWithoutLosingOutput(t *testing.T) {
	// The pump keeps producing *during* the replay, which is exactly when a
	// snapshot-then-install handover drops output. The sleeps make that window
	// wide enough to be a certainty rather than a race the test might miss.
	const chunks = 200
	tee := newTee(newRing(ringSize))

	var want bytes.Buffer
	for i := 0; i < chunks; i++ {
		want.WriteString(strconv.Itoa(i) + ";")
	}
	if want.Len() > ringSize {
		t.Fatalf("test writes %d bytes, more than the ring holds", want.Len())
	}

	// A pump writing continuously, exactly as a live session does.
	pumped := make(chan struct{})
	go func() {
		defer close(pumped)
		for i := 0; i < chunks; i++ {
			_, _ = tee.Write([]byte(strconv.Itoa(i) + ";"))
			time.Sleep(time.Millisecond)
		}
	}()

	// Attach in the middle of the stream, with a replay slow enough that the
	// pump is guaranteed to produce while it runs.
	time.Sleep(50 * time.Millisecond)
	got := &syncBuf{}
	var replayed []byte
	if err := tee.goLive(got, func(snap []byte) error {
		replayed = append([]byte(nil), snap...)
		time.Sleep(50 * time.Millisecond)
		return nil
	}); err != nil {
		t.Fatalf("goLive: %v", err)
	}
	<-pumped
	tee.unsetLive(got)

	stream := string(replayed) + got.String()
	if stream != want.String() {
		// Report the divergence point rather than dumping 10 KB of digits.
		for i := 0; i < len(stream) && i < want.Len(); i++ {
			if stream[i] != want.String()[i] {
				lo := i - 40
				if lo < 0 {
					lo = 0
				}
				t.Fatalf("stream diverges at byte %d\n got: %q\nwant: %q",
					i, stream[lo:min(len(stream), i+40)], want.String()[lo:min(want.Len(), i+40)])
			}
		}
		t.Fatalf("stream length %d, want %d (output was lost or repeated at the handover)",
			len(stream), want.Len())
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
