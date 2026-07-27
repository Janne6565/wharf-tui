package sshx

import (
	"io"
	"sync"
)

// ringSize is the capacity of every session's scrollback ring: 256 KiB is
// enough to replay a couple of full-screen redraws when the UI re-attaches.
const ringSize = 256 * 1024

// ring is a fixed-capacity circular byte buffer keeping the most recent
// ringSize bytes written to it. It is safe for concurrent Write/Snapshot.
type ring struct {
	mu    sync.Mutex
	data  []byte
	cap   int
	start int // index of the oldest valid byte
	len   int // number of valid bytes (<= cap)
}

func newRing(n int) *ring { return &ring{data: make([]byte, n), cap: n} }

// Write appends p, dropping the oldest bytes once capacity is exceeded. It
// never returns an error and never short-writes, so it is safe as an io.Copy
// destination.
func (r *ring) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	total := len(p)
	if total == 0 {
		return 0, nil
	}
	// A single write larger than the buffer: keep only its tail.
	if total >= r.cap {
		copy(r.data, p[total-r.cap:])
		r.start = 0
		r.len = r.cap
		return total, nil
	}
	// Write in at most two segments (wrap around the physical end).
	writePos := (r.start + r.len) % r.cap
	n1 := copy(r.data[writePos:], p)
	if n1 < total {
		copy(r.data, p[n1:])
	}
	newLen := r.len + total
	if newLen > r.cap {
		// Overwrote r.len+total-cap of the oldest bytes; advance start.
		r.start = (r.start + (newLen - r.cap)) % r.cap
		r.len = r.cap
	} else {
		r.len = newLen
	}
	return total, nil
}

// Snapshot returns a copy of the buffer contents in write order.
func (r *ring) Snapshot() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]byte, r.len)
	tail := r.cap - r.start
	if tail >= r.len {
		copy(out, r.data[r.start:r.start+r.len])
	} else {
		copy(out, r.data[r.start:])
		copy(out[tail:], r.data[:r.len-tail])
	}
	return out
}

// tee fans remote output into the ring (always) and, while a client is
// attached, into a live writer as well. A failing live writer is dropped
// rather than propagated, so a broken terminal never stops the pump that
// keeps the ring recording.
type tee struct {
	ring *ring

	mu   sync.Mutex
	live io.Writer
}

func newTee(r *ring) *tee { return &tee{ring: r} }

// Write records into the ring and mirrors to the live writer under one lock, so
// that goLive can define an exact handover point: every chunk is either in the
// replay it hands out or delivered live afterwards, never both and never
// neither. The lock costs nothing in practice — a single pump goroutine writes.
func (t *tee) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ring.Write(p)
	if t.live != nil {
		if _, err := t.live.Write(p); err != nil {
			t.live = nil // a broken terminal must not stop the ring recording
		}
	}
	return len(p), nil
}

// goLive replays the scrollback to w and installs it as the live writer, both
// under the tee lock. Output arriving meanwhile queues behind the replay rather
// than interleaving with it or slipping through the gap between the two — the
// gap a plain Snapshot-then-setLive leaves open.
func (t *tee) goLive(w io.Writer, replay func([]byte) error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := replay(t.ring.Snapshot()); err != nil {
		return err
	}
	t.live = w
	return nil
}

// unsetLive clears the live writer if it is still w (an attach clearing its
// own writer on return must not clobber a writer a later attach installed).
func (t *tee) unsetLive(w io.Writer) {
	t.mu.Lock()
	if t.live == w {
		t.live = nil
	}
	t.mu.Unlock()
}
