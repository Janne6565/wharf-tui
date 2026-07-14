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

func (t *tee) Write(p []byte) (int, error) {
	t.ring.Write(p)
	t.mu.Lock()
	w := t.live
	t.mu.Unlock()
	if w != nil {
		if _, err := w.Write(p); err != nil {
			// Drop this writer but only if it is still the current one, so we
			// don't clobber a concurrent re-attach.
			t.mu.Lock()
			if t.live == w {
				t.live = nil
			}
			t.mu.Unlock()
		}
	}
	return len(p), nil
}

func (t *tee) setLive(w io.Writer) {
	t.mu.Lock()
	t.live = w
	t.mu.Unlock()
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
