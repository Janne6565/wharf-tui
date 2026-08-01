package termsig

import (
	"time"

	"golang.org/x/term"
)

// resizePoll is how often the Windows watcher checks for a size change.
// Windows has no SIGWINCH, and the console API's resize events are only
// delivered through a console input handle that the attach path has already
// handed to the remote shell — so polling is what is left.
//
// 200ms is below what reads as lag when dragging a window edge, and a GetSize
// call is a single syscall against a handle we already hold.
const resizePoll = 200 * time.Millisecond

// There is no SIGQUIT on Windows: ctrl+\ is not a signal-generating key there,
// so it always arrives as byte 0x1C and needs no guard.
func ignoreQuit() func() { return func() {} }

func watchResize(fd int, onResize func(cols, rows int)) func() {
	// Baseline, so the first tick reports a change rather than the current
	// size — matching the unix behaviour of only firing on an actual resize.
	lastCols, lastRows, err := term.GetSize(fd)
	if err != nil {
		return func() {}
	}

	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(resizePoll)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				cols, rows, err := term.GetSize(fd)
				if err != nil || (cols == lastCols && rows == lastRows) {
					continue
				}
				lastCols, lastRows = cols, rows
				onResize(cols, rows)
			}
		}
	}()

	return func() { close(stop) }
}
