// Package termsig isolates the two terminal signals a session takeover needs,
// because neither exists on Windows.
//
// Both attach paths — sshx's in-process one and sessd's socket-backed one —
// want the same two things while they hold the terminal: ignore the quit signal
// (ctrl+\ is the detach key and must arrive as a byte, not as a signal), and
// learn when the window is resized so the remote pty can be told. On unix both
// are signals; on Windows there is no SIGQUIT to ignore and no SIGWINCH to
// listen for, so the resize watcher polls instead.
//
// Keeping the split here rather than in each attach.go means there is exactly
// one place per platform to look at, and the attach logic itself stays
// platform-neutral.
package termsig

// IgnoreQuit suppresses the terminal's quit signal until the returned function
// is called. On Windows it does nothing and returns a no-op: there is no such
// signal, and ctrl+\ reaches the reader as byte 0x1C.
//
// It is a guard, not the mechanism: raw mode already delivers ctrl+\ as a byte.
// This only matters if raw mode failed to engage.
func IgnoreQuit() (restore func()) { return ignoreQuit() }

// WatchResize calls onResize with the terminal's new size whenever fd changes
// size, until the returned function is called. The initial size is not
// reported — callers that need it read it themselves before starting the watch,
// which is also what makes the unix implementation a pure signal handler.
//
// onResize runs on WatchResize's own goroutine and must not block.
func WatchResize(fd int, onResize func(cols, rows int)) (stop func()) {
	return watchResize(fd, onResize)
}
