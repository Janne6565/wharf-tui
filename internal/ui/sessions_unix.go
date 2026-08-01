//go:build !windows

package ui

// sessionsSurviveQuit reports whether a session outlives the wharf that dialed
// it. On unix each session runs in its own detached child process and a later
// run adopts it; on Windows sessions run in this process and end with it (see
// the internal/sessd package doc).
//
// It exists so the copy the user reads is true on the platform they are on —
// promising a session will still be there after a quit, and then killing it, is
// worse than not offering the feature.
const sessionsSurviveQuit = true

// quitSessionNotice describes what quitting does to n live sessions.
func quitSessionNotice(n int) string {
	return itoa(n) + " live session(s) keep running — reattach next time."
}

// attachSurvivalNotice is the line on the attach modal explaining how far a
// detached session's life extends.
const attachSurvivalNotice = "Sessions survive quitting wharf — reattach from a later run."
