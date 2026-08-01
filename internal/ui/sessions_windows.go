package ui

// See sessions_unix.go. On Windows sessions run inside wharf itself, so they
// end when it does.
const sessionsSurviveQuit = false

func quitSessionNotice(n int) string {
	return itoa(n) + " live session(s) will be closed."
}

const attachSurvivalNotice = "Detaching keeps the session running while wharf is open; quitting closes it."
