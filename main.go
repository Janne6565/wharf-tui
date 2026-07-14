// Command wharf is a terminal-based SSH client with a keyboard-driven TUI.
//
// Wharf is local-first: hosts, keys and sessions work with no account, backed by
// a local encrypted vault. Signing in adds cross-machine sync and team projects.
package main

import (
	"fmt"
	"os"

	"github.com/Janne6565/wharf-tui/internal/ui"
	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	p := tea.NewProgram(ui.New(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "wharf:", err)
		os.Exit(1)
	}
}
