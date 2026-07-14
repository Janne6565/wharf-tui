// Command wharf is a terminal-based SSH client with a keyboard-driven TUI.
//
// Wharf is local-first: hosts, keys and sessions work with no account, backed by
// a local encrypted vault. Signing in adds cross-machine sync and team projects.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Janne6565/wharf-tui/internal/sshx"
	"github.com/Janne6565/wharf-tui/internal/ui"
	"github.com/Janne6565/wharf-tui/internal/vault"
	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	demo := flag.Bool("demo", false, "run with sample data and a simulated session (no disk I/O, no real SSH)")
	flag.Parse()

	if *demo {
		run(ui.New(ui.Config{Demo: true}), nil)
		return
	}

	vaultPath := os.Getenv("WHARF_VAULT")
	if vaultPath == "" {
		p, err := vault.DefaultPath()
		if err != nil {
			fmt.Fprintln(os.Stderr, "wharf: resolving vault path:", err)
			os.Exit(1)
		}
		vaultPath = p
	}

	knownHosts := "known_hosts"
	if home, err := os.UserHomeDir(); err == nil {
		knownHosts = filepath.Join(home, ".ssh", "known_hosts")
	}

	mgr := sshx.NewManager(knownHosts, true)
	model := ui.New(ui.Config{VaultPath: vaultPath, Manager: mgr})
	run(model, mgr)
}

// run wires the manager's notify callback to the program and runs it. The
// callback must be set before any Dial, so it is wired before p.Run.
func run(model tea.Model, mgr *sshx.Manager) {
	p := tea.NewProgram(model, tea.WithAltScreen())
	if mgr != nil {
		mgr.SetNotify(p.Send)
	}
	_, err := p.Run()
	// Belt and braces: the model closes these on quit, but ensure sessions are
	// torn down even on an abnormal exit.
	if mgr != nil {
		mgr.CloseAll()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "wharf:", err)
		os.Exit(1)
	}
}
