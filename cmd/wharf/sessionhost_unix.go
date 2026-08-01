//go:build !windows

package main

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/Janne6565/wharf-tui/internal/sessd"
)

// runSessionHost is the child process behind a surviving session. The TUI
// created the listening socket and passed its descriptor as fd 3, so there is
// no window where the socket exists with nothing accepting on it.
func runSessionHost(sockPath string) error {
	f := os.NewFile(3, "wharf-session-listener")
	if f == nil {
		return errors.New("no listener on fd 3")
	}
	defer f.Close()
	ln, err := net.FileListener(f)
	if err != nil {
		return fmt.Errorf("adopting the listener: %w", err)
	}
	return sessd.Serve(ln, sockPath)
}
