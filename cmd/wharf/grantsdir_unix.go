//go:build !windows

package main

import (
	"path/filepath"

	"github.com/Janne6565/wharf-tui/internal/sessd"
)

// grantsDir reports the directory remote-access grant sockets live in, for
// --doctor.
//
// It asks sessd for a socket path and takes the parent, rather than rebuilding
// the path from its parts, so that doctor can never report a directory the real
// client and server would disagree with. The discarded socket name costs
// nothing: no file is created for it.
//
// It does create the directory itself, and validates its ownership and mode.
// That is deliberate — an empty 0700 directory is harmless, and the check is
// exactly the one a grant would fail on, so doctor reports the real answer
// instead of a path that happens to be unusable.
func grantsDir() (string, error) {
	sock, err := sessd.GrantSocketPath()
	if err != nil {
		return "", err
	}
	return filepath.Dir(sock), nil
}
