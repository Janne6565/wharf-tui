//go:build !windows

package remoteaccess

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/Janne6565/wharf-tui/internal/sessd"
)

// Open mints a token, creates the grant socket and starts serving on it. The
// returned Grant is revoked with Close.
//
// The socket is created 0600 inside the 0700 grants directory that
// sessd.GrantSocketPath validates for ownership and mode. That validation
// refuses rather than repairs when the directory belongs to someone else, which
// is the right call here for the same reason it is there: quietly tightening a
// directory another user controls does not make it ours, it just hides that it
// is not.
func Open(opts Options) (*Grant, error) {
	if opts.Exec == nil {
		return nil, errors.New("remoteaccess: a grant needs an executor")
	}
	sock, err := sessd.GrantSocketPath()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("remoteaccess: listening on %s: %w", sock, err)
	}
	// Between Listen and Chmod the socket exists with the process umask's mode.
	// The window is closed by the directory: it is 0700, so nobody else can
	// reach the socket to connect in the first place. Chmod is belt to the
	// directory's braces, and a failure is fatal rather than tolerated.
	if err := os.Chmod(sock, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(sock)
		return nil, fmt.Errorf("remoteaccess: securing %s: %w", sock, err)
	}
	g, err := newGrant(opts, ln, sock)
	if err != nil {
		_ = ln.Close()
		_ = os.Remove(sock)
		return nil, err
	}
	return g, nil
}

// grantsDir is the directory Dial scans. It is derived from a throwaway call to
// sessd.GrantSocketPath rather than from a second copy of the path and
// permission logic: one owner of those rules means the client cannot drift into
// scanning a directory the server would have refused to serve from. The
// returned socket name is discarded — nothing was created for it.
func grantsDir() (string, error) {
	sock, err := sessd.GrantSocketPath()
	if err != nil {
		return "", err
	}
	return filepath.Dir(sock), nil
}
