//go:build !windows

package sessd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// sockSuffix marks the socket files this package owns.
const sockSuffix = ".sock"

// maxSockPath is the portable ceiling on a unix socket path. sockaddr_un.sun_path
// is 104 bytes on the BSDs (108 on Linux) including the terminator, and bind
// fails with EINVAL past it — a failure mode worth naming rather than
// rediscovering. Everything below is sized to stay well under it.
const maxSockPath = 100

// RuntimeDir resolves the 0700 directory holding session sockets, creating it
// if needed. $XDG_RUNTIME_DIR is preferred because it is already per-user and
// wiped at logout. The fallback is /tmp/wharf-<uid> rather than $TMPDIR:
// macOS hands out a ~50-character per-user TMPDIR, which alone eats half the
// socket-path budget. Sockets never live next to the vault — they are
// machine-local runtime state, and the vault directory is a sync surface.
func RuntimeDir() (string, error) {
	base := strings.TrimSpace(os.Getenv("WHARF_RUNTIME_DIR"))
	if base == "" {
		if xdg := strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")); xdg != "" {
			base = filepath.Join(xdg, "wharf")
		} else {
			base = filepath.Join("/tmp", "wharf-"+strconv.Itoa(os.Getuid()))
		}
	}
	// The parent is checked too, not just the socket directory itself. Under a
	// world-writable /tmp anyone can create /tmp/wharf-<uid> first; owning that
	// parent lets them rename or replace "sessions" underneath us however
	// carefully we create it. Validating only the leaf is a lock on a door in a
	// wall someone else built.
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", fmt.Errorf("sessd: creating %s: %w", base, err)
	}
	if err := checkPrivateParent(base); err != nil {
		return "", err
	}
	dir := filepath.Join(base, "sessions")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("sessd: creating %s: %w", dir, err)
	}
	// MkdirAll leaves an existing directory alone, so verify rather than trust:
	// under a world-writable /tmp the directory may have been planted by someone
	// else, and a group- or world-reachable one would expose every live shell.
	if err := checkPrivateDir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

// GrantSocketPath returns a fresh, validated path for a remote-access grant
// socket. Grants live in a "grants" directory beside the session sockets rather
// than among them: everything in the sessions directory is a session to
// Pool.Adopt, and a grant socket dropped in there would be probed, found mute
// and unlinked on the next start.
//
// The token is deliberately not part of the name. A filename is metadata anyone
// who can list the directory can read, and the grant's whole premise is that
// the token exists only in memory — see docs/REMOTE-ACCESS.md. The name is the
// same <prefix>-<10 hex>.sock shape sessions use, so it stays inside the
// maxSockPath budget socketPath enforces.
func GrantSocketPath() (string, error) {
	// RuntimeDir is what validates the base directory's ownership and mode, so
	// it is called for its checks as much as for its answer; the grants
	// directory is its sibling.
	sessions, err := RuntimeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(filepath.Dir(sessions), "grants")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("sessd: creating %s: %w", dir, err)
	}
	// Verify rather than trust, exactly as RuntimeDir does for sessions:
	// MkdirAll leaves an existing directory alone, and a group- or
	// world-reachable one would hand the grant socket to anyone on the machine.
	if err := checkPrivateDir(dir); err != nil {
		return "", err
	}
	return socketPath(dir, "grant")
}

// checkPrivateParent enforces that the directory holding the socket directory
// is ours and not writable by anyone else. Unlike checkPrivateDir it never
// chmods: the base can be user-chosen (WHARF_RUNTIME_DIR), and silently
// tightening a directory wharf was merely pointed at is not wharf's call —
// saying why it refuses is.
func checkPrivateParent(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("sessd: checking %s: %w", dir, err)
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("sessd: %s is not a directory", dir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("sessd: %s is owned by uid %d, not %d — refusing to keep "+
			"session sockets under a directory another user controls", dir, st.Uid, os.Getuid())
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("sessd: %s is writable by group or others (%#o); "+
			"chmod 700 it or point WHARF_RUNTIME_DIR somewhere private", dir, perm)
	}
	return nil
}

// checkPrivateDir enforces that dir is a real directory, owned by this user,
// and reachable only by them.
func checkPrivateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("sessd: checking %s: %w", dir, err)
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("sessd: %s is not a directory", dir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("sessd: %s is owned by uid %d, not %d", dir, st.Uid, os.Getuid())
	}
	if fi.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("sessd: securing %s: %w", dir, err)
		}
	}
	return nil
}

// socketPath invents a unique socket path for a new session. The host ID is
// only a readability aid — uniqueness comes from the random suffix, so a
// re-dial of the same host while an old session lingers cannot collide.
func socketPath(dir, hostID string) (string, error) {
	var buf [5]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	name := sanitize(hostID) + "-" + hex.EncodeToString(buf[:]) + sockSuffix
	path := filepath.Join(dir, name)
	if len(path) > maxSockPath {
		return "", fmt.Errorf("sessd: socket path %q is %d bytes, over the %d-byte limit — "+
			"set WHARF_RUNTIME_DIR to a shorter directory", path, len(path), maxSockPath)
	}
	return path, nil
}

// sanitize reduces an ID to characters safe in a filename. Host IDs are hex
// today; this keeps a hand-edited vault from writing paths.
func sanitize(s string) string {
	if s == "" {
		return "session"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if len(out) > 12 {
		out = out[:12]
	}
	return out
}

// listSockets returns the session sockets currently in dir.
func listSockets(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), sockSuffix) {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	return out, nil
}

// logPathFor is where a session host's stderr goes: beside its socket, with a
// suffix listSockets ignores. A child is spawned with no terminal, so without
// this a panic or a failed Serve vanishes and the user is left with a session
// that simply never appeared.
func logPathFor(sockPath string) string { return sockPath + ".log" }

// sessionIDFor derives a session's stable identifier from its socket path: the
// basename without the suffix. It is unique by construction (socketPath adds
// random bytes) and needs no bookkeeping to survive adoption by a later wharf.
func sessionIDFor(sockPath string) string {
	return strings.TrimSuffix(filepath.Base(sockPath), sockSuffix)
}
