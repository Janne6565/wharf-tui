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

// sessionIDFor derives a session's stable identifier from its socket path: the
// basename without the suffix. It is unique by construction (socketPath adds
// random bytes) and needs no bookkeeping to survive adoption by a later wharf.
func sessionIDFor(sockPath string) string {
	return strings.TrimSuffix(filepath.Base(sockPath), sockSuffix)
}
