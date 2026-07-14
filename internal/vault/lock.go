package vault

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// lockName is the sidecar file that guards a vault directory. It is separate
// from the vault file so the lock survives the atomic rename during Save.
const lockName = "vault.lock"

// acquireLock takes an exclusive, non-blocking flock on <dir>/vault.lock. The
// returned file must be kept open for the lifetime of the lock; closing it
// releases the lock. A lock already held by another process yields ErrLocked.
func acquireLock(vaultPath string) (*os.File, error) {
	lockPath := filepath.Join(filepath.Dir(vaultPath), lockName)
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return f, nil
}

// zero best-effort scrubs sensitive key material from memory.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
