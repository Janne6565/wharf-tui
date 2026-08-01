package vault

import (
	"errors"
	"os"
	"path/filepath"
)

// lockName is the sidecar file that guards a vault directory. It is separate
// from the vault file so the lock survives the atomic rename during Save.
const lockName = "vault.lock"

// acquireLock takes an exclusive, non-blocking lock on <dir>/vault.lock. The
// returned file must be kept open for the lifetime of the lock; closing it
// releases the lock. A lock already held by another process yields ErrLocked.
//
// Only the locking call itself is per-platform (flock on unix, LockFileEx on
// Windows) — opening the sidecar is not, so it stays here.
func acquireLock(vaultPath string) (*os.File, error) {
	lockPath := filepath.Join(filepath.Dir(vaultPath), lockName)
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// LockPath resolves the lock sidecar guarding a vault's directory.
func LockPath(vaultPath string) string {
	return filepath.Join(filepath.Dir(vaultPath), lockName)
}

// InUse reports whether another wharf process currently holds the vault lock.
// It probes by taking the lock and releasing it again, so a false answer is
// only true of that instant — callers use it as a courtesy check, not a
// guarantee (deleting a vault under a running instance, for one, would simply
// be undone by that instance's next save).
func InUse(vaultPath string) bool {
	f, err := acquireLock(vaultPath)
	if err != nil {
		return errors.Is(err, ErrLocked)
	}
	f.Close()
	return false
}

// zero best-effort scrubs sensitive key material from memory.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
