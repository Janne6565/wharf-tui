package vault

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// lockFile takes an exclusive, non-blocking byte-range lock.
//
// LockFileEx is the closest Windows equivalent of flock for this purpose: the
// lock is owned by the file handle and the kernel drops it when the handle
// closes, including on a crash, so a killed wharf leaves no stale lock behind.
// Locking one byte rather than the whole file is the usual idiom — the sidecar
// is empty and the range only has to be one both sides agree on.
func lockFile(f *os.File) error {
	var overlapped windows.Overlapped
	err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1, 0, // lock exactly one byte
		&overlapped,
	)
	// Held by another process. ERROR_IO_PENDING cannot occur with
	// FAIL_IMMEDIATELY, so a violation is the only contended outcome.
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrLocked
	}
	return err
}
