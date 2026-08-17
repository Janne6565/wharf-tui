package main

import "errors"

// grantsDir has no answer on Windows: a grant is served on a 0600 unix socket,
// and that mechanism is unix-only (see remoteaccess.ErrUnsupported). It returns
// a short error rather than the sentinel's full explanation because --doctor is
// a table of one-liners; the full sentence is what --remote itself prints.
func grantsDir() (string, error) {
	return "", errors.New("unix only")
}
