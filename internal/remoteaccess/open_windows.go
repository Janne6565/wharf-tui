package remoteaccess

import (
	"context"
	"io"
)

// Open never succeeds on Windows: a grant's security model is a bearer token on
// a 0600 socket inside a 0700 directory, and the file-mode half of that has no
// Windows equivalent — a named pipe is secured by an ACL, which is a different
// design and deserves to be made on its own terms rather than as a footnote to
// a port.
//
// It exists, and fails with a sentence rather than a panic, because the UI is
// built for every platform and must be able to say why the key did nothing.
//
// Note that exec itself works on Windows — sessd runs sessions in-process
// there. What is missing is the cross-process capability, not the capability.
func Open(Options) (*Grant, error) { return nil, ErrUnsupported }

// Dial never succeeds on Windows, for the same reason as Open: there is no
// grant socket to find. The signature matches the unix one so cmd/wharf needs
// no build tag of its own.
func Dial(ctx context.Context, token string, req Request, stdout, stderr io.Writer) (int, error) {
	return 0, ErrUnsupported
}
