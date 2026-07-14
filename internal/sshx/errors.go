package sshx

import "errors"

// Typed errors returned by Dial. They are sentinels so the UI can branch on
// them with errors.Is without pattern-matching on message strings.
var (
	// ErrHostKeyChanged is returned when the server presents a host key that
	// differs from the one recorded in known_hosts. This is never prompted —
	// it is treated as a hard failure (potential MITM).
	ErrHostKeyChanged = errors.New("sshx: host key changed")

	// ErrHostKeyRejected is returned when the user declines to trust an
	// unknown host key (answered false to the TOFU prompt).
	ErrHostKeyRejected = errors.New("sshx: host key rejected by user")

	// ErrCanceled is returned when the user cancels a secret prompt (sends
	// nil on the Reply channel) or no Notify callback is wired to surface the
	// prompt.
	ErrCanceled = errors.New("sshx: canceled")

	// ErrAuthFailed wraps the underlying handshake error when the server
	// rejected every authentication method.
	ErrAuthFailed = errors.New("sshx: authentication failed")
)
