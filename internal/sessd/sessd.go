// Package sessd owns wharf's SSH sessions.
//
// It has two implementations behind one API, chosen at build time:
//
//   - unix (client.go, host.go, proto.go, attach.go, paths.go): each session
//     runs in a **detached child process** that owns the SSH connection. The
//     TUI talks to it over a unix socket whose descriptor it handed the child
//     at spawn, so sessions survive quitting wharf and are picked up again by
//     the next run via Pool.Adopt.
//
//   - windows (pool_windows.go): each session runs **in this process**, on top
//     of internal/sshx. Detaching (ctrl+\), the sessions overlay and reattach
//     with replay all work exactly the same; what does not is survival — when
//     wharf exits, its sessions go with it.
//
// The Windows split is not a stylistic choice. The unix path spawns the child
// with the listening socket as fd 3, and os/exec does not support ExtraFiles on
// Windows at all; there is likewise no Setsid to detach it from the terminal.
// Making sessions outlive wharf there needs a different handoff (named pipes
// and a service-like child), which is worth doing on its own terms rather than
// as a footnote to a port.
//
// Both implementations present the same Pool and Remote, so internal/ui never
// branches on platform.
package sessd

import "time"

// SessionHostFlag is the argument that puts a wharf binary into session-host
// mode. The unix TUI re-executes itself with it; main wires it to Serve.
//
// It is declared for every platform so main can recognise it and refuse it
// with a clear message on Windows, where nothing ever passes it.
const SessionHostFlag = "--session-host"

// AttachOptions is everything the attach loop has to know about the keys it
// watches while the Bubble Tea program is suspended. It mirrors
// sshx.AttachOptions field for field; the Windows Remote translates one into
// the other.
//
// It is declared here, with no build constraint, and duplicated rather than
// aliased for the same reason ExecRequest is: internal/ui names it on both
// platforms, and sessd's API must not turn into sshx's API on one of them —
// the unix path has no sshx types in it at all.
type AttachOptions struct {
	// Detach ends the takeover. Zero falls back to the default (ctrl+\).
	Detach byte

	// RemoteAccess toggles the remote-access grant without leaving the session.
	// Zero disables the hotkey, as does a nil OnRemoteAccess: the byte is then
	// ordinary input on its way to the remote, exactly as before this existed.
	RemoteAccess byte

	// OnRemoteAccess is called when RemoteAccess is typed, and returns the text
	// to print on the local terminal. The terminal is raw, so the text has to
	// use \r\n itself; the attach loop prints it verbatim and adds nothing.
	OnRemoteAccess func() string
}

// ExecRequest is one non-interactive command to run on a session's host. It
// mirrors sshx.ExecRequest rather than reusing it, for the same reason
// hostSpecWire mirrors sshx.HostSpec: on unix this crosses a process boundary
// between two possibly different wharf builds, and a field added to the
// engine's struct must not silently change what travels over the socket.
//
// It lives here, with no build constraint, because internal/remoteaccess names
// it in an interface that has to compile on Windows too — where Exec is served
// in-process and there is no socket at all.
type ExecRequest struct {
	Command string        // the command line, already assembled by the caller
	Stdin   []byte        // optional; nil sends an immediately-closed stdin
	Timeout time.Duration // zero means no deadline beyond ctx
}
