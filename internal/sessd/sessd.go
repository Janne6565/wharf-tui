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

// SessionHostFlag is the argument that puts a wharf binary into session-host
// mode. The unix TUI re-executes itself with it; main wires it to Serve.
//
// It is declared for every platform so main can recognise it and refuse it
// with a clear message on Windows, where nothing ever passes it.
const SessionHostFlag = "--session-host"
