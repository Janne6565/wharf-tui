// Package sshx is Wharf's SSH engine: connection manager, auth chain,
// known-hosts verification, and live sessions with detach/reattach.
//
// Sessions outlive the UI's attach state: a per-session pump goroutine
// drains remote output into a ring buffer for the session's whole life, and
// additionally into the real terminal while attached (full-screen takeover
// via tea.Exec). All interactive prompts (host-key TOFU, key passphrase,
// password, keyboard-interactive) surface as messages through the Notify
// callback and block on their Reply channel — the UI renders a modal and
// answers.
package sshx

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"
)

// HostKeyPromptMsg asks the user to trust an unknown host key (TOFU).
// Send true on Reply to accept (the key is appended to known_hosts), false
// to abort the connection. A CHANGED host key never prompts — it is a hard
// typed error.
type HostKeyPromptMsg struct {
	HostID      string
	Host        string // "addr:port"
	KeyType     string // e.g. "ssh-ed25519"
	Fingerprint string // SHA256:...
	Reply       chan<- bool
}

// SecretPromptMsg asks the user for a secret (key passphrase, password, or a
// keyboard-interactive answer). Echo=true means the input may be shown.
// Send nil on Reply to cancel authentication.
type SecretPromptMsg struct {
	HostID string
	Title  string // e.g. "passphrase for ~/.ssh/id_ed25519"
	Detail string
	Echo   bool
	Reply  chan<- []byte
}

// SessionEndedMsg is delivered when a session terminates for any reason
// (remote exit, network drop, Close). Err is nil on clean exit.
type SessionEndedMsg struct {
	HostID string
	Err    error
}

// HostSpec is the connection recipe the UI hands to Dial (derived from
// store.Host; kept separate so sshx does not depend on the store).
type HostSpec struct {
	ID      string
	Name    string
	User    string
	Addr    string
	Port    int
	KeyPath string // optional explicit identity file
}

// Manager owns all live sessions and the known-hosts policy.
type Manager struct {
	// implemented in WP3
}

// NewManager creates a manager verifying against knownHostsPath
// (typically ~/.ssh/known_hosts). keepalive enables 30s server pings.
func NewManager(knownHostsPath string, keepalive bool) *Manager {
	panic("sshx: unimplemented")
}

// SetNotify wires prompt/lifecycle messages into the UI event loop
// (tea.Program.Send). Must be set before Dial.
func (m *Manager) SetNotify(fn func(tea.Msg)) { panic("sshx: unimplemented") }

// Dial connects, authenticates (agent -> key file -> password ->
// keyboard-interactive), requests a PTY of cols x rows, starts the remote
// shell and the output pump, and registers the session under hs.ID.
func (m *Manager) Dial(ctx context.Context, hs HostSpec, cols, rows int) (*Session, error) {
	panic("sshx: unimplemented")
}

// Get returns the live session for hostID, or nil.
func (m *Manager) Get(hostID string) *Session { panic("sshx: unimplemented") }

// List returns all live sessions in dial order.
func (m *Manager) List() []*Session { panic("sshx: unimplemented") }

// CloseAll terminates every session (used on quit).
func (m *Manager) CloseAll() { panic("sshx: unimplemented") }

// Session is one live remote shell.
type Session struct {
	// implemented in WP3
}

// Host returns the spec the session was dialed with.
func (s *Session) Host() HostSpec { panic("sshx: unimplemented") }

// Attach returns the tea.ExecCommand that performs the full-screen terminal
// takeover: raw mode, replay of the ring buffer, bidirectional copy, WINCH
// forwarding. Typing ctrl+\ (0x1C) detaches — Run returns with the session
// still alive.
func (s *Session) Attach() tea.ExecCommand { panic("sshx: unimplemented") }

// Alive reports whether the remote shell is still running.
func (s *Session) Alive() bool { panic("sshx: unimplemented") }

// Done is closed when the session ends.
func (s *Session) Done() <-chan struct{} { panic("sshx: unimplemented") }

// Close terminates the session.
func (s *Session) Close() error { panic("sshx: unimplemented") }
