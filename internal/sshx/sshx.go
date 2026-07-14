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
//
// The exported surface (Manager, Session, and the message types below) is a
// frozen contract consumed by the UI package. The Manager and Session types
// and their methods are implemented in the sibling files of this package
// (manager.go, dial.go, session.go, attach.go, …); only the message and spec
// value types live here.
package sshx

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

// Auth-method preferences for HostSpec.AuthMethod. Auto keeps the full
// chain; Key and Password restrict it so servers with a low MaxAuthTries are
// not burned on methods the host will never accept.
const (
	AuthAuto     = ""         // agent → key file → password → keyboard-interactive
	AuthKey      = "key"      // agent + key file (+ keyboard-interactive for 2FA)
	AuthPassword = "password" // password + keyboard-interactive only
)

// HostSpec is the connection recipe the UI hands to Dial (derived from
// store.Host; kept separate so sshx does not depend on the store).
type HostSpec struct {
	ID         string
	Name       string
	User       string
	Addr       string
	Port       int
	KeyPath    string // optional explicit identity file
	AuthMethod string // AuthAuto | AuthKey | AuthPassword
	Password   string // stored password; tried once before prompting
}
