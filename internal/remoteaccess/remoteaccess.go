// Package remoteaccess grants a local process — in practice an AI coding agent
// — a revocable, auditable, exec-only capability on exactly one host that wharf
// is already connected to.
//
// The grant is a bearer token on a 0600 unix socket in a 0700 runtime
// directory. Anyone who can read the token and open the socket can run commands
// on that host as that user, until the grant is revoked or its TTL expires.
// That is a deliberate narrowing of the trust boundary internal/sessd already
// accepts ("anyone who can open the socket can type into that shell"): a grant
// adds a 32-byte token on top of the file mode, runs commands in their own exec
// channel instead of the user's TTY, dies on revocation, TTL, lock or quit, and
// prints every command it runs in the TUI as it happens.
//
// Hard rules, from docs/REMOTE-ACCESS.md:
//
//   - The token is generated with crypto/rand and lives only in memory. It is
//     never written to disk, never part of the socket filename, never in an
//     error message and never logged. An error that varied with the token —
//     or with whether a grant exists — would hand an attacker an oracle.
//   - Token comparison is crypto/subtle.ConstantTimeCompare.
//   - Revocation is synchronous: when Close returns, the listener is closed,
//     the socket file is unlinked and no further command can start.
//
// The wire format is the sessd framing shape (1-byte kind, big-endian uint32
// length, JSON payloads, a hard cap on the length) so the codebase has one
// framing idiom, with one addition: the mandatory first frame carries the
// token. The few lines are reimplemented here rather than exported from sessd,
// because sharing them would make sessd's private protocol a public one and
// couple two packages that only happen to look alike.
package remoteaccess

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/Janne6565/wharf-tui/internal/sessd"
)

// ExecRequest is one non-interactive command to run on the granted host.
//
// It is an alias rather than a second struct so that *sessd.Remote satisfies
// Executor without an adapter, while readers of this package do not have to
// follow an import to learn what a grant can ask for. sessd owns the type
// because sessd is what puts it on a wire.
type ExecRequest = sessd.ExecRequest

// Executor is the entire authority a grant holds: run one command, stream its
// output, report its exit code. It is an interface rather than a *sessd.Remote
// so a grant cannot reach anything else on the session — no PTY, no forwards,
// no host spec — and so the server is testable without an SSH connection.
//
// It is satisfied by *sessd.Remote.
type Executor interface {
	Exec(ctx context.Context, req ExecRequest, stdout, stderr io.Writer) (int, error)
}

// The assertion is here rather than in a test because the two packages are
// written against each other: a signature drifting on either side should fail
// the build that caused it, not a test run somebody might not do.
var _ Executor = (*sessd.Remote)(nil)

// Event is one audited command run through a grant. The live audit log is what
// makes a prompt-injected agent survivable, so it is a core feature rather than
// decoration: every command is reported when it starts and again when it ends.
type Event struct {
	// ID correlates the start event of a command with its terminal one. It is
	// assigned by the grant, counts from one, and is unique within that grant —
	// not across grants, so a consumer keeping a log across a revocation must
	// namespace it (Holder pairs it with a generation counter).
	//
	// It exists because the two events about one command have to be folded into
	// one audit row, and the only thing available to fold on used to be the
	// command *text*. That heuristic mismatched two identical commands running
	// concurrently — the exact case MaxInFlight allows — and swapped their
	// outcomes. An id is a key; text never was one.
	//
	// Zero means unstamped. Nothing in this package emits a zero id; a consumer
	// that sees one should treat the event as its own row rather than folding it
	// into an unrelated one.
	ID      uint64
	Command string
	At      time.Time
	Code    int
	Err     error
	// Finished is false for the start event and true for the terminal one. Code
	// and Err are meaningful only when it is true.
	Finished bool
	// Refused marks a command that was turned away — revoked grant, lapsed TTL,
	// too many already running — and therefore never reached the host. A refusal
	// is a single terminal event with no start event before it, and Err always
	// says why in text that begins "refused:", so a consumer that does not know
	// this field still renders something honest.
	//
	// It is additive and zero-valued-safe on purpose: every event a previous
	// build produced has Refused false, which is exactly what those events meant.
	// A burst of refusals is the shape a prompt-injected agent makes when it
	// keeps trying after being cut off, and an audit log that showed only
	// successes would hide precisely that.
	Refused bool
}

// Options configures a grant. Only Exec is required; the zero value of every
// other field is a safe default.
type Options struct {
	Exec     Executor
	HostID   string
	HostName string
	// TTL bounds the grant's life. DefaultTTL when zero, and deliberately
	// short: the token transits a clipboard and then an agent's context, which
	// is frequently logged and summarised. Do not raise the default.
	TTL time.Duration
	// MaxInFlight caps concurrent commands. DefaultMaxInFlight when zero.
	MaxInFlight int
	// Notify receives the audit events. It is called from arbitrary goroutines
	// — one per in-flight command, plus whichever goroutine finishes one — so
	// an implementation that touches UI state must hand off to the event loop
	// (the p.Send bridge) rather than mutating it in place. It must not block:
	// a command's start event is emitted on the path that runs the command.
	Notify func(Event)
}

// Request is one command sent through a grant by the client half.
type Request struct {
	Command string
	Stdin   []byte
	Timeout time.Duration
}

// DefaultTTL is how long a grant lives when Options.TTL is zero. An hour is
// long enough for an agent's task and short enough that a token leaked into a
// transcript is usually already dead.
const DefaultTTL = 60 * time.Minute

// DefaultMaxInFlight is the concurrent-command ceiling when Options.MaxInFlight
// is zero. It exists to bound how much a single grant can do to a host at once,
// not to be a performance knob; four is enough for an agent that parallelises a
// little and small enough to notice in the audit log.
const DefaultMaxInFlight = 4

// tokenBytes is the token's entropy. 32 bytes is not negotiable-down: the token
// is the only thing between a filesystem-local attacker and a shell.
const tokenBytes = 32

// maxPendingConns bounds how many connections may be in the handshake at once.
// Past it the accept loop stops accepting and the kernel's backlog absorbs the
// rest, which is the whole point: an unauthenticated peer must cost a bounded
// amount of memory no matter how many of it there are.
//
// It is a package constant rather than an Options field because it is not a
// tuning knob for a user to get wrong — nothing legitimate opens sixteen
// simultaneous grant connections when DefaultMaxInFlight is four, and the number
// only needs to be comfortably above real use and far below what would matter to
// the heap. Refusing over-quota connections outright was rejected: a slot frees
// within authTimeout, so making an honest client wait beats making it fail.
const maxPendingConns = 16

// authTimeout bounds how long a connection may take to present its token. A
// legitimate client sends it as its first write, so this is short on purpose —
// an unauthenticated connection must not be able to hold a serving slot open.
const authTimeout = 5 * time.Second

// requestTimeout bounds the wait for the command frame after a successful
// authentication. Same reasoning as authTimeout: the client has nothing to
// think about between the two frames.
const requestTimeout = 10 * time.Second

// dialTimeout bounds one connect attempt while Dial walks the grants
// directory. A local socket answers in microseconds; anything slower is a dead
// socket and the next candidate deserves the time.
const dialTimeout = 2 * time.Second

// ErrNoGrant is the single opaque failure Dial reports when no live grant
// accepted the token. It deliberately does not distinguish "wrong token" from
// "no grants at all" from "the grant expired between listing and connecting":
// telling them apart would confirm to a caller that some grant exists, which is
// exactly the fact the token is meant to protect.
var ErrNoGrant = errors.New("remoteaccess: no grant accepted this token")

// ErrRevoked is returned by a grant's own methods after Close.
var ErrRevoked = errors.New("remoteaccess: the grant has been revoked")

// ErrUnsupported is what Open returns on Windows. It is declared on every
// platform so callers can test for it without build tags.
var ErrUnsupported = errors.New("remote access grants are a unix-only mechanism: " +
	"the grant is served on a 0600 unix socket, and the file-mode half of its " +
	"security model has no Windows equivalent")

// errRejected is the wire text for a failed authentication. One constant string
// for every rejection reason, so the response carries no information beyond
// "no".
const errRejected = "remoteaccess: rejected"
