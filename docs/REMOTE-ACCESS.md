# Remote access — design contract

> This document is the authoritative contract for the `remote access` feature.
> It is written before the code and is the spec every implementation phase is
> reviewed against. Signatures here are binding; deviating from them breaks a
> sibling package that was written against them in parallel.

## What it is

A user attached to a host in wharf can grant a **revocable, auditable,
exec-only capability** on that one host to a local process — in practice an AI
coding agent — without handing over any credential.

Wharf prints (and copies) a command:

```
wharf --remote 8Q2c…  -- curl -sS localhost:9000/health
```

The agent runs that in its own shell. Wharf ships the argv over the SSH
connection it already holds, runs it in a **separate exec channel**, and proxies
stdout/stderr/exit code back to the agent's terminal.

### Why this is worth building

The agent never sees key material, never sees the master password, never touches
the vault. It gets one capability, scoped to one host, revocable with one
keystroke, and every command it runs is printed in the TUI as it happens. That is
strictly less authority than the two things people do today — handing an agent
`~/.ssh` outright, or leaving an OpenSSH `ControlMaster` socket lying around,
which grants a full shell to anyone who can `stat` it, silently and with no log.

### Non-goals for v1

- No interactive/PTY commands. Exec only. `top` will not work; that is correct.
- No persistence. A grant never touches the vault or `localcfg`. Wharf restarts,
  grants are gone.
- No multi-host grants. One grant, one host, always.
- Unix only (see "Windows" below).

## Threat model

The grant is a bearer token on a `0600` unix socket in a `0700` runtime
directory. Anyone who can read the token **and** open the socket can run commands
on that host as that user, until the grant is revoked or expires.

This is deliberately a *narrowing* of the trust boundary `internal/sessd` already
accepts (its README text: "Anyone who can open the socket can type into that
shell"). The differences that matter:

| | session socket (`sessd`) | grant socket (`remoteaccess`) |
|---|---|---|
| authentication | none — file mode only | file mode **and** a 32-byte token |
| capability | full interactive shell, types into the user's TTY | exec only, separate channel |
| lifetime | until the session dies | until revoked, TTL, session end, lock, or quit |
| visibility | none | every command logged in the TUI live |

The token is the reason a grant is safer than just handing over the session
socket path: it can be rotated and revoked without killing the session, and it
is never written to disk.

**Accepted risks, stated plainly:**

- The token transits the clipboard and then an agent's context, which is
  frequently logged and summarised. Mitigated by a short default TTL and
  single-host binding, not eliminated. Do not raise the default TTL.
- A prompt-injected agent has real shell on a real host for the life of the
  grant. The live audit log is what makes that survivable; it is a core feature,
  not decoration.
- The token appears in the agent's shell history and process list (`ps` shows
  argv). Accepted for v1 — the alternative, an env var, is barely better and
  much worse ergonomically. `WHARF_REMOTE_TOKEN` is supported as an alternative
  so a caller who cares can avoid argv.
- Revocation withdraws the capability, it does not reach into the host. A
  command the agent already started may keep running after the grant is closed;
  what revocation guarantees is that no *further* command can be started. Phrase
  it to users that way — never as "the command was killed".

**Hard rules:**

- The token is **never** written to disk, never in a filename, never in
  `localcfg`, never in the vault, never in a log file.
- Token comparison is `crypto/subtle.ConstantTimeCompare`.
- Revocation is synchronous: when the grant closes, the listener closes and the
  socket is unlinked before the UI reports it revoked.

## Architecture

```
  agent's shell                     wharf TUI process              session host child
  ─────────────                     ─────────────────              ──────────────────
  wharf --remote TOK -- argv
        │  unix socket, framed        │                             │
        │  HMAC challenge–response ───►│ remoteaccess.Server        │
        │                             │  · constant-time token cmp  │
        │                             │  · TTL / revocation check   │
        │                             │  · emits audit event ──► UI │
        │                             │                             │
        │                             │ sessd.Remote.Exec ─────────►│ kindExec
        │                             │                             │  sshx.Session.Exec
        │                             │                             │   └─ client.NewSession()
        │                             │                             │      (no PTY, new channel
        │◄── stdout/stderr/exit ──────│◄──── kindExecOut/ExecEnd ───│       on the LIVE client)
```

The exec channel rides the **existing** `*ssh.Client`. That is the whole trick:
no second dial, therefore no re-auth, therefore it can never re-prompt for a
passphrase or a TOFU decision, and it costs one `SSH_MSG_CHANNEL_OPEN`. It is
also completely isolated from the PTY session's ring buffer, so nothing the
agent runs appears in the user's scrollback.

Contrast with `internal/sshx/forward.go`, which *does* re-dial per forward — it
has to, because a forward must outlive detach. An exec does not.

## Package contracts

### `internal/sshx` — exec on a live session

```go
// ExecRequest is one non-interactive command on an already-connected host.
type ExecRequest struct {
	Command string        // the command line, already assembled by the caller
	Stdin   []byte        // optional; nil sends an immediately-closed stdin
	Timeout time.Duration // zero means no deadline beyond ctx
}

// ExecResult reports how a command finished. Code is the remote exit status;
// it is meaningful only when Err is nil.
type ExecResult struct {
	Code int
}

// Exec runs cmd on the session's existing SSH connection in its own channel,
// streaming output to stdout and stderr as it arrives.
//
// It does not request a PTY and does not touch the session's ring buffer, so
// nothing it runs appears in the user's scrollback. It cannot prompt: the
// connection is already authenticated.
func (s *Session) Exec(ctx context.Context, req ExecRequest, stdout, stderr io.Writer) (ExecResult, error)
```

Requirements:

- Returns `ErrSessionClosed` (new sentinel in `errors.go`) if `s.done` is already
  closed, and aborts an in-flight exec if the session dies mid-command — the
  waiter closes `s.client`, which would otherwise leave the exec hanging.
- A remote non-zero exit is **not** a Go error. `*ssh.ExitError` →
  `ExecResult{Code: e.ExitStatus()}, nil`. `*ssh.ExitMissingError` → `Code 255`,
  no error (the remote closed without a status; this is what OpenSSH reports).
- `ctx` cancellation and `Timeout` both abort the exec: `Exec` returns promptly
  with `context.DeadlineExceeded` / `context.Canceled` and stops writing to the
  caller's writers, then signals the remote (SIGTERM, SIGKILL after a grace
  period) and closes the channel. Killing the remote process is **best-effort,
  not guaranteed** — an exec has no PTY, so there is no controlling terminal for
  sshd to hang up, and OpenSSH is not reliably known to honour `signal`
  requests. A cancelled command that produces output normally dies of SIGPIPE;
  one that produces none may run to completion on the host.
- A writer handed to `Exec` is safe to read once `Exec` returns. This is the
  guarantee `sessd`'s `execCall.seal()` depends on.
- Concurrency-safe: several `Exec` calls may be in flight at once alongside the
  PTY session.

### `internal/sessd` — exec across the process boundary

New frame kinds, taking the next free numbers in each direction:

```go
kindExec    frameKind = 9  // client → host, JSON execRequest
kindExecOut frameKind = 26 // host → client, JSON execOutput
kindExecEnd frameKind = 27 // host → client, JSON execEnd
```

```go
type execRequest struct {
	ID      string `json:"id"`             // correlation id, client-generated
	Command string `json:"command"`
	Stdin   []byte `json:"stdin,omitempty"`
	Timeout int    `json:"timeoutMs,omitempty"`
}

type execOutput struct {
	ID     string `json:"id"`
	Stream string `json:"stream"` // "out" | "err"
	Data   []byte `json:"data"`   // base64 in JSON
}

type execEnd struct {
	ID   string `json:"id"`
	Code int    `json:"code"`
	Err  string `json:"err,omitempty"`
}
```

```go
// Exec runs a command on the session's host and streams its output.
func (r *Remote) Exec(ctx context.Context, req ExecRequest, stdout, stderr io.Writer) (int, error)

// ExecRequest mirrors sshx.ExecRequest across the socket.
type ExecRequest struct {
	Command string
	Stdin   []byte
	Timeout time.Duration
}
```

**Correlation is mandatory and must not use `r.ctl`.** That channel is depth-4,
unkeyed, and already races between `requestInfo` and `dial`; two concurrent execs
routed through it would cross-deliver. Add a dedicated registry:

```go
execMu sync.Mutex
execs  map[string]*execCall   // id → in-flight call
```

and explicit `case kindExecOut:` / `case kindExecEnd:` arms in `Remote.readLoop`,
alongside `kindOutput`/`kindPrompt` — never falling through to the `ctl` default.

Host side: `case kindExec:` in `conn.handle` must `return true` and dispatch on
**its own goroutine**. Blocking the read loop deadlocks anything whose answer
arrives as an inbound frame, per the existing comment at `host.go:328`.

`Host` does not currently retain the `*sshx.Manager`; it does not need to here —
`h.sess` is enough, since `Session.Exec` is a method on the session.

Also add:

```go
// GrantSocketPath returns a fresh, validated 0700-directory path for a
// remote-access grant socket. It lives beside the session sockets and reuses
// their ownership and mode checks.
func GrantSocketPath() (string, error)
```

The token must **not** appear in the filename — the path budget is 100 bytes
(`maxSockPath`) and a filename is world-readable metadata. Use the same
`<prefix>-<10 hex>.sock` shape as sessions, in a sibling `grants` directory.

**Windows:** `pool_windows.go` needs an `Exec` twin with an identical signature
that calls `r.sess.Exec` directly. It is simpler there, not harder — no socket,
no framing. Do not stub it with an error; the in-process path works fine.

### `internal/remoteaccess` — the grant

Its own package, `//go:build !windows` for the server (see Windows below).

```go
// Executor is what a grant is allowed to do. Satisfied by *sessd.Remote.
type Executor interface {
	Exec(ctx context.Context, req sessd.ExecRequest, stdout, stderr io.Writer) (int, error)
}

// Event is one audited command run through a grant.
type Event struct {
	Command  string
	At       time.Time
	Code     int
	Err      error
	Finished bool // false = just started, true = terminal
}

type Options struct {
	Exec     Executor
	HostID   string
	HostName string
	TTL      time.Duration      // default 60m if zero
	MaxInFlight int             // default 4
	Notify   func(Event)        // audit sink; called from arbitrary goroutines
}

// Open mints a token, creates the socket and starts serving. The returned
// Grant is revoked with Close, which is synchronous: when it returns, the
// socket is gone and no further command can run. A command already in flight is
// aborted from wharf's side and its output stops, but the remote process is
// only asked to die, not guaranteed to — see sshx.Session.Exec.
func Open(opts Options) (*Grant, error)

func (g *Grant) Token() string      // never logged, never persisted
func (g *Grant) SocketPath() string
func (g *Grant) HostName() string
func (g *Grant) HostID() string     // as shipped: the UI needs it to revoke on session end
func (g *Grant) ExpiresAt() time.Time
func (g *Grant) Expired() bool      // as shipped: checked per request, not by a timer
func (g *Grant) Count() int         // commands run so far
func (g *Grant) Close() error

// CommandLine returns the exact string to show and copy, e.g.
//   wharf --remote <token> -- <your command>
// The socket path is not in it: the client finds the grant by token.
func (g *Grant) CommandLine() string
```

Client half, used by `cmd/wharf`:

```go
// Dial finds the grant whose token matches and runs one command through it.
// Returns the remote exit code.
func Dial(ctx context.Context, token string, req Request, stdout, stderr io.Writer) (int, error)

type Request struct {
	Command string
	Stdin   []byte
	Timeout time.Duration
}
```

`Dial` scans the grants directory and authenticates against each socket in turn;
a mismatch is rejected without revealing which grant exists, as a single opaque
error.

**The token is never sent on the wire.** An earlier design had `Dial` offer the
plaintext token to each socket and inspect the reply — which meant any process
running as the same uid, *including the agent this feature exists to constrain*,
could bind `grants/grant-0000000000.sock`, sort first, harvest the token of a
later grant issued to some other tool, and let the honest client move on none
the wiser. That was demonstrated, not theorised. Capability confusion of exactly
the kind the one-grant-one-host binding is supposed to prevent.

The handshake is therefore challenge–response, HMAC-SHA256 keyed by the token:

1. server → client: a 32-byte random challenge, sent unconditionally before the
   server knows anything about the peer, so it is not an oracle;
2. client → server: `clientNonce ‖ HMAC(token, label ‖ serverNonce ‖ clientNonce
   ‖ socketBaseName)`;
3. server → client: the same MAC under a distinct label — a **server proof** the
   client verifies in constant time **before** it sends the command.

The server proof means a planted socket never learns the argv and cannot feed
back fabricated output. Binding the socket's base name into the transcript kills
the relay variant, where a rogue forwards the real grant's challenge: the MAC it
gets back is computed over its own name and the real grant rejects it. The base
name rather than the full path, because both sides must derive byte-identical
strings and only the leaf is guaranteed to match however each side cleaned the
prefix.

Residual, documented rather than papered over: a same-uid attacker that unlinks
a live socket and binds at the *identical* name within the handshake window.
Nothing short of a kernel-provided channel binding closes it, and an attacker
who can rewrite our runtime directory has already won.

Wire format: reuse the `sessd` framing shape (1-byte kind, big-endian uint32
length, JSON or raw payload) so there is one framing idiom in the codebase.
Every **pre-auth** read is capped at the handshake frame's true maximum
(`nonce + mac`), not the generic 1 MiB — unbounded connections each declaring a
1 MiB frame drove the heap to 189 MiB in testing, and OOM-killing the TUI would
destroy the memory-only audit log, letting an attacker erase the record of what
it ran. Outstanding un-authenticated connections are bounded by a semaphore that
also selects on the grant's context, so revocation never waits out an attacker's
handshake timeout.

### `internal/clipboard` — new, tiny

There is no clipboard code in the repo today. `github.com/aymanbagabas/go-osc52/v2`
is already in `go.sum` as an indirect dep of termenv.

```go
// Copy writes s to the terminal's clipboard using OSC 52.
func Copy(s string) error
```

Promote `go-osc52/v2` to a direct require rather than hand-rolling the escape
sequence — it already handles the tmux and screen passthrough wrapping, which is
the part that is easy to get wrong. Write to stderr, not stdout.

Must be injectable: `Config.CopyToClipboard func(string) error`, defaulting to
the real implementation in `ui.New`, exactly like `Config.OpenBrowser`. Headless
tests must never emit an escape sequence.

OSC 52 is not universally supported (Terminal.app, notably). The UI must always
show the command as selectable text as well, and must not claim it copied when
`Copy` returned an error.

### `cmd/wharf` — the client command

The repo's documented rule is that **verbs are spelled as flags, never
positionals**, because a positional argument names a host (`main.go:10-12`,
`README.md:97`). `wharf remote <token>` would break that rule and would collide
with a host actually named `remote`. So:

```
wharf --remote <token> [--timeout 2m] [--sh] -- <argv...>
```

Handled **before `flag.Parse()`**, exactly like `--session-host` at
`main.go:48`, because stdlib `flag` swallows `--` and the remaining words would
then trip the "at most one host argument" check.

Two command forms:

- `-- argv...` (default): the argv is shell-quoted **once, by wharf**, and run as
  `<login shell> -lc '<quoted>'`. This gives login-shell `PATH` parity with what
  the user sees interactively, while making it impossible for the agent's
  quoting to be mangled by two shell layers. This is the important one — JSON
  payloads in `curl -d` are exactly where the naive approach breaks.
- `--sh 'raw string'`: the string is passed through verbatim, for pipes and
  redirection.

Behaviour:

- stdout → stdout, stderr → stderr, streamed, never buffered wholesale.
- stdin is forwarded when it is not a terminal, capped at **720 KiB** (v1 sends
  it in the request rather than streaming; document the cap in the error). The
  number is derived, not chosen: `(1 MiB frame limit − 64 KiB reserve) × 3/4`,
  because `encoding/json` base64-encodes a `[]byte` and inflates it by a third.
  An earlier 1 MiB figure was unreachable — it encoded to ~1.33 MiB and every
  large pipe failed with a framing error from a package the user has never heard
  of. The command line is budgeted against the same frame separately, measured
  with `json.Marshal` rather than by byte count, since JSON escaping is what
  makes the encoded length unpredictable.
- **Exit codes:** the remote's exit code is passed through verbatim. Wharf's own
  failures use **125** (unreachable grant, bad token, timeout), following the
  `env`/`timeout` convention, because 1 and 2 belong to the remote and to usage
  respectively. Document that a remote exiting 125 is indistinguishable.
- `WHARF_REMOTE_TOKEN` is read when the token argument is absent.
- Put the logic in a function taking explicit argv + `io.Reader`/`io.Writer` and
  returning an exit code, so it is testable without spawning a process — the
  `resetInstance` precedent at `main.go:390`.

### `internal/ui` — grant lifecycle and audit

State, following the `fwd*` convention, with a `// --- remote access ---` banner:

```go
// remote access (real mode; never persisted — a grant dies with wharf)
raGrant *remoteaccess.Grant
raLog   []raEntry // most recent first, capped at raLogMax
raIdx   int
raErr   string
raCopied bool     // whether OSC 52 actually succeeded
```

Keys — mirroring the `f`/`F` forwards pair, both free on the hosts tab:

- **`r`** on the hosts tab: toggle a grant on the selected host's live session.
  With no live session, set an inline error rather than dialling — a grant must
  ride an existing connection.
- **`A`**: the remote-access overlay (`modalRemoteAccess`) showing the command,
  the token's expiry, and the live command log. As shipped it is reachable from
  *any* tab in real mode, mirroring `F` for forwards, and carries its own keys:
  `j`/`k` through the log, `c` to re-copy the command line (the first attempt is
  often swallowed by the terminal), `x`/`d` to revoke, `esc`/`A` to close.

Note `r` is bound on the *projects* tab for identity reset; that is a different
key map and does not clash.

Header badge: a `remoteAccessChip` next to `forwardChip` in `view.go:332-349`,
inserted in the same two branches. Use `t.Warn` — `t.Blue` is forwards',
`t.Ok`/`t.Err` are the sync dot's. It must be visually obvious: this is the
indicator that something else can run commands on a real host.

Audit events arrive from arbitrary goroutines via the `SetNotify`/`p.Send`
bridge, exactly like `sshx.ForwardEndedMsg`. Define a `ui`-local msg type fed by
`Options.Notify`.

Revocation must fire on **all** of: `r` toggled off, TTL expiry, the session
ending, `lock()`, and `doQuit()`. The `lock()` one matters most and is easy to
miss — a grant outliving a vault lock would be a real hole, since locking is what
a user does when they walk away.

### Windows

The grant server is unix-only in v1, matching the session-host split. Provide a
`remoteaccess_windows.go` whose `Open` returns a clear error explaining why, in
the register of `sessionhost_windows.go:11-13`. The UI must degrade to an inline
error, not a crash. CI builds and tests on `windows-latest`, so everything must
compile there.

`sessd.Remote.Exec` **does** work on Windows (in-process) and must be implemented
there — the limitation is the grant socket, not exec.

## Verification

CI runs exactly `go vet ./...` and `go test -race ./...` on ubuntu and windows.
Reproduce locally, and additionally cross-check the Windows build:

```sh
go vet ./...
go test -race ./...
GOOS=windows GOARCH=amd64 go build ./...
```

Tests required per phase:

- `sshx`: exec against the in-process gliderlabs sshd — stdout, stderr and a
  non-zero exit code; and the load-bearing assertion that **the PTY session's
  ring buffer is unchanged** after an exec, which is what proves isolation.
  `t.Setenv("SSH_AUTH_SOCK", "")` in every test, no `t.Parallel`, mutex-guarded
  buffers only.
- `sessd`: exec round-trip through a real spawned host process, plus a
  **concurrent** exec test that would fail if correlation were dropped.
- `remoteaccess`: a wrong token is rejected; a revoked grant refuses new
  commands and its socket is gone; TTL expiry; audit events fire on both start
  and finish.
- `cmd/wharf`: argv quoting round-trip (the `curl -d '{"a":1}'` case), exit-code
  passthrough, and 125 on an unreachable grant.
- `ui`: grant toggles on/off, the badge appears, the log renders, revocation on
  lock, and demo-mode inertness (`TestForwardDemoInert` is the template).

## Style

The repo has no linter and no style guide; the comment prose *is* the
convention. Every exported identifier gets a comment explaining **why**, and
where a choice was contentious it names the alternative that was rejected —
see `sessd.go:16-21`, `paths.go:41-45`, `main.go:149-150`. Match that register.
Test names are sentences.

---

# Phase 2 — the in-session hotkey

Phase 1 put the grant toggle on the dashboard (`r`), because that is where the
TUI is running. This phase adds the thing the feature was originally asked for:
a hotkey pressed **while attached to the session**, so you never leave the shell
you are working in.

## The problem this has to solve

While attached, `tea.Exec` hands the raw TTY to the session-host child and the
Bubble Tea program is suspended. `Update` is not running. Therefore:

- No `tea.KeyMsg` exists to bind. The only thing that sees the keystroke is the
  byte scanner in `sessd/attach.go:forward`, which already watches for the
  detach byte.
- **The grant cannot live in `Model`.** `Model` is a value copied on every
  update and mutated only by `Update`; a callback firing from the attach
  goroutine may not touch it. Ownership has to move out of the Model.
- Nothing can be rendered through the view layer. Feedback has to be written
  directly to the terminal, in raw mode, with `\r\n` line endings.

## `remoteaccess.Holder` — grant ownership moves here

A concurrency-safe holder for *the* grant (there is one app-wide, per phase 1).
The `Model` keeps a stable `*Holder` pointer and reads through it; the attach
callback calls it directly.

```go
// Holder owns the process's single remote-access grant. It exists because the
// grant must be toggled from two places that never run at the same time: the
// dashboard reducer, and the attach byte scanner running while the Bubble Tea
// program is suspended. A value on the Model could not serve the second.
type Holder struct{ ... }

func NewHolder() *Holder

// Toggle revokes the current grant, or mints one for this host if there is
// none (or if the live grant belongs to a different host). It reports what it
// did so a caller with no view layer can say so.
func (h *Holder) Toggle(opts Options) (Outcome, error)

func (h *Holder) Current() *Grant     // nil when none
func (h *Holder) Revoke()             // idempotent
func (h *Holder) Log() []Entry        // newest first, capped
func (h *Holder) Changed() <-chan struct{} // coalescing re-render nudge
```

**The audit log moves into the Holder too.** In phase 1 it lived on the Model,
fed by a depth-64 channel that dropped events when full — a defect a security
review flagged, since an agent could flood trivial commands to hide a real one.
While attached, the program is suspended for minutes at a time, which makes
dropping a certainty rather than an edge case. With the log in the Holder,
nothing is ever lost: `Changed()` becomes a coalescing *nudge* to re-render,
and a dropped nudge costs nothing because the UI re-reads the whole log.

This is a real simplification, not just a move: it deletes the queue, the
generation stamps that guarded against stale queued events, and the drain-on-
revoke path.

## The attach byte

`internal/detachkey` already owns the name-to-control-byte mapping and the
`allowed` set, and already explains why a bindable key must be a single control
byte. Extend it rather than adding a parallel package — but the two bindings
**must not be allowed to collide**, and the capture modal must say so plainly
when a user tries.

Default: `ctrl+]` (0x1D). It is already in `allowed`, it is not needed by the
remote shell, and its telnet-escape heritage makes it a natural "talk to the
client, not the server" key. Stored in `localcfg` beside `detachKey`, as
`remoteKey` — machine-local, never synced, same as the detach key.

`sessd`'s attach path grows a second watched byte and a callback:

```go
type AttachOptions struct {
	Detach       byte
	RemoteAccess byte                  // 0 disables the hotkey
	OnRemoteAccess func() string       // returns the line(s) to print, raw-mode ready
}

func (r *Remote) AttachWith(opts AttachOptions) tea.ExecCommand
```

`forward` flushes the bytes before the hotkey, invokes the callback, prints its
return value to the local terminal, and **continues the session with the rest of
the chunk** — unlike the detach byte, which returns. The hotkey byte itself is
never forwarded to the remote.

The same must be done in `internal/sshx/attach.go`, which is the Windows
in-process path. On Windows `remoteaccess.Open` returns `ErrUnsupported`, so the
callback there prints that explanation rather than doing nothing — a key that
silently does nothing is worse than one that says why.

## What gets printed

Raw mode, so `\r\n`, and short. On grant:

```
  wharf: remote access ON for web1, expires 15:04 — copied to clipboard
  wharf --remote <token> -- <your command>
```

On revoke: one line. On failure: one line naming the cause.

The command line is printed in full even when the OSC 52 copy succeeds, because
the copy is silently swallowed by some terminals and the printed line is the
only fallback. That does put the token in the local terminal's scrollback —
the same exposure the dashboard overlay already accepts, and consistency is
worth more here than a marginal reduction.

**Known limitation, to be documented rather than worked around:** printing into
a full-screen remote application (vim, htop) corrupts its display until it
repaints. There is no general fix — wharf does not know what the remote is
drawing. The OSC 52 copy is what makes this survivable in practice: the user can
press the key, ignore the smudge, `ctrl+l`, and paste.

## Requirements

- Pressing the key twice toggles; the second press revokes and says so.

**The two entry points deliberately do not mean the same thing**, and the
asymmetry needs to be written down or it reads as a bug:

| | dashboard `r` | attached `ctrl+]` |
|---|---|---|
| a grant is live elsewhere | **revokes it**, whatever the cursor is on | **replaces it**, naming the host that lost it |
| no grant is live | grants on the selected host | grants on the attached host |

Revoking must never depend on cursor position — least of all when the granted
host's session has since died and its row may not even be selectable, which is
exactly when a user reaches for the key. Attached, the host is not in question,
so replace is the only sensible reading there. The cost is a small trap: cursor
on `db1`, grant live on `web1`, press `r` expecting to grant `db1` and you
revoke `web1` instead, needing a second press. That is accepted, and mitigated
by the hint bar reading `r revoke remote` whenever a grant exists and by the
toast naming the host that lost it.
- Pressing it while a grant is live **on another host** replaces it, and the
  printed line says which host lost it. Silently moving a capability is not
  acceptable.
- The byte is never forwarded to the remote, in either the grant or revoke case.
- After detach, the dashboard reflects reality — badge, overlay and log all read
  from the Holder, so no synchronisation step is needed.
- Everything phase 1 revokes on (toggle, TTL, session end, lock, quit) must
  still revoke a grant minted in-session. `lock()` especially.

## Tests

- `detachkey`: the two bindings cannot collide; the error names the conflict.
- `sessd` / `sshx`: the hotkey byte is **not** forwarded to the remote (assert on
  what the server received); the callback fires; the session continues after it;
  bytes before and after the hotkey in the same chunk both arrive intact — that
  chunk-splitting case is where this will break if it breaks.
- `remoteaccess.Holder`: concurrent Toggle/Revoke under `-race`; the log is
  never lossy under a flood, which is the property the queue failed to give.
- `ui`: a grant minted while attached is visible after `detachedMsg` with no
  extra step; `lock()` still revokes it.
