# wharf ⌢

> your fleet, one terminal

Wharf is a keyboard-driven, terminal-based SSH client — manage your hosts, keys and
team projects from a fast TUI. It is **local-first**: everything works with no account,
backed by a local encrypted vault. Signing in only adds the *online* features —
cross-machine sync and team projects — and the server never sees your plaintext.

This repo is the **TUI client** (the flagship). Other surfaces (web auth + landing,
mobile companion, sync backend, deployment) live in sibling `wharf-*` repos.

## Status

**Usable SSH client with real account sync.** Real SSH transport, encrypted vault
persistence, host management, `~/.ssh/config` import, reachability probes and key
generation are implemented and tested. Device-code sign-in and cross-machine
**vault sync** now run against the live `wharf-backend`
(see [Account sync](#account-sync)); team projects are still simulated. See
[Roadmap](#roadmap).

## Run

```sh
go run .
# or build a single static binary:
go build -o wharf . && ./wharf

# stamp a release identity (otherwise --version reports "dev (<commit>)"):
go build -ldflags "-X main.version=v1.2.3" -o wharf .

# the original design prototype (sample data, simulated shell, no disk I/O):
go run . --demo
```

Requires Go 1.24+. No root, no daemon. The vault lives at
`${XDG_DATA_HOME:-~/.local/share}/wharf/vault.enc` (override with `WHARF_VAULT`).

## CLI

```
wharf [flags] [host]
```

Bare `wharf` opens the TUI. A **host argument** names a saved host to connect to right
after the vault unlocks — exact name, else a unique name prefix, both case-insensitive
(`wharf prod` works while only one host starts with `prod`). An argument that matches
nothing, or several hosts, only raises a toast: you land on the hosts list, never back
at your shell. Personal hosts only — project hosts need a projects sync that has not
run yet at unlock time.

Verbs are spelled as **flags** precisely so they never claim a name a host could have:

| flag | what it does |
| --- | --- |
| `--version` | print the version and exit |
| `--logout` | delete the local sync session (sign this device out) and exit |
| `--doctor` | print resolved paths and environment, then exit |
| `--reset` | **destructive:** erase this device's vault, session and caches |
| `--vault <path>` | vault file path, overriding `$WHARF_VAULT` |
| `--demo` | sample data and a simulated session — no disk I/O, no real SSH |

`--logout` deliberately needs no master password. The session file is sealed under the
vault DEK, so the in-TUI sign-out is only reachable while unlocked — this is the escape
hatch for a vault you cannot open at all. It is **local only**: the refresh token cannot
be read, let alone revoked server-side, without the vault key. To invalidate sessions on
the server, reset with your recovery code — that rotates the code and revokes every
token.

`--reset` erases this device's wharf state — `vault.enc`, `session.enc`, the cached
project blobs and the lock sidecar — and it cannot be undone: the recovery code unlocks
a vault *file*, so once the file is gone, so is every host, key and stored password in
it. The one exception worth knowing: if the device is signed in, the **server's copy is
untouched**, so signing in again with your master password pulls the vault back.

It only deletes after a typed confirmation:

```
$ wharf --reset
Are you sure you want to reset your wharf instance?

This permanently erases, on this device:
  • ~/.local/share/wharf/projects
  • ~/.local/share/wharf/session.enc
  • ~/.local/share/wharf/vault.enc
  • ~/.local/share/wharf/vault.lock
…
Type "I am sure" to confirm:
```

`y`/`yes` does not count — the phrase has to be typed out (case, spacing and the
apostrophe in `I'm sure` are forgiven). Three further guards: it lists only paths that
actually exist, it refuses when **stdin is not a terminal** so a pipe or CI job can never
satisfy the prompt, and it refuses while **another wharf instance holds the vault lock**,
whose next save would otherwise write the vault straight back.

`--doctor` reads no secrets and never unlocks the vault; it prints the version, Go
version and platform, the resolved vault / session / `known_hosts` paths (with a
present/missing marker each), and the API base and device URL. It is what to paste into
a bug report.

Environment: `WHARF_VAULT` (vault file path), `WHARF_API_BASE` (sync backend base URL).

## How it works

- **First run** creates your vault: choose a master password, then write down the
  **40-character recovery code** — it is shown exactly once and is the *only* way back
  in if you forget the password. Every later run starts at the unlock screen
  (`r` switches to recovery-code entry, which forces a password reset and issues a
  *new* code).
- **Sessions are full-fidelity, and they outlive wharf.** Connecting hands your real
  terminal to the remote shell — vim, htop and tmux behave exactly as over plain `ssh`.
  Press **`ctrl+\`** to detach: the session keeps running while you use the dashboard,
  and reattaching replays recent output. Press **`S`** for the live-sessions overlay.
  Quitting wharf does **not** kill them — see
  [Sessions that outlive wharf](#sessions-that-outlive-wharf).
- **A host can have several sessions.** `enter` on a host that already has one opens a
  picker: reattach to a specific session, kill one (`x` twice — a live shell is not
  something to lose to a stray key), or start another with `n`.
- **Two auth modes per host.** **key** (the default): ssh-agent → configured key
  file (passphrase prompted in the TUI) → keyboard-interactive (2FA). **password**:
  stored/prompted password → keyboard-interactive — it never offers public keys,
  so servers with a strict `MaxAuthTries` aren't burned on key attempts they'll
  never accept. The host form shows only the field the mode needs (key path or
  password). Host keys are verified against `~/.ssh/known_hosts`; unknown hosts
  show a fingerprint confirmation (TOFU), and a **changed** host key is a hard
  refusal — no override.
- **Passwords can be saved per host** (they live only inside the encrypted
  vault): set one in the host form, or press `ctrl+r` ("remember") in the
  password prompt — after a successful login it's stored and future connects go
  straight to the shell. A rejected saved password falls back to the interactive
  prompt.
- **Probes are advisory.** The online/degraded/offline dots come from an async TCP
  check; they never block connecting.

## Account sync

Signing in pairs the TUI with your account at
[wharf.jannekeipert.de](https://wharf.jannekeipert.de) and keeps the vault in sync
across machines. The server only ever stores **ciphertext** (the vault blob is
uploaded verbatim); it never sees your master password or plaintext.

**Pairing** (no account password is ever typed into the terminal):

1. Open `wharf.jannekeipert.de/device` in your browser and sign in — it shows an
   8-character pairing code.
2. In the TUI: settings tab → *Account* → `enter` (or `enter` on the projects
   gate), then type the code (the `XXXX-XXXX` dash form is fine).
3. Done — the header shows your email plus a live sync indicator:
   `● synced` / `⠋ syncing` / `● offline` / `● conflict`.

**Your email must be verified** before the backend hands out a session. If it
isn't, pairing is refused with "email not verified" — confirm the address in
the browser (verification is web-only; the TUI never registers or verifies) and
type the *same* code again: a rejection on this path does not use it up.

**What syncs:** the whole vault payload — hosts (including saved per-host
passwords) and settings. SSH key *files* are not synced; they stay in `~/.ssh`.

**When it syncs:** on unlock (pull), a few seconds after each change (debounced
push), and on demand with `s` on the settings tab. Sync uses optimistic
versioning: pushes carry the last-seen remote version, and a lost race pulls
first and re-evaluates.

**Conflicts:** if this machine *and* the account vault both changed since the
last sync, Wharf never merges silently — a prompt asks you to **keep local**
(overwrite remote) or **take remote** (discard local changes). One exception:
right after pairing, if one side has zero hosts and the other doesn't, the
non-empty side wins automatically.

**Session file:** pairing stores a device-local session (refresh token + sync
bookkeeping) next to the vault as `session.enc`, mode `0600`, encrypted with a
key derived from the unlocked vault (HKDF subkey of the vault DEK,
XChaCha20-Poly1305). It is never part of the synced payload. Consequences: sync
only works while the vault is unlocked, and re-creating the vault (new DEK)
invalidates the session — just pair again. Signing out (settings → *Account*)
deletes the session file and keeps the local vault.

**Master password note:** a remote vault blob is encrypted by whichever client
wrote it, under *your master password* with its own salts. The TUI keeps the
password you unlocked with in memory (zeroed on lock/quit) to open pulled
blobs. If your local vault password differs from your account master password,
pulls fail with an explicit error — set them to the same password to sync.

**Backend:** defaults to `https://wharf.jannekeipert.de`; override with
`WHARF_API_BASE` (e.g. a local `wharf-backend` on `http://localhost:8080`).

## Upgrading

Projects add a **v2 vault payload** carrying your X25519 project identity. By
design, a pre-projects (v1) build **hard-errors** on a v2 payload rather than
silently dropping the identity — so once any device writes v2, **upgrade all of
your devices** before opening the vault on them. Your master password and
recovery code are unaffected by the bump; the vault DEK and both unlock slots are
unchanged. If a device that first created your identity is lost for good, open
the projects tab and press **`R`** on the "sync first" notice to reset your
project identity (rotates your published key; every project re-enters
awaiting-access until an admin re-grants).

## The model

| Without an account (local) | Adds when you sign in |
| --- | --- |
| Hosts, keys/identities, settings — encrypted vault | Cross-machine **sync** of your vault |
| Real SSH sessions: connect / detach / reattach | **Projects**: shared host workspaces *(planned)* |
| `~/.ssh/config` import, key generation, probes | Invite teammates, roles (owner/admin/member) *(planned)* |

### Security model

- Master password → key via **argon2id**, entirely client-side.
- Vault sealed with **XChaCha20-Poly1305**; the file is designed to be synced verbatim
  as an opaque ciphertext blob (zero-knowledge server).
- Two unlock slots: master password and the one-time **recovery code**. Regenerating
  the code invalidates the old one. No email reset, no support backdoor.
- Sign-in is a **browser device-code** pairing — no account password is ever typed
  into the TUI. The device session lives in an encrypted `session.enc` next to the
  vault (see [Account sync](#account-sync)).
- **The server distributes project public keys, so its copy of yours is checked.**
  Project keys are sealed to each member's published X25519 key; a server that
  swapped in its own key for your account would receive every project key shared
  with you, and the only symptom would be projects stuck in awaiting-access. On
  every visit to the projects tab wharf compares the key the server publishes for
  your account against the one in this vault. On a difference it shows a warning
  with **both fingerprints** (SHA-256 of the key, base64, first 16 characters in
  blocks of four — identical across the web and mobile clients, so you can compare
  them by eye), refuses to hand project keys to anyone until it is resolved, and
  offers **`p`** to republish your local key over the server's copy. A server that
  cannot be reached is *unknown*, not a mismatch.

## Sessions that outlive wharf

Connecting does not open the SSH connection inside the TUI. wharf re-executes itself as
a **session host** — one child process per session — hands it a listening unix socket,
and that child owns the `ssh.Client`, the PTY and the 256 KiB scrollback ring. The TUI
attaches over the socket and proxies bytes to your terminal.

So quitting wharf just drops a control connection. The shell keeps running, and the next
`wharf` scans the socket directory, reattaches to whatever is still alive and lists it in
the live strip — `alt+1..9` or `enter` on a host row marked live picks up where you left
off, scrollback and all.

One child per session is deliberate: no singleton daemon to supervise, no protocol
handshake to keep compatible across upgrades, and a crash costs one session instead of
all of them.

```
wharf (TUI)                     wharf --session-host (one per session)
  │                               │ owns ssh.Client + PTY + scrollback ring
  │  spawn, listener on fd 3 ──▶  │ serves $XDG_RUNTIME_DIR/wharf/sessions/*.sock
  │  attach: raw stream ◀──────▶  │
  │  quit ──▶ (child lives on)    │
  └── next run: scan + adopt ──▶  │ still there
```

### Reattaching

`S` opens the live-sessions overlay from any tab: every running session, newest state,
`enter` to attach and `x x` to kill. `enter` on a host row that already has sessions
opens the same picker scoped to that host, plus a **+ new session** row.

`alt+1..9` also jumps to a session, but only in terminals that send Option/Alt as Meta —
**macOS does not by default**. In Terminal.app enable *Settings → Profiles → Keyboard →
Use Option as Meta key*; in iTerm2 set *Settings → Profiles → Keys → Left Option key →
Esc+*. Without that, `S` is the portable route and needs no configuration.

**Boundaries.** Sessions do not survive a reboot or a logout (the runtime directory is
wiped). **Port forwards are not hosted this way** — they are documented as ephemeral and
never persisted, so they still die with the TUI, and the quit prompt says so.

**Trust model.** The socket directory is `0700` (verified, not assumed — it is checked
for ownership and mode on every start) and each socket is `0600`. Anyone who can open
the socket can type into that shell: the same exposure `tmux` and OpenSSH's
`ControlMaster` accept, but new for wharf. The child never receives the master password
and never touches the vault — it gets one host spec over the socket, authenticates with
it, and holds nothing else. `WHARF_RUNTIME_DIR` overrides the location.

## Keybindings

| Key | Action |
| --- | --- |
| `j` / `k`, `↑` / `↓` | move selection |
| `1`–`4` | switch tab (hosts / projects / keys / settings) |
| `/` | filter hosts (search as you type) |
| `tab` | cycle list ⇄ detail pane focus |
| `enter` | connect / open / toggle |
| `a` / `e` / `d` | add / edit / delete host |
| `m` | import `~/.ssh/config` |
| `R` | re-probe reachability |
| `g` | generate an ed25519 key *(keys tab)* |
| `s` | sync now *(settings tab, signed in)* |
| `ctrl+r` | remember the typed password *(password prompt)* |
| `ctrl+\` | **detach** the attached session |
| `S` | live sessions: reattach, kill, or open another |
| `alt`+`1..9` | reattach a live session *(needs Option-as-Meta — see below)* |
| `q` | lock the vault |
| `ctrl+q` | quit (confirms when sessions or forwards are running) |
| `?` | toggle help |

## Layout

```
main.go                     program entry (Bubble Tea)
internal/
  theme/    abyss · phosphor · amber palettes
  vault/    argon2id + XChaCha20-Poly1305 encrypted vault file
  store/    hosts & settings document persisted through the vault
  api/      HTTP client for wharf-backend (pairing, refresh, vault get/put)
  identity/ cross-client fingerprint of the X25519 project identity key
  sync/     sync engine: session file, optimistic versioning, conflicts
  sshx/     SSH engine: auth chain, known_hosts/TOFU, detachable sessions
  sessd/    session-host child processes + their unix-socket protocol
  keys/     ~/.ssh scan + ed25519 generation
  sshcfg/   ~/.ssh/config import
  probe/    advisory TCP reachability checks
  data/     demo-mode fixtures
  ui/       model · update · view (Elm architecture)
```

Built with [Bubble Tea](https://github.com/charmbracelet/bubbletea) +
[Lip Gloss](https://github.com/charmbracelet/lipgloss) and
[`golang.org/x/crypto/ssh`](https://pkg.go.dev/golang.org/x/crypto/ssh).

## Roadmap

- [x] Sync client against `wharf-backend` (device-code auth, ciphertext push/pull)
- [x] Port forwarding (`-L`/`-R`/`-D`, per host)
- [x] Sessions that survive quitting wharf (session-host child processes)
- [ ] Team projects backed by the real backend
- [ ] Hardware keys (YubiKey resident / `-SK`)
- [ ] Assign a scanned key to a host from the keys tab
- [ ] mosh fallback

## License

MIT — see [LICENSE](LICENSE).
