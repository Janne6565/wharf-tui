# wharf

> your fleet, one terminal

Wharf is a keyboard-driven, terminal-based SSH client — manage your hosts, keys and
team projects from a fast TUI. It is **local-first**: everything works with no account,
backed by a local encrypted vault. Signing in only adds the *online* features —
cross-machine sync and team projects — and the server never sees your plaintext.

This repo is the **TUI client** (the flagship). Other surfaces (web auth + landing,
mobile companion, sync backend, deployment) live in sibling `wharf-*` repos.

## Status

**Usable SSH client with real account sync.** Real SSH transport, encrypted vault
persistence, host management, `~/.ssh/config` and Termius import, reachability probes and key
generation are implemented and tested. Device-code sign-in, cross-machine
**vault sync** and **team projects** all run against the live `wharf-backend`
(see [Account sync](#account-sync)). See [Roadmap](#roadmap).

## Install

The command is `wharf` everywhere. Pick whichever fits your machine:

```sh
# macOS
brew install Janne6565/tap/wharf

# anywhere with npm, bun or pnpm — the package is wharf-tui, the command is wharf
bun i -g wharf-tui

# Arch Linux
yay -S wharf-tui-bin

# Debian / Ubuntu
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://janne6565.github.io/wharf-tui/wharf-archive-keyring.gpg \
  | sudo tee /etc/apt/keyrings/wharf-archive-keyring.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/wharf-archive-keyring.gpg] https://janne6565.github.io/wharf-tui stable main" \
  | sudo tee /etc/apt/sources.list.d/wharf.list
sudo apt update && sudo apt install wharf

# Windows
winget install Janne6565.Wharf
# or: scoop bucket add janne6565 https://github.com/Janne6565/scoop-bucket; scoop install wharf
# or: choco install wharf

# anything else with a shell (checksum-verified, no root needed)
curl -fsSL https://raw.githubusercontent.com/Janne6565/wharf-tui/main/scripts/install.sh | sh
```

Or grab a `.tar.gz`, `.deb`, `.rpm` or `.apk` straight from the
[releases page](https://github.com/Janne6565/wharf-tui/releases) — every release ships
a `checksums.txt` to verify against.

**On Windows, one thing differs:** sessions run inside wharf and close when it quits.
Detaching with `ctrl+\`, the sessions overlay and reattaching with replay all work the
same; what does not is a session surviving to the *next* run, which is built on POSIX
primitives Windows has no equivalent for. See
[docs/PACKAGING.md](docs/PACKAGING.md#what-windows-gives-up).

No root, no daemon. The vault lives at
`${XDG_DATA_HOME:-~/.local/share}/wharf/vault.enc` (override with `WHARF_VAULT`).

## Build from source

```sh
go install github.com/Janne6565/wharf-tui/cmd/wharf@latest

# or from a checkout:
go run ./cmd/wharf
go build -o wharf ./cmd/wharf && ./wharf

# stamp a release identity (otherwise --version reports "dev (<commit>)"):
go build -ldflags "-X main.version=v1.2.3" -o wharf ./cmd/wharf

# the original design prototype (sample data, simulated shell, no disk I/O):
go run ./cmd/wharf --demo
```

Requires Go 1.26+. Releases are cut with GoReleaser — see
[docs/PACKAGING.md](docs/PACKAGING.md).

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
| `--proxy <url>` | egress proxy for outbound SSH, overriding `$WHARF_PROXY` and the saved setting |
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
version and platform, the resolved vault / config / session / `known_hosts` paths (with
a present/missing marker each), the API base and device URL, and the proxy in effect
with any password redacted. It is what to paste into a bug report.

Environment: `WHARF_VAULT` (vault file path), `WHARF_CONFIG` (machine-local config file),
`WHARF_API_BASE` (sync backend base URL), `WHARF_NO_BROWSER` (set to anything to stop
sign-in opening the pairing page for you), and the proxy variables below.

### Egress proxy

On a network that only reaches the outside world through a proxy, point wharf at it —
settings tab → **Egress proxy**, or `--proxy`, or `$WHARF_PROXY`:

```
socks5://proxy.corp:1080          SOCKS5 (socks5h:// is accepted and identical)
http://proxy.corp:3128            HTTP CONNECT — what most corporate proxies speak
https://proxy.corp:3129           the same, with TLS to the proxy itself
proxy.corp:1080                   no scheme: read as socks5://
off                               force direct, ignoring $ALL_PROXY
```

Interactive sessions, port forwards and the reachability probes all take this path; the
local end of a `-R` forward does not, since that is a dial from this machine to something
this machine can already reach. `$NO_PROXY` is honoured with its usual grammar (suffixes,
CIDRs, bare IPs, `*`), and loopback is always dialled directly.

Precedence, highest first: `--proxy`, `$WHARF_PROXY`, the saved setting, then
`$ALL_PROXY` / `$HTTPS_PROXY`. The saved setting deliberately outranks the last pair:
those are ambient defaults exported for whatever tooling reads them, while a value typed
into wharf's settings screen means wharf. Setting it to `off` at any level forces a
direct connection and stops the search.

The setting is **not synced**. It describes the network the machine is on, not the
account — syncing an office proxy onto a laptop at home would break every connection
there. It lives in `${XDG_CONFIG_HOME:-~/.config}/wharf/config.json`, which is plaintext:
a password in the URL is **stripped before writing**, so proxies that need credentials
want `$WHARF_PROXY` instead, which lives no longer than the process you set it on.

Behind a proxy the status dots read `? unknown` rather than `offline` when a probe fails:
a proxy declining CONNECT to port 22 on policy and a host that is genuinely down look
identical from here, and calling a reachable host offline is the mistake that stops
someone trying.

### Detach key

`ctrl+\` leaves an attached session running. Some terminals and multiplexers claim that
combination before wharf ever sees it, so it is rebindable: **settings → Detach key**,
then press the key you want. It is stored beside the proxy in the same machine-local
`config.json` (`"detachKey": "ctrl+]"`), and for the same reason — which control keys
survive the trip depends on the terminal in front of you, not on the account.

An attached terminal is in raw mode: wharf sees a byte stream on its way to the remote,
not keypresses. So the binding has to be a `ctrl` combination, and the ones the remote
shell cannot do without — `ctrl+c`, `ctrl+d`, `ctrl+z`, escape, tab, enter, backspace,
flow control — are refused with the reason why. A change takes effect immediately,
including for sessions that are already running.

## How it works

- **First run asks one question:** use wharf on this machine only, or sign in to a
  Wharf account.
  - **`1` — local only** creates your vault here: choose a master password, then write
    down the **40-character recovery code** — it is shown exactly once and is the
    *only* way back in if you forget the password.
  - **`2` — sign in** opens the pairing page in your browser, pairs there, and then
    *installs your account's vault*
    as this machine's vault, so the account's master password and recovery code are
    the only ones this machine has. Nothing is created locally.

  Every later run starts at the unlock screen (`r` switches to recovery-code entry,
  which forces a password reset and issues a *new* code).
- **Sessions are full-fidelity, and they outlive wharf.** Connecting hands your real
  terminal to the remote shell — vim, htop and tmux behave exactly as over plain `ssh`.
  Press **`ctrl+\`** (rebindable — see [Detach key](#detach-key)) to detach: the
  session keeps running while you use the dashboard,
  and reattaching replays recent output. Press **`S`** for the live-sessions overlay.
  Quitting wharf does **not** kill them (on macOS and Linux) — see
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

**One password, one recovery code.** Signing in does not leave the machine with two
vaults. A vault blob carries its own password slot *and* its own recovery slot, and an
account additionally has server-side credentials derived from the same password and
the same code — so a locally created vault pushed into an account would answer to a
recovery code the server has never heard of, and the browser's reset flow would break.
Instead, pairing **adopts the account vault**: it is downloaded, installed verbatim as
this machine's vault file, and the hosts and keys you already had here are merged into
it and pushed on the next pass. Afterwards the account's master password and recovery
code are the ones that work here too.

- If this machine's password already matches the account's, the adoption is silent.
  If it doesn't, the TUI asks for the *account's* master password once.
- Merging never overwrites: a local host or key whose name is already taken on the
  account side is skipped, and the toast says how many were kept and how many clashed.
- An account created through Google/GitHub that has never set a master password has no
  vault to adopt. The TUI will not invent one — it points you at
  `wharf.jannekeipert.de/set-password` and leaves the account untouched.

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
blobs. If it turns out not to open the account's vault, sync does not wedge:
the TUI offers to adopt the account vault, asking for its master password once
and merging this machine's hosts into it.

## Projects

A project is a shared host workspace: its hosts live in their own encrypted
blob, sealed to every member's published key. Private keys are never shared.

- **Opening a project keeps you on the projects tab.** `enter` moves the cursor
  into that project's hosts in the detail pane — `enter` connects, `esc` goes
  back. `tab` rings through list → hosts → members. `f` is the old behaviour on
  purpose: the merged hosts tab, filtered to this project (`esc` clears it).
- **Moving a host in or out** is `p` on the hosts tab: pick the personal vault
  or any project you can write to. The host leaves one document and lands in the
  other, each pushed on its own. A name already taken at the destination is
  refused *before* anything is removed — the two sides are separate blobs with
  separate versioned pushes and cannot be made atomic, so the host must never be
  in flight between them. Saved passwords travel with the host; a host in a
  project is readable by every member, so move deliberately.

**Backend:** defaults to `https://wharf.jannekeipert.de`; override with
`WHARF_API_BASE` (e.g. a local `wharf-backend` on `http://localhost:8080`).

## Upgrading

Projects add a **v2 vault payload** carrying your project identity. By design, a
pre-projects (v1) build **hard-errors** on a v2 payload rather than silently
dropping the identity — so once any device writes v2, **upgrade all of your
devices** before opening the vault on them. The same applies to every later bump:
v3 added synced SSH keys, and **v4** added the ML-KEM-768 half of your project
identity (see below). Your master password and recovery code are unaffected by
any of them; the vault DEK and both unlock slots are unchanged.

**Post-quantum project keys (v4).** Project keys used to be sealed to a bare
X25519 key — classical, and the server keeps every sealed key indefinitely, so a
copy taken today could be decrypted by a future quantum computer. wharf now seals
them with a hybrid **ML-KEM-768 + X25519** wrap, which needs both to be broken.
The first time you open the projects tab after upgrading, wharf adds the ML-KEM
half to your existing identity and republishes it. **Nothing is re-granted and no
project loses access:** the upgraded key keeps your X25519 key, so everything
already sealed to you still opens. Other members seal to you in whichever version
your published key is, so a device still on an older build keeps working. If a device that first created your identity is lost for good, open
the projects tab and press **`R`** on the "sync first" notice to reset your
project identity (rotates your published key; every project re-enters
awaiting-access until an admin re-grants).

## The model

| Without an account (local) | Adds when you sign in |
| --- | --- |
| Hosts, keys/identities, settings — encrypted vault | Cross-machine **sync** of your vault |
| Real SSH sessions: connect / detach / reattach | **Projects**: shared host workspaces *(planned)* |
| `~/.ssh/config` + Termius import, key generation, probes | Invite teammates, roles (owner/admin/member) *(planned)* |

### Security model

- Master password → key via **argon2id**, entirely client-side.
- Vault sealed with **XChaCha20-Poly1305**; the file is designed to be synced verbatim
  as an opaque ciphertext blob (zero-knowledge server).
- Two unlock slots: master password and the one-time **recovery code**. Regenerating
  the code invalidates the old one. No email reset, no support backdoor.
- Sign-in is a **browser device-code** pairing: authentication happens in the browser
  and the TUI never sends a password to the server. It may ask for your account's
  *master* password — that is the key to your vault ciphertext, needed locally to open
  the blob it just downloaded, exactly as the unlock screen needs it every run. The
  device session lives in an encrypted `session.enc` next to the vault (see
  [Account sync](#account-sync)).
- **One password and one recovery code per account, on every device.** Signing in
  installs the account's vault blob verbatim rather than uploading a locally created
  one, so the recovery slot inside the blob and the recovery credential on the server
  stay the same secret — which is what the browser's reset flow requires.
- **The server distributes project public keys, so its copy of yours is checked.**
  Project keys are sealed to each member's published key; a server that
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

> **macOS and Linux only.** On Windows sessions run inside wharf itself and end when it
> does — `os/exec` has no `ExtraFiles` there, so the descriptor handoff below is not
> expressible. Everything else in this section, detach included, behaves the same while
> wharf is open.

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
| `tab` | cycle pane focus (projects tab: list → hosts → members) |
| `enter` | connect / open / toggle |
| `a` / `e` / `d` | add / edit / delete host |
| `p` | move the selected host into a project (or back to personal) |
| `f` | show this project's hosts on the hosts tab *(projects tab)* |
| `m` | import hosts + keys (`~/.ssh/config` or a local Termius profile) |
| `R` | re-probe reachability |
| `g` | generate an ed25519 key *(keys tab)* |
| `s` | sync now *(settings tab, signed in)* |
| `ctrl+r` | remember the typed password *(password prompt)* |
| `ctrl+\` | **detach** the attached session *(rebindable in settings)* |
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
  termius/  local Termius profile import (IndexedDB + keyring, PuTTY .ppk conversion)
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
- [x] Team projects backed by the real backend
- [ ] Hardware keys (YubiKey resident / `-SK`)
- [ ] Assign a scanned key to a host from the keys tab
- [ ] mosh fallback

## License

MIT — see [LICENSE](LICENSE).
