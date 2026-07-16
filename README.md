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

# the original design prototype (sample data, simulated shell, no disk I/O):
go run . --demo
```

Requires Go 1.24+. No root, no daemon. The vault lives at
`${XDG_DATA_HOME:-~/.local/share}/wharf/vault.enc` (override with `WHARF_VAULT`).

## How it works

- **First run** creates your vault: choose a master password, then write down the
  **40-character recovery code** — it is shown exactly once and is the *only* way back
  in if you forget the password. Every later run starts at the unlock screen
  (`r` switches to recovery-code entry, which forces a password reset and issues a
  *new* code).
- **Sessions are full-fidelity.** Connecting hands your real terminal to the remote
  shell — vim, htop and tmux behave exactly as over plain `ssh`. Press **`ctrl+\`** to
  detach: the session keeps running while you use the dashboard, and reattaching
  replays recent output. `alt+1..9` jumps straight back into a live session.
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
| `alt`+`1..9` | reattach a live session |
| `q` | lock the vault |
| `ctrl+q` | quit (confirms if sessions are live) |
| `?` | toggle help |

## Layout

```
main.go                     program entry (Bubble Tea)
internal/
  theme/    abyss · phosphor · amber palettes
  vault/    argon2id + XChaCha20-Poly1305 encrypted vault file
  store/    hosts & settings document persisted through the vault
  api/      HTTP client for wharf-backend (pairing, refresh, vault get/put)
  sync/     sync engine: session file, optimistic versioning, conflicts
  sshx/     SSH engine: auth chain, known_hosts/TOFU, detachable sessions
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
- [ ] Port forwarding (`-L`-style local forwards per host)
- [ ] Team projects backed by the real backend
- [ ] Hardware keys (YubiKey resident / `-SK`)
- [ ] Assign a scanned key to a host from the keys tab
- [ ] mosh fallback

## License

MIT — see [LICENSE](LICENSE).
