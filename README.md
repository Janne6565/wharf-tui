# wharf ⌢

> your fleet, one terminal

Wharf is a keyboard-driven, terminal-based SSH client — manage your hosts, keys and
team projects from a fast TUI. It is **local-first**: everything works with no account,
backed by a local encrypted vault. Signing in only adds the *online* features —
cross-machine sync and team projects — and the server never sees your plaintext.

This repo is the **TUI client** (the flagship). Other surfaces (web auth + landing,
mobile companion, sync backend, deployment) live in sibling `wharf-*` repos.

## Status

**Usable SSH client.** Real SSH transport, encrypted vault persistence, host management,
`~/.ssh/config` import, reachability probes and key generation are implemented and
tested. The account/sync features (device-code sign-in, team projects) are still
simulated pending `wharf-backend`. See [Roadmap](#roadmap).

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
- **Auth chain:** ssh-agent → configured key file (passphrase prompted in the TUI) →
  password → keyboard-interactive. Host keys are verified against
  `~/.ssh/known_hosts`; unknown hosts show a fingerprint confirmation (TOFU), and a
  **changed** host key is a hard refusal — no override.
- **Probes are advisory.** The online/degraded/offline dots come from an async TCP
  check; they never block connecting.

## The model

| Without an account (local) | Adds when you sign in *(planned)* |
| --- | --- |
| Hosts, keys/identities, settings — encrypted vault | Cross-machine **sync** of your vault |
| Real SSH sessions: connect / detach / reattach | **Projects**: shared host workspaces |
| `~/.ssh/config` import, key generation, probes | Invite teammates, roles (owner/admin/member) |

### Security model

- Master password → key via **argon2id**, entirely client-side.
- Vault sealed with **XChaCha20-Poly1305**; the file is designed to be synced verbatim
  as an opaque ciphertext blob (zero-knowledge server).
- Two unlock slots: master password and the one-time **recovery code**. Regenerating
  the code invalidates the old one. No email reset, no support backdoor.
- Sign-in (when the backend lands) is a **browser device-code** pairing — no account
  password is ever typed into the TUI.

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

- [ ] Port forwarding (`-L`-style local forwards per host)
- [ ] Sync client against `wharf-backend` (device-code auth, ciphertext push/pull)
- [ ] Team projects backed by the real backend
- [ ] Hardware keys (YubiKey resident / `-SK`)
- [ ] Assign a scanned key to a host from the keys tab
- [ ] mosh fallback

## License

MIT — see [LICENSE](LICENSE).
