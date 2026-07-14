# wharf ⌢

> your fleet, one terminal

Wharf is a keyboard-driven, terminal-based SSH client — manage your hosts, keys and
team projects from a fast TUI. It is **local-first**: everything works with no account,
backed by a local encrypted vault. Signing in only adds the *online* features —
cross-machine sync and team projects — and the server never sees your plaintext.

This repo is the **TUI client** (the flagship). Other surfaces (web auth + landing,
mobile companion, sync backend, deployment) live in sibling `wharf-*` repos.

## Status

Early prototype. The full UI, navigation and flows from the design spec are implemented
and driven by in-memory sample data. SSH sessions are **simulated** for now — the
`exec()` seam in `internal/ui/update.go` is where a real `golang.org/x/crypto/ssh`
channel slots in. See [Roadmap](#roadmap).

## Run

```sh
go run .
# or build a single static binary:
go build -o wharf . && ./wharf
```

Requires Go 1.24+. No root, no daemon.

## The model

| Without an account (local) | Adds when you sign in |
| --- | --- |
| Hosts, keys/identities, settings | Cross-machine **sync** of your vault |
| Open / detach / reconnect SSH sessions | **Projects**: shared host workspaces |
| All three themes, live-switchable | Invite teammates, roles (owner/admin/member) |

The login screen is the entry point, but it always offers **`l` — skip & use local**.

### Security model (target)

- Master password → key via **argon2id**, entirely client-side.
- Vault blobs sealed with **XChaCha20-Poly1305** before they ever leave the device.
- Sign-in is a **browser device-code** pairing — no password is ever typed into the TUI.
- The only password recovery path is a **40-character recovery code** shown once at
  onboarding. No email reset, no support backdoor.

## Keybindings

| Key | Action |
| --- | --- |
| `j` / `k`, `↑` / `↓` | move selection |
| `1`–`4` | switch tab (hosts / projects / keys / settings) |
| `/` | filter hosts (search as you type) |
| `tab` | cycle list ⇄ detail pane focus |
| `enter` | connect / open / toggle |
| `i` | invite member (projects, signed in) |
| `esc` | back / clear search / **detach** session |
| `alt`+`1..9` | switch between open session tabs |
| `q` | lock → login screen (sign in / out) |
| `l` | *(login screen)* skip · use local |
| `?` | toggle help |
| `ctrl`+`c` | quit |

## Layout

```
main.go                     program entry (Bubble Tea)
internal/
  theme/    abyss · phosphor · amber palettes
  data/     in-memory sample vault (hosts / projects / keys)
  ui/       model · update · view (Elm architecture)
```

Built with [Bubble Tea](https://github.com/charmbracelet/bubbletea) +
[Lip Gloss](https://github.com/charmbracelet/lipgloss).

## Roadmap

- [ ] Real SSH transport (`x/crypto/ssh`), PTY, agent forwarding, keep-alive, mosh fallback
- [ ] Local encrypted vault (argon2id + XChaCha20-Poly1305) with on-disk persistence
- [ ] Sync client against `wharf-backend` (device-code auth, ciphertext push/pull)
- [ ] Hardware keys (YubiKey resident / `-SK`)
- [ ] Config import from `~/.ssh/config`

## License

MIT — see [LICENSE](LICENSE).
