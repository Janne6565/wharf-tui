<!-- AUTO-SYNCED from agents KB: projects/wharf.md @ 257caad.
     Do NOT edit here — edit the source in ~/projects/agents and re-run scripts/sync-conventions.sh. -->

# Wharf

A terminal-based SSH client (think Termius, but a keyboard-driven TUI) with optional
cloud sync and team collaboration. **Local-first**: hosts, keys and sessions work with
no account against a local encrypted vault; an account only adds the *online* features —
cross-machine sync and team projects — under a **zero-knowledge** model where the server
only ever holds ciphertext.

- **Repos:**
  - github.com/Janne6565/wharf-tui — **flagship TUI client** (Go + Bubble Tea). Exists.
  - github.com/Janne6565/wharf-web — landing + web auth flow (React + **TanStack Start**,
    deliberate upgrade from plain Vite SPA for future landing-page SSR). Exists.
  - github.com/Janne6565/wharf-backend — sync + device-code auth (Java 21 + Spring Boot).
    Exists. Projects/team endpoints still planned.
  - `wharf-mobile` — companion app (React Native + Expo). Planned.
  - github.com/Janne6565/wharf-deployment — Kustomize base + single `main` overlay
    (merge-to-main = prod deploy), ArgoCD app wired via cluster-deployment. Exists.
- **Local:** clone the repo(s) above into `~/projects/wharf/<repo-name>/` (multi-repo, one
  subfolder per repo). Always `git pull` before reading. See
  [repo conventions](README.md#local-repos--clone-on-demand-pull-before-reading).
- **Cluster:** namespace `wharf` — **deployed** (2026-07-15): backend + web (Nitro
  Node) + postgres StatefulSet, single host `wharf.jannekeipert.de` with `/api`
  path-routed to the backend (same-origin, no CORS, SameSite=Strict cookie works).
  Sealed secrets for JWT key + DB password. CI: push to main builds
  `ghcr.io/janne6565/wharf-*:main-<sha>` (public packages) and bumps the pin in
  wharf-deployment — auth via a repo-scoped **deploy key** (`DEPLOY_REPO_SSH_KEY`
  secret on both product repos; see concepts/CICD.md), bump retries on concurrent
  pushes. Loop verified end-to-end 2026-07-15.
- **Design source:** Claude Design project `33a77f79-40ef-4774-8324-6ece35835b06`
  (files: Wharf TUI v2, Wharf Web Auth **v2** (authoritative; v1 superseded),
  Wharf Landing, Wharf Favicon (variant 1a "prompt" selected), Wharf Mobile). Import
  via the `claude_design` MCP (`DesignSync` tool). Removed by decision:
  shared/multiplayer SSH sessions, session chat, member presence.

## Idea
Manage your SSH fleet — hosts (searchable/filterable by tags, projects, status), keys/
identities (ED25519, RSA, YubiKey resident), and tabbed sessions (detach keeps them
running) — entirely from a fast TUI: `j/k`, `/`, `1–4`, `tab`, `enter`, `?`. Three themes
(abyss/phosphor/amber). Signing in unlocks the **Projects** tab: shared host workspaces,
invite by email, roles (owner/admin/member); private keys are never shared.

## Security model
- Master password → vault key via **argon2id**, client-side only.
- Vault blobs sealed with **XChaCha20-Poly1305** before upload; server stores ciphertext.
- Sign-in is a **browser device-code** pairing (Google/GitHub/email OAuth) — no password
  is ever typed into the terminal.
- Only recovery path is a **40-character recovery code** shown once at onboarding;
  resetting issues a new code and invalidates the old one. No email reset, no backdoor.

## Stack
- **TUI (flagship):** Go + [Bubble Tea](https://github.com/charmbracelet/bubbletea)
  (Elm architecture) + Lip Gloss + `x/ansi`. Single static binary, no root. This is the
  portfolio's **first Go+Bubble Tea TUI** — a deliberate deviation from the house
  React/Spring stack, justified by the "single binary, no root" client requirement.
- **Web:** TanStack Start (React 19, Bun, Tailwind, TanStack Router/Query, Orval,
  react-hook-form+Zod, typed i18n). Auth routes are `ssr:false` — all crypto is
  client-only: argon2id via **hash-wasm** (libsodium.js can't do parallelism=4),
  XChaCha20 via libsodium-wrappers (CJS-aliased — its ESM entry is broken), and a
  TS port of the WHARFV vault format proven byte-compatible with the Go
  implementation via a committed fixture.
- **Backend:** Java 21 + Spring Boot per house AUTH.md (jjwt access/refresh,
  `tokenVersion` claim for mass revocation, Bucket4j, Flyway, PostgreSQL/H2).
  Zero-knowledge credential contract (documented in wharf-backend README):
  masterKey = argon2id(password, salt=SHA-256(email)[0:16], t=3/m=64MiB/p=4);
  authKey / recoveryAuthKey = HKDF-SHA256 with infos `wharf/auth/v1` /
  `wharf/recovery-auth/v1`; server bcrypt-hashes those keys and stores the vault
  as an opaque blob. Device pairing is **web→terminal**: web issues an 8-char code
  (`POST /device-codes`), TUI exchanges it (`POST /device-codes/exchange`).
- **Mobile (planned):** React Native+Expo. **Deploy (planned):** Kustomize+ArgoCD.

## Status
- **wharf-tui:** **usable SSH client** (v1 milestone done, 2026-07-14). Real SSH via
  `internal/sshx` (agent/keyfile/password/keyboard-interactive auth, skeema/knownhosts
  TOFU, detachable sessions with ring-buffer replay, full-screen takeover via
  `tea.Exec`, `ctrl+\` detach). Per-host auth mode — **key (default) or password**,
  form shows only the mode's field; password mode skips pubkey offers for
  strict-MaxAuthTries servers — with a **stored per-host password** in the vault
  (host form field, or `ctrl+r` "remember" in the password prompt; stored password
  replays silently, falls back to prompt on rejection; legacy ""/"auto" values read
  as key mode). Encrypted vault persistence (`internal/vault`,
  argon2id + XChaCha20-Poly1305, password + one-time recovery-code slots) with a
  typed store (`internal/store`). Host CRUD forms, `~/.ssh/config` import
  (`internal/sshcfg`), async reachability probes (`internal/probe`), ed25519 keygen +
  `~/.ssh` scan (`internal/keys`). `--demo` preserves the design prototype. Account
  sign-in/projects remain **simulated** pending the TUI sync client. Roadmap next: port
  forwarding, sync client against the now-real backend.
- **wharf-backend:** **v1 auth/vault/pairing API done** (2026-07-14): register/login/
  refresh (COOKIE|DIRECT token modes), recovery verify/reset (rotates code, bumps
  `tokenVersion` to revoke all sessions), device-code issue/exchange (one-time,
  pessimistic-locked), vault GET/PUT with optimistic versioning. Hardened after
  review: pre-decode base64 size cap, bcrypt timing equalization against user
  enumeration, XFF only trusted behind proxy, Caffeine-backed rate buckets,
  fail-closed prod secret guard. 25 tests green; `openapi.json` committed at repo
  root (Orval source). Projects/team endpoints + deployment still open.
- **wharf-web:** **web auth flow + landing done** (2026-07-15): the 5 auth screens
  restyled to `Wharf Web Auth v2.dc.html` (all-mono, square, fieldset label chips,
  bracketed buttons, `❯_` logo; Google/GitHub OAuth buttons rendered but disabled —
  no backend OAuth yet; recover screen keeps an email field the design omits since
  recovery verify is keyed email+code). **SSR landing page** at `/` per
  `Wharf Landing.dc.html` (server-rendered — the reason for TanStack Start; auth
  routes stay `ssr:false`) + `favicon.svg` (design variant 1a). Client-side WHARFV
  vault create/unlock/re-encrypt with byte-compat proven against the Go vault via
  committed fixture; E2E suite against the live backend (opt-in `E2E=1`). Design
  sources copied to `~/projects/wharf/design/`.

## Notable (stands out vs other projects)
- **Only Go + Bubble Tea TUI** in the portfolio (alongside Cosy's Go/Rust as non-house
  languages).
- **Local-first with an optional account** — unusual for these projects, which are
  normally account-gated.
- **Zero-knowledge** end-to-end encryption with a no-backdoor recovery-code model.

## Notes for agents
- The TUI follows the Elm architecture: `internal/ui/{model,update,view}.go` plus
  flow-specific files (`update_unlock.go`, `update_session.go`, `view_forms.go`, …).
  Color is stored as theme *roles* (resolved at render) so live theme switches recolor
  scrollback.
- `internal/ui/render_test.go` drives the model headlessly and dumps frames
  (`go test ./internal/ui -run TestDumpFrames -v`) — the fastest way to eyeball layout
  without a TTY (demo mode). `internal/ui/flows_test.go` covers the real-mode flows
  with injected fake vault hooks (`Config.OpenVault`/`CreateVault`).
- Engine contract: prompts (TOFU, secrets) arrive as `sshx` messages with buffered(1)
  `Reply` channels via `Manager.SetNotify(p.Send)` — reply exactly once.
  `Attach().Run()` returns nil on both detach and death; distinguish via
  `Manager.Get`/`SessionEndedMsg`. Session state lives in the Manager, never the Model.
- Multi-rune `tea.KeyMsg` (fast typing/paste) is split per-rune at the top of
  `handleKey` — don't add input handlers that assume single-rune messages elsewhere.
- `internal/sshx` tests run an in-process gliderlabs sshd; keep them race-clean
  (`go test -race ./internal/sshx/`).
