<!-- AUTO-SYNCED from agents KB: projects/wharf.md @ fab34a5.
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
    Exists. Projects/team endpoints live (2026-07-16).
  - github.com/Janne6565/wharf-mobile — companion app (React Native + Expo, public).
    Exists (2026-07-16): M0–M5 done (scaffold, crypto core w/ local wharf-argon2
    Expo Module, auth/pairing/biometric-DEK unlock, personal sync engine + host
    CRUD, member-level projects, invite+finalize). In-app Google/GitHub sign-in
    (2026-07-16): authorize?client=mobile in the system browser, wharf://oauth
    deep link returns a one-time device code exchanged in-app — no manual
    pairing-code typing (/pair kept as fallback). Remaining: M6 polish + EAS
    TestFlight/Play release, on-hardware crypto self-test (Settings → Developer,
    dev builds). Mobile v1 boundary: NO rotation/removal/role-change endpoints
    surfaced. Plan in repo `docs/PLAN.md`.
    **Native crypto fix (2026-07-17):** react-native-libsodium's JSI only accepts
    AEAD additional_data as a UTF-8 string — impossible for the binary WHARFV/WHARFP
    header AAD, so every on-device vault open failed as "wrong master password".
    Device backend now uses pure-JS @noble XChaCha20-Poly1305 + a faithful NaCl
    sealed box, byte-parity-tested against libsodium in CI; only real auth failures
    map to wrong-secret. **M7 SSH terminal built (2026-07-17,** pending on-device
    verify): gomobile Go engine `sshengine/` ports wharf-tui sshx (TOFU,
    stored-password replay, ring scrollback; password+keyboard-interactive ONLY —
    no key mode on mobile, decision 5 in PLAN.md), `modules/wharf-ssh` Expo module
    (Swift done + app compiles; Kotlin awaits an NDK for the aar), xterm.js in an
    offline WebView asset, terminal screen per mock 03 with sticky ctrl/alt key row;
    vault lock closes all sessions; 33 MB iOS xcframework committed so builds need
    no Go toolchain (`scripts/build-ssh-engine.sh` rebuilds).
    **Liquid Glass tab bar (2026-07-17,** pending on-device verify — needs a
    dev-client rebuild): on iOS 26+ (`isLiquidGlassAvailable()`) the `(tabs)` bar
    floats absolute/transparent over a native `GlassView` (expo-glass-effect
    ~57.0.1); `ScreenContainer` pads bottom by the bar height via
    `BottomTabBarHeightContext` from **`expo-router/js-tabs`** — SDK 57 vendors
    bottom-tabs inside expo-router, so `@react-navigation/bottom-tabs` must NOT
    be installed separately (a second copy would be a different context object
    and the padding would silently read 0). Android/older iOS keep the solid
    `shellRaised` bar unchanged.
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

- **Projects (team workspaces) shipped 2026-07-16** across backend + TUI + web
  (mobile follows). Zero-knowledge sharing: per-user X25519 identity keypair stored
  in the personal vault payload (**store schema 2** — pre-projects builds hard-error
  on v2 payloads, deliberate), per-project **WHARFP** blob (32B header AAD +
  XChaCha20 body, no key slots) under a random DEK, DEK distributed as 80-byte
  `crypto_box_seal` sealed boxes to member pubkeys (server-distributed pubkeys =
  accepted v1 MITM caveat, documented in wharf-backend README). Invites are
  accept-then-finalize (invitee joins unkeyed; any admin client seals the DEK on its
  next pass); member removal is only expressible via the atomic rotate endpoint
  (fresh DEK, re-wrap remaining). Roles owner/admin/member, server ACL, 404-not-403
  for non-members. Cross-impl byte-compat proven by committed Go-generated fixtures
  (`project-fixture.json`) in wharf-web and wharf-mobile. Invite notification
  emails go through the **mail-service** (`MAIL_SERVICE_API_KEY` sealed secret,
  send-scoped key on the info@jannekeipert.de connection; Noop client when unset).
  Project payload note: TUI marshals empty docs as `hosts:null` — clients must
  treat null as empty for fingerprint parity.
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
  `~/.ssh` scan (`internal/keys`). `--demo` preserves the design prototype.
  **Real cloud sync done** (2026-07-15): `internal/api` (hand-rolled client, DIRECT
  tokens, refresh-retry-on-401, `WHARF_API_BASE` override) + `internal/sync`
  (full-blob optimistic-version engine: fast-forward pull/push, 409 → re-pass,
  both-changed → keep-local/take-remote modal, zero-hosts side auto-loses on first
  sync). Device pairing via the web `/device` code. Session file `session.enc` next
  to the vault, XChaCha20 under an HKDF subkey of the vault DEK — sync only while
  unlocked; unreadable file → signed-out → re-pair. Master password retained in
  memory while unlocked (needed to adopt remote blobs with foreign salts), zeroed on
  lock. Opt-in live E2E via `WHARF_E2E_BASE`. **Projects tab is real**
  (2026-07-16): store schema v2 identity, per-project WHARFP sync with offline blob
  cache, invites/finalize/rotation — see the Projects entry at the top of Status.
  Roadmap next: port forwarding.
- **wharf-backend:** **v1 auth/vault/pairing API done** (2026-07-14): register/login/
  refresh (COOKIE|DIRECT token modes), recovery verify/reset (rotates code, bumps
  `tokenVersion` to revoke all sessions), device-code issue/exchange (one-time,
  pessimistic-locked), vault GET/PUT with optimistic versioning. Hardened after
  review: pre-decode base64 size cap, bcrypt timing equalization against user
  enumeration, XFF only trusted behind proxy, Caffeine-backed rate buckets,
  fail-closed prod secret guard. **Google/GitHub OAuth login done** (2026-07-15) per
  AUTH.md: authorize/callback/providers endpoints, one-time DB state store,
  `oauth_identities` auto-linked by verified email, nullable `auth_key_hash` (dummy
  bcrypt keeps timing equal), atomic `POST /auth/setup` (recovery + initial vault +
  optional password authKey) for OAuth-first accounts, `users/me` exposes
  `hasPassword/hasRecovery/hasVault`. Providers enabled only when `OAUTH_*` env
  creds are set (prod: sealed `wharf-oauth-secret`, optional — see
  wharf-deployment/docs/secrets.md). 61 tests green; `openapi.json` committed at
  repo root (Orval source). Projects/invites/rotation endpoints + mail client live (2026-07-16, 109 tests).
  **Mobile OAuth deep-link hand-off** (2026-07-16): `authorize?client=mobile`
  (client recorded on the one-time state row, V5 migration); a mobile callback
  issues a one-time device code and 302s to `wharf://oauth?code=…` (config
  `OAUTH_MOBILE_REDIRECT_URI`; no cookie, no refresh token minted), exchanged
  at the existing `/device-codes/exchange`. Errors deep-link as `?error=<code>`;
  `invalid_state` (client unknowable) keeps the web target. 122 tests.
- **wharf-web:** **web auth flow + landing done** (2026-07-15): the 5 auth screens
  restyled to `Wharf Web Auth v2.dc.html` (all-mono, square, fieldset label chips,
  bracketed buttons, `❯_` logo; Google/GitHub OAuth buttons rendered but disabled —
  no backend OAuth yet; recover screen keeps an email field the design omits since
  recovery verify is keyed email+code). **SSR landing page** at `/` per
  `Wharf Landing.dc.html` (server-rendered — the reason for TanStack Start; auth
  routes stay `ssr:false`) + `favicon.svg` (design variant 1a). Client-side WHARFV
  vault create/unlock/re-encrypt with byte-compat proven against the Go vault via
  committed fixture; E2E suite against the live backend (opt-in `E2E=1`). **OAuth
  flows wired** (2026-07-15): buttons enable from `GET /auth/oauth/providers`,
  `/oauth/complete` (refresh → route by `hasVault`), `/set-password` (OAuth-first
  onboarding via atomic `/auth/setup`, shares `buildOnboardingVault` with signup),
  `/unlock` (returning OAuth user). Design sources copied to
  `~/projects/wharf/design/`. **`/connections` is the post-auth hub**
  (2026-07-15): the landing nav shows a `[ profile ]` link (→ `/unlock`) for a
  signed-in visitor instead of "sign in" (gated on `useAuthInformation`; SSR
  renders the anonymous branch until the silent refresh resolves, no hydration
  mismatch); password sign-in, the returning-OAuth `/unlock`, and the
  `requireAnonymous` redirect all land on `/connections` (was `/device`), which
  lists hosts and links out to the terminal-pairing screen. `/unlock`
  short-circuits to `/connections` when the vault is already primed in memory.
  Fresh-signup onboarding still ends on `/device` (guided "pair your terminal"
  step 3). Note: the root `beforeLoad` silent refresh is dehydrated from SSR and
  does **not** re-run on initial client hydration, so `RootDocument` also kicks
  the (memoized) `ensureSessionBootstrapped()` off in a mount effect — otherwise
  signed-in state only resolved on the next navigation/link-preload (the nav
  appeared as "sign in" until you hovered a link). For the same dehydration
  reason the **route guards** (`requireAuth`/`requireAnonymous`/`requireVault`)
  each `await ensureSessionBootstrapped()` themselves before reading the token —
  otherwise a hard reload of an `ssr:false` guarded route (e.g. `/unlock`)
  checked the token before the refresh ran and bounced an authenticated user to
  `/signin`. Memoized, so no extra request. **Back-nav + onboarding
  chrome** (2026-07-15): `AuthShell` already had `backTo`/`step` props; every
  auth screen now wires a back link to its predecessor (recover→signin,
  unlock→`/`, connections→`/`, hub-context device→`/connections`), while the
  forward-only onboarding screens (recovery-code, set-password, oauth-complete)
  intentionally have none. `/device` takes an `onboarding` **search param**
  (`validateSearch`): the recovery-code→device step passes `onboarding:true` to
  show the 3-step indicator; connections' "pair a terminal" links pass
  `onboarding:false` so a returning user gets no onboarding steps and a back
  link instead. The page reads it via `getRouteApi("/device").useSearch()`.
  UI uses **lucide-react** icons (never ASCII/UTF glyphs) per REACT.md — brand
  marks, the terminal mockup and prose punctuation excepted. The device screen's
  "install wharf first" opens a reusable `<Modal>` (backdrop/Escape/close,
  Card-style panel) with the `curl … | sh` one-liner + copy button;
  `INSTALL_COMMAND` lives in shared `@/lib/install` (landing + device).
  Blinking cursors are only rendered where the user can actually type: web
  dropped the decorative hero-headline and device terminal-hint cursors (and the
  `blink` keyframe); the TUI dropped the cursor next to the `⚓ wharf` logo but
  keeps the focus-gated cursor in every real input (forms, unlock, `/` search,
  session prompt, device-code entry, invite email). The web brand chip keeps its
  `❯_` "prompt" mark (design variant 1a) — the underscore is static plain text,
  never animated, so it reads as part of the logo, not a live cursor.

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
