# Packaging and releases

Everything ships from **one git tag**. `git tag v1.2.3 && git push origin v1.2.3`
runs [`.github/workflows/release.yml`](../.github/workflows/release.yml), which runs
GoReleaser against [`.goreleaser.yaml`](../.goreleaser.yaml) and then the npm publisher.

```
tag v1.2.3
  └─ Release workflow
       ├─ go test -race ./...
       ├─ goreleaser release --clean
       │    ├─ GitHub release: tar.gz + .zip archives + checksums.txt
       │    ├─ .deb / .rpm / .apk attached to the same release
       │    ├─ Homebrew cask   → Janne6565/homebrew-tap
       │    ├─ Scoop manifest  → Janne6565/scoop-bucket
       │    ├─ winget manifest → PR against microsoft/winget-pkgs
       │    └─ AUR PKGBUILD    → aur.archlinux.org/wharf-tui-bin
       └─ scripts/npm-publish.mjs → @wharf-tui/* + wharf-tui on npm
  └─ Chocolatey job (Windows runner, needs: release)
       └─ choco pack + push → community.chocolatey.org
  └─ APT repository workflow (on Release success)
       └─ signed apt repo → GitHub Pages
```

A channel whose credential is missing is **skipped, not failed** — the release job
writes a table to the run summary saying which ones published and which did not.

## What users run

| channel | command | covers |
| --- | --- | --- |
| Homebrew | `brew install Janne6565/tap/wharf` | macOS (Intel + Apple Silicon) |
| npm / bun | `bun i -g wharf-tui` | macOS, Linux, Windows — x64 + arm64 |
| AUR | `yay -S wharf-tui-bin` | Arch Linux |
| APT | see the [repo index page](https://janne6565.github.io/wharf-tui/) | Debian / Ubuntu |
| winget | `winget install Janne6565.Wharf` | Windows |
| Scoop | `scoop bucket add janne6565 https://github.com/Janne6565/scoop-bucket` | Windows |
| Chocolatey | `choco install wharf` | Windows |
| direct | `curl -fsSL …/scripts/install.sh \| sh` | macOS + Linux |
| source | `go install github.com/Janne6565/wharf-tui/cmd/wharf@latest` | anywhere Go builds |

The command is always `wharf`. The npm package is `wharf-tui` only because `wharf`
was already taken on npm.

## One-time setup

### 1. Homebrew tap

Create a **public** repo `Janne6565/homebrew-tap` (public is not optional — `brew`
clones it anonymously). The workflow's own `GITHUB_TOKEN` cannot push to it: it is
scoped to `wharf-tui` and does not reach another repository.

Instead of a PAT, the cask is pushed over SSH with a **deploy key** — scoped to the
one repo by construction, and with no expiry to renew:

```sh
ssh-keygen -t ed25519 -C "wharf-release" -f ~/.ssh/wharf-tap -N ""
pbcopy < ~/.ssh/wharf-tap.pub   # → homebrew-tap → Settings → Deploy keys → Add
pbcopy < ~/.ssh/wharf-tap       # → wharf-tui → Secrets → TAP_DEPLOY_KEY
```

**Tick "Allow write access"** when adding the public key — a read-only deploy key
is the default and the push fails with a plain `access denied`.

### 2. AUR

Register at [aur.archlinux.org](https://aur.archlinux.org), add an SSH **public** key
to the account, and store the matching **private** key as the `AUR_KEY` secret. The
first push creates the `wharf-tui-bin` package; no review or moderation is involved.

### 3. npm

The platform packages live under the `@wharf-tui` scope, so the **organisation
`wharf-tui` has to exist on npm** — free for public packages. Create it, then create
an automation access token and store it as `NPM_TOKEN`.

### 4. APT repository

Enable **Settings → Pages → Source: GitHub Actions**. Generate a signing key, export
the private half, and store it as `APT_GPG_PRIVATE_KEY` (plus `APT_GPG_PASSPHRASE` if
the key has one):

```sh
gpg --quick-generate-key "Wharf Archive Signing Key <jabbekeipert@gmail.com>" rsa4096 sign never
gpg --armor --export-secret-keys "Wharf Archive Signing Key" | pbcopy
```

Keep that key: rotating it forces every existing user to reinstall the keyring.

### 5. Scoop bucket

Create a **public** repo `Janne6565/scoop-bucket` — a bucket is a plain git repo of
JSON manifests, and Scoop clones it anonymously. Same deploy-key arrangement as the
Homebrew tap, stored as `SCOOP_DEPLOY_KEY`:

```sh
ssh-keygen -t ed25519 -C "wharf-release" -f ~/.ssh/wharf-scoop -N ""
pbcopy < ~/.ssh/wharf-scoop.pub   # → scoop-bucket → Settings → Deploy keys → Add (write access)
pbcopy < ~/.ssh/wharf-scoop       # → wharf-tui → Secrets → SCOOP_DEPLOY_KEY
```

### 6. winget

Fork [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) to
`Janne6565/winget-pkgs` — GoReleaser pushes a branch there and opens the PR from it.
A deploy key cannot open a pull request, so this one needs a token — and it has to be
a **classic** PAT with the **`public_repo`** scope, stored as `WINGET_TOKEN`. A
fine-grained PAT is scoped to repositories you own, which is enough to push the
branch to the fork but not to open a PR against `microsoft/winget-pkgs`; classic
`public_repo` is what the winget tooling assumes and the only combination that
reliably does both halves.

This is the one credential here that is not scoped to a single repo — `public_repo`
grants write to every public repo on the account, so give it a short expiry and
rotate it rather than treating it as permanent.

Merges into winget-pkgs are largely automated, but the **first** submission of a new
package identifier gets a human look.

### 7. Chocolatey

Register at [community.chocolatey.org](https://community.chocolatey.org), create an
API key and store it as `CHOCO_API_KEY`. The first version of a new package goes
through **manual moderation**, which can take days — a green job means "submitted",
not "installable".

## Secrets

| secret | channel | missing ⇒ |
| --- | --- | --- |
| `TAP_DEPLOY_KEY` | Homebrew cask | cask not pushed |
| `AUR_KEY` | AUR | PKGBUILD not pushed |
| `NPM_TOKEN` | npm / bun | npm packages not published |
| `SCOOP_DEPLOY_KEY` | Scoop | manifest not pushed |
| `WINGET_TOKEN` | winget | no PR opened |
| `CHOCO_API_KEY` | Chocolatey | package not packed or pushed |
| `APT_GPG_PRIVATE_KEY` | APT repo | apt repo not rebuilt |
| `APT_GPG_PASSPHRASE` | APT repo | only needed for a passphrase-protected key |

## Why npm needs a platform-package split

`bun i -g wharf-tui` has to deliver a **Go binary**, and the usual trick — a
`postinstall` script that downloads the right one — does not work under bun, which
does not run lifecycle scripts for untrusted dependencies.

So each platform gets its own package holding just the binary, tagged with npm's
`os`/`cpu` fields, and the `wharf-tui` package lists all of them as
`optionalDependencies`. The package manager evaluates `os`/`cpu`, installs the one
match and skips the rest without erroring. `npm/wharf-tui/bin/wharf.js` resolves
whichever one landed and execs it with `stdio: "inherit"`, which is what gives the
TUI a real TTY.

[`scripts/npm-publish.mjs`](../scripts/npm-publish.mjs) assembles all seven packages
from `dist/artifacts.json` after GoReleaser has built the binaries, and publishes the
platform packages **before** the meta package so its `optionalDependencies` always
resolve.

## What Windows gives up

Windows ships, with **one** behavioural difference: a session does not outlive the
wharf that dialed it. Detaching with `ctrl+\`, the sessions overlay, reattaching with
replay — all of that works. Quitting wharf closes its sessions instead of leaving them
running for the next run to adopt.

That is a deliberate scope cut, not an oversight. On unix each session runs in a
**detached child process** that owns the SSH connection, reached over a unix socket
whose descriptor the TUI hands the child at spawn. Neither half of that has a Windows
equivalent: `os/exec` does not support `ExtraFiles` on Windows at all, and there is no
`Setsid` to detach the child from the terminal. Making sessions survive there needs a
different handoff — named pipes and a service-like child — which is worth doing on its
own terms rather than as a footnote to a port.

So `internal/sessd` has two implementations behind one API:

| | unix | windows |
| --- | --- | --- |
| session lives in | a detached child process | the wharf process |
| implementation | `client.go`, `host.go`, `proto.go`, `attach.go`, `paths.go` | `pool_windows.go`, on top of `internal/sshx` |
| survives quit | yes, adopted by the next run via `Pool.Adopt` | no |

`internal/ui` never branches on platform — both present the same `Pool` and `Remote`.
The two strings that would otherwise promise the wrong thing live in
`internal/ui/sessions_{unix,windows}.go`.

The other platform splits are small and mechanical:

- `internal/vault/lock_{unix,windows}.go` — `flock` vs `LockFileEx`. Both release the
  lock when the handle closes, so a crash leaves nothing stale behind.
- `internal/termsig` — there is no `SIGWINCH` on Windows, so the resize watcher polls
  `term.GetSize` every 200ms; there is no `SIGQUIT` to ignore, because `ctrl+\` is not
  a signal-generating key there.

CI runs the full suite on `windows-latest` as well as Linux. Two things it cannot
check, and that want a look on real hardware before the first Windows release: that
`ctrl+\` arrives as byte `0x1C` in the Windows console under raw mode, and that the
alt-screen takeover restores cleanly.

## Cutting a release

```sh
git checkout main && git pull
go test -race ./...
goreleaser check
goreleaser release --snapshot --clean   # full dry run into dist/
git tag v1.2.3 && git push origin v1.2.3
```

A tag with a prerelease suffix (`v1.2.3-rc.1`) is marked as a prerelease on GitHub
and published to npm under the `next` dist-tag, so it never becomes what
`bun i -g wharf-tui` installs.
