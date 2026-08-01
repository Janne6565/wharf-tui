# Packaging and releases

Everything ships from **one git tag**. `git tag v1.2.3 && git push origin v1.2.3`
runs [`.github/workflows/release.yml`](../.github/workflows/release.yml), which runs
GoReleaser against [`.goreleaser.yaml`](../.goreleaser.yaml) and then the npm publisher.

```
tag v1.2.3
  └─ Release workflow
       ├─ go test -race ./...
       ├─ goreleaser release --clean
       │    ├─ GitHub release: tar.gz archives + checksums.txt
       │    ├─ .deb / .rpm / .apk attached to the same release
       │    ├─ Homebrew cask  → Janne6565/homebrew-tap
       │    └─ AUR PKGBUILD   → aur.archlinux.org/wharf-tui-bin
       └─ scripts/npm-publish.mjs → @wharf-tui/* + wharf-tui on npm
  └─ APT repository workflow (on Release success)
       └─ signed apt repo → GitHub Pages
```

A channel whose credential is missing is **skipped, not failed** — the release job
writes a table to the run summary saying which ones published and which did not.

## What users run

| channel | command | covers |
| --- | --- | --- |
| Homebrew | `brew install Janne6565/tap/wharf` | macOS (Intel + Apple Silicon) |
| npm / bun | `bun i -g wharf-tui` | macOS + Linux, any arch we build |
| AUR | `yay -S wharf-tui-bin` | Arch Linux |
| APT | see the [repo index page](https://janne6565.github.io/wharf-tui/) | Debian / Ubuntu |
| direct | `curl -fsSL …/scripts/install.sh \| sh` | macOS + Linux |
| source | `go install github.com/Janne6565/wharf-tui/cmd/wharf@latest` | anywhere Go builds |

The command is always `wharf`. The npm package is `wharf-tui` only because `wharf`
was already taken on npm.

## One-time setup

### 1. Homebrew tap

Create a **public** repo `Janne6565/homebrew-tap` (public is not optional — `brew`
clones it anonymously). Then create a fine-grained PAT with **Contents: read and
write** scoped to that repo alone, and add it to this repo as the
`TAP_GITHUB_TOKEN` secret. The workflow's own `GITHUB_TOKEN` cannot be used: it is
scoped to `wharf-tui` and cannot push to another repository.

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

## Secrets

| secret | channel | missing ⇒ |
| --- | --- | --- |
| `TAP_GITHUB_TOKEN` | Homebrew cask | cask not pushed |
| `AUR_KEY` | AUR | PKGBUILD not pushed |
| `NPM_TOKEN` | npm / bun | npm packages not published |
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

[`scripts/npm-publish.mjs`](../scripts/npm-publish.mjs) assembles all five packages
from `dist/artifacts.json` after GoReleaser has built the binaries, and publishes the
platform packages **before** the meta package so its `optionalDependencies` always
resolve.

## Windows is not wired up

winget, Chocolatey and Scoop are all deliberately absent, because **wharf does not
compile for Windows** today:

- `internal/vault/lock.go` locks its sidecar with `unix.Flock`.
- `internal/sessd/client.go` passes a listening unix socket to a **detached child
  process over fd 3** and sets `SysProcAttr.Setsid`.
- `internal/sessd/paths.go` checks socket ownership via `syscall.Stat_t.Uid`.
- `internal/sessd/attach.go` and `internal/sshx/attach.go` use `SIGWINCH`/`SIGQUIT`.

The lock, the ownership check and the signals are all straightforward build-tagged
ports. The session handoff is not: sessions that outlive wharf are a core feature,
and Windows has no fd-inheritance equivalent — it would need named pipes and a
different handoff protocol.

Once that lands, adding the three channels is mostly config: add `windows` to
`builds.goos`, then a `scoops:` block (own bucket repo, no review), a `winget:` block
(opens a PR against `microsoft/winget-pkgs`) and a `chocolateys:` block (first package
goes through manual moderation). `npm/wharf-tui/bin/wharf.js` already has the
`win32-x64` slot mapped out in its error message.

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
