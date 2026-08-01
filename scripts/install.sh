#!/bin/sh
# Installs the latest wharf release from GitHub.
#
#   curl -fsSL https://raw.githubusercontent.com/Janne6565/wharf-tui/main/scripts/install.sh | sh
#
# Environment:
#   WHARF_VERSION       version to install (default: the latest release)
#   WHARF_INSTALL_DIR   where to put the binary (default: /usr/local/bin if
#                       writable, else ~/.local/bin)
#
# POSIX sh on purpose: this has to run under dash and busybox ash, not just bash.
# The download is always checksum-verified against the release's checksums.txt.

set -eu

REPO="Janne6565/wharf-tui"
BINARY="wharf"

info() { printf '%s\n' "$*" >&2; }
die() {
	printf 'install: %s\n' "$*" >&2
	exit 1
}

need() {
	command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"
}

# fetch writes a URL to stdout using whichever downloader is present.
fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$1"
	else
		wget -qO- "$1"
	fi
}

command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 ||
	die "either curl or wget is required"
need tar

detect_platform() {
	os=$(uname -s)
	arch=$(uname -m)
	case "$os" in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	MINGW* | MSYS* | CYGWIN*)
		# A POSIX shell on Windows still installs a Windows binary, and the
		# native package managers put it on PATH properly.
		die "on Windows, install with one of:
  winget install Janne6565.Wharf
  scoop bucket add janne6565 https://github.com/Janne6565/scoop-bucket; scoop install wharf
  choco install wharf"
		;;
	*)
		die "unsupported OS: $os — only macOS, Linux and Windows have prebuilt binaries.
Build from source instead: go install github.com/$REPO/cmd/$BINARY@latest"
		;;
	esac
	case "$arch" in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) die "unsupported architecture: $arch" ;;
	esac
	printf '%s_%s' "$os" "$arch"
}

# latest_version reads the newest release tag from the GitHub API. Parsed with
# sed rather than jq, which is not installed on a stock system.
latest_version() {
	fetch "https://api.github.com/repos/$REPO/releases/latest" |
		sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' |
		head -n 1
}

# install_dir picks somewhere on PATH we can actually write to. Preferring a
# writable directory over sudo means the common case needs no privileges.
install_dir() {
	if [ -n "${WHARF_INSTALL_DIR:-}" ]; then
		printf '%s' "$WHARF_INSTALL_DIR"
	elif [ -w /usr/local/bin ] 2>/dev/null; then
		printf '/usr/local/bin'
	else
		printf '%s/.local/bin' "$HOME"
	fi
}

verify_checksum() {
	archive=$1
	expected=$2
	if command -v sha256sum >/dev/null 2>&1; then
		actual=$(sha256sum "$archive" | cut -d' ' -f1)
	elif command -v shasum >/dev/null 2>&1; then
		actual=$(shasum -a 256 "$archive" | cut -d' ' -f1)
	else
		info "warning: no sha256sum or shasum found — skipping checksum verification"
		return 0
	fi
	[ "$actual" = "$expected" ] ||
		die "checksum mismatch for $archive
  expected $expected
  got      $actual"
}

main() {
	platform=$(detect_platform)

	version=${WHARF_VERSION:-$(latest_version)}
	[ -n "$version" ] || die "could not determine the latest version — is there a release yet?"
	# The tag carries a leading v; the artifact names do not.
	bare=${version#v}

	archive="${BINARY}_${bare}_${platform}.tar.gz"
	base="https://github.com/$REPO/releases/download/$version"

	tmp=$(mktemp -d)
	# Leaving a half-downloaded archive behind on failure helps nobody.
	trap 'rm -rf "$tmp"' EXIT INT TERM

	info "Downloading $BINARY $version ($platform)…"
	fetch "$base/$archive" >"$tmp/$archive" ||
		die "download failed — no build for $platform in $version?"

	info "Verifying checksum…"
	fetch "$base/checksums.txt" >"$tmp/checksums.txt" || die "could not fetch checksums.txt"
	expected=$(grep " $archive\$" "$tmp/checksums.txt" | cut -d' ' -f1)
	[ -n "$expected" ] || die "$archive is not listed in checksums.txt"
	verify_checksum "$tmp/$archive" "$expected"

	tar -xzf "$tmp/$archive" -C "$tmp"
	[ -f "$tmp/$BINARY" ] || die "the archive did not contain a $BINARY binary"

	dir=$(install_dir)
	mkdir -p "$dir" 2>/dev/null || true
	if [ -w "$dir" ]; then
		install -m 0755 "$tmp/$BINARY" "$dir/$BINARY"
	else
		info "$dir is not writable, using sudo…"
		need sudo
		sudo install -m 0755 "$tmp/$BINARY" "$dir/$BINARY"
	fi

	info "Installed $BINARY $version to $dir/$BINARY"

	# A binary outside PATH is installed but not usable; say so rather than
	# letting the next `wharf` fail with "command not found".
	case ":$PATH:" in
	*":$dir:"*) info "Run: $BINARY" ;;
	*) info "$dir is not on your PATH — add it, or run $dir/$BINARY directly." ;;
	esac
}

main "$@"
