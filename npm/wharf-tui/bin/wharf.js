#!/usr/bin/env node
// Launcher for the `wharf` command installed from npm.
//
// The Go binary cannot live in this package: npm would then ship every
// platform's binary to every user. Instead each platform gets its own package
// (@wharf-tui/darwin-arm64, …) declared with `os`/`cpu` and listed in this
// package's optionalDependencies, so the package manager installs exactly the
// one that matches and silently skips the rest. This file finds it and execs it.
//
// Deliberately dependency-free and free of install scripts: bun does not run
// lifecycle scripts for untrusted dependencies, so a postinstall downloader —
// the other common approach — would simply never fire under `bun i -g`.

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");

// npm's `cpu` values, not Go's: process.arch reports x64/arm64.
const PLATFORMS = {
  "darwin x64": "darwin-x64",
  "darwin arm64": "darwin-arm64",
  "linux x64": "linux-x64",
  "linux arm64": "linux-arm64",
};

function resolveBinary() {
  const key = `${process.platform} ${process.arch}`;
  const slug = PLATFORMS[key];
  if (!slug) {
    return {
      error:
        `wharf: no prebuilt binary for ${key}.\n` +
        `Supported: ${Object.keys(PLATFORMS).join(", ")}.\n` +
        (process.platform === "win32"
          ? "Windows is not supported yet — wharf's detachable sessions need POSIX\n" +
            "primitives that have no Windows equivalent yet.\n"
          : "") +
        "Build from source instead: go install github.com/Janne6565/wharf-tui/cmd/wharf@latest",
    };
  }
  try {
    return { path: require.resolve(`@wharf-tui/${slug}/bin/wharf`) };
  } catch {
    // The optional dependency was skipped or pruned. This is what an
    // --omit=optional install, or a lockfile built on another platform,
    // looks like from here.
    return {
      error:
        `wharf: the @wharf-tui/${slug} package is missing.\n` +
        "Reinstall without --omit=optional, or run:\n" +
        `  npm i -g wharf-tui --force`,
    };
  }
}

const resolved = resolveBinary();
if (resolved.error) {
  console.error(resolved.error);
  process.exit(1);
}

// npm preserves the executable bit through the tarball, but a stray umask or an
// exotic extractor can drop it, and the failure would otherwise read as EACCES.
try {
  fs.accessSync(resolved.path, fs.constants.X_OK);
} catch {
  try {
    fs.chmodSync(resolved.path, 0o755);
  } catch {
    /* read-only store — let the spawn below report the real error */
  }
}

// stdio: "inherit" hands wharf the real TTY, which a TUI needs: raw mode, the
// alt screen, SIGWINCH on resize and ctrl+\ detach all depend on it.
const result = spawnSync(resolved.path, process.argv.slice(2), {
  stdio: "inherit",
});

if (result.error) {
  console.error("wharf:", result.error.message);
  process.exit(1);
}
// Re-raise a fatal signal rather than masking it as an exit code, so callers
// see the same disposition they would from running the binary directly.
if (result.signal) {
  process.kill(process.pid, result.signal);
}
process.exit(result.status ?? 1);
