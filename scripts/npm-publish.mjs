#!/usr/bin/env node
// Assembles and publishes the npm/bun distribution from a finished GoReleaser
// build.
//
// Layout (the esbuild/biome pattern):
//
//   @wharf-tui/darwin-arm64   one package per platform, holding just the binary,
//   @wharf-tui/darwin-x64     tagged with npm's `os`/`cpu` fields
//   @wharf-tui/linux-x64
//   @wharf-tui/linux-arm64
//   wharf-tui                 meta package: a `bin` shim plus the four above as
//                             optionalDependencies
//
// The package manager evaluates os/cpu and installs only the matching platform
// package, skipping the others without failing. Nothing is downloaded at install
// time and no lifecycle script runs — which is what makes `bun i -g wharf-tui`
// work, since bun does not run postinstall scripts for untrusted dependencies.
//
// Usage:
//   node scripts/npm-publish.mjs --version 1.2.3 [--dry-run] [--tag next]
//
// Expects `goreleaser release` (or `--snapshot`) to have populated dist/.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DIST = path.join(ROOT, "dist");
const STAGE = path.join(DIST, "npm");
const SCOPE = "@wharf-tui";
const META_PACKAGE = "wharf-tui";

// Go's GOOS/GOARCH on the left, npm's process.platform/process.arch on the
// right. bin/wharf.js keys off the npm spelling, so the two must agree.
const PLATFORMS = [
  { goos: "darwin", goarch: "amd64", os: "darwin", cpu: "x64" },
  { goos: "darwin", goarch: "arm64", os: "darwin", cpu: "arm64" },
  { goos: "linux", goarch: "amd64", os: "linux", cpu: "x64" },
  { goos: "linux", goarch: "arm64", os: "linux", cpu: "arm64" },
  { goos: "windows", goarch: "amd64", os: "win32", cpu: "x64" },
  { goos: "windows", goarch: "arm64", os: "win32", cpu: "arm64" },
];

// Windows needs the .exe suffix to be executable at all; everywhere else the
// bare name is the convention. bin/wharf.js resolves the same two names.
function binaryName(platform) {
  return platform.os === "win32" ? "wharf.exe" : "wharf";
}

const DESCRIPTION =
  "Keyboard-driven terminal SSH client with a local-first encrypted vault";
const REPOSITORY = {
  type: "git",
  url: "git+https://github.com/Janne6565/wharf-tui.git",
};

function parseArgs(argv) {
  const args = { dryRun: false, tag: "latest", version: "" };
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case "--dry-run":
        args.dryRun = true;
        break;
      case "--version":
        args.version = argv[++i];
        break;
      case "--tag":
        args.tag = argv[++i];
        break;
      default:
        fail(`unknown argument: ${argv[i]}`);
    }
  }
  if (!args.version) fail("--version is required");
  // npm rejects a leading v; the git tag has one.
  args.version = args.version.replace(/^v/, "");
  if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(args.version)) {
    fail(`--version ${args.version} is not a semver version`);
  }
  return args;
}

function fail(message) {
  console.error(`npm-publish: ${message}`);
  process.exit(1);
}

// binariesByTarget indexes the GoReleaser build output by "<goos>/<goarch>".
// artifacts.json is the contract between the two halves of the release; reading
// it beats guessing at dist/ directory names, which encode GOAMD64/GOARM levels.
function binariesByTarget() {
  const manifest = path.join(DIST, "artifacts.json");
  if (!fs.existsSync(manifest)) {
    fail(`${manifest} not found — run goreleaser first`);
  }
  const found = new Map();
  for (const artifact of JSON.parse(fs.readFileSync(manifest, "utf8"))) {
    if (artifact.type !== "Binary") continue;
    found.set(`${artifact.goos}/${artifact.goarch}`, path.join(ROOT, artifact.path));
  }
  return found;
}

function writeJSON(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

// stagePlatformPackage builds one @wharf-tui/<os>-<cpu> package around a single
// binary.
function stagePlatformPackage(platform, binary, version) {
  const name = `${platform.os}-${platform.cpu}`;
  const dir = path.join(STAGE, name);
  fs.mkdirSync(path.join(dir, "bin"), { recursive: true });

  const target = path.join(dir, "bin", binaryName(platform));
  fs.copyFileSync(binary, target);
  // npm preserves the mode in the tarball, so setting it here is what makes the
  // installed file executable on the user's machine.
  fs.chmodSync(target, 0o755);

  writeJSON(path.join(dir, "package.json"), {
    name: `${SCOPE}/${name}`,
    version,
    description: `${DESCRIPTION} (${platform.os} ${platform.cpu} binary)`,
    license: "MIT",
    homepage: "https://wharf.jannekeipert.de",
    repository: REPOSITORY,
    os: [platform.os],
    cpu: [platform.cpu],
    files: ["bin"],
    // Yarn PnP keeps dependencies zipped; a binary has to be a real file on
    // disk to be executable.
    preferUnplugged: true,
  });
  fs.copyFileSync(path.join(ROOT, "LICENSE"), path.join(dir, "LICENSE"));
  return { name: `${SCOPE}/${name}`, dir };
}

// stageMetaPackage builds the package users actually install.
function stageMetaPackage(version, platformNames) {
  const dir = path.join(STAGE, META_PACKAGE);
  fs.mkdirSync(dir, { recursive: true });
  fs.cpSync(path.join(ROOT, "npm", META_PACKAGE), dir, { recursive: true });

  // Exact pins: the shim and the binary ship as one unit, and a caret range
  // would let a resolver pair mismatched halves.
  const optionalDependencies = Object.fromEntries(
    platformNames.map((name) => [name, version]),
  );

  writeJSON(path.join(dir, "package.json"), {
    name: META_PACKAGE,
    version,
    description: DESCRIPTION,
    license: "MIT",
    homepage: "https://wharf.jannekeipert.de",
    repository: REPOSITORY,
    bugs: { url: "https://github.com/Janne6565/wharf-tui/issues" },
    keywords: ["ssh", "tui", "terminal", "ssh-client", "cli"],
    // The command is `wharf`; the package is `wharf-tui` because `wharf` is
    // already taken on npm.
    bin: { wharf: "bin/wharf.js" },
    files: ["bin"],
    optionalDependencies,
    engines: { node: ">=18" },
  });
  fs.copyFileSync(path.join(ROOT, "LICENSE"), path.join(dir, "LICENSE"));
  fs.copyFileSync(path.join(ROOT, "README.md"), path.join(dir, "README.md"));
  return dir;
}

function publish(dir, { dryRun, tag }) {
  const args = ["publish", "--access", "public", "--tag", tag];
  if (dryRun) args.push("--dry-run");
  execFileSync("npm", args, { cwd: dir, stdio: "inherit" });
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const binaries = binariesByTarget();

  fs.rmSync(STAGE, { recursive: true, force: true });

  const staged = [];
  for (const platform of PLATFORMS) {
    const key = `${platform.goos}/${platform.goarch}`;
    const binary = binaries.get(key);
    // A missing target would silently ship a meta package whose optional
    // dependency does not exist, and the failure would only surface on a user's
    // machine at install time.
    if (!binary) fail(`no ${key} binary in dist/artifacts.json`);
    staged.push(stagePlatformPackage(platform, binary, args.version));
  }

  const metaDir = stageMetaPackage(
    args.version,
    staged.map((p) => p.name),
  );

  // Order matters: the meta package's optionalDependencies must already resolve
  // when it goes live, or an install racing the publish gets a broken tree.
  for (const platform of staged) {
    console.log(`\n==> publishing ${platform.name}@${args.version}`);
    publish(platform.dir, args);
  }
  console.log(`\n==> publishing ${META_PACKAGE}@${args.version}`);
  publish(metaDir, args);

  console.log(
    args.dryRun
      ? "\nDry run complete — nothing was published."
      : `\nPublished ${META_PACKAGE}@${args.version}. Try: bun i -g ${META_PACKAGE}`,
  );
}

main();
