// Package termius imports hosts from a local Termius profile into Wharf's
// store schema.
//
// Termius has no export feature, so there is no file to parse: the data lives
// in the desktop app's Chromium IndexedDB, with individual fields sealed by a
// NaCl secretbox whose key sits in the OS credential store. This package reads
// that profile directly, read-only, without Termius running.
//
// The format is reverse-engineered and undocumented, so every layer here fails
// loudly rather than guessing — an unknown cipher header or an undecodable
// record is an error, never a silently dropped host. Format knowledge is owed
// to two MIT-licensed projects: github.com/y01and3/termius-export (offline
// decryption, keyring service names) and github.com/huangzheng2016/termius_exporter
// (reading the LevelDB from Go).
package termius

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// dataDirs are the literal profile locations, tried in order.
//
// Termius derives the keyring service name from its executable name, so the
// snap build stores things under a different name than the macOS build; the
// path list and localkey.services must stay in step.
var dataDirs = []string{
	"~/snap/termius-app/current/.config/Termius",
	"~/.config/Termius",
	"~/Library/Application Support/Termius",
	"~/AppData/Roaming/Termius",
}

// dataDirGlobs cover installs whose path embeds a bundle id — the macOS App
// Store build is sandboxed, so Electron puts userData inside the app container
// rather than under Application Support. The id is globbed because the DMG and
// App Store builds use different ones (com.termius-dmg.mac vs com.termius.mac).
//
// Tried only after every literal: a machine carrying leftovers from a previous
// App Store install should still resolve to its live profile.
var dataDirGlobs = []string{
	"~/Library/Containers/*ermius*/Data/Library/Application Support/Termius",
}

// expand resolves a leading ~/ against the current user's home directory.
func expand(p string) string {
	if len(p) < 2 || p[0] != '~' || p[1] != '/' {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, p[2:])
}

// DefaultDataDir returns the first Termius profile directory that exists, or ""
// when none is found.
func DefaultDataDir() string {
	for _, c := range dataDirs {
		if fi, err := os.Stat(expand(c)); err == nil && fi.IsDir() {
			return expand(c)
		}
	}
	for _, pattern := range dataDirGlobs {
		matches, err := filepath.Glob(expand(pattern))
		if err != nil {
			continue
		}
		// Sorted so a machine with more than one matching container resolves
		// the same way on every run rather than following directory order.
		sort.Strings(matches)
		for _, m := range matches {
			if fi, err := os.Stat(m); err == nil && fi.IsDir() {
				return m
			}
		}
	}
	return ""
}

// SearchedDataDirs lists every location DefaultDataDir tries, for error text.
func SearchedDataDirs() []string {
	out := make([]string, 0, len(dataDirs)+len(dataDirGlobs))
	for _, c := range append(append([]string{}, dataDirs...), dataDirGlobs...) {
		out = append(out, expand(c))
	}
	return out
}

// locateLevelDB accepts a profile directory, an IndexedDB directory or the
// leveldb directory itself and returns the leveldb directory.
func locateLevelDB(path string) (string, bool) {
	p := expand(path)
	for _, c := range []string{
		p,
		filepath.Join(p, "file__0.indexeddb.leveldb"),
		filepath.Join(p, "IndexedDB", "file__0.indexeddb.leveldb"),
	} {
		if fi, err := os.Stat(filepath.Join(c, "CURRENT")); err == nil && !fi.IsDir() {
			return c, true
		}
	}
	return "", false
}

// Supported reports whether this build can read a Termius profile at all. The
// reader itself is pure Go and platform-independent; only the credential-store
// lookup is per-OS, and all three supported ones are implemented.
func Supported() bool {
	switch runtime.GOOS {
	case "darwin", "linux", "windows":
		return true
	default:
		return false
	}
}
