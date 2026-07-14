// Package sshcfg imports hosts from OpenSSH client config (~/.ssh/config,
// including Include directives) into Wharf's store schema.
package sshcfg

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	ssh_config "github.com/kevinburke/ssh_config"

	"github.com/Janne6565/wharf-tui/internal/store"
)

// userHome resolves the current user's home directory. It is a package-level
// variable so tests can point tilde-expansion at a temp dir without touching
// real $HOME semantics.
var userHome = os.UserHomeDir

// maxIncludeDepth guards against Include cycles (a file including itself,
// directly or transitively).
const maxIncludeDepth = 16

// Import parses the ssh_config at path and returns one store.Host per
// concrete Host alias (patterns containing '*' or '?' are skipped and
// reported in the second return). Hosts carry Source "ssh_config",
// HostName/User/Port defaults resolved, and IdentityFile tilde-expanded.
func Import(path string) ([]store.Host, []string, error) {
	home, _ := userHome() // empty home is tolerable; only tilde expansion needs it

	var hosts []store.Host
	seenAlias := make(map[string]bool)
	skipped := make(map[string]bool)

	if err := collect(path, home, 0, &hosts, seenAlias, skipped); err != nil {
		return nil, nil, err
	}

	skippedList := make([]string, 0, len(skipped))
	for p := range skipped {
		skippedList = append(skippedList, p)
	}
	sort.Strings(skippedList)

	return hosts, skippedList, nil
}

// collect parses one config file and appends its concrete hosts, recursing into
// Include directives. We expand includes ourselves (rather than relying on the
// library's ~/.ssh-anchored resolution) so paths resolve relative to the
// including file's directory — which for the real ~/.ssh/config is ~/.ssh, and
// for test fixtures is the fixture directory.
func collect(path, home string, depth int, hosts *[]store.Host, seenAlias, skipped map[string]bool) error {
	if depth > maxIncludeDepth {
		return fmt.Errorf("sshcfg: include depth exceeded at %s", path)
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	cfg, decErr := ssh_config.Decode(f)
	f.Close()
	if decErr != nil {
		return fmt.Errorf("sshcfg: parsing %s: %w", path, decErr)
	}

	for i, block := range cfg.Hosts {
		// cfg.Hosts[0] is always the parser's implicit "Host *" catch-all; it
		// carries global defaults but is never a host of its own.
		if i == 0 {
			continue
		}

		for _, pat := range block.Patterns {
			alias := pat.String()
			if alias == "" {
				continue
			}
			// Negated patterns ("!foo") are exceptions, not concrete hosts.
			if strings.HasPrefix(alias, "!") {
				continue
			}
			if strings.ContainsAny(alias, "*?") {
				skipped[alias] = true
				continue
			}
			if seenAlias[alias] {
				continue // first definition wins; keep the import deterministic
			}
			seenAlias[alias] = true
			*hosts = append(*hosts, resolveHost(cfg, alias, home))
		}
	}

	// Expand Include directives from the raw file and recurse. cfg.Get already
	// chases the library's own include parsing for value lookups, but the
	// included files' host *aliases* are not visible in cfg.Hosts, so we must
	// enumerate them ourselves.
	for _, inc := range includePaths(path, home) {
		matches, gerr := filepath.Glob(inc)
		if gerr != nil {
			continue
		}
		for _, m := range matches {
			if err := collect(m, home, depth+1, hosts, seenAlias, skipped); err != nil {
				return err
			}
		}
	}

	return nil
}

// resolveHost builds a store.Host for one concrete alias, applying OpenSSH
// defaults (HostName falls back to the alias, Port to 22) and tilde-expanding
// the first IdentityFile.
func resolveHost(cfg *ssh_config.Config, alias, home string) store.Host {
	addr, _ := cfg.Get(alias, "HostName")
	if addr == "" {
		addr = alias
	}

	user, _ := cfg.Get(alias, "User")

	port := 22
	if p, _ := cfg.Get(alias, "Port"); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}

	var keyPath string
	if ids, _ := cfg.GetAll(alias, "IdentityFile"); len(ids) > 0 {
		keyPath = expandTilde(ids[0], home)
	}

	return store.Host{
		Name:    alias,
		Addr:    addr,
		User:    user,
		Port:    port,
		KeyPath: keyPath,
		Source:  "ssh_config",
	}
}

// includePaths scans the raw config for Include directives and returns the glob
// patterns to expand, resolved for our own recursion. Resolution order matches
// OpenSSH intent: absolute as-is, "~/" via home, otherwise relative to the
// including file's directory.
func includePaths(path, home string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	base := filepath.Dir(path)

	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "Include") {
			continue
		}
		// An Include line may list several space-separated file globs.
		for _, directive := range fields[1:] {
			out = append(out, resolveIncludePath(directive, base, home))
		}
	}
	return out
}

func resolveIncludePath(directive, base, home string) string {
	switch {
	case filepath.IsAbs(directive):
		return directive
	case directive == "~" || strings.HasPrefix(directive, "~/"):
		return expandTilde(directive, home)
	default:
		return filepath.Join(base, directive)
	}
}

// expandTilde replaces a leading "~" with home. A key path like
// "~/.ssh/id_ed25519" becomes an absolute path the connector can hand to ssh.
func expandTilde(p, home string) string {
	if home == "" {
		return p
	}
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}
