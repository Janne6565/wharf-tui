// Package sshcfg imports hosts from OpenSSH client config (~/.ssh/config,
// including Include directives) into Wharf's store schema.
package sshcfg

import "github.com/Janne6565/wharf-tui/internal/store"

// Import parses the ssh_config at path and returns one store.Host per
// concrete Host alias (patterns containing '*' or '?' are skipped and
// reported in the second return). Hosts carry Source "ssh_config",
// HostName/User/Port defaults resolved, and IdentityFile tilde-expanded.
func Import(path string) ([]store.Host, []string, error) {
	panic("sshcfg: unimplemented")
}
