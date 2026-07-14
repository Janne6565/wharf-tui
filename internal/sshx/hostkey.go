package sshx

import (
	"context"
	"net"
	"os"
	"path/filepath"

	"github.com/skeema/knownhosts"
	"golang.org/x/crypto/ssh"
)

// openKnownHosts loads the known_hosts DB, creating the file (0600) and its
// parent directory if they don't exist. The skeema/knownhosts wrapper is used
// (rather than x/crypto's knownhosts directly) because it also exposes the
// per-host key algorithm ordering needed to avoid spurious "host key changed"
// errors when a host has keys of multiple types.
func (m *Manager) openKnownHosts() (*knownhosts.HostKeyDB, error) {
	if err := ensureFile(m.knownHostsPath); err != nil {
		return nil, err
	}
	return knownhosts.NewDB(m.knownHostsPath)
}

func ensureFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	return f.Close()
}

// hostKeyCallback builds the ssh.HostKeyCallback enforcing Wharf's TOFU
// policy: unknown hosts prompt the user and, if accepted, are appended to
// known_hosts; changed keys are a hard error and never prompt.
func (m *Manager) hostKeyCallback(ctx context.Context, hs HostSpec, db *knownhosts.HostKeyDB) ssh.HostKeyCallback {
	inner := db.HostKeyCallback()
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := inner(hostname, remote, key)
		switch {
		case err == nil:
			return nil
		case knownhosts.IsHostKeyChanged(err):
			// Hard stop — never prompt, this could be a MITM.
			return ErrHostKeyChanged
		case knownhosts.IsHostUnknown(err):
			fp := ssh.FingerprintSHA256(key)
			ok, perr := m.promptHostKey(ctx, hs.ID, hostname, key.Type(), fp)
			if perr != nil {
				return perr
			}
			if !ok {
				return ErrHostKeyRejected
			}
			if werr := appendKnownHost(m.knownHostsPath, hostname, remote, key); werr != nil {
				return werr
			}
			return nil
		default:
			return err
		}
	}
}

// appendKnownHost writes a single known_hosts line for the accepted key.
func appendKnownHost(path, hostname string, remote net.Addr, key ssh.PublicKey) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return knownhosts.WriteKnownHost(f, hostname, remote, key)
}
