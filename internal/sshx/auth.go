package sshx

import (
	"context"
	"errors"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// authMethods assembles the ordered authentication chain:
//
//	(a) ssh-agent, if SSH_AUTH_SOCK points at a dialable socket
//	(b) the explicit identity file, if hs.KeyPath is set
//	(c) password (retried up to 3 times)
//	(d) keyboard-interactive
//
// Each interactive method defers its prompt to a callback so the modal only
// fires when the server actually offers/tries that method.
func (m *Manager) authMethods(ctx context.Context, hs HostSpec) []ssh.AuthMethod {
	var methods []ssh.AuthMethod

	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			ag := agent.NewClient(conn)
			methods = append(methods, ssh.PublicKeysCallback(ag.Signers))
		}
	}

	if hs.KeyPath != "" {
		methods = append(methods, ssh.PublicKeysCallback(m.keyFileSigners(ctx, hs)))
	}

	methods = append(methods, ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
		secret, err := m.promptSecret(ctx, hs.ID, "password", hs.User+"@"+hs.Addr, false)
		if err != nil {
			return "", err
		}
		return string(secret), nil
	}), 3))

	methods = append(methods, ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i, q := range questions {
			secret, err := m.promptSecret(ctx, hs.ID, q, instruction, echos[i])
			if err != nil {
				return nil, err
			}
			answers[i] = string(secret)
		}
		return answers, nil
	}))

	return methods
}

// keyFileSigners returns a lazy signer source for hs.KeyPath. It only reads
// and parses the key when the public-key method is actually attempted, and
// prompts for a passphrase (via SecretPromptMsg) only when the key is
// encrypted. A canceled passphrase prompt aborts with ErrCanceled.
func (m *Manager) keyFileSigners(ctx context.Context, hs HostSpec) func() ([]ssh.Signer, error) {
	return func() ([]ssh.Signer, error) {
		raw, err := os.ReadFile(hs.KeyPath)
		if err != nil {
			return nil, err
		}
		signer, err := ssh.ParsePrivateKey(raw)
		if err == nil {
			return []ssh.Signer{signer}, nil
		}
		var missing *ssh.PassphraseMissingError
		if !errors.As(err, &missing) {
			return nil, err
		}
		pass, perr := m.promptSecret(ctx, hs.ID, "passphrase for "+hs.KeyPath, "", false)
		if perr != nil {
			return nil, perr
		}
		signer, err = ssh.ParsePrivateKeyWithPassphrase(raw, pass)
		if err != nil {
			return nil, err
		}
		return []ssh.Signer{signer}, nil
	}
}
