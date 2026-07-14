package sshx

import (
	"context"
	"errors"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// authMethods assembles the ordered authentication chain, honoring
// hs.AuthMethod:
//
//	AuthAuto:     agent → key file → password → keyboard-interactive
//	AuthKey:      agent + key file + keyboard-interactive (2FA), no password
//	AuthPassword: password + keyboard-interactive only
//
// AuthPassword omits every public-key method even when hs.KeyPath is set or an
// agent is reachable: servers with a low MaxAuthTries must not have their
// budget burned on pubkey offers the host will never accept. An unknown
// AuthMethod value is treated as AuthAuto (the store validates; be lenient
// here). Each interactive method defers its prompt to a callback so the modal
// only fires when the server actually offers/tries that method.
func (m *Manager) authMethods(ctx context.Context, hs HostSpec) []ssh.AuthMethod {
	var methods []ssh.AuthMethod

	// Public-key methods are offered for every mode except AuthPassword.
	if hs.AuthMethod != AuthPassword {
		if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
			if conn, err := net.Dial("unix", sock); err == nil {
				ag := agent.NewClient(conn)
				methods = append(methods, ssh.PublicKeysCallback(ag.Signers))
			}
		}

		if hs.KeyPath != "" {
			methods = append(methods, ssh.PublicKeysCallback(m.keyFileSigners(ctx, hs)))
		}
	}

	// Password is offered for AuthAuto and AuthPassword, but never for AuthKey.
	if hs.AuthMethod != AuthKey {
		methods = append(methods, m.passwordMethod(ctx, hs))
	}

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

// passwordMethod builds the retryable password method. When hs.Password is set
// the first attempt replays it without prompting; if the server rejects it,
// later attempts prompt interactively (4 total: 1 stored + 3 prompts, versus 3
// prompts when nothing is stored). The interactive prompt Title stays exactly
// "password" — the UI keys its "remember password" toggle on that string — so
// a rejected stored password is signalled through Detail instead of the Title.
func (m *Manager) passwordMethod(ctx context.Context, hs HostSpec) ssh.AuthMethod {
	hasStored := hs.Password != ""
	maxAttempts := 3
	if hasStored {
		maxAttempts = 4 // 1 silent replay of the stored password + 3 prompts
	}

	attempt := 0
	cb := ssh.PasswordCallback(func() (string, error) {
		n := attempt
		attempt++
		if hasStored && n == 0 {
			return hs.Password, nil
		}
		detail := hs.User + "@" + hs.Addr
		if hasStored {
			// The stored password has already been tried and rejected; explain
			// why we're asking without disturbing the Title the UI toggles on.
			detail = "saved password was rejected"
		}
		secret, err := m.promptSecret(ctx, hs.ID, "password", detail, false)
		if err != nil {
			return "", err
		}
		return string(secret), nil
	})
	return ssh.RetryableAuthMethod(cb, maxAttempts)
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
