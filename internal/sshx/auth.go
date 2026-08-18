package sshx

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// authMethods assembles the ordered authentication chain for hs.AuthMethod's
// two modes:
//
//	AuthPassword: password → keyboard-interactive; never offers a public key.
//	key mode (anything else, incl. "" / legacy "auto"): one public-key method
//	              fed by agent → key file → vault keys, then
//	              keyboard-interactive; never offers a password. A host bound to
//	              one vault key (hs.KeyBound) offers that key and skips the
//	              agent.
//
// Every public-key source goes into a SINGLE ssh.PublicKeysCallback. This is
// not cosmetic: x/crypto/ssh records tried methods by *name*, so once one
// "publickey" AuthMethod has failed, every later publickey entry in the slice
// is skipped for the rest of the handshake. Three separate callbacks meant
// only the first one ever ran — a reachable agent silently swallowed both the
// key file and the vault keys, and the connection died as "attempted methods
// [none publickey]" with the right key never offered.
//
// Password mode omits every public-key method even when hs.KeyPath is set or an
// agent is reachable, so servers with a low MaxAuthTries do not have their
// budget burned on pubkey offers the host will never accept. keyboard-
// interactive is offered in both modes for 2FA / PAM. Each interactive method
// defers its prompt to a callback so the modal only fires when the server
// actually offers/tries that method.
func (m *Manager) authMethods(ctx context.Context, hs HostSpec, ring *keyRing) []ssh.AuthMethod {
	var methods []ssh.AuthMethod

	if hs.AuthMethod == AuthPassword {
		// Password mode: a saved/prompted password only, never a public key.
		methods = append(methods, m.passwordMethod(ctx, hs))
	} else {
		// Key mode (default; also legacy "" / "auto"): agent + key file +
		// vault keys, no password. Auto's old password fallback is gone.
		methods = append(methods, ssh.PublicKeysCallback(m.publicKeySigners(ctx, hs, ring)))
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

// publicKeySigners is the one lazy signer source behind key mode's single
// public-key method. It collects, in offer order, the agent's keys, hs.KeyPath
// and the personal synced vault keys, and is only invoked when the server
// actually offers publickey.
//
// Duplicates are dropped by wire-format public key: the same key commonly sits
// in both the agent and the vault, and every redundant offer costs one of the
// server's MaxAuthTries (6 by default) before the right key is reached.
//
// A source that fails does not sink the others — one unreadable key file must
// not hide a working vault key. The first error is kept and only returned when
// nothing at all could be collected, so a lone broken key file still surfaces
// its real reason (including ErrCanceled for a dismissed passphrase prompt)
// instead of a bare "no supported methods remain".
func (m *Manager) publicKeySigners(ctx context.Context, hs HostSpec, ring *keyRing) func() ([]ssh.Signer, error) {
	return func() ([]ssh.Signer, error) {
		if ring.built {
			// A later round of the same connect: the signers (and any passphrase
			// prompts they cost) were collected once, on the first round.
			return ring.next(), ring.err
		}

		var (
			signers  []ssh.Signer
			firstErr error
			seen     = map[string]bool{}
		)
		add := func(s ssh.Signer) {
			if s == nil {
				return
			}
			fp := string(s.PublicKey().Marshal())
			if seen[fp] {
				return
			}
			seen[fp] = true
			signers = append(signers, s)
		}
		collect := func(src func() ([]ssh.Signer, error)) {
			got, err := src()
			if err != nil && firstErr == nil {
				firstErr = err
			}
			for _, s := range got {
				add(s)
			}
		}

		// A host bound to its own key skips the agent: the binding exists
		// precisely so the server's small try budget is not spent on keys that
		// belong to other hosts.
		if m.UseAgent() && !hs.KeyBound {
			collect(m.agentSigners())
		}
		if hs.KeyPath != "" {
			collect(m.keyFileSigners(ctx, hs))
		}
		if len(hs.VaultKeys) > 0 {
			collect(m.vaultKeySigners(ctx, hs))
		}

		ring.build(signers, firstErr)
		if len(signers) == 0 && firstErr != nil {
			return nil, firstErr
		}
		return ring.next(), nil
	}
}

// keyBatchSize is how many public keys one connection offers. Every offer
// counts against the server's MaxAuthTries — 6 by default in both OpenSSH and
// x/crypto/ssh — and the "none" probe that opens the handshake spends one of
// them, so five is the largest batch a default server tolerates before it hangs
// up with "Too many authentication failures".
const keyBatchSize = 5

// maxKeyRounds bounds how many connections one connect attempt may spend
// working through the key list, so a large vault cannot turn a hopeless host
// into a long series of failed logins in the server's auth log.
const maxKeyRounds = 6

// keyRing hands the collected public-key signers to the handshake in
// MaxAuthTries-sized batches, and remembers the position across the rounds of a
// single connect.
//
// A vault holding more keys than the server will let us offer cannot
// authenticate in one connection, however correct the chain is: the server hangs
// up partway through. Rather than making the user guess which key a host wants,
// connect redials and offers the next batch, which is invisible when the right
// key is in the first batch and merely slower when it is not.
//
// It carries no lock: all access happens on the goroutine driving one connect.
type keyRing struct {
	built   bool
	signers []ssh.Signer
	err     error
	offset  int
}

// build records the one-time collection result.
func (r *keyRing) build(signers []ssh.Signer, err error) {
	r.built, r.signers, r.err = true, signers, err
}

// next returns the next batch of at most keyBatchSize signers and advances.
func (r *keyRing) next() []ssh.Signer {
	if r == nil || r.offset >= len(r.signers) {
		return nil
	}
	end := min(r.offset+keyBatchSize, len(r.signers))
	batch := r.signers[r.offset:end]
	r.offset = end
	return batch
}

// hasMore reports whether any collected signer is still unoffered.
func (r *keyRing) hasMore() bool { return r != nil && r.offset < len(r.signers) }

// agentTimeout bounds the agent's key listing. Agents answer in microseconds;
// this only exists so a socket that accepts and then goes silent degrades to
// "no agent keys" instead of a connect that never returns.
const agentTimeout = 3 * time.Second

// agentSigners returns the keys held by $SSH_AUTH_SOCK, or none when there is
// no agent to talk to. An unreachable or silent agent is not an error worth
// failing the connection over — the other sources still get their turn.
func (m *Manager) agentSigners() func() ([]ssh.Signer, error) {
	return func() ([]ssh.Signer, error) {
		sock := os.Getenv("SSH_AUTH_SOCK")
		if sock == "" {
			return nil, nil
		}
		conn, err := net.Dial("unix", sock)
		if err != nil {
			return nil, nil
		}
		// A wedged agent (a socket that accepts but never answers) must not
		// hang the connect: the deadline bounds the list request, and the other
		// key sources still get their turn.
		_ = conn.SetDeadline(time.Now().Add(agentTimeout))
		return agent.NewClient(conn).Signers()
	}
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

// vaultKeySigners returns a lazy signer source for the personal synced vault
// keys, parsed only when the public-key method is actually attempted. Each key
// is tried in the order given; an encrypted key prompts for its passphrase.
//
// Unlike the single keyFileSigners flow, one bad key must not abort the whole
// chain: with a fleet of synced keys a canceled passphrase, a wrong
// passphrase, or any parse error SKIPS that key and continues with the rest.
// The collected signers may be empty, in which case the public-key method
// simply offers nothing and the chain falls through to keyboard-interactive.
func (m *Manager) vaultKeySigners(ctx context.Context, hs HostSpec) func() ([]ssh.Signer, error) {
	return func() ([]ssh.Signer, error) {
		var signers []ssh.Signer
		for _, k := range hs.VaultKeys {
			signer, err := ssh.ParsePrivateKey(k.PEM)
			if err == nil {
				signers = append(signers, signer)
				continue
			}
			var missing *ssh.PassphraseMissingError
			if !errors.As(err, &missing) {
				// Corrupt / unsupported key material: skip it, keep going.
				continue
			}
			pass, perr := m.promptSecret(ctx, hs.ID, "passphrase for "+k.Name+" (vault)", "", false)
			if perr != nil {
				// Canceled prompt (ErrCanceled) or ctx done: skip this key rather
				// than abort — the user may still authenticate with another key.
				continue
			}
			signer, err = ssh.ParsePrivateKeyWithPassphrase(k.PEM, pass)
			if err != nil {
				// Wrong passphrase or other parse failure: skip this key.
				continue
			}
			signers = append(signers, signer)
		}
		return signers, nil
	}
}
