package sshx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// preferredKexAlgos pins the key-exchange preference order for every outbound
// connection. mlkem768x25519-sha256 leads: it is a hybrid ML-KEM-768 + X25519
// exchange, so a recorded session cannot be decrypted later by a quantum
// attacker (OpenSSH 9.9+ / 10 negotiate it; older servers fall through to
// classical X25519 as before).
//
// This list is deliberately identical to x/crypto/ssh's own default, including
// the SHA-1 Diffie-Hellman tail — the point is to *pin* what we would otherwise
// inherit, so a dependency bump that reorders the default cannot silently drop
// the post-quantum exchange. Compatibility is unchanged; only the guarantee is
// new. TestKexIsPostQuantum asserts the negotiated result.
var preferredKexAlgos = []string{
	ssh.KeyExchangeMLKEM768X25519,
	ssh.KeyExchangeCurve25519,
	ssh.KeyExchangeECDHP256,
	ssh.KeyExchangeECDHP384,
	ssh.KeyExchangeECDHP521,
	ssh.KeyExchangeDH14SHA256,
	ssh.InsecureKeyExchangeDH14SHA1,
}

// connect performs the shared prefix of every outbound connection: default
// port, known-hosts lookup, auth chain, TOFU host-key verification, TCP dial
// under ctx, and the SSH handshake. Both interactive shells (Dial) and
// standalone port forwards (StartForward) build on the *ssh.Client it returns;
// ctx governs only this connect/handshake phase, never the client's lifetime.
func (m *Manager) connect(ctx context.Context, hs HostSpec) (*ssh.Client, error) {
	// One ring across all rounds: the keys (and any passphrase prompts they
	// cost) are collected once and handed out in MaxAuthTries-sized batches.
	ring := &keyRing{}
	var err error
	for round := 0; round < maxKeyRounds; round++ {
		var client *ssh.Client
		client, err = m.connectOnce(ctx, hs, ring)
		if err == nil {
			return client, nil
		}
		// Only an exhausted key budget is worth another connection, and only
		// while keys remain: a rejected host key, a canceled prompt or a dead
		// address must fail on the spot.
		if !ring.hasMore() || !(errors.Is(err, ErrAuthFailed) || errors.Is(err, ErrTooManyAuthAttempts)) {
			return nil, err
		}
	}
	return nil, err
}

// connectOnce is one TCP dial plus handshake, offering whatever batch of keys
// ring hands out for this round.
func (m *Manager) connectOnce(ctx context.Context, hs HostSpec, ring *keyRing) (*ssh.Client, error) {
	port := hs.Port
	if port == 0 {
		port = 22
	}
	addr := net.JoinHostPort(hs.Addr, strconv.Itoa(port))

	db, err := m.openKnownHosts()
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User:              hs.User,
		Auth:              m.authMethods(ctx, hs, ring),
		HostKeyCallback:   m.hostKeyCallback(ctx, hs, db),
		HostKeyAlgorithms: db.HostKeyAlgorithms(addr),
		Config:            ssh.Config{KeyExchanges: preferredKexAlgos},
	}

	// The single outbound TCP dial for SSH: interactive sessions and standalone
	// port forwards both land here, so this is the one place an egress proxy has
	// to be applied. A nil proxy dials direct.
	conn, err := m.Proxy().DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		_ = conn.Close()
		return nil, classifyHandshakeErr(err)
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

// Dial connects, authenticates (key mode: agent + key file + vault keys in one
// public-key method, then keyboard-interactive; password mode: password then
// keyboard-interactive), requests a PTY of cols x rows, starts the remote
// shell and the output pump, and registers the session under hs.ID.
func (m *Manager) Dial(ctx context.Context, hs HostSpec, cols, rows int) (*Session, error) {
	client, err := m.connect(ctx, hs)
	if err != nil {
		return nil, err
	}

	sess, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, err
	}

	termType := os.Getenv("TERM")
	if termType == "" {
		termType = "xterm-256color"
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := sess.RequestPty(termType, rows, cols, modes); err != nil {
		_ = sess.Close()
		_ = client.Close()
		return nil, err
	}

	stdin, err := sess.StdinPipe()
	if err != nil {
		_ = sess.Close()
		_ = client.Close()
		return nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		_ = sess.Close()
		_ = client.Close()
		return nil, err
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		_ = sess.Close()
		_ = client.Close()
		return nil, err
	}

	if err := sess.Shell(); err != nil {
		_ = sess.Close()
		_ = client.Close()
		return nil, err
	}

	ring := newRing(ringSize)
	s := &Session{
		host:   hs,
		mgr:    m,
		client: client,
		sess:   sess,
		stdin:  stdin,
		ring:   ring,
		tee:    newTee(ring),
		cols:   cols,
		rows:   rows,
		done:   make(chan struct{}),
	}

	// Register before starting goroutines so a fast remote exit can't race
	// its own removal ahead of the insert.
	m.register(s)
	s.start(stdout, stderr)

	return s, nil
}

// classifyHandshakeErr maps a raw ssh.NewClientConn error onto sshx's typed
// errors. Host-key and cancellation sentinels raised inside the callbacks
// propagate through the handshake and are returned unchanged; a server
// rejecting every auth method becomes ErrAuthFailed.
func classifyHandshakeErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrHostKeyChanged),
		errors.Is(err, ErrHostKeyRejected),
		errors.Is(err, ErrCanceled),
		errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		return err
	// OpenSSH capitalizes the message and x/crypto/ssh's own server does not,
	// so the match is case-insensitive.
	case strings.Contains(strings.ToLower(err.Error()), "too many authentication failures"):
		// The server hung up mid-chain rather than rejecting us: it counted more
		// auth attempts than MaxAuthTries allows. Say which knob that is — the
		// raw disconnect reads like a network fault.
		return fmt.Errorf("%w: it accepted only a few key offers before hanging up "+
			"(MaxAuthTries); offer fewer keys, or set this host to password auth", ErrTooManyAuthAttempts)
	case strings.Contains(err.Error(), "unable to authenticate"):
		return fmt.Errorf("%w: %v", ErrAuthFailed, err)
	default:
		return err
	}
}
