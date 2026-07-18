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

// connect performs the shared prefix of every outbound connection: default
// port, known-hosts lookup, auth chain, TOFU host-key verification, TCP dial
// under ctx, and the SSH handshake. Both interactive shells (Dial) and
// standalone port forwards (StartForward) build on the *ssh.Client it returns;
// ctx governs only this connect/handshake phase, never the client's lifetime.
func (m *Manager) connect(ctx context.Context, hs HostSpec) (*ssh.Client, error) {
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
		Auth:              m.authMethods(ctx, hs),
		HostKeyCallback:   m.hostKeyCallback(ctx, hs, db),
		HostKeyAlgorithms: db.HostKeyAlgorithms(addr),
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
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

// Dial connects, authenticates (agent -> key file -> password ->
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
	case strings.Contains(err.Error(), "unable to authenticate"):
		return fmt.Errorf("%w: %v", ErrAuthFailed, err)
	default:
		return err
	}
}
