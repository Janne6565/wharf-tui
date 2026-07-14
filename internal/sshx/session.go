package sshx

import (
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const keepaliveInterval = 30 * time.Second

// Session is one live remote shell. Its remote output is pumped into a ring
// buffer for the session's whole life, independent of whether the UI is
// currently attached.
type Session struct {
	host HostSpec
	mgr  *Manager

	client *ssh.Client
	sess   *ssh.Session
	stdin  io.WriteCloser
	ring   *ring
	tee    *tee

	mu    sync.Mutex
	alive bool
	cols  int
	rows  int

	done      chan struct{}
	closeOnce sync.Once
}

// start wires up the pump, waiter, and (optionally) keepalive goroutines and
// marks the session live. Called by Dial once the shell is running.
func (s *Session) start(stdout, stderr io.Reader) {
	s.mu.Lock()
	s.alive = true
	s.mu.Unlock()

	// Pump goroutines: drain remote stdout+stderr into the tee (ring + live
	// writer) until EOF. The tee never errors, so io.Copy runs to completion.
	go func() { _, _ = io.Copy(s.tee, stdout) }()
	go func() { _, _ = io.Copy(s.tee, stderr) }()

	// Waiter: block on the remote shell exiting, then tear down once.
	go func() {
		err := s.sess.Wait()
		_ = s.client.Close()
		s.end(err)
	}()

	if s.mgr.keepalive {
		go s.keepaliveLoop()
	}
}

// end marks the session dead exactly once: closes done, unregisters from the
// manager, and notifies the UI. err is nil on a clean remote exit.
func (s *Session) end(err error) {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.alive = false
		s.mu.Unlock()
		close(s.done)
		s.mgr.remove(s.host.ID, s)
		s.mgr.notify(SessionEndedMsg{HostID: s.host.ID, Err: err})
	})
}

// keepaliveLoop sends periodic keepalive requests; a failed send tears the
// session down (the connection is gone).
func (s *Session) keepaliveLoop() {
	t := time.NewTicker(keepaliveInterval)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			if _, _, err := s.client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				_ = s.Close()
				return
			}
		}
	}
}

// Host returns the spec the session was dialed with.
func (s *Session) Host() HostSpec { return s.host }

// Alive reports whether the remote shell is still running.
func (s *Session) Alive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.alive
}

// Done is closed when the session ends.
func (s *Session) Done() <-chan struct{} { return s.done }

// Close terminates the session. It is idempotent and safe to call from any
// goroutine; the waiter goroutine performs the actual bookkeeping via end.
func (s *Session) Close() error {
	if s.sess != nil {
		_ = s.sess.Close()
	}
	if s.client != nil {
		_ = s.client.Close()
	}
	return nil
}
