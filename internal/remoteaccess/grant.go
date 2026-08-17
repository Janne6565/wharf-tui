package remoteaccess

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Grant is one live capability: one host, one token, one socket. It is created
// by Open and destroyed by Close; nothing about it is ever persisted, so a
// wharf restart is itself a revocation.
type Grant struct {
	// token never leaves this struct except through Token and the
	// constant-time comparison in authenticate. It is not in the socket name,
	// not in any error, not in any log line.
	token    string
	sock     string
	hostID   string
	hostName string
	exec     Executor
	notify   func(Event)

	maxInFlight int
	expiresAt   time.Time

	// ctx is cancelled by Close, which is how revocation reaches a command that
	// is already running: an in-flight exec is aborted rather than allowed to
	// finish after the user asked for the capability back.
	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	ln       net.Listener
	closed   bool
	count    int
	inFlight int

	// served is closed when the accept loop has returned, so Close can promise
	// that nothing further will be accepted by the time it returns.
	served chan struct{}

	// seq numbers audited commands so a start event and its terminal one can be
	// folded into a single audit row. It is atomic rather than guarded by mu
	// because it is read on the command path, which deliberately runs outside
	// the lock, and it counts attempts rather than successes: a refusal gets an
	// id too, so that a consumer never has to special-case it.
	seq atomic.Uint64

	// pending is a counting semaphore over connections that have not yet
	// authenticated. A slot is taken in the accept loop and released the moment
	// the handshake succeeds — after that the command's own MaxInFlight gate
	// applies, and a long-running command must not hold a handshake slot.
	pending chan struct{}
}

// newGrant mints the token and assembles the grant around an already-listening
// socket. Splitting it from Open is what keeps socket creation the only
// platform-specific part of the server.
func newGrant(opts Options, ln net.Listener, sock string) (*Grant, error) {
	if opts.Exec == nil {
		return nil, errors.New("remoteaccess: a grant needs an executor")
	}
	var raw [tokenBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, fmt.Errorf("remoteaccess: generating the token: %w", err)
	}
	// Lowercase base32, unpadded: an alphanumeric alphabet, deliberately.
	//
	// base64url was the obvious choice and was rejected. Its alphabet includes
	// '-' and '_', so about one token in 64 starts with a dash — and a token
	// that starts with a dash is read as a flag by wharf's own CLI, by every
	// other tool it gets pasted into, and by any shell script that forwards it.
	// A secret that breaks 1.6% of the time, for a reason nothing in the error
	// message hints at, is worse than a longer one. Padding is dropped for the
	// same reason: '=' is a token that needs quoting in some shells.
	//
	// The alphabet is less dense, so the token is 52 characters instead of 43.
	// The 32 random bytes are what matters and they are unchanged: length is
	// free here, entropy is not.
	token := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:]))

	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	maxInFlight := opts.MaxInFlight
	if maxInFlight <= 0 {
		maxInFlight = DefaultMaxInFlight
	}
	ctx, cancel := context.WithCancel(context.Background())
	g := &Grant{
		token:       token,
		sock:        sock,
		hostID:      opts.HostID,
		hostName:    opts.HostName,
		exec:        opts.Exec,
		notify:      opts.Notify,
		maxInFlight: maxInFlight,
		expiresAt:   time.Now().Add(ttl),
		ctx:         ctx,
		cancel:      cancel,
		ln:          ln,
		served:      make(chan struct{}),
		pending:     make(chan struct{}, maxPendingConns),
	}
	go g.serve(ln)
	return g, nil
}

// Token is the bearer secret the client presents. It is returned for exactly
// one purpose — showing and copying the command line — and must never be
// written to a file, a log or the vault.
func (g *Grant) Token() string { return g.token }

// SocketPath is where the grant listens. It is safe to show: the token, not the
// path, is what authenticates.
func (g *Grant) SocketPath() string { return g.sock }

// HostName is the host this grant is scoped to, for display.
func (g *Grant) HostName() string { return g.hostName }

// HostID identifies the host the grant rides. The UI needs it to revoke the
// grant when that particular session ends — a grant must never outlive the
// connection it was minted on.
func (g *Grant) HostID() string { return g.hostID }

// ExpiresAt is when the TTL runs out. It is fixed at Open and never extended:
// a renewable grant is a permanent one with extra steps.
func (g *Grant) ExpiresAt() time.Time { return g.expiresAt }

// Count is how many commands have been started through this grant so far,
// including the ones still running.
func (g *Grant) Count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.count
}

// CommandLine is the exact string to display and copy. The socket path is
// deliberately absent: the client finds the grant by offering the token to each
// socket, so the path is never something a user has to handle or an agent has
// to be told.
func (g *Grant) CommandLine() string {
	return "wharf --remote " + g.token + " -- <your command>"
}

// Close revokes the grant, synchronously. When it returns, the listener is
// closed, the socket file is unlinked and the accept loop has exited, so no
// further command can start; commands already running are cancelled through the
// grant's context.
//
// It does not wait for a cancelled command to unwind. Waiting would make
// revocation — the thing a user reaches for when something is going wrong —
// hostage to a remote process that may never return, and the capability is
// already gone by then: the socket is unlinked and the context cancelled.
func (g *Grant) Close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	ln := g.ln
	g.ln = nil
	g.mu.Unlock()

	g.cancel()

	var err error
	if ln != nil {
		err = ln.Close()
	}
	if rmErr := os.Remove(g.sock); rmErr != nil && !os.IsNotExist(rmErr) && err == nil {
		err = rmErr
	}
	if ln != nil {
		<-g.served
	}
	return err
}

// Expired reports whether the TTL has run out. It is separate from the closed
// flag because an expired grant still holds its socket until something closes
// it — the check that matters is the one on every request, not a timer.
func (g *Grant) Expired() bool { return time.Now().After(g.expiresAt) }

// serve accepts connections until the listener is closed by Close. The
// listener is a parameter rather than a field read: Close clears the field, and
// a loop that re-read it would race with exactly the call that stops it.
//
// Every accepted connection takes a pending slot before it gets a goroutine.
// One goroutine per accept with nothing bounding it was measured to turn 300
// connections declaring a megabyte each into 189 MiB of heap held for the full
// authTimeout — and being OOM-killed would destroy the memory-only audit log,
// which is the one record of what an agent did. Backpressure here costs an
// attacker nothing but gives it nothing either.
func (g *Grant) serve(ln net.Listener) {
	defer close(g.served)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case g.pending <- struct{}{}:
		case <-g.ctx.Done():
			// Close cancels before it closes the listener, so a loop parked on a
			// full semaphore still stops immediately: revocation must never wait
			// out an attacker's handshake timeout.
			_ = c.Close()
			return
		}
		go g.handle(c)
	}
}

// handle runs one connection: authenticate, then run at most one command.
//
// One command per connection is deliberate. It makes the client trivial, and it
// means a connection that has been idle since its command finished cannot be
// reused later — after a revocation, say — because it no longer exists.
func (g *Grant) handle(c net.Conn) {
	defer c.Close()

	// The pending slot is released exactly once, whichever way this connection
	// leaves the handshake. A local flag rather than a sync.Once because only
	// this goroutine ever touches it.
	released := false
	release := func() {
		if !released {
			released = true
			<-g.pending
		}
	}
	defer release()

	// The handshake must complete promptly: an unauthenticated peer gets a few
	// seconds and no more. The deadline covers writes too, so a peer that
	// accepts the challenge and then stops reading cannot pin the goroutine.
	_ = c.SetDeadline(time.Now().Add(authTimeout))

	var serverNonce [nonceLen]byte
	if _, err := rand.Read(serverNonce[:]); err != nil {
		return
	}
	if err := writeFrame(c, kindChallenge, serverNonce[:]); err != nil {
		return
	}
	// Capped at the handshake's true size, not maxFrame: see maxHandshakeFrame.
	kind, payload, err := readFrameLimit(c, maxHandshakeFrame)
	if err != nil || kind != kindAuth || len(payload) != nonceLen+macLen {
		// Anything other than exactly one well-formed auth frame is a hang-up
		// with no reply at all. There is nothing to say to a peer that has not
		// proven it holds the token, and saying it would be a probe oracle.
		return
	}
	clientNonce, mac := payload[:nonceLen], payload[nonceLen:]
	if !g.authenticate(serverNonce[:], clientNonce, mac) {
		_ = writeJSON(c, kindError, errFrame{Err: errRejected})
		return
	}
	// Authenticated: this is no longer an unidentified peer, so it stops
	// occupying a handshake slot. What it may do next is bounded by MaxInFlight.
	release()
	// The reply is the server's own proof over the same transcript. It is what
	// lets the client tell this grant apart from a socket someone else planted
	// in the directory, so it is not optional and not empty.
	if err := writeFrame(c, kindAuthOK, g.handshakeMAC(macLabelServer, serverNonce[:], clientNonce)); err != nil {
		return
	}

	_ = c.SetDeadline(time.Now().Add(requestTimeout))
	kind, payload, err = readFrame(c)
	if err != nil || kind != kindRun {
		return
	}
	var req runRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		_ = writeJSON(c, kindError, errFrame{Err: "remoteaccess: malformed request"})
		return
	}
	// A command may legitimately run for a long time, so the deadline that
	// bounded the handshake must not bound the command.
	_ = c.SetDeadline(time.Time{})
	g.run(c, req)
}

// handshakeMAC computes this grant's proof over a transcript. The socket's base
// name is part of it, so a MAC minted for a socket someone else planted in the
// grants directory does not verify here — see the handshake commentary in
// proto.go.
func (g *Grant) handshakeMAC(label string, serverNonce, clientNonce []byte) []byte {
	return handshakeMAC(g.token, label, serverNonce, clientNonce, filepath.Base(g.sock))
}

// authenticate verifies the client's proof in constant time. The token itself
// is never presented, so there is nothing on the wire to steal; what is compared
// is two MACs over the same transcript.
//
// Both operands are exactly macLen bytes — the caller rejects any other auth
// frame length outright — so ConstantTimeCompare's length check cannot fire.
// That early return on a length mismatch is real (an earlier comment here
// claimed otherwise and was simply wrong); it is neutralised by fixing the
// length, not by hoping the comparison hides it. hmac.Equal was the obvious
// alternative and is the identical call underneath; subtle.ConstantTimeCompare
// is spelled out because docs/REMOTE-ACCESS.md names it as the hard rule and a
// grep for it should find this line.
func (g *Grant) authenticate(serverNonce, clientNonce, mac []byte) bool {
	want := g.handshakeMAC(macLabelClient, serverNonce, clientNonce)
	return subtle.ConstantTimeCompare(mac, want) == 1
}

// run executes one command and streams it back. Every gate — revocation, TTL,
// concurrency — is checked here rather than at connect time, because a grant
// can die between the two and the request is the thing that must be refused.
func (g *Grant) run(c net.Conn, req runRequest) {
	fw := &frameWriter{w: c}

	// The audit id is taken before any gate, so that a refusal is as identifiable
	// as a command that ran. It is deliberately not g.count: count is rolled back
	// when a command turns out never to have started, and an identifier that can
	// be reissued is not an identifier.
	id := g.seq.Add(1)

	g.mu.Lock()
	switch {
	case g.closed:
		g.mu.Unlock()
		g.refuse(fw, id, req.Command, "this grant has been revoked")
		return
	case g.Expired():
		g.mu.Unlock()
		g.refuse(fw, id, req.Command, "this grant has expired")
		return
	case g.inFlight >= g.maxInFlight:
		g.mu.Unlock()
		// Refused rather than queued: a queue would let an agent stack up work
		// that outlives the revocation it was supposed to be stopped by, and it
		// would hide the burst from the audit log until much later.
		g.refuse(fw, id, req.Command, fmt.Sprintf(
			"%d commands are already running on this grant", g.maxInFlight))
		return
	}
	g.inFlight++
	g.count++
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.inFlight--
		g.mu.Unlock()
	}()

	dispatch()

	// Close can land between releasing the lock above and dispatching below, and
	// Close's contract — and docs/REMOTE-ACCESS.md — say that when it returns, no
	// further command can start. Re-checking the context here closes that window
	// down to the dispatch itself, where the guarantee still holds by other
	// means: Exec is handed g.ctx, so a Close landing after this check hands it
	// an already-cancelled context and the command is aborted rather than run.
	//
	// The alternative, holding g.mu across the Exec call, was rejected outright:
	// that is a lock held across the network, and it would let one slow host
	// block Count, Close and every other command on the grant.
	if g.ctx.Err() != nil {
		g.mu.Lock()
		// Roll the counters back. A command that never started must not show up
		// in Count, which the UI presents as "commands run".
		g.count--
		g.mu.Unlock()
		g.refuse(fw, id, req.Command, "this grant has been revoked")
		return
	}

	g.emit(Event{ID: id, Command: req.Command, At: time.Now()})

	ctx := g.ctx
	if req.TimeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(req.TimeoutMs)*time.Millisecond)
		defer cancel()
	}
	code, err := g.exec.Exec(ctx, ExecRequest{
		Command: req.Command,
		Stdin:   req.Stdin,
		Timeout: time.Duration(req.TimeoutMs) * time.Millisecond,
	}, &streamWriter{fw: fw, stream: "out"}, &streamWriter{fw: fw, stream: "err"})

	end := endFrame{Code: code}
	if err != nil {
		end.Err = err.Error()
	}
	_ = fw.writeJSON(kindEnd, end)
	g.emit(Event{ID: id, Command: req.Command, At: time.Now(), Code: code, Err: err, Finished: true})
}

// dispatchProbe is a test seam, nil in every build that is not a test. run
// calls it in the window between releasing the grant's lock and dispatching the
// command, which is precisely the window a Close must not slip through.
//
// A seam rather than a hammer loop because that window is nanoseconds wide: a
// review that ran the race 280 times never observed it, so a test built on
// repetition would pass whether the guard is there or not — it would assert
// nothing. It is an atomic.Pointer rather than a plain variable so that setting
// it can never race the server goroutine that reads it.
var dispatchProbe atomic.Pointer[func()]

func dispatch() {
	if p := dispatchProbe.Load(); p != nil {
		(*p)()
	}
}

// refuse tells the client why its command will not run and records the attempt
// in the audit log.
//
// The audit event is the point. A refusal used to be invisible: an agent that
// kept hammering a revoked grant, or that tried to burst past MaxInFlight, left
// no trace at all, so the log showed only what succeeded. What was attempted is
// exactly what the user needs to see when something has gone wrong, so a refusal
// is emitted as a single terminal event marked Refused, with the same wording
// the client is given. There is no start event to pair it with, because nothing
// started.
func (g *Grant) refuse(fw *frameWriter, id uint64, command, why string) {
	_ = fw.writeJSON(kindError, errFrame{Err: "remoteaccess: " + why})
	g.emit(Event{
		ID:       id,
		Command:  command,
		At:       time.Now(),
		Err:      errors.New("refused: " + why),
		Finished: true,
		Refused:  true,
	})
}

// emit delivers an audit event outside the grant's lock, since Notify hands the
// event to the UI's event loop and must never be able to deadlock the server.
func (g *Grant) emit(ev Event) {
	if g.notify != nil {
		g.notify(ev)
	}
}
