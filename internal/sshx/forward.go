package sshx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Forward kinds, mirroring OpenSSH's -L/-R/-D. The string values are part of
// the frozen UI contract (they travel through ForwardSpec.Kind).
const (
	ForwardLocal   = "local"   // -L: local listener → target dialed through the server
	ForwardRemote  = "remote"  // -R: listener on the server → target dialed locally
	ForwardDynamic = "dynamic" // -D: local SOCKS5 (CONNECT-only) → dialed through the server
)

// defaultForwardAddr is the loopback default applied to an empty bind or target
// address, so a forward never accidentally listens on all interfaces.
const defaultForwardAddr = "127.0.0.1"

// ForwardSpec is the recipe for a single port forward. Empty BindAddr/TargetAddr
// default to loopback; BindPort 0 asks the OS (or the server, for remote) to pick
// a free port, reported afterwards via Forward.BoundAddr.
type ForwardSpec struct {
	Kind       string // ForwardLocal | ForwardRemote | ForwardDynamic
	BindAddr   string // listen address; "" defaults to "127.0.0.1" (local+dynamic: local bind; remote: bind on the server)
	BindPort   int    // 0 = pick a free port (report via BoundAddr)
	TargetAddr string // "" defaults to "127.0.0.1"; unused for dynamic
	TargetPort int    // unused for dynamic
}

// Label renders the compact human-readable form shown in the UI, e.g.
//
//	"L 127.0.0.1:8080 → db.internal:5432"
//	"R server:9000 → 127.0.0.1:3000"
//	"D socks5 127.0.0.1:1080"
func (s ForwardSpec) Label() string {
	bind := labelAddr(s.BindAddr, s.BindPort)
	switch s.Kind {
	case ForwardRemote:
		return "R " + bind + " → " + labelAddr(s.TargetAddr, s.TargetPort)
	case ForwardDynamic:
		return "D socks5 " + bind
	default:
		return "L " + bind + " → " + labelAddr(s.TargetAddr, s.TargetPort)
	}
}

// labelAddr renders one endpoint for Label, applying the loopback default so
// an unspecified address reads the same way it will actually bind.
func labelAddr(addr string, port int) string {
	if addr == "" {
		addr = defaultForwardAddr
	}
	return addr + ":" + strconv.Itoa(port)
}

// normalize applies the loopback defaults and rejects malformed specs. It runs
// before any network work so a bad request fails fast without leaving a client
// or listener behind. It mutates the receiver in place with the resolved
// defaults StartForward then hands to the Forward.
func (s *ForwardSpec) normalize() error {
	switch s.Kind {
	case ForwardLocal, ForwardRemote, ForwardDynamic:
	default:
		return fmt.Errorf("sshx: unknown forward kind %q", s.Kind)
	}
	if s.BindPort < 0 || s.BindPort > 65535 {
		return fmt.Errorf("sshx: bind port %d out of range", s.BindPort)
	}
	if s.BindAddr == "" {
		s.BindAddr = defaultForwardAddr
	}
	// Dynamic forwards resolve their target per-connection from the SOCKS5
	// request, so target fields are meaningful only for local/remote.
	if s.Kind == ForwardLocal || s.Kind == ForwardRemote {
		if s.TargetAddr == "" {
			s.TargetAddr = defaultForwardAddr
		}
		if s.TargetPort < 1 || s.TargetPort > 65535 {
			return fmt.Errorf("sshx: target port %d out of range", s.TargetPort)
		}
	}
	return nil
}

// Forward is one standalone port forward. It owns its own *ssh.Client,
// independent of any interactive session, and lives until Close or the
// underlying SSH connection drops.
type Forward struct {
	id   string
	host HostSpec
	spec ForwardSpec
	mgr  *Manager

	client    *ssh.Client
	ln        net.Listener
	boundAddr string
	startedAt time.Time

	mu    sync.Mutex
	alive bool
	conns int

	done    chan struct{}
	endOnce sync.Once
}

// ID returns the forward's random identifier (stable for its lifetime).
func (f *Forward) ID() string { return f.id }

// Host returns the spec the forward's client was connected with.
func (f *Forward) Host() HostSpec { return f.host }

// Spec returns the (normalized) forward recipe.
func (f *Forward) Spec() ForwardSpec { return f.spec }

// BoundAddr returns the actual listener address, with any port-0 request
// resolved to the concrete port the OS or server assigned.
func (f *Forward) BoundAddr() string { return f.boundAddr }

// StartedAt returns when the forward began accepting connections.
func (f *Forward) StartedAt() time.Time { return f.startedAt }

// Alive reports whether the forward is still accepting connections.
func (f *Forward) Alive() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.alive
}

// Conns returns the number of connections currently piped through the forward.
func (f *Forward) Conns() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conns
}

// Done is closed when the forward ends.
func (f *Forward) Done() <-chan struct{} { return f.done }

// Close tears the forward down. It is idempotent and safe to call from any
// goroutine; a deliberate Close reports a nil Err in ForwardEndedMsg even if
// the accept loop subsequently observes its own listener closing.
func (f *Forward) Close() error {
	f.end(nil)
	return nil
}

// StartForward opens a dedicated SSH connection for hs and starts a standalone
// port forward described by spec. ctx governs only the connect/handshake phase;
// once running, the forward lives until Close or the SSH connection drops.
func (m *Manager) StartForward(ctx context.Context, hs HostSpec, spec ForwardSpec) (*Forward, error) {
	if err := spec.normalize(); err != nil {
		return nil, err
	}

	client, err := m.connect(ctx, hs)
	if err != nil {
		return nil, err
	}

	ln, boundAddr, err := forwardListen(client, spec)
	if err != nil {
		_ = client.Close()
		return nil, err
	}

	f := &Forward{
		id:        newForwardID(),
		host:      hs,
		spec:      spec,
		mgr:       m,
		client:    client,
		ln:        ln,
		boundAddr: boundAddr,
		startedAt: time.Now(),
		alive:     true,
		done:      make(chan struct{}),
	}

	// Register before starting goroutines so a fast connection death can't race
	// its own removal ahead of the insert.
	m.registerForward(f)
	f.start()

	return f, nil
}

// forwardListen opens the forward's listener: a local socket for local/dynamic,
// or a server-side socket (via the SSH protocol) for remote. The returned
// address carries the resolved port for a port-0 request.
func forwardListen(client *ssh.Client, spec ForwardSpec) (net.Listener, string, error) {
	bind := net.JoinHostPort(spec.BindAddr, strconv.Itoa(spec.BindPort))
	var (
		ln  net.Listener
		err error
	)
	if spec.Kind == ForwardRemote {
		ln, err = client.Listen("tcp", bind)
	} else {
		ln, err = net.Listen("tcp", bind)
	}
	if err != nil {
		return nil, "", err
	}
	return ln, ln.Addr().String(), nil
}

// start wires up the accept loop, the connection-death waiter, and (optionally)
// keepalive. Called by StartForward once the listener is open.
func (f *Forward) start() {
	go f.acceptLoop()

	// Waiter: the SSH connection dying is one of the two paths that end a
	// forward (the other is a listener failure surfaced by the accept loop).
	go func() {
		err := f.client.Wait()
		f.end(err)
	}()

	if f.mgr.keepalive {
		go f.keepaliveLoop()
	}
}

// acceptLoop accepts connections until the listener fails (which, after Close or
// connection death, is our own teardown). Every accept error funnels into end.
func (f *Forward) acceptLoop() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			f.end(err)
			return
		}
		switch f.spec.Kind {
		case ForwardRemote:
			go f.handleRemote(conn)
		case ForwardDynamic:
			go f.handleDynamic(conn)
		default:
			go f.handleLocal(conn)
		}
	}
}

// handleLocal serves one -L connection: dial the target through the server,
// then pipe. A failed target dial simply drops the local connection.
func (f *Forward) handleLocal(local net.Conn) {
	target := net.JoinHostPort(f.spec.TargetAddr, strconv.Itoa(f.spec.TargetPort))
	remote, err := f.client.Dial("tcp", target)
	if err != nil {
		_ = local.Close()
		return
	}
	f.pipe(local, remote)
}

// handleRemote serves one -R connection: the server accepted it and we dial the
// local target for it, then pipe.
func (f *Forward) handleRemote(remote net.Conn) {
	target := net.JoinHostPort(f.spec.TargetAddr, strconv.Itoa(f.spec.TargetPort))
	local, err := net.Dial("tcp", target)
	if err != nil {
		_ = remote.Close()
		return
	}
	f.pipe(remote, local)
}

// handleDynamic serves one -D connection: run the SOCKS5 handshake to learn the
// requested target, dial it through the server, answer the client, then pipe.
func (f *Forward) handleDynamic(local net.Conn) {
	target, err := socks5Negotiate(local)
	if err != nil {
		_ = local.Close()
		return
	}
	remote, err := f.client.Dial("tcp", target)
	if err != nil {
		_ = socks5Reply(local, socks5ReplyCode(err))
		_ = local.Close()
		return
	}
	if err := socks5Reply(local, socksReplySuccess); err != nil {
		_ = remote.Close()
		_ = local.Close()
		return
	}
	f.pipe(local, remote)
}

// pipe copies bytes bidirectionally between a and b, propagating a half-close
// (CloseWrite) when either direction reaches EOF so a one-way shutdown doesn't
// prematurely kill the other. The connection is counted for the whole transfer.
func (f *Forward) pipe(a, b net.Conn) {
	f.incConns()
	defer func() {
		_ = a.Close()
		_ = b.Close()
		f.decConns()
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		halfCloseWrite(a)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		halfCloseWrite(b)
	}()
	wg.Wait()
}

// halfCloser is implemented by both *net.TCPConn and x/crypto/ssh's tunnelled
// channel connections, letting one direction signal EOF without tearing the
// whole connection down.
type halfCloser interface {
	CloseWrite() error
}

func halfCloseWrite(c net.Conn) {
	if hc, ok := c.(halfCloser); ok {
		_ = hc.CloseWrite()
	}
}

func (f *Forward) incConns() {
	f.mu.Lock()
	f.conns++
	f.mu.Unlock()
}

func (f *Forward) decConns() {
	f.mu.Lock()
	f.conns--
	f.mu.Unlock()
}

// keepaliveLoop mirrors the session keepalive: a failed send means the
// connection is gone, so the forward is torn down.
func (f *Forward) keepaliveLoop() {
	t := time.NewTicker(keepaliveInterval)
	defer t.Stop()
	for {
		select {
		case <-f.done:
			return
		case <-t.C:
			if _, _, err := f.client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				_ = f.Close()
				return
			}
		}
	}
}

// end tears the forward down exactly once: closes the listener and client,
// marks it dead, unregisters from the manager, and notifies the UI. err is nil
// on a deliberate Close and non-nil when a listener or connection failure ended
// it; the sync.Once guarantees a deliberate Close's nil result isn't later
// overwritten by the accept loop observing its own closed listener.
func (f *Forward) end(err error) {
	f.endOnce.Do(func() {
		f.mu.Lock()
		f.alive = false
		f.mu.Unlock()
		if f.ln != nil {
			_ = f.ln.Close()
		}
		if f.client != nil {
			_ = f.client.Close()
		}
		close(f.done)
		f.mgr.removeForward(f.id, f)
		f.mgr.notify(ForwardEndedMsg{ForwardID: f.id, HostID: f.host.ID, Err: err})
	})
}

// newForwardID returns 8 random bytes as lowercase hex. crypto/rand does not
// fail on the platforms Wharf targets, so a failure is treated as fatal.
func newForwardID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("sshx: crypto/rand unavailable: %v", err))
	}
	return hex.EncodeToString(b[:])
}
