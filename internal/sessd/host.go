package sessd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/Janne6565/wharf-tui/internal/sshx"
	tea "github.com/charmbracelet/bubbletea"
)

// outChunk caps one output frame. Remote output is streamed continuously, so
// the chunk size only bounds latency and frame overhead.
const outChunk = 32 * 1024

// Host is the session-host child: it owns exactly one SSH session and serves it
// over one unix socket for the session's lifetime. It outlives the TUI that
// spawned it — that is the entire point — so it holds no vault, no master
// password and no state beyond the live connection.
type Host struct {
	ln        net.Listener
	sockPath  string
	startedAt time.Time

	mu       sync.Mutex
	sess     *sshx.Session
	spec     sshx.HostSpec
	dialing  bool  // a dial is in flight; prompts route to dialConn
	dialConn *conn // client that issued the dial, and answers its prompts
	attached *conn // client currently streaming, if any
	conns    map[*conn]struct{}
	ended    bool

	done chan struct{} // closed when the session is over and Serve should return
}

// conn is one connected client. Frame writes are serialized per connection;
// reads happen only on that connection's own goroutine.
type conn struct {
	net  net.Conn
	host *Host

	wmu sync.Mutex

	replies chan promptReply // answers to prompts this client was asked

	// closed fires when this client goes away. Anything waiting on the client —
	// an outstanding prompt, the dial it is driving — must select on it, or a
	// TUI that quits mid-prompt strands this process forever.
	closed    chan struct{}
	closeOnce sync.Once
}

// idleGrace is how long a host may sit with no session and no clients before it
// gives up and exits. It has to outlast the spawn handshake (the parent dials
// within dialTimeout), and exists so a child can never outlive the run that
// spawned it without having anything to show for itself. A var only so tests
// can shrink it; nothing outside this package changes it.
var idleGrace = 30 * time.Second

// Serve runs the session host on ln until the session ends or a client kills
// it. sockPath is unlinked on return. Serve owns ln and closes it.
//
// The engine is not created here but on dial, because the client is what knows
// which known_hosts file and keepalive policy to use.
func Serve(ln net.Listener, sockPath string) error {
	h := &Host{
		ln:        ln,
		sockPath:  sockPath,
		startedAt: time.Now(),
		conns:     map[*conn]struct{}{},
		done:      make(chan struct{}),
	}
	go h.acceptLoop()
	go h.watchdog()
	<-h.done

	_ = ln.Close()
	if sockPath != "" {
		_ = os.Remove(sockPath)
		// Returning normally means nothing went wrong worth keeping: only a
		// crash should leave a log behind.
		_ = os.Remove(logPathFor(sockPath))
	}
	h.closeClients()
	return nil
}

func (h *Host) acceptLoop() {
	for {
		c, err := h.ln.Accept()
		if err != nil {
			return // listener closed on shutdown
		}
		cn := &conn{
			net:     c,
			host:    h,
			replies: make(chan promptReply, 1),
			closed:  make(chan struct{}),
		}
		h.mu.Lock()
		h.conns[cn] = struct{}{}
		h.mu.Unlock()
		go cn.serve()
	}
}

// shutdown ends the host: every client is told, then Serve returns.
func (h *Host) shutdown(sessionErr error) {
	h.mu.Lock()
	if h.ended {
		h.mu.Unlock()
		return
	}
	h.ended = true
	clients := make([]*conn, 0, len(h.conns))
	for c := range h.conns {
		clients = append(clients, c)
	}
	h.mu.Unlock()

	notice := endedNotice{}
	if sessionErr != nil {
		notice.Err = sessionErr.Error()
	}
	for _, c := range clients {
		_ = c.writeJSON(kindEnded, notice)
	}
	close(h.done)
}

func (h *Host) closeClients() {
	h.mu.Lock()
	clients := make([]*conn, 0, len(h.conns))
	for c := range h.conns {
		clients = append(clients, c)
	}
	h.mu.Unlock()
	for _, c := range clients {
		_ = c.net.Close()
	}
}

func (h *Host) drop(c *conn) {
	h.mu.Lock()
	delete(h.conns, c)
	if h.attached == c {
		h.attached = nil
	}
	if h.dialConn == c {
		h.dialConn = nil
	}
	sess, idle := h.sess, len(h.conns) == 0
	h.mu.Unlock()
	// Unblock anything waiting on this client: an outstanding prompt, and the
	// dial it was driving.
	c.closeOnce.Do(func() { close(c.closed) })
	if sess != nil {
		sess.UnsetLive(c.outWriter())
	}
	_ = c.net.Close()
	// The last client left before there was ever a session: nothing can arrive
	// on this socket that would give the process a purpose again, so go now
	// rather than waiting out idleGrace.
	if sess == nil && idle {
		h.shutdown(nil)
	}
}

// watchdog exits a host that never got a session and has no client to get one
// from. Without it a spawn whose parent died — or gave up — leaves a process
// and a socket behind for the rest of the login session, and every later wharf
// start pays to re-probe it.
func (h *Host) watchdog() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var idleFor time.Duration
	for {
		select {
		case <-h.done:
			return
		case <-t.C:
			h.mu.Lock()
			idle := h.sess == nil && len(h.conns) == 0
			h.mu.Unlock()
			if !idle {
				idleFor = 0
				continue
			}
			if idleFor += time.Second; idleFor >= idleGrace {
				h.shutdown(nil)
				return
			}
		}
	}
}

// notify receives the engine's messages. Prompts are relayed to the dialing
// client; the session's death shuts the host down.
func (h *Host) notify(msg tea.Msg) {
	switch m := msg.(type) {
	case sshx.HostKeyPromptMsg:
		go h.relayPrompt(promptRequest{
			Kind:        promptHostKey,
			Host:        m.Host,
			KeyType:     m.KeyType,
			Fingerprint: m.Fingerprint,
		}, func(r promptReply, ok bool) { m.Reply <- ok && !r.Canceled && r.Accept })
	case sshx.SecretPromptMsg:
		go h.relayPrompt(promptRequest{
			Kind:   promptSecret,
			Title:  m.Title,
			Detail: m.Detail,
			Echo:   m.Echo,
		}, func(r promptReply, ok bool) {
			if !ok || r.Canceled {
				m.Reply <- nil
				return
			}
			m.Reply <- r.Secret
		})
	case sshx.SessionEndedMsg:
		h.shutdown(m.Err)
	}
}

// relayPrompt asks the dialing client and hands the answer to respond. A client
// that vanishes mid-prompt answers as a cancel, which fails the dial cleanly
// rather than hanging the auth chain.
func (h *Host) relayPrompt(req promptRequest, respond func(promptReply, bool)) {
	h.mu.Lock()
	c := h.dialConn
	h.mu.Unlock()
	if c == nil {
		respond(promptReply{}, false)
		return
	}
	if err := c.writeJSON(kindPrompt, req); err != nil {
		respond(promptReply{}, false)
		return
	}
	select {
	case r := <-c.replies:
		respond(r, true)
	case <-c.closed:
		respond(promptReply{}, false)
	case <-h.done:
		respond(promptReply{}, false)
	}
}

// --- per-connection handling ------------------------------------------------

func (c *conn) writeFrame(kind frameKind, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return writeFrame(c.net, kind, payload)
}

func (c *conn) writeJSON(kind frameKind, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.writeFrame(kind, b)
}

// outWriter is the io.Writer handed to the session's tee while this client is
// attached. It is a stable value per connection so UnsetLive can match it.
func (c *conn) outWriter() io.Writer { return (*connOut)(c) }

type connOut conn

func (o *connOut) Write(p []byte) (int, error) {
	c := (*conn)(o)
	// Counted up as frames land rather than reported from the loop variable:
	// p is consumed as it is chunked, so returning len(p) at the end reported
	// a zero-length write for every call. io.Copy would call that ErrShortWrite.
	var written int
	for len(p) > 0 {
		n := len(p)
		if n > outChunk {
			n = outChunk
		}
		if err := c.writeFrame(kindOutput, p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (c *conn) serve() {
	defer c.host.drop(c)
	for {
		kind, payload, err := readFrame(c.net)
		if err != nil {
			return
		}
		if !c.handle(kind, payload) {
			return
		}
	}
}

// handle processes one frame, reporting whether the connection should live on.
func (c *conn) handle(kind frameKind, payload []byte) bool {
	h := c.host
	switch kind {
	case kindInfo:
		_ = c.writeJSON(kindInfoOK, h.info())

	case kindDial:
		var req dialRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			_ = c.writeJSON(kindError, errorNotice{Err: "bad dial request: " + err.Error()})
			return false
		}
		// Dialing must not run on this connection's read loop: the auth chain
		// raises prompts whose answers arrive as frames on this very
		// connection, and a blocked reader could never deliver them.
		go c.dial(req)

	case kindAttach:
		var req attachRequest
		_ = json.Unmarshal(payload, &req)
		c.attach(req)

	case kindDetach:
		c.detach()

	case kindData:
		h.mu.Lock()
		sess, attached := h.sess, h.attached == c
		h.mu.Unlock()
		if sess != nil && attached {
			_, _ = sess.Write(payload)
		}

	case kindResize:
		var req resizeRequest
		if err := json.Unmarshal(payload, &req); err == nil {
			h.mu.Lock()
			sess := h.sess
			h.mu.Unlock()
			if sess != nil {
				_ = sess.Resize(req.Cols, req.Rows)
			}
		}

	case kindPromptReply:
		var r promptReply
		if err := json.Unmarshal(payload, &r); err != nil {
			r = promptReply{Canceled: true}
		}
		select {
		case c.replies <- r:
		default: // no prompt outstanding; ignore
		}

	case kindKill:
		h.mu.Lock()
		sess := h.sess
		h.mu.Unlock()
		if sess != nil {
			_ = sess.Close() // SessionEndedMsg drives the shutdown
		} else {
			h.shutdown(nil)
		}
		// Stay readable: shutdown still has to deliver kindEnded on this very
		// connection, and dropping it here would race that write away.
		return true
	}
	return true
}

func (h *Host) info() infoResponse {
	h.mu.Lock()
	defer h.mu.Unlock()
	resp := infoResponse{
		Protocol:  protocolVersion,
		PID:       os.Getpid(),
		HostID:    h.spec.ID,
		HostName:  h.spec.Name,
		User:      h.spec.User,
		Addr:      h.spec.Addr,
		Port:      h.spec.Port,
		StartedAt: h.startedAt.Unix(),
		Attached:  h.attached != nil,
	}
	if h.sess != nil {
		resp.Alive = h.sess.Alive()
		resp.Cols, resp.Rows = h.sess.Size()
	}
	return resp
}

// dial authenticates and starts the remote shell. Prompts raised by the auth
// chain are relayed back to this connection until the dial settles.
func (c *conn) dial(req dialRequest) {
	h := c.host
	h.mu.Lock()
	if h.sess != nil || h.dialing {
		h.mu.Unlock()
		_ = c.writeJSON(kindError, errorNotice{Err: "session already dialed"})
		return
	}
	h.dialing = true
	h.dialConn = c
	spec := specFromWire(req.Spec)
	h.spec = spec
	h.mu.Unlock()

	if req.Term != "" {
		// Dial reads TERM from the environment for the PTY request; the child
		// inherits the TUI's environment, but an explicit value wins.
		_ = os.Setenv("TERM", req.Term)
	}
	mgr := sshx.NewManager(req.KnownHosts, req.Keepalive)
	mgr.SetNotify(h.notify)

	cols, rows := req.Cols, req.Rows
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}

	// The dial belongs to the client that asked for it: if that client gives up
	// — the TUI quit, the terminal closed — the auth chain must unwind instead
	// of blocking on a prompt nobody will ever answer. Without this the process
	// hangs for the rest of the login session.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-c.closed:
			cancel()
		case <-ctx.Done():
		}
	}()

	sess, err := mgr.Dial(ctx, spec, cols, rows)

	h.mu.Lock()
	h.dialing = false
	h.mu.Unlock()

	if err != nil {
		_ = c.writeJSON(kindError, errorNotice{Err: err.Error()})
		h.shutdown(nil) // nothing to keep alive; the client reports the error
		return
	}

	// The client vanished while the dial was completing: it never learned about
	// this session, so nothing can ever reattach to it. Close it rather than
	// leave a shell running that no wharf will claim.
	select {
	case <-c.closed:
		_ = sess.Close()
		h.shutdown(nil)
		return
	default:
	}

	h.mu.Lock()
	h.sess = sess
	h.mu.Unlock()
	_ = c.writeFrame(kindDialOK, nil)
}

// attach starts streaming this session to c: replay first, then live output.
// Only one client streams at a time.
func (c *conn) attach(req attachRequest) {
	h := c.host
	h.mu.Lock()
	sess := h.sess
	switch {
	case sess == nil:
		h.mu.Unlock()
		_ = c.writeJSON(kindError, errorNotice{Err: "no session"})
		return
	case h.attached != nil && h.attached != c:
		h.mu.Unlock()
		_ = c.writeJSON(kindError, errorNotice{Err: "session is attached in another terminal"})
		return
	}
	h.attached = c
	h.mu.Unlock()

	if req.Cols > 0 && req.Rows > 0 {
		_ = sess.Resize(req.Cols, req.Rows)
	}
	// Replay and handover are one step: output produced while the scrollback is
	// being sent queues behind it instead of falling into the gap between the
	// snapshot and the live install.
	w := c.outWriter()
	err := sess.GoLive(w, func(snap []byte) error {
		if len(snap) == 0 {
			return nil
		}
		_, err := w.Write(snap)
		return err
	})
	if err != nil {
		h.mu.Lock()
		h.attached = nil
		h.mu.Unlock()
	}
}

func (c *conn) detach() {
	h := c.host
	h.mu.Lock()
	sess := h.sess
	if h.attached == c {
		h.attached = nil
	}
	h.mu.Unlock()
	if sess != nil {
		sess.UnsetLive(c.outWriter())
	}
}

func specFromWire(w hostSpecWire) sshx.HostSpec {
	spec := sshx.HostSpec{
		ID:         w.ID,
		Name:       w.Name,
		User:       w.User,
		Addr:       w.Addr,
		Port:       w.Port,
		KeyPath:    w.KeyPath,
		AuthMethod: w.AuthMethod,
		Password:   w.Password,
	}
	for _, k := range w.VaultKeys {
		spec.VaultKeys = append(spec.VaultKeys, sshx.VaultKeySpec{Name: k.Name, PEM: k.PEM})
	}
	return spec
}

func specToWire(s sshx.HostSpec) hostSpecWire {
	w := hostSpecWire{
		ID:         s.ID,
		Name:       s.Name,
		User:       s.User,
		Addr:       s.Addr,
		Port:       s.Port,
		KeyPath:    s.KeyPath,
		AuthMethod: s.AuthMethod,
		Password:   s.Password,
	}
	for _, k := range s.VaultKeys {
		w.VaultKeys = append(w.VaultKeys, vaultKeyWir{Name: k.Name, PEM: k.PEM})
	}
	return w
}

// errNoSession is returned by client calls made against a host whose session is
// already gone.
var errNoSession = errors.New("sessd: session is gone")
