//go:build !windows

package sessd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/Janne6565/wharf-tui/internal/proxydial"
	"github.com/Janne6565/wharf-tui/internal/sshx"
	tea "github.com/charmbracelet/bubbletea"
)

// dialTimeout bounds how long a freshly spawned child gets to accept the
// control connection before the spawn is called a failure.
const dialTimeout = 5 * time.Second

// adoptTimeout bounds each probe during adoption. Adoption runs before the UI
// paints, once per socket, so this is startup latency the user waits on: a
// local socket answers in microseconds, and anything that does not is not worth
// blocking a cold start for.
const adoptTimeout = 1500 * time.Millisecond

// Pool is the TUI-side view of every session host: the ones it spawned and the
// ones it adopted from a previous run. It mirrors the slice of *sshx.Manager
// the UI used to consume for sessions, so prompts and lifecycle still arrive as
// the same tea messages.
//
// Port forwards deliberately stay in sshx: they are documented as ephemeral and
// never persisted, so hoisting them into a surviving process would change
// behaviour nobody asked for.
type Pool struct {
	dir        string
	knownHosts string
	keepalive  bool
	exe        string

	// Sessions are keyed by session ID, not host ID: a host can have several
	// shells open at once, each in its own child process.
	mu      sync.Mutex
	proxy   *proxydial.Setting // shared egress-proxy holder, read per spawn
	remotes map[string]*Remote
	order   []string

	notifyMu sync.Mutex
	notifyFn func(tea.Msg)
}

// NewPool creates a pool rooted at dir (see RuntimeDir). exe is the wharf
// binary to re-execute for new sessions; an empty value resolves os.Executable
// at spawn time.
func NewPool(dir, knownHosts string, keepalive bool) *Pool {
	return &Pool{
		dir:        dir,
		knownHosts: knownHosts,
		keepalive:  keepalive,
		remotes:    map[string]*Remote{},
	}
}

// SetExecutable overrides the binary spawned for new sessions (tests point this
// at a built test binary).
func (p *Pool) SetExecutable(path string) { p.exe = path }

// SetKeepalive controls the keepalive policy handed to session hosts spawned
// from now on. The pool is built before the vault is unlocked, so the value it
// starts with is a default the UI corrects; children already running keep the
// policy they were dialed with, since it lives in their own manager.
func (p *Pool) SetKeepalive(on bool) {
	p.mu.Lock()
	p.keepalive = on
	p.mu.Unlock()
}

// Keepalive reports the policy new sessions will be dialed with.
func (p *Pool) Keepalive() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.keepalive
}

// SetProxy points the pool at the shared proxy setting, which it reads at each
// spawn. Wiring only: changing the proxy goes through the setting itself, so
// the pool and the engine cannot drift apart.
//
// Children already running keep the proxy they were dialed through: their TCP
// connection is established and cannot be re-routed under a live SSH transport.
func (p *Pool) SetProxy(s *proxydial.Setting) {
	p.mu.Lock()
	p.proxy = s
	p.mu.Unlock()
}

// Proxy returns the shared setting new sessions will be spawned with.
func (p *Pool) Proxy() *proxydial.Setting {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.proxy
}

// SetNotify wires prompt and lifecycle messages into the UI event loop, exactly
// as sshx.Manager.SetNotify does.
func (p *Pool) SetNotify(fn func(tea.Msg)) {
	p.notifyMu.Lock()
	p.notifyFn = fn
	p.notifyMu.Unlock()
}

func (p *Pool) notify(msg tea.Msg) {
	p.notifyMu.Lock()
	fn := p.notifyFn
	p.notifyMu.Unlock()
	if fn != nil {
		fn(msg)
	}
}

func (p *Pool) register(r *Remote) {
	id := r.id
	p.mu.Lock()
	if _, ok := p.remotes[id]; !ok {
		p.order = append(p.order, id)
	}
	p.remotes[id] = r
	p.mu.Unlock()
}

func (p *Pool) remove(id string, r *Remote) {
	p.mu.Lock()
	if p.remotes[id] == r {
		delete(p.remotes, id)
		for i, x := range p.order {
			if x == id {
				p.order = append(p.order[:i], p.order[i+1:]...)
				break
			}
		}
	}
	p.mu.Unlock()
}

// Get returns the session with this session ID, or nil.
func (p *Pool) Get(sessionID string) *Remote {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.remotes[sessionID]
}

// ForHost returns every live session for a host, oldest first. A host can have
// any number of them; the UI offers a picker when there is more than zero.
func (p *Pool) ForHost(hostID string) []*Remote {
	var out []*Remote
	for _, r := range p.List() {
		if r.spec.ID == hostID {
			out = append(out, r)
		}
	}
	return out
}

// List returns every live session in dial (then adoption) order.
func (p *Pool) List() []*Remote {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*Remote, 0, len(p.order))
	for _, id := range p.order {
		if r := p.remotes[id]; r != nil && r.Alive() {
			out = append(out, r)
		}
	}
	return out
}

// Adopt connects to every socket in the pool directory and registers the
// sessions still running there — this is what makes a session survive a quit.
// Stale sockets (no listener) are unlinked. It returns the number adopted.
func (p *Pool) Adopt() (int, error) {
	socks, err := listSockets(p.dir)
	if err != nil {
		return 0, err
	}
	var n int
	for _, sock := range socks {
		c, err := net.DialTimeout("unix", sock, adoptTimeout)
		if err != nil {
			// Nobody is listening: the host died without cleaning up. Its log
			// goes too — Serve only leaves one behind after a crash, and it has
			// already outlived anything that could read it.
			_ = os.Remove(sock)
			_ = os.Remove(logPathFor(sock))
			continue
		}
		r := newRemote(p, sock, c)
		info, err := r.requestInfo(adoptTimeout)
		switch {
		case err != nil:
			// Reachable but not answering. Leave the socket: the host's own
			// watchdog retires a purposeless one, and a busy host deserves
			// another chance on the next run rather than being unlinked here.
			r.closeConn()
			continue
		case info.Protocol != protocolVersion:
			// A different build's host. Its session may well be real, so the
			// socket stays; this wharf just cannot frame a stream to it.
			r.closeConn()
			continue
		case !info.Alive:
			// Reachable, understood, and has nothing running: retire it, or it
			// is re-probed on every start for the rest of the login session.
			_ = r.writeFrame(kindKill, nil)
			r.closeConn()
			_ = os.Remove(sock)
			_ = os.Remove(logPathFor(sock))
			continue
		}
		r.spec = sshx.HostSpec{
			ID:   info.HostID,
			Name: info.HostName,
			User: info.User,
			Addr: info.Addr,
			Port: info.Port,
		}
		r.startedAt = time.Unix(info.StartedAt, 0)
		r.setAlive(true)
		p.register(r)
		n++
	}
	return n, nil
}

// Dial spawns a session host for spec and drives it through authentication.
// Prompts surface as the usual sshx messages while this runs.
func (p *Pool) Dial(ctx context.Context, spec sshx.HostSpec, cols, rows int) (*Remote, error) {
	exe := p.exe
	if exe == "" {
		var err error
		exe, err = os.Executable()
		if err != nil {
			return nil, fmt.Errorf("sessd: locating the wharf binary: %w", err)
		}
	}
	sock, err := socketPath(p.dir, spec.ID)
	if err != nil {
		return nil, err
	}

	// The parent creates the listener and hands the child its file descriptor,
	// so there is no window in which the socket exists but nothing is accepting
	// and no need to poll for readiness.
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("sessd: listening on %s: %w", sock, err)
	}
	unix, ok := ln.(*net.UnixListener)
	if !ok {
		_ = ln.Close()
		return nil, errors.New("sessd: unexpected listener type")
	}
	unix.SetUnlinkOnClose(false) // the child owns the socket file's lifetime
	if err := os.Chmod(sock, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(sock)
		return nil, fmt.Errorf("sessd: securing %s: %w", sock, err)
	}
	lnFile, err := unix.File()
	if err != nil {
		_ = ln.Close()
		_ = os.Remove(sock)
		return nil, fmt.Errorf("sessd: exporting the listener: %w", err)
	}
	defer lnFile.Close()

	cmd := exec.Command(exe, SessionHostFlag, sock)
	cmd.ExtraFiles = []*os.File{lnFile} // becomes fd 3 in the child
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	// The child has no terminal, so its stderr goes to a file beside the socket
	// and Serve deletes it on a clean exit. Failing to open it is not worth
	// failing the spawn over — it only costs diagnosability.
	if logf, err := os.OpenFile(logPathFor(sock), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		cmd.Stderr = logf
		defer logf.Close()
	}
	// A new session detaches the child from the terminal, so quitting the TUI
	// (or closing the window) does not take the shell down with it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = ln.Close()
		_ = os.Remove(sock)
		return nil, fmt.Errorf("sessd: starting the session host: %w", err)
	}
	// Reap the child if it dies while we are still running; once we exit it is
	// reparented and this goroutine goes with us.
	go func() { _ = cmd.Wait() }()
	_ = ln.Close() // the child holds its own copy of the descriptor

	conn, err := net.DialTimeout("unix", sock, dialTimeout)
	if err != nil {
		_ = os.Remove(sock)
		return nil, fmt.Errorf("sessd: connecting to the session host: %w", err)
	}

	r := newRemote(p, sock, conn)
	r.spec = spec
	r.startedAt = time.Now()
	if err := r.dial(ctx, spec, cols, rows, p.knownHosts, p.Keepalive(), p.Proxy().Dialer().RawURL()); err != nil {
		r.closeConn()
		return nil, err
	}
	r.setAlive(true)
	p.register(r)
	return r, nil
}

// Detach drops the control connections without touching the sessions. This is
// what quitting wharf now does: the children keep running.
func (p *Pool) Detach() {
	for _, r := range p.List() {
		r.closeConn()
	}
}

// CloseAll terminates every session (used by the explicit "close sessions"
// path, not by a plain quit).
func (p *Pool) CloseAll() {
	for _, r := range p.List() {
		_ = r.Close()
	}
}

// --- Remote -----------------------------------------------------------------

// Remote is one session living in a child process. Its method set mirrors the
// part of *sshx.Session the UI used, so the dashboard, the live strip and the
// attach path did not have to learn a second shape.
type Remote struct {
	pool *Pool
	sock string
	// id identifies this session for its whole life, on this machine. It is the
	// socket's basename, so it is unique by construction and survives adoption
	// by a later wharf without any bookkeeping.
	id        string
	startedAt time.Time

	wmu  sync.Mutex
	conn net.Conn

	spec sshx.HostSpec

	mu       sync.Mutex
	alive    bool
	live     io.Writer     // terminal to stream to while attached
	ctl      chan ctlFrame // dial/info replies
	done     chan struct{}
	doneOnce sync.Once
}

// ctlFrame is a control reply routed from the read loop to a waiting caller.
type ctlFrame struct {
	kind    frameKind
	payload []byte
}

func newRemote(p *Pool, sock string, c net.Conn) *Remote {
	r := &Remote{
		pool: p,
		sock: sock,
		id:   sessionIDFor(sock),
		conn: c,
		ctl:  make(chan ctlFrame, 4),
		done: make(chan struct{}),
	}
	go r.readLoop()
	return r
}

// Host returns the spec the session was dialed with (reconstructed from the
// host's info frame for an adopted session).
func (r *Remote) Host() sshx.HostSpec { return r.spec }

// ID is the stable per-session identifier (unique per machine).
func (r *Remote) ID() string { return r.id }

// StartedAt is when the session was dialed, for "up 20m" style display.
func (r *Remote) StartedAt() time.Time { return r.startedAt }

// Alive reports whether the remote shell is still running.
func (r *Remote) Alive() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.alive
}

// Done is closed when the session ends or the control connection drops.
func (r *Remote) Done() <-chan struct{} { return r.done }

func (r *Remote) setAlive(v bool) {
	r.mu.Lock()
	r.alive = v
	r.mu.Unlock()
}

func (r *Remote) writeFrame(kind frameKind, payload []byte) error {
	r.wmu.Lock()
	defer r.wmu.Unlock()
	if r.conn == nil {
		return errNoSession
	}
	return writeFrame(r.conn, kind, payload)
}

func (r *Remote) writeJSON(kind frameKind, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return r.writeFrame(kind, b)
}

func (r *Remote) closeConn() {
	r.wmu.Lock()
	c := r.conn
	r.conn = nil
	r.wmu.Unlock()
	if c != nil {
		_ = c.Close()
	}
	r.finish()
}

// finish marks the session finished, closes done exactly once and drops the
// remote from its pool.
//
// Clearing alive belongs here rather than at the call sites: closeConn nils the
// connection, so readLoop can observe that at the top of its next iteration and
// return without ever reaching its error path. When it does, this is the only
// place left that runs — and an alive flag left set would outlive the session
// it describes.
func (r *Remote) finish() {
	r.doneOnce.Do(func() {
		r.setAlive(false)
		close(r.done)
		r.pool.remove(r.id, r)
	})
}

// readLoop dispatches frames from the session host until the connection ends.
func (r *Remote) readLoop() {
	for {
		r.wmu.Lock()
		c := r.conn
		r.wmu.Unlock()
		if c == nil {
			return
		}
		kind, payload, err := readFrame(c)
		if err != nil {
			r.finish() // clears alive
			return
		}
		switch kind {
		case kindOutput:
			r.mu.Lock()
			w := r.live
			r.mu.Unlock()
			if w != nil {
				_, _ = w.Write(payload)
			}

		case kindPrompt:
			var req promptRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				_ = r.writeJSON(kindPromptReply, promptReply{Canceled: true})
				continue
			}
			go r.relayPrompt(req)

		case kindEnded:
			var notice endedNotice
			_ = json.Unmarshal(payload, &notice)
			r.setAlive(false)
			var endErr error
			if notice.Err != "" {
				endErr = errors.New(notice.Err)
			}
			r.pool.notify(sshx.SessionEndedMsg{HostID: r.spec.ID, Err: endErr})
			r.closeConn()
			return

		default:
			select {
			case r.ctl <- ctlFrame{kind: kind, payload: payload}:
			default:
			}
		}
	}
}

// relayPrompt turns a host prompt back into the tea message the UI already
// knows how to render, then ships the answer back over the socket.
func (r *Remote) relayPrompt(req promptRequest) {
	switch req.Kind {
	case promptHostKey:
		reply := make(chan bool, 1)
		r.pool.notify(sshx.HostKeyPromptMsg{
			HostID:      r.spec.ID,
			Host:        req.Host,
			KeyType:     req.KeyType,
			Fingerprint: req.Fingerprint,
			Reply:       reply,
		})
		select {
		case ok := <-reply:
			_ = r.writeJSON(kindPromptReply, promptReply{Accept: ok, Canceled: !ok})
		case <-r.done:
		}
	case promptSecret:
		reply := make(chan []byte, 1)
		r.pool.notify(sshx.SecretPromptMsg{
			HostID: r.spec.ID,
			Title:  req.Title,
			Detail: req.Detail,
			Echo:   req.Echo,
			Reply:  reply,
		})
		select {
		case secret := <-reply:
			if secret == nil {
				_ = r.writeJSON(kindPromptReply, promptReply{Canceled: true})
				return
			}
			_ = r.writeJSON(kindPromptReply, promptReply{Secret: secret})
		case <-r.done:
		}
	default:
		_ = r.writeJSON(kindPromptReply, promptReply{Canceled: true})
	}
}

// awaitCtl waits for the next control reply, honouring ctx and the connection
// dying underneath us.
func (r *Remote) awaitCtl(ctx context.Context) (ctlFrame, error) {
	select {
	case f := <-r.ctl:
		return f, nil
	case <-r.done:
		return ctlFrame{}, errNoSession
	case <-ctx.Done():
		return ctlFrame{}, ctx.Err()
	}
}

func (r *Remote) dial(ctx context.Context, spec sshx.HostSpec, cols, rows int, knownHosts string, keepalive bool, proxy string) error {
	req := dialRequest{
		Spec:       specToWire(spec),
		Cols:       cols,
		Rows:       rows,
		KnownHosts: knownHosts,
		Keepalive:  keepalive,
		Term:       os.Getenv("TERM"),
		Proxy:      proxy,
	}
	if err := r.writeJSON(kindDial, req); err != nil {
		return err
	}
	f, err := r.awaitCtl(ctx)
	if err != nil {
		return err
	}
	switch f.kind {
	case kindDialOK:
		return nil
	case kindError:
		var notice errorNotice
		_ = json.Unmarshal(f.payload, &notice)
		return errors.New(notice.Err)
	default:
		return fmt.Errorf("sessd: unexpected reply %d to dial", f.kind)
	}
}

func (r *Remote) requestInfo(timeout time.Duration) (infoResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := r.writeFrame(kindInfo, nil); err != nil {
		return infoResponse{}, err
	}
	f, err := r.awaitCtl(ctx)
	if err != nil {
		return infoResponse{}, err
	}
	if f.kind != kindInfoOK {
		return infoResponse{}, fmt.Errorf("sessd: unexpected reply %d to info", f.kind)
	}
	var info infoResponse
	if err := json.Unmarshal(f.payload, &info); err != nil {
		return infoResponse{}, err
	}
	return info, nil
}

// Close terminates the remote session and its child process.
func (r *Remote) Close() error {
	_ = r.writeFrame(kindKill, nil)
	select {
	case <-r.done:
	case <-time.After(dialTimeout):
		r.closeConn()
	}
	return nil
}

// setLive installs the terminal that streams output for one attach lifetime.
func (r *Remote) setLive(w io.Writer) {
	r.mu.Lock()
	r.live = w
	r.mu.Unlock()
}

func (r *Remote) unsetLive(w io.Writer) {
	r.mu.Lock()
	if r.live == w {
		r.live = nil
	}
	r.mu.Unlock()
}
