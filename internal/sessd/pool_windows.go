package sessd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Janne6565/wharf-tui/internal/proxydial"
	"github.com/Janne6565/wharf-tui/internal/sshx"
	tea "github.com/charmbracelet/bubbletea"
)

// The Windows pool runs sessions in this process on top of sshx, because the
// unix design — a detached child holding the SSH connection, reached over a
// socket handed to it as fd 3 — has no Windows equivalent (see the package
// doc). Everything the UI touches behaves identically except that sessions do
// not outlive wharf.

// Pool owns the live sessions. Its API matches the unix pool exactly, so
// internal/ui never has to know which one it is talking to.
type Pool struct {
	knownHosts string

	mu        sync.Mutex
	keepalive bool
	proxy     *proxydial.Setting // shared egress-proxy holder, read per dial
	// Keyed by session ID rather than host ID: a host can have several shells
	// open at once, which is also why each session gets its own sshx.Manager —
	// a Manager indexes sessions by host and would collide on the second one.
	remotes map[string]*Remote
	order   []string

	notifyMu sync.Mutex
	notifyFn func(tea.Msg)
}

// NewPool creates a pool. dir is accepted for signature parity with the unix
// pool and ignored: there are no sockets to place, because there are no child
// processes.
func NewPool(dir, knownHosts string, keepalive bool) *Pool {
	return &Pool{
		knownHosts: knownHosts,
		keepalive:  keepalive,
		remotes:    map[string]*Remote{},
	}
}

// SetExecutable is a no-op. Nothing is re-executed on Windows.
func (p *Pool) SetExecutable(string) {}

// SetKeepalive controls the keepalive policy for sessions dialed from now on.
// Live sessions keep the policy they were dialed with, matching the unix pool,
// where the policy lives in the child's own manager.
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

// SetProxy points the pool at the shared proxy setting, read at each dial.
// Wiring only, as on unix: the setting itself is what changes. Live sessions
// keep the proxy they were dialed through.
func (p *Pool) SetProxy(s *proxydial.Setting) {
	p.mu.Lock()
	p.proxy = s
	p.mu.Unlock()
}

// Proxy returns the shared setting new sessions will be dialed with.
func (p *Pool) Proxy() *proxydial.Setting {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.proxy
}

// SetNotify wires prompt and lifecycle messages into the UI event loop.
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
	p.mu.Lock()
	if _, ok := p.remotes[r.id]; !ok {
		p.order = append(p.order, r.id)
	}
	p.remotes[r.id] = r
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

// ForHost returns every live session for a host, oldest first.
func (p *Pool) ForHost(hostID string) []*Remote {
	var out []*Remote
	for _, r := range p.List() {
		if r.spec.ID == hostID {
			out = append(out, r)
		}
	}
	return out
}

// List returns every live session in dial order.
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

// Adopt always reports zero. Adoption is how the unix pool reconnects to
// sessions a previous wharf left running; in-process sessions never outlive the
// wharf that dialed them, so there is nothing to find.
func (p *Pool) Adopt() (int, error) { return 0, nil }

// Dial opens a session for spec. Prompts surface as the usual sshx messages
// while this runs.
func (p *Pool) Dial(ctx context.Context, spec sshx.HostSpec, cols, rows int) (*Remote, error) {
	id, err := sessionID(spec.ID)
	if err != nil {
		return nil, err
	}

	// One manager per session. A Manager keys its sessions by host ID, so a
	// shared one would silently drop the first session when a host is opened
	// twice — the exact case the pool exists to support.
	mgr := sshx.NewManager(p.knownHosts, p.Keepalive())
	mgr.SetNotify(p.notify)
	mgr.SetProxy(p.Proxy())

	sess, err := mgr.Dial(ctx, spec, cols, rows)
	if err != nil {
		return nil, err
	}

	r := &Remote{
		pool:      p,
		id:        id,
		spec:      spec,
		startedAt: time.Now(),
		mgr:       mgr,
		sess:      sess,
	}
	p.register(r)

	// The session can also end on its own (remote logout, connection drop).
	// sshx already notifies the UI; the pool still has to stop listing it.
	go func() {
		<-sess.Done()
		p.remove(r.id, r)
	}()

	return r, nil
}

// Detach closes every session.
//
// On unix this drops the control connections and deliberately leaves the
// children running — that is what makes a session survive a quit. Here there is
// no child to leave behind, so the honest equivalent is a clean shutdown: the
// remote gets a proper SSH close instead of having its connection torn down
// when the process exits.
func (p *Pool) Detach() { p.CloseAll() }

// CloseAll terminates every session.
func (p *Pool) CloseAll() {
	for _, r := range p.List() {
		_ = r.Close()
	}
}

// sessionID mints an identifier unique for this session's lifetime. The unix
// pool derives one from its socket filename; without sockets, a random suffix
// on the host ID gives the same shape and the same guarantee.
func sessionID(hostID string) (string, error) {
	var buf [5]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	if hostID == "" {
		hostID = "session"
	}
	return hostID + "-" + hex.EncodeToString(buf[:]), nil
}

// RuntimeDir reports where per-session state would live. Nothing is written
// there on Windows — it exists so main's --doctor output and the unix code
// paths share one shape.
func RuntimeDir() (string, error) {
	if dir := os.Getenv("WHARF_RUNTIME_DIR"); dir != "" {
		return dir, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "wharf", "run"), nil
}

// --- Remote -----------------------------------------------------------------

// Remote is one session. It wraps an sshx.Session and adds the identity the
// unix Remote carries — a session ID and a start time — which sshx does not
// track because it keys sessions by host.
type Remote struct {
	pool      *Pool
	id        string
	spec      sshx.HostSpec
	startedAt time.Time

	// mgr is retained for the session's lifetime: it owns the notify wiring the
	// session's goroutines call into.
	mgr  *sshx.Manager
	sess *sshx.Session
}

// Host returns the spec this session was dialed with.
func (r *Remote) Host() sshx.HostSpec { return r.spec }

// ID identifies this session for its whole life.
func (r *Remote) ID() string { return r.id }

// StartedAt is when the session was dialed.
func (r *Remote) StartedAt() time.Time { return r.startedAt }

// Alive reports whether the session is still usable.
func (r *Remote) Alive() bool { return r.sess.Alive() }

// Done closes when the session ends, however it ends.
func (r *Remote) Done() <-chan struct{} { return r.sess.Done() }

// Attach hands this terminal to the session until the user detaches (ctrl+\)
// or it dies.
func (r *Remote) Attach(detach byte) tea.ExecCommand { return r.sess.Attach(detach) }

// Close terminates the session.
func (r *Remote) Close() error {
	err := r.sess.Close()
	r.pool.remove(r.id, r)
	return err
}
