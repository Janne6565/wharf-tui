package sshx

import (
	"sync"

	tea "github.com/charmbracelet/bubbletea"
)

// Manager owns all live sessions and the known-hosts policy. Its methods are
// safe for concurrent use by the engine's per-session goroutines and the UI
// goroutine.
type Manager struct {
	knownHostsPath string
	keepalive      bool

	mu           sync.Mutex
	sessions     map[string]*Session
	order        []string // dial order, for List
	forwards     map[string]*Forward
	forwardOrder []string // start order, for Forwards

	notifyMu sync.Mutex
	notifyFn func(tea.Msg)
}

// NewManager creates a manager verifying against knownHostsPath
// (typically ~/.ssh/known_hosts). keepalive enables 30s server pings.
func NewManager(knownHostsPath string, keepalive bool) *Manager {
	return &Manager{
		knownHostsPath: knownHostsPath,
		keepalive:      keepalive,
		sessions:       make(map[string]*Session),
		forwards:       make(map[string]*Forward),
	}
}

// SetNotify wires prompt/lifecycle messages into the UI event loop
// (tea.Program.Send). Must be set before Dial. If it is never set, prompts
// fail gracefully (treated as canceled) instead of deadlocking.
func (m *Manager) SetNotify(fn func(tea.Msg)) {
	m.notifyMu.Lock()
	m.notifyFn = fn
	m.notifyMu.Unlock()
}

// notify delivers msg to the UI if a callback is wired.
func (m *Manager) notify(msg tea.Msg) {
	m.notifyMu.Lock()
	fn := m.notifyFn
	m.notifyMu.Unlock()
	if fn != nil {
		fn(msg)
	}
}

// hasNotify reports whether a callback is wired (prompts fail fast otherwise).
func (m *Manager) hasNotify() bool {
	m.notifyMu.Lock()
	defer m.notifyMu.Unlock()
	return m.notifyFn != nil
}

// register adds s under its host ID in dial order.
func (m *Manager) register(s *Session) {
	id := s.host.ID
	m.mu.Lock()
	if _, exists := m.sessions[id]; !exists {
		m.order = append(m.order, id)
	}
	m.sessions[id] = s
	m.mu.Unlock()
}

// remove drops the session for id (idempotent). It only removes the mapping
// if it still points at the ended session, so a fresh re-dial that reused the
// ID isn't accidentally evicted.
func (m *Manager) remove(id string, s *Session) {
	m.mu.Lock()
	if m.sessions[id] == s {
		delete(m.sessions, id)
		for i, x := range m.order {
			if x == id {
				m.order = append(m.order[:i], m.order[i+1:]...)
				break
			}
		}
	}
	m.mu.Unlock()
}

// Get returns the live session for hostID, or nil.
func (m *Manager) Get(hostID string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[hostID]
}

// List returns all live sessions in dial order.
func (m *Manager) List() []*Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Session, 0, len(m.order))
	for _, id := range m.order {
		if s := m.sessions[id]; s != nil {
			out = append(out, s)
		}
	}
	return out
}

// registerForward adds f under its ID in start order.
func (m *Manager) registerForward(f *Forward) {
	m.mu.Lock()
	if _, exists := m.forwards[f.id]; !exists {
		m.forwardOrder = append(m.forwardOrder, f.id)
	}
	m.forwards[f.id] = f
	m.mu.Unlock()
}

// removeForward drops the forward for id (idempotent). It only removes the
// mapping if it still points at the ended forward, mirroring remove's guard.
func (m *Manager) removeForward(id string, f *Forward) {
	m.mu.Lock()
	if m.forwards[id] == f {
		delete(m.forwards, id)
		for i, x := range m.forwardOrder {
			if x == id {
				m.forwardOrder = append(m.forwardOrder[:i], m.forwardOrder[i+1:]...)
				break
			}
		}
	}
	m.mu.Unlock()
}

// GetForward returns the live forward for id, or nil.
func (m *Manager) GetForward(id string) *Forward {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.forwards[id]
}

// Forwards returns all live forwards in start order.
func (m *Manager) Forwards() []*Forward {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Forward, 0, len(m.forwardOrder))
	for _, id := range m.forwardOrder {
		if f := m.forwards[id]; f != nil {
			out = append(out, f)
		}
	}
	return out
}

// CloseAll terminates every session and forward (used on quit).
func (m *Manager) CloseAll() {
	for _, s := range m.List() {
		_ = s.Close()
	}
	for _, f := range m.Forwards() {
		_ = f.Close()
	}
}
