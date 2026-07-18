package ui

import (
	"context"
	"net"
	"strconv"
	"strings"

	"github.com/Janne6565/wharf-tui/internal/sshx"
	"github.com/Janne6565/wharf-tui/internal/store"
	tea "github.com/charmbracelet/bubbletea"
)

// defaultForwardBindAddr is the loopback prefill for the bind/target address
// fields, matching the engine's own loopback default.
const defaultForwardBindAddr = "127.0.0.1"

// forwardKinds is the toggle order for the kind selector: local (-L) first, then
// remote (-R), then dynamic SOCKS5 (-D).
var forwardKinds = []string{sshx.ForwardLocal, sshx.ForwardRemote, sshx.ForwardDynamic}

// forwardKindLabel is the human-readable name for a forward kind.
func forwardKindLabel(kind string) string {
	switch kind {
	case sshx.ForwardRemote:
		return "remote (-R)"
	case sshx.ForwardDynamic:
		return "dynamic socks5 (-D)"
	default:
		return "local (-L)"
	}
}

// cycleForwardKind advances the kind selector by dir (+1 / -1), wrapping around.
func cycleForwardKind(cur string, dir int) string {
	idx := 0
	for i, k := range forwardKinds {
		if k == cur {
			idx = i
			break
		}
	}
	idx = (idx + dir + len(forwardKinds)) % len(forwardKinds)
	return forwardKinds[idx]
}

// fwdFieldVisible reports whether forward-form field i is shown for the given
// kind. The two target fields are hidden (and skipped by navigation) for a
// dynamic forward, which resolves its target per-connection.
func fwdFieldVisible(kind string, i int) bool {
	switch i {
	case ffTargetAddr, ffTargetPort:
		return kind != sshx.ForwardDynamic
	default:
		return true
	}
}

// fwdNextField advances the forward-form focus by dir (+1 / -1), skipping any
// hidden field. ffKind is always visible, so this always terminates.
func (m Model) fwdNextField(dir int) int {
	f := m.fwdFocus
	for {
		f = (f + dir + ffCount) % ffCount
		if fwdFieldVisible(m.fwdVals[ffKind], f) {
			return f
		}
	}
}

// --- forward form -----------------------------------------------------------

// startForwardForm opens the forward form for the selected host (personal or
// project). Inert when no host is under the cursor.
func (m Model) startForwardForm() (tea.Model, tea.Cmd) {
	mh, ok := m.selectedMergedHost()
	if !ok {
		return m, nil
	}
	return m.openForwardForm(mh.Host), nil
}

// openForwardForm prepares the forward modal for host h, prefilled with the
// loopback defaults or — if the host was forwarded before this session — the
// last submitted spec (an ephemeral convenience; nothing is read from disk).
func (m Model) openForwardForm(h store.Host) Model {
	m.modal = modalForwardForm
	m.fwdHost = h
	m.fwdFocus = 0
	m.fwdErr = ""
	m.fwdVals = [ffCount]string{}
	m.fwdVals[ffKind] = sshx.ForwardLocal
	m.fwdVals[ffBindAddr] = defaultForwardBindAddr
	m.fwdVals[ffTargetAddr] = defaultForwardBindAddr
	if spec, ok := m.fwdPrefill[h.ID]; ok {
		m.fwdVals[ffKind] = spec.Kind
		m.fwdVals[ffBindAddr] = spec.BindAddr
		if spec.BindPort != 0 {
			m.fwdVals[ffBindPort] = itoa(spec.BindPort)
		}
		m.fwdVals[ffTargetAddr] = spec.TargetAddr
		if spec.TargetPort != 0 {
			m.fwdVals[ffTargetPort] = itoa(spec.TargetPort)
		}
	}
	return m
}

func (m Model) forwardFormKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.modal = modalNone
		return m, nil
	case "tab", "down":
		m.fwdFocus = m.fwdNextField(+1)
		return m, nil
	case "shift+tab", "up":
		m.fwdFocus = m.fwdNextField(-1)
		return m, nil
	case "enter":
		return m.submitForwardForm()
	}
	// The kind field is a selector, not a text input: arrows/space cycle it and
	// every other key is inert.
	if m.fwdFocus == ffKind {
		switch key {
		case "left":
			m.fwdVals[ffKind] = cycleForwardKind(m.fwdVals[ffKind], -1)
		case "right", " ":
			m.fwdVals[ffKind] = cycleForwardKind(m.fwdVals[ffKind], +1)
		}
		return m, nil
	}
	switch key {
	case "backspace":
		if v := m.fwdVals[m.fwdFocus]; len(v) > 0 {
			m.fwdVals[m.fwdFocus] = v[:len(v)-1]
		}
	default:
		if isPrintable(key) {
			m.fwdVals[m.fwdFocus] += key
		}
	}
	return m, nil
}

// submitForwardForm validates the form, remembers the spec for a later reopen,
// then starts the forward through the same dial machinery a connect uses so
// esc-cancel and prompt restoration work unchanged.
func (m Model) submitForwardForm() (tea.Model, tea.Cmd) {
	kind := m.fwdVals[ffKind]

	// Bind port: empty → 0 (auto-pick), otherwise an integer 0-65535.
	bindPort := 0
	if s := strings.TrimSpace(m.fwdVals[ffBindPort]); s != "" {
		p, err := strconv.Atoi(s)
		if err != nil || p < 0 || p > 65535 {
			m.fwdErr = "bind port must be 0-65535"
			return m, nil
		}
		bindPort = p
	}

	spec := sshx.ForwardSpec{
		Kind:     kind,
		BindAddr: strings.TrimSpace(m.fwdVals[ffBindAddr]),
		BindPort: bindPort,
	}
	// Target is required for local/remote; a dynamic forward has none.
	if kind != sshx.ForwardDynamic {
		ts := strings.TrimSpace(m.fwdVals[ffTargetPort])
		if ts == "" {
			m.fwdErr = "target port is required"
			return m, nil
		}
		tp, err := strconv.Atoi(ts)
		if err != nil || tp < 1 || tp > 65535 {
			m.fwdErr = "target port must be 1-65535"
			return m, nil
		}
		spec.TargetAddr = strings.TrimSpace(m.fwdVals[ffTargetAddr])
		spec.TargetPort = tp
	}

	// Remember the spec so reopening the form for this host prefills it. This is
	// in-memory only for the app's lifetime — nothing is persisted.
	if m.fwdPrefill == nil {
		m.fwdPrefill = map[string]sshx.ForwardSpec{}
	}
	m.fwdPrefill[m.fwdHost.ID] = spec

	if m.mgr == nil {
		m.modal = modalNone
		return m.setToast("no ssh engine available", "err"), nil
	}

	// Async start: reuse dialCancel/dialHostID so a cancel during the handshake
	// and any TOFU/secret prompt raised through the notify path route exactly as
	// a connect does. fwdInFlight lets the connecting modal say "starting forward".
	h := m.fwdHost
	ctx, cancel := context.WithCancel(context.Background())
	m.dialCancel = cancel
	m.dialHostID = h.ID
	m.fwdInFlight = true
	m.modal = modalConnecting
	hs := sshx.HostSpec{ID: h.ID, Name: h.Name, User: h.User, Addr: h.Addr, Port: h.Port, KeyPath: h.KeyPath, AuthMethod: h.AuthMethod, Password: h.Password}
	return m, startForwardCmd(m.mgr, ctx, hs, spec)
}

// handleForwardDone clears the in-flight state and reports the result. A forward
// is ephemeral, so — unlike a dial — success never stamps LastSeen and never
// persists a remembered password; any pending remembered password (even one
// typed during this handshake) is dropped.
func (m Model) handleForwardDone(msg forwardDoneMsg) (tea.Model, tea.Cmd) {
	m.dialHostID = ""
	m.dialCancel = nil
	m.fwdInFlight = false
	if m.modal == modalConnecting {
		m.modal = modalNone
	}
	m.pendingPW = nil
	if msg.err != nil {
		return m.handleDialErr(msg.hostID, msg.err)
	}
	if msg.fwd == nil {
		// Degenerate start (test seam): nothing live to announce.
		return m, nil
	}
	return m.setToast("forwarding "+forwardLabel(msg.fwd), "ok"), nil
}

// handleForwardEnded toasts a forward's termination. A deliberate Close reports a
// nil Err ("closed"); any other end reason carries the error.
func (m Model) handleForwardEnded(msg sshx.ForwardEndedMsg) (tea.Model, tea.Cmd) {
	name := m.forwardHostName(msg.HostID)
	if msg.Err != nil {
		return m.setToast("forward to "+name+" ended: "+msg.Err.Error(), "err"), nil
	}
	return m.setToast("forward to "+name+" closed", "ok"), nil
}

// --- active-forwards overlay ------------------------------------------------

// openForwards shows the active-forwards overlay. Callers guarantee mgr != nil.
func (m Model) openForwards() Model {
	m.modal = modalForwards
	if m.mgr != nil {
		m.fwdIdx = clampIdx(m.fwdIdx, len(m.mgr.Forwards()))
	}
	return m
}

func (m Model) forwardsKey(key string) (tea.Model, tea.Cmd) {
	if m.mgr == nil {
		m.modal = modalNone
		return m, nil
	}
	fwds := m.mgr.Forwards()
	switch key {
	case "esc", "F":
		m.modal = modalNone
	case "j", "down":
		m.fwdIdx = clampIdx(m.fwdIdx+1, len(fwds))
	case "k", "up":
		m.fwdIdx = clampIdx(m.fwdIdx-1, len(fwds))
	case "x", "d":
		if len(fwds) == 0 {
			return m, nil
		}
		f := fwds[clampIdx(m.fwdIdx, len(fwds))]
		label := forwardLabel(f)
		_ = f.Close() // ephemeral: no confirm; ForwardEndedMsg also toasts
		m.fwdIdx = clampIdx(m.fwdIdx, len(fwds)-1)
		return m.setToast("closed "+label, "ok"), nil
	}
	return m, nil
}

// --- labels & lookups -------------------------------------------------------

// forwardLabel renders a forward's Label, substituting the OS/server-assigned
// port when the bind port was auto-picked (BindPort 0) so the user sees the
// real listening port rather than ":0".
func forwardLabel(f *sshx.Forward) string {
	return forwardSpecLabel(f.Spec(), f.BoundAddr())
}

// forwardSpecLabel is the pure core of forwardLabel: given a spec and its
// resolved bound address, it substitutes the concrete port for a port-0 request.
func forwardSpecLabel(spec sshx.ForwardSpec, boundAddr string) string {
	if spec.BindPort == 0 {
		if _, portStr, err := net.SplitHostPort(boundAddr); err == nil {
			if p, err := strconv.Atoi(portStr); err == nil {
				spec.BindPort = p
			}
		}
	}
	return spec.Label()
}

// forwardName resolves a display name for a live forward's host: the merged-hosts
// lookup first (so project host names render too), then the name carried in the
// forward's own HostSpec, then the raw ID.
func (m Model) forwardName(f *sshx.Forward) string {
	id := f.Host().ID
	for _, mh := range m.mergedHosts() {
		if mh.Host.ID == id {
			return mh.Name
		}
	}
	if n := f.Host().Name; n != "" {
		return n
	}
	return id
}

// forwardHostName resolves a display name from a host ID alone (used by
// handleForwardEnded, where the ended forward is already unregistered). It tries
// the merged-hosts lookup, then any still-live forward to the same host, then
// hostName's personal-store lookup (which falls back to the ID).
func (m Model) forwardHostName(hostID string) string {
	for _, mh := range m.mergedHosts() {
		if mh.Host.ID == hostID {
			return mh.Name
		}
	}
	if m.mgr != nil {
		for _, f := range m.mgr.Forwards() {
			if f.Host().ID == hostID {
				return f.Host().Name
			}
		}
	}
	return m.hostName(hostID)
}

// hostForwardCount returns how many active forwards target the given host.
func (m Model) hostForwardCount(id string) int {
	if m.mgr == nil {
		return 0
	}
	n := 0
	for _, f := range m.mgr.Forwards() {
		if f.Host().ID == id {
			n++
		}
	}
	return n
}
