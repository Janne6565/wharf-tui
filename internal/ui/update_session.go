package ui

import (
	"context"
	"errors"
	"time"

	"github.com/Janne6565/wharf-tui/internal/sshx"
	"github.com/Janne6565/wharf-tui/internal/store"
	tea "github.com/charmbracelet/bubbletea"
)

// startConnect reattaches a live session or dials a new one.
func (m Model) startConnect(h store.Host) (tea.Model, tea.Cmd) {
	if m.mgr == nil {
		return m.setToast("no ssh engine available", "err"), nil
	}
	if s := m.mgr.Get(h.ID); s != nil && s.Alive() {
		return m.attach(h.ID, s)
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.dialCancel = cancel
	m.dialHostID = h.ID
	m.modal = modalConnecting
	spec := sshx.HostSpec{ID: h.ID, Name: h.Name, User: h.User, Addr: h.Addr, Port: h.Port, KeyPath: h.KeyPath, AuthMethod: h.AuthMethod, Password: h.Password}
	return m, dialCmd(m.mgr, ctx, spec, m.w, m.h)
}

// attach hands the terminal to a session via tea.Exec, suspending the tick loop
// until the callback delivers detachedMsg.
func (m Model) attach(hostID string, s *sshx.Session) (tea.Model, tea.Cmd) {
	m.attaching = true
	m.modal = modalNone
	return m, tea.Exec(s.Attach(), func(error) tea.Msg { return detachedMsg{hostID: hostID} })
}

// reattachByIndex reattaches the idx-th live session (alt+1..9).
func (m Model) reattachByIndex(idx int) (tea.Model, tea.Cmd) {
	if m.mgr == nil {
		return m, nil
	}
	sessions := m.mgr.List()
	if idx < 0 || idx >= len(sessions) {
		return m, nil
	}
	s := sessions[idx]
	if !s.Alive() {
		return m, nil
	}
	return m.attach(s.Host().ID, s)
}

func (m Model) handleDialDone(msg dialDoneMsg) (tea.Model, tea.Cmd) {
	m.dialHostID = ""
	m.dialCancel = nil
	if m.modal == modalConnecting {
		m.modal = modalNone
	}
	if msg.err != nil {
		m.pendingPW = nil // dial failed → never persist the remembered password
		return m.handleDialErr(msg.hostID, msg.err)
	}
	// Record a successful connection, then hand over the terminal.
	var syncCmd tea.Cmd
	if m.st != nil {
		if h, ok := m.st.HostByID(msg.hostID); ok {
			h.LastSeen = time.Now()
			_ = m.st.UpdateHost(h)
			m, syncCmd = m.saveVault()
		} else {
			// Project hosts live in a decrypted project doc, not the personal store.
			m, syncCmd = m.recordProjectHostSeen(msg.hostID)
		}
	}
	// Persist a remembered password before attaching, so the takeover is never
	// blocked on disk I/O. A pending value for any other host is discarded.
	if m.pendingPW != nil {
		if m.pendingPW.hostID == msg.hostID {
			m = m.persistPassword(msg.hostID, m.pendingPW.pw)
		}
		m.pendingPW = nil
	}
	if msg.sess == nil {
		// No live session to hand over (degenerate dial / test): stay put so the
		// toast remains visible instead of driving a nil attach.
		return m, syncCmd
	}
	am, attachCmd := m.attach(msg.hostID, msg.sess)
	return am, tea.Batch(syncCmd, attachCmd)
}

// recordProjectHostSeen stamps LastSeen on a successfully-connected project host
// and arms the existing debounced project push, so a burst of connects coalesces
// into one upload rather than a push per connect (why LastSeen was personal-only
// through M3). No-op when the host isn't a keyed project host.
func (m Model) recordProjectHostSeen(hostID string) (Model, tea.Cmd) {
	for projID, doc := range m.projectDocs {
		if doc == nil {
			continue
		}
		h, ok := doc.HostByID(hostID)
		if !ok {
			continue
		}
		h.LastSeen = time.Now()
		if err := doc.UpdateHost(h); err != nil {
			return m, nil
		}
		return m.scheduleProjectPush(projID)
	}
	return m, nil
}

// rememberedPassword is a typed password captured from the secret prompt with
// "remember" on, held until the matching dial succeeds.
type rememberedPassword struct {
	hostID string
	pw     string
}

// persistPassword writes pw onto the stored host and raises a confirming toast.
func (m Model) persistPassword(hostID, pw string) Model {
	if m.st == nil {
		return m
	}
	h, ok := m.st.HostByID(hostID)
	if !ok {
		return m
	}
	h.Password = pw
	if err := m.st.UpdateHost(h); err != nil {
		return m
	}
	_ = m.st.Save()
	return m.setToast("password saved to vault", "ok")
}

// samePassword reports whether pw already matches the host's stored password,
// so a no-op "remember" never bothers to re-save.
func (m Model) samePassword(hostID, pw string) bool {
	if m.st == nil {
		return false
	}
	if h, ok := m.st.HostByID(hostID); ok {
		return h.Password == pw
	}
	return false
}

func (m Model) handleDialErr(hostID string, err error) (tea.Model, tea.Cmd) {
	switch {
	case errors.Is(err, sshx.ErrHostKeyChanged):
		name := m.hostName(hostID)
		m.modal = modalError
		m.errTitle = "host key CHANGED for " + name
		m.errBody = "The server key does not match ~/.ssh/known_hosts — possible MITM.\n" +
			"Wharf will not connect. Fix ~/.ssh/known_hosts manually if you trust it."
		return m, nil
	case errors.Is(err, context.Canceled), errors.Is(err, sshx.ErrCanceled):
		return m.setToast("connection canceled", "err"), nil
	case errors.Is(err, sshx.ErrHostKeyRejected):
		return m.setToast("host key rejected", "err"), nil
	case errors.Is(err, sshx.ErrAuthFailed):
		msg := "authentication failed"
		// A key-mode host that fails auth often just wants password auth; point
		// the user at the fix. Password-mode hosts get the plain message.
		if m.st != nil {
			if h, ok := m.st.HostByID(hostID); ok && h.AuthMethod != sshx.AuthPassword {
				msg += " · hint: this server may want password auth — edit the host (e) and switch auth to password"
			}
		}
		return m.setToast(msg, "err"), nil
	case errors.Is(err, context.DeadlineExceeded):
		return m.setToast("connection timed out", "err"), nil
	default:
		return m.setToast("connect failed: "+err.Error(), "err"), nil
	}
}

func (m Model) handleDetached(msg detachedMsg) (tea.Model, tea.Cmd) {
	m.attaching = false
	if m.mgr != nil {
		if s := m.mgr.Get(msg.hostID); s != nil && s.Alive() {
			// A real detach (ctrl+\): the session lives on. A dead session is
			// announced separately by SessionEndedMsg, so stay quiet here.
			m = m.setToast("detached · session still running", "ok")
		}
	}
	// Restart the tick loop suspended during the takeover.
	return m, tickCmd()
}

// --- engine prompts ---------------------------------------------------------

func (m Model) handleHostKeyPrompt(msg sshx.HostKeyPromptMsg) (tea.Model, tea.Cmd) {
	pending := msg
	m.pendingHostKey = &pending
	m.modal = modalHostKey
	return m, nil
}

func (m Model) hostKeyModalKey(key string) (tea.Model, tea.Cmd) {
	if m.pendingHostKey == nil {
		m.modal = modalNone
		return m, nil
	}
	switch key {
	case "y", "Y", "enter":
		// Reply channel is buffered(1): a plain send never blocks. Send once.
		m.pendingHostKey.Reply <- true
		m.pendingHostKey = nil
		return m.restoreAfterPrompt(), nil
	case "n", "N", "esc":
		m.pendingHostKey.Reply <- false
		m.pendingHostKey = nil
		return m.restoreAfterPrompt(), nil
	}
	return m, nil
}

func (m Model) handleSecretPrompt(msg sshx.SecretPromptMsg) (tea.Model, tea.Cmd) {
	pending := msg
	m.pendingSecret = &pending
	m.secretInput = ""
	m.secretRemember = false
	m.modal = modalSecret
	return m, nil
}

func (m Model) secretModalKey(key string) (tea.Model, tea.Cmd) {
	if m.pendingSecret == nil {
		m.modal = modalNone
		return m, nil
	}
	switch key {
	case "enter":
		typed := m.secretInput
		title, hostID := m.pendingSecret.Title, m.pendingSecret.HostID
		// Reply channel is buffered(1): send exactly once.
		m.pendingSecret.Reply <- []byte(typed)
		m.pendingSecret = nil
		m.secretInput = ""
		// Stash the password for persistence once this host's dial succeeds.
		if m.secretRemember && title == "password" && !m.samePassword(hostID, typed) {
			m.pendingPW = &rememberedPassword{hostID: hostID, pw: typed}
		}
		m.secretRemember = false
		return m.restoreAfterPrompt(), nil
	case "esc":
		m.pendingSecret.Reply <- nil // nil cancels authentication
		m.pendingSecret = nil
		m.secretInput = ""
		m.secretRemember = false
		m.pendingPW = nil
		return m.restoreAfterPrompt(), nil
	case "ctrl+r":
		// Toggle "remember" only for interactive password prompts.
		if m.pendingSecret.Title == "password" {
			m.secretRemember = !m.secretRemember
		}
		return m, nil
	case "backspace":
		if len(m.secretInput) > 0 {
			m.secretInput = m.secretInput[:len(m.secretInput)-1]
		}
	default:
		if isPrintable(key) {
			m.secretInput += key
		}
	}
	return m, nil
}

// restoreAfterPrompt returns to the connecting spinner if a dial is still in
// flight, otherwise clears the overlay.
func (m Model) restoreAfterPrompt() Model {
	if m.dialHostID != "" {
		m.modal = modalConnecting
	} else {
		m.modal = modalNone
	}
	return m
}

func (m Model) handleSessionEnded(msg sshx.SessionEndedMsg) (tea.Model, tea.Cmd) {
	name := m.hostName(msg.HostID)
	if msg.Err != nil {
		return m.setToast("session to "+name+" ended: "+msg.Err.Error(), "err"), nil
	}
	return m.setToast("session to "+name+" closed", "ok"), nil
}

// --- connecting / error modals ----------------------------------------------

func (m Model) connectingKey(key string) (tea.Model, tea.Cmd) {
	if key == "esc" && m.dialCancel != nil {
		m.dialCancel()
		// The dial goroutine returns dialDoneMsg{ctx.Canceled}, which clears the
		// modal and raises a toast.
	}
	return m, nil
}

func (m Model) errorModalKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "enter", "esc", "q":
		m.modal = modalNone
		m.errTitle, m.errBody = "", ""
	}
	return m, nil
}

func (m Model) hostName(id string) string {
	if m.st != nil {
		if h, ok := m.st.HostByID(id); ok {
			return h.Name
		}
	}
	return id
}
