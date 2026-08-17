package ui

import (
	"github.com/Janne6565/wharf-tui/internal/detachkey"
	tea "github.com/charmbracelet/bubbletea"
)

// detachByte resolves the configured detach key for an attach. Resolution
// happens here, per attach, rather than once at startup: a key changed while a
// session is detached then applies the next time it is picked up.
func (m Model) detachByte() byte {
	return detachkey.Detach.Byte(m.detachName)
}

// remoteByte resolves the configured remote-access key for an attach, on the
// same per-attach terms as detachByte and for the same reason.
//
// Zero would disable the hotkey in the attach loop; Byte never returns zero for
// this binding — an unreadable name falls back to the default — because a key
// that quietly stops existing is the failure mode this whole feature is least
// able to explain from inside a session.
func (m Model) remoteByte() byte {
	return detachkey.RemoteAccess.Byte(m.remoteName)
}

// openDetachKeyForm opens the capture modal. There is nothing to seed: the
// modal asks for a keypress, and the current binding is shown as context
// rather than as an editable value.
func (m Model) openDetachKeyForm() Model {
	m.modal = modalDetachKey
	m.dkErr = ""
	return m
}

// openRemoteKeyForm is openDetachKeyForm for the remote-access binding.
func (m Model) openRemoteKeyForm() Model {
	m.modal = modalRemoteKey
	m.rkErr = ""
	return m
}

// detachKeyCapture handles a keypress inside the capture modal. The key is
// taken as the binding itself rather than typed out as text: the name has to
// match what bubbletea reports, and asking someone to spell "ctrl+]" correctly
// is a worse way to find that out than pressing it.
//
// esc cancels — it is also unbindable (it is escape, which the remote needs),
// so nothing is lost by spending it here.
//
// Validation is ParseAgainst rather than Parse, so the key the remote-access
// binding already holds is refused here too. The collision has to be blocked
// from both directions or it is not blocked at all: whichever byte the attach
// loop swallows first, the other binding never sees, so binding both to one key
// silently disables one of them — and the one it disables is decided by a tie
// break inside the attach loop, which is not something a user can be expected
// to reason about.
func (m Model) detachKeyCapture(key string) (tea.Model, tea.Cmd) {
	if key == "esc" {
		m.modal = modalNone
		m.dkErr = ""
		return m, nil
	}
	if m.applyDetachKey == nil {
		m.modal = modalNone
		return m.setToast("changing the detach key needs a real vault", "err"), nil
	}
	if _, err := detachkey.Detach.ParseAgainst(key, m.remoteName); err != nil {
		// Stay open: the point of a capture modal is to try another key, not to
		// reopen it after each miss.
		m.dkErr = err.Error()
		return m, nil
	}
	if err := m.applyDetachKey(key); err != nil {
		m.dkErr = err.Error()
		return m, nil
	}
	m.detachName = key
	m.modal = modalNone
	m.dkErr = ""
	// Live sessions are covered too — the byte is read per attach — so the
	// toast can promise this without qualification.
	return m.setToast("detach key set to "+key, "ok"), nil
}

// remoteKeyCapture is detachKeyCapture for the remote-access binding: same
// modal, same refusals, same per-attach resolution, and the same collision
// check pointed the other way.
func (m Model) remoteKeyCapture(key string) (tea.Model, tea.Cmd) {
	if key == "esc" {
		m.modal = modalNone
		m.rkErr = ""
		return m, nil
	}
	if m.applyRemoteKey == nil {
		m.modal = modalNone
		return m.setToast("changing the remote-access key needs a real vault", "err"), nil
	}
	if _, err := detachkey.RemoteAccess.ParseAgainst(key, m.detachName); err != nil {
		m.rkErr = err.Error()
		return m, nil
	}
	if err := m.applyRemoteKey(key); err != nil {
		m.rkErr = err.Error()
		return m, nil
	}
	m.remoteName = key
	m.modal = modalNone
	m.rkErr = ""
	return m.setToast("remote-access key set to "+key, "ok"), nil
}
