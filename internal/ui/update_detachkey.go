package ui

import (
	"github.com/Janne6565/wharf-tui/internal/detachkey"
	tea "github.com/charmbracelet/bubbletea"
)

// detachByte resolves the configured detach key for an attach. Resolution
// happens here, per attach, rather than once at startup: a key changed while a
// session is detached then applies the next time it is picked up.
func (m Model) detachByte() byte {
	return detachkey.Byte(m.detachName)
}

// openDetachKeyForm opens the capture modal. There is nothing to seed: the
// modal asks for a keypress, and the current binding is shown as context
// rather than as an editable value.
func (m Model) openDetachKeyForm() Model {
	m.modal = modalDetachKey
	m.dkErr = ""
	return m
}

// detachKeyCapture handles a keypress inside the capture modal. The key is
// taken as the binding itself rather than typed out as text: the name has to
// match what bubbletea reports, and asking someone to spell "ctrl+]" correctly
// is a worse way to find that out than pressing it.
//
// esc cancels — it is also unbindable (it is escape, which the remote needs),
// so nothing is lost by spending it here.
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
	if _, err := detachkey.Parse(key); err != nil {
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
