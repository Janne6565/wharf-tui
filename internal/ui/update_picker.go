package ui

import (
	"time"

	"github.com/Janne6565/wharf-tui/internal/sessd"
	"github.com/Janne6565/wharf-tui/internal/store"
	tea "github.com/charmbracelet/bubbletea"
)

// noKillArmed is the pickKill value meaning "no row is armed".
const noKillArmed = -1

// hostSessions lists the live sessions for a host, oldest first.
func (m Model) hostSessions(hostID string) []*sessd.Remote {
	if m.pool == nil {
		return nil
	}
	return m.pool.ForHost(hostID)
}

func (m Model) hostSessionCount(hostID string) int { return len(m.hostSessions(hostID)) }

// sessionLabel names a session for the live strip: the host name, plus a
// disambiguating ordinal when that host has more than one session open.
func (m Model) sessionLabel(s *sessd.Remote) string {
	name := s.Host().Name
	peers := m.hostSessions(s.Host().ID)
	if len(peers) < 2 {
		return name
	}
	for i, p := range peers {
		if p.ID() == s.ID() {
			return name + "#" + itoa(i+1)
		}
	}
	return name
}

// openSessionPicker offers the host's existing sessions plus a "new session"
// row. Connecting to a busy host used to silently reattach to its one session;
// with several possible, the choice belongs to the user.
func (m Model) openSessionPicker(h store.Host) (tea.Model, tea.Cmd) {
	m.pickHost = h
	m.pickIdx = 0
	m.pickKill = noKillArmed
	m.modal = modalSessionPicker
	return m, nil
}

// openAllSessions is the S overlay: every live session across all hosts. With
// no host in context there is nothing to open "another" of, so the list has no
// new-session row.
func (m Model) openAllSessions() (tea.Model, tea.Cmd) {
	if m.liveSessions() == 0 {
		return m.setToast("no live sessions", "dim"), nil
	}
	m.pickHost = store.Host{}
	m.pickIdx = 0
	m.pickKill = noKillArmed
	m.modal = modalSessionPicker
	return m, nil
}

// pickerSessions is what the picker lists: one host's sessions, or all of them
// in the S overlay.
func (m Model) pickerSessions() []*sessd.Remote {
	if m.pickHost.ID == "" {
		if m.pool == nil {
			return nil
		}
		return m.pool.List()
	}
	return m.hostSessions(m.pickHost.ID)
}

// pickerHasNewRow reports whether the "new session" row is offered — only when
// the picker was opened by connecting to a specific host.
func (m Model) pickerHasNewRow() bool { return m.pickHost.ID != "" }

// sessionPickerKey drives the picker: move, choose, or arm-then-confirm a kill.
func (m Model) sessionPickerKey(key string) (tea.Model, tea.Cmd) {
	sessions := m.pickerSessions()
	newRow := len(sessions) // the "new session" row sits below the list
	if len(sessions) == 0 {
		// Everything died while the picker was open.
		if m.pickerHasNewRow() {
			return m.dialNewSession(m.pickHost)
		}
		m.modal = modalNone
		return m.setToast("no live sessions left", "dim"), nil
	}
	rows := newRow
	if m.pickerHasNewRow() {
		rows++
	}

	switch key {
	case "esc", "q":
		m.modal = modalNone
		m.pickKill = noKillArmed
		return m, nil

	case "j", "down":
		m.pickIdx = clampIdx(m.pickIdx+1, rows)
		m.pickKill = noKillArmed
		return m, nil

	case "k", "up":
		if m.pickIdx > 0 {
			m.pickIdx--
		}
		m.pickKill = noKillArmed
		return m, nil

	case "n":
		if !m.pickerHasNewRow() {
			return m, nil
		}
		return m.dialNewSession(m.pickHost)

	case "x", "X":
		// Two presses to kill: a live shell is not something to lose to a
		// mistyped key. The first arms the row, the second acts.
		if m.pickIdx >= len(sessions) {
			return m, nil // the "new session" row has nothing to kill
		}
		if m.pickKill != m.pickIdx {
			m.pickKill = m.pickIdx
			return m, nil
		}
		return m.killPicked(sessions[m.pickIdx])

	case "enter":
		m.pickKill = noKillArmed
		if m.pickIdx >= len(sessions) {
			if !m.pickerHasNewRow() {
				return m, nil
			}
			return m.dialNewSession(m.pickHost)
		}
		s := sessions[m.pickIdx]
		m.modal = modalNone
		if !s.Alive() {
			return m.setToast("that session just ended", "err"), nil
		}
		return m.attach(s.ID(), s)
	}

	// 1..9 jump straight to a row (the last one being "new session").
	if len(key) == 1 && key[0] >= '1' && key[0] <= '9' {
		if idx := int(key[0] - '1'); idx < rows {
			m.pickIdx = idx
			m.pickKill = noKillArmed
		}
	}
	return m, nil
}

// killPicked terminates one session from the picker, leaving it open so several
// can be cleaned up in a row. The pool drops the session when the child exits,
// which also raises the usual SessionEndedMsg toast.
func (m Model) killPicked(s *sessd.Remote) (tea.Model, tea.Cmd) {
	name := m.sessionLabel(s)
	m.pickKill = noKillArmed
	go s.Close() // the child's teardown is not worth blocking the UI on

	// With the last one gone there is nothing left to pick from: the per-host
	// picker closes (its caller wanted to connect), the S overlay just closes.
	if len(m.pickerSessions()) <= 1 && !m.pickerHasNewRow() {
		m.modal = modalNone
	}
	m.pickIdx = clampIdx(m.pickIdx, maxInt(1, len(m.pickerSessions())-1))
	return m.setToast("killed session to "+name, "ok"), nil
}

// dialNewSession starts an additional session for the host, even though one is
// already open.
func (m Model) dialNewSession(h store.Host) (tea.Model, tea.Cmd) {
	m.modal = modalNone
	m.pickKill = noKillArmed
	return m.dial(h)
}

// sessionAge renders how long a session has been up, coarsely.
func sessionAge(started time.Time) string {
	if started.IsZero() {
		return "unknown"
	}
	d := time.Since(started)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return itoa(int(d.Minutes())) + "m ago"
	case d < 24*time.Hour:
		return itoa(int(d.Hours())) + "h ago"
	default:
		return itoa(int(d.Hours()/24)) + "d ago"
	}
}

// maxInt is the small helper the picker needs to keep a cursor in range while
// the list shrinks under it.
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
