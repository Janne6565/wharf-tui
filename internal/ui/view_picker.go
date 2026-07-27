package ui

import (
	"github.com/Janne6565/wharf-tui/internal/theme"
)

// pickerWidth is the picker modal's outer width — the same 66 modalBox uses, so
// rows can be padded to the box's content width and read as full-width bars.
const pickerWidth = 66

// sessionPickerView renders a host's open sessions plus a "new session" row,
// or — opened with S — every live session across all hosts.
func (m Model) sessionPickerView(t theme.Theme) []string {
	sessions := m.pickerSessions()
	title := "sessions · " + m.pickHost.Name
	if !m.pickerHasNewRow() {
		title = "live sessions"
	}
	inner := boxContentW(pickerWidth)

	var body []string
	for i, s := range sessions {
		sel := i == m.pickIdx
		bg := t.Panel
		if sel {
			bg = t.Sel
		}
		// Within one host every row is the same host, so the ordinal and the age
		// are what distinguish them; the S overlay needs the host name instead.
		label := "session " + itoa(i+1)
		if !m.pickerHasNewRow() {
			// Across hosts the name identifies the row; sessionLabel adds the
			// #n ordinal when one host has several open.
			label = m.sessionLabel(s)
		}
		row := stl(t.Dim, bg).Render(itoa(i+1)+" ") +
			stl(t.Hi, bg).Render(padTo2(trunc(label, 18), 18)) +
			stl(t.Dim, bg).Render(padTo2("started "+sessionAge(s.StartedAt()), 17))
		switch {
		case m.pickKill == i:
			row += stl(t.Err, bg).Render("press x again to kill")
		case !s.Alive():
			row += stl(t.Err, bg).Render("ended")
		}
		body = append(body, padTo(row, inner, bg))
	}

	if m.pickerHasNewRow() {
		sel := m.pickIdx == len(sessions)
		bg := t.Panel
		if sel {
			bg = t.Sel
		}
		row := stl(t.Dim, bg).Render(itoa(len(sessions)+1)+" ") +
			stl(t.Ok, bg).Render(padTo2("+ new session", 18)) +
			stl(t.Dim, bg).Render("open another shell on this host")
		body = append(body, padTo(row, inner, bg))
	}

	body = append(body, "", m.pickerKeys(t))
	box := boxPanelAuto(t, title, colorFor(t, "hi"), pickerWidth, body)
	return centerInArea(box, m.w, m.h, t.Bg)
}

// pickerKeys renders the picker's key legend, which differs slightly between
// the per-host picker and the global overlay.
func (m Model) pickerKeys(t theme.Theme) string {
	key := func(k, rest string) string {
		return stl(t.Hi, t.Panel).Render(k) + stl(t.Dim, t.Panel).Render(rest)
	}
	line := key("↑↓/jk", " move · ") + key("enter", " attach · ")
	if m.pickerHasNewRow() {
		line += key("n", " new · ")
	}
	return line + key("x x", " kill · ") + key("esc", " cancel")
}
