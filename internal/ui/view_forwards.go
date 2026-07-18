package ui

import (
	"github.com/Janne6565/wharf-tui/internal/sshx"
	"github.com/Janne6565/wharf-tui/internal/theme"
)

// --- forward form -----------------------------------------------------------

func (m Model) forwardFormView(t theme.Theme) []string {
	labels := [ffCount]string{"kind", "bind addr", "bind port", "target addr", "target port"}
	hints := [ffCount]string{"", defaultForwardBindAddr, "auto", defaultForwardBindAddr, ""}
	kind := m.fwdVals[ffKind]

	body := []string{
		stl(t.Dim, t.Panel).Render("forward for ") + stl(t.Hi, t.Panel).Render(m.fwdHost.Name),
		"",
	}
	for i := 0; i < ffCount; i++ {
		if !fwdFieldVisible(kind, i) {
			continue // hidden target field (dynamic forward)
		}
		focused := i == m.fwdFocus
		line := stl(t.Dim, t.Panel).Render(padTo2(labels[i], 12))
		if i == ffKind {
			line += m.forwardKindSelector(t, focused)
		} else {
			if m.fwdVals[i] == "" && !focused && hints[i] != "" {
				line += stl(t.Dim, t.Panel).Render(hints[i])
			} else {
				line += stl(t.Hi, t.Panel).Render(m.fwdVals[i])
			}
			if focused {
				line += m.cur(t.Hi, t.Panel)
			}
		}
		body = append(body, line)
	}
	if m.fwdErr != "" {
		body = append(body, "", stl(t.Err, t.Panel).Render(m.fwdErr))
	}
	body = append(body, "",
		stl(t.Hi, t.Panel).Render("tab/↑↓")+stl(t.Dim, t.Panel).Render(" move · ")+
			stl(t.Hi, t.Panel).Render("enter")+stl(t.Dim, t.Panel).Render(" start · ")+
			stl(t.Hi, t.Panel).Render("esc")+stl(t.Dim, t.Panel).Render(" cancel"))
	return m.modalBox(t, "forward port", "hi", body)
}

// forwardKindSelector renders the current kind lit with a change hint, matching
// the host form's project selector.
func (m Model) forwardKindSelector(t theme.Theme, focused bool) string {
	seg := stl(t.Hi, t.Sel).Render(" "+forwardKindLabel(m.fwdVals[ffKind])+" ") +
		stl(t.Dim, t.Panel).Render("  ‹ › to change")
	if focused {
		seg += m.cur(t.Hi, t.Panel)
	}
	return seg
}

// --- active-forwards overlay ------------------------------------------------

func (m Model) forwardsView(t theme.Theme) []string {
	var fwds []*sshx.Forward
	if m.mgr != nil {
		fwds = m.mgr.Forwards()
	}
	var body []string
	if len(fwds) == 0 {
		body = append(body, stl(t.Dim, t.Panel).Render("no active forwards · press f on a host to start one"))
	} else {
		idx := clampIdx(m.fwdIdx, len(fwds))
		for i, f := range fwds {
			body = append(body, m.forwardRow(t, f, i == idx))
		}
	}
	body = append(body, "",
		stl(t.Hi, t.Panel).Render("j/k")+stl(t.Dim, t.Panel).Render(" move · ")+
			stl(t.Hi, t.Panel).Render("x")+stl(t.Dim, t.Panel).Render(" close · ")+
			stl(t.Hi, t.Panel).Render("esc")+stl(t.Dim, t.Panel).Render(" close overlay"))
	return m.modalBox(t, "active forwards", "hi", body)
}

// forwardRow renders one overlay row: cursor, host name, resolved label, live
// connection count and uptime.
func (m Model) forwardRow(t theme.Theme, f *sshx.Forward, sel bool) string {
	mark := "  "
	nameFg := t.Fg
	if sel {
		mark = "▸ "
		nameFg = t.Hi
	}
	meta := itoa(f.Conns()) + " conn"
	if up := humanizeAgo(f.StartedAt()); up != "" {
		meta += " · " + up
	}
	return stl(t.Hi, t.Panel).Render(mark) +
		stl(nameFg, t.Panel).Render(padTo2(m.forwardName(f), 14)) +
		stl(t.Dim, t.Panel).Render("  ") +
		stl(t.Fg, t.Panel).Render(forwardLabel(f)) +
		stl(t.Dim, t.Panel).Render("  "+meta)
}
