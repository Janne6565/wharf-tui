package ui

import (
	"github.com/Janne6565/wharf-tui/internal/detachkey"
	"github.com/Janne6565/wharf-tui/internal/theme"
)

// detachKeyView renders the capture modal: what is bound now, what to press,
// and why the set of usable keys is as small as it is.
func (m Model) detachKeyView(t theme.Theme) []string {
	body := []string{
		stl(t.Fg, t.Panel).Render("Press the key that should detach you from a session."),
		"",
		stl(t.Dim, t.Panel).Render(padTo2("current", 10)) + stl(t.Hi, t.Panel).Render(m.detachName),
	}
	if m.dkErr != "" {
		body = append(body, "", stl(t.Err, t.Panel).Render(m.dkErr))
	}

	body = append(body, "",
		// The restriction is not arbitrary and looks it, so it is named: while
		// attached there are no key events, only bytes on their way to the
		// remote.
		stl(t.Dim, t.Panel).Render("An attached terminal sees bytes, not keypresses, so the"),
		stl(t.Dim, t.Panel).Render("detach key has to be a ctrl combination. Keys the remote"),
		stl(t.Dim, t.Panel).Render("shell needs — ctrl+c, ctrl+d, ctrl+z, escape — are refused."),
		"",
		stl(t.Dim, t.Panel).Render("Available:"))
	for _, row := range wrapWords(detachkey.Names(), 56) {
		body = append(body, stl(t.Dim, t.Panel).Render("  "+row))
	}

	body = append(body, "",
		stl(t.Dim, t.Panel).Render("Saved on this machine only — never synced."),
		"",
		stl(t.Hi, t.Panel).Render("esc")+stl(t.Dim, t.Panel).Render(" cancel"))

	return m.modalBox(t, "detach key", "hi", body)
}

// wrapWords packs words into space-joined lines of at most width columns. The
// key names are all ASCII, so byte length is column count here.
func wrapWords(words []string, width int) []string {
	var out []string
	cur := ""
	for _, w := range words {
		switch {
		case cur == "":
			cur = w
		case len(cur)+1+len(w) <= width:
			cur += " " + w
		default:
			out = append(out, cur)
			cur = w
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
