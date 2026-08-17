package ui

import (
	"github.com/Janne6565/wharf-tui/internal/detachkey"
	"github.com/Janne6565/wharf-tui/internal/theme"
)

// detachKeyView renders the capture modal: what is bound now, what to press,
// and why the set of usable keys is as small as it is.
func (m Model) detachKeyView(t theme.Theme) []string {
	return m.hotkeyCaptureView(t, "detach key",
		"Press the key that should detach you from a session.",
		"detach key has to be a ctrl combination. Keys the remote",
		m.detachName, m.dkErr)
}

// remoteKeyView is the same modal for the remote-access binding. The two share
// one renderer rather than one being copied: the explanation of *why* only
// control bytes are bindable is identical, and two copies of it would drift
// until only one of them was true.
func (m Model) remoteKeyView(t theme.Theme) []string {
	return m.hotkeyCaptureView(t, "remote-access key",
		"Press the key that should grant or revoke remote access",
		"remote-access key must be a ctrl combination. Keys the remote",
		m.remoteName, m.rkErr)
}

// hotkeyCaptureView renders one binding's capture modal. line2 is the middle of
// the three-line explanation, which is the only part that names the binding.
func (m Model) hotkeyCaptureView(t theme.Theme, title, prompt, line2, current, errMsg string) []string {
	body := []string{
		stl(t.Fg, t.Panel).Render(prompt),
		"",
		stl(t.Dim, t.Panel).Render(padTo2("current", 10)) + stl(t.Hi, t.Panel).Render(current),
	}
	if errMsg != "" {
		body = append(body, "", stl(t.Err, t.Panel).Render(errMsg))
	}

	body = append(body, "",
		// The restriction is not arbitrary and looks it, so it is named: while
		// attached there are no key events, only bytes on their way to the
		// remote.
		stl(t.Dim, t.Panel).Render("An attached terminal sees bytes, not keypresses, so the"),
		stl(t.Dim, t.Panel).Render(line2),
		stl(t.Dim, t.Panel).Render("shell needs — ctrl+c, ctrl+d, ctrl+z, escape — are refused."),
		"",
		// The two hotkeys draw from one set, so the other one's key is missing
		// from the list here as well as refused on capture. Saying which keys are
		// free is more useful than making someone find out by elimination.
		stl(t.Dim, t.Panel).Render("The detach and remote-access keys cannot share a key:"),
		stl(t.Dim, t.Panel).Render("the attach loop swallows it, so only one would ever fire."),
		"",
		stl(t.Dim, t.Panel).Render("Available:"))
	for _, row := range wrapWords(detachkey.Names(), 56) {
		body = append(body, stl(t.Dim, t.Panel).Render("  "+row))
	}

	body = append(body, "",
		stl(t.Dim, t.Panel).Render("Saved on this machine only — never synced."),
		"",
		stl(t.Hi, t.Panel).Render("esc")+stl(t.Dim, t.Panel).Render(" cancel"))

	return m.modalBox(t, title, "hi", body)
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
