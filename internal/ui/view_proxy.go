package ui

import (
	"github.com/Janne6565/wharf-tui/internal/theme"
)

// proxyView renders the egress-proxy editor: one field, plus the context needed
// to understand a value that may not be the one in effect.
func (m Model) proxyView(t theme.Theme) []string {
	line := stl(t.Dim, t.Panel).Render(padTo2("proxy", 10))
	if m.pxVal == "" {
		line += stl(t.Dim, t.Panel).Render("socks5://host:1080 · off · empty for none")
	} else {
		line += stl(t.Hi, t.Panel).Render(m.pxVal)
	}
	line += m.cur(t.Hi, t.Panel)

	body := []string{line}
	if m.pxErr != "" {
		body = append(body, "", stl(t.Err, t.Panel).Render(m.pxErr))
	}

	body = append(body, "",
		stl(t.Dim, t.Panel).Render("Routes outbound SSH through a corporate proxy."),
		stl(t.Dim, t.Panel).Render("socks5://, http:// and https:// (CONNECT) are supported;"),
		stl(t.Dim, t.Panel).Render("$NO_PROXY still reaches those hosts directly."),
		"",
		// Two things people get wrong: that this syncs (it does not — it
		// describes the network, not the account), and that a password typed
		// here is kept (it is not — the file is plaintext).
		stl(t.Dim, t.Panel).Render("Saved on this machine only — never synced."),
		stl(t.Dim, t.Panel).Render("A password in the URL is not stored; use $WHARF_PROXY."))

	if m.proxyOverridden() {
		body = append(body, "",
			stl(t.Warn, t.Panel).Render("In effect: "+m.proxy.Dialer().String()),
			stl(t.Warn, t.Panel).Render("from "+m.proxy.Dialer().Source().String()+", which outranks this setting."))
	}

	body = append(body, "",
		stl(t.Hi, t.Panel).Render("enter")+stl(t.Dim, t.Panel).Render(" save · ")+
			stl(t.Hi, t.Panel).Render("esc")+stl(t.Dim, t.Panel).Render(" cancel"))

	return m.modalBox(t, "egress proxy", "hi", body)
}
