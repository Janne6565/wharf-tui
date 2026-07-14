package ui

import (
	"strings"

	"github.com/Janne6565/wharf-tui/internal/sshx"
	"github.com/Janne6565/wharf-tui/internal/store"
	"github.com/Janne6565/wharf-tui/internal/theme"
)

// modalView dispatches to the active modal renderer.
func (m Model) modalView(t theme.Theme) []string {
	switch m.modal {
	case modalHostForm:
		return m.hostFormView(t)
	case modalDeleteConfirm:
		return m.deleteConfirmView(t)
	case modalKeygen:
		return m.keygenView(t)
	case modalImportSummary:
		return m.importSummaryView(t)
	case modalQuitConfirm:
		return m.quitConfirmView(t)
	case modalConnecting:
		return m.connectingView(t)
	case modalHostKey:
		return m.hostKeyView(t)
	case modalSecret:
		return m.secretView(t)
	case modalError:
		return m.errorView(t)
	}
	return m.mainView(t)
}

// modalBox centers a titled panel over the full screen.
func (m Model) modalBox(t theme.Theme, title, border string, body []string) []string {
	pw := 66
	if pw > m.w-6 {
		pw = m.w - 6
	}
	box := panel(t, title, colorFor(t, border), pw, len(body)+2, body)
	return centerInArea(box, m.w, m.h, t.Bg)
}

// --- host form --------------------------------------------------------------

func (m Model) hostFormView(t theme.Theme) []string {
	title := "add host"
	if m.formEditID != "" {
		title = "edit host"
	}
	labels := [fCount]string{"name", "user", "address", "port", "tags", "key path", "auth", "password"}
	hints := [fCount]string{"", "", "host or ip", "default 22", "comma-separated", "~/.ssh/id_…", "", ""}

	var body []string
	for i := 0; i < fCount; i++ {
		focused := i == m.formFocus
		line := stl(t.Dim, t.Panel).Render(" " + padTo2(labels[i], 10))
		switch i {
		case fAuth:
			line += m.authSelector(t, focused)
		case fPassword:
			line += m.passwordField(t, focused)
		default:
			if m.formVals[i] == "" && !focused && hints[i] != "" {
				line += stl(t.Dim, t.Panel).Render(hints[i])
			} else {
				line += stl(t.Hi, t.Panel).Render(m.formVals[i])
			}
			if focused {
				line += m.cur(t.Hi, t.Panel)
			}
		}
		body = append(body, line)
	}
	if m.formErr != "" {
		body = append(body, "", stl(t.Err, t.Panel).Render(" "+m.formErr))
	}
	body = append(body, "",
		stl(t.Hi, t.Panel).Render(" tab/↑↓")+stl(t.Dim, t.Panel).Render(" move · ")+
			stl(t.Hi, t.Panel).Render("enter")+stl(t.Dim, t.Panel).Render(" save · ")+
			stl(t.Hi, t.Panel).Render("esc")+stl(t.Dim, t.Panel).Render(" cancel"))
	return m.modalBox(t, title, "hi", body)
}

// authSelector renders the three auth options inline with the active one lit.
func (m Model) authSelector(t theme.Theme, focused bool) string {
	cur := m.formVals[fAuth]
	var b strings.Builder
	for i, a := range authMethods {
		if i > 0 {
			b.WriteString(stl(t.Dim, t.Panel).Render("  "))
		}
		if a == cur {
			b.WriteString(stl(t.Hi, t.Sel).Render(" " + authLabel(a) + " "))
		} else {
			b.WriteString(stl(t.Dim, t.Panel).Render(authLabel(a)))
		}
	}
	seg := b.String()
	if focused {
		seg += m.cur(t.Hi, t.Panel)
	}
	return seg
}

// passwordField renders the masked host-form password (bullets, like the unlock
// screen), disabled when key auth is selected (its value is then unused).
func (m Model) passwordField(t theme.Theme, focused bool) string {
	var seg string
	switch {
	case m.formVals[fAuth] == sshx.AuthKey:
		seg = stl(t.Dim, t.Panel).Render("(unused with key auth)")
	case m.formVals[fPassword] != "":
		seg = stl(t.Hi, t.Panel).Render(strings.Repeat("•", len([]rune(m.formVals[fPassword]))))
	case !focused:
		seg = stl(t.Dim, t.Panel).Render("(optional)")
	}
	if focused {
		seg += m.cur(t.Hi, t.Panel)
	}
	return seg
}

// authDetail describes a host's effective auth method for the detail pane.
func authDetail(h store.Host) string {
	switch h.AuthMethod {
	case sshx.AuthPassword:
		if h.Password != "" {
			return "password (saved)"
		}
		return "password"
	case sshx.AuthKey:
		if h.KeyPath != "" {
			return "key " + h.KeyPath
		}
		return "key"
	default:
		if h.Password != "" {
			return "auto (saved)"
		}
		return "auto"
	}
}

// --- delete confirm ---------------------------------------------------------

func (m Model) deleteConfirmView(t theme.Theme) []string {
	body := []string{
		stl(t.Fg, t.Panel).Render(" Delete host ") + stl(t.Hi, t.Panel).Render(m.delName) + stl(t.Fg, t.Panel).Render(" ?"),
		"",
		stl(t.Dim, t.Panel).Render(" This removes it from the vault permanently."),
		"",
		stl(t.Hi, t.Panel).Render(" y") + stl(t.Dim, t.Panel).Render("/") + stl(t.Hi, t.Panel).Render("enter") +
			stl(t.Dim, t.Panel).Render(" delete · ") + stl(t.Hi, t.Panel).Render("esc") +
			stl(t.Dim, t.Panel).Render("/") + stl(t.Hi, t.Panel).Render("n") + stl(t.Dim, t.Panel).Render(" cancel"),
	}
	return m.modalBox(t, "delete host", "err", body)
}

// --- connecting -------------------------------------------------------------

func (m Model) connectingView(t theme.Theme) []string {
	name := m.hostName(m.dialHostID)
	body := []string{
		stl(t.Warn, t.Panel).Render(" " + m.spinner() + " connecting to " + name + " …"),
		"",
		stl(t.Dim, t.Panel).Render(" ") + stl(t.Hi, t.Panel).Render("esc") + stl(t.Dim, t.Panel).Render(" cancel"),
	}
	return m.modalBox(t, "connecting", "hi", body)
}

// --- host-key TOFU ----------------------------------------------------------

func (m Model) hostKeyView(t theme.Theme) []string {
	p := m.pendingHostKey
	if p == nil {
		return m.mainView(t)
	}
	rw := panelInner(m.w)
	body := []string{
		stl(t.Warn, t.Panel).Render(" The authenticity of this host can't be established."),
		"",
		kv(t, " host", p.Host, t.Fg, rw),
		kv(t, " key type", p.KeyType, t.Fg, rw),
		kv(t, " fingerprint", p.Fingerprint, t.Hi, rw),
		"",
		stl(t.Dim, t.Panel).Render(" Trusting appends the key to ~/.ssh/known_hosts."),
		"",
		stl(t.Hi, t.Panel).Render(" y") + stl(t.Dim, t.Panel).Render("/") + stl(t.Hi, t.Panel).Render("enter") +
			stl(t.Dim, t.Panel).Render(" trust & connect · ") + stl(t.Hi, t.Panel).Render("esc") +
			stl(t.Dim, t.Panel).Render("/") + stl(t.Hi, t.Panel).Render("n") + stl(t.Dim, t.Panel).Render(" reject"),
	}
	return m.modalBox(t, "verify host key", "warn", body)
}

// --- secret prompt ----------------------------------------------------------

func (m Model) secretView(t theme.Theme) []string {
	p := m.pendingSecret
	if p == nil {
		return m.mainView(t)
	}
	shown := strings.Repeat("•", len([]rune(m.secretInput)))
	if p.Echo {
		shown = m.secretInput
	}
	body := []string{
		stl(t.Fg, t.Panel).Render(" " + p.Title),
	}
	if p.Detail != "" {
		body = append(body, stl(t.Dim, t.Panel).Render(" "+p.Detail))
	}
	body = append(body,
		"",
		stl(t.Hi, t.Panel).Render(" "+shown)+m.cur(t.Hi, t.Panel))
	// Offer to persist the secret only for interactive password prompts.
	if p.Title == "password" {
		mark := "[ ]"
		if m.secretRemember {
			mark = "[x]"
		}
		body = append(body, "",
			stl(t.Hi, t.Panel).Render(" "+mark+" remember password")+stl(t.Dim, t.Panel).Render("  ctrl+r"))
	}
	body = append(body,
		"",
		stl(t.Hi, t.Panel).Render(" enter")+stl(t.Dim, t.Panel).Render(" submit · ")+
			stl(t.Hi, t.Panel).Render("esc")+stl(t.Dim, t.Panel).Render(" cancel"))
	return m.modalBox(t, "authentication", "hi", body)
}

// --- import summary ---------------------------------------------------------

func (m Model) importSummaryView(t theme.Theme) []string {
	body := []string{
		stl(t.Fg, t.Panel).Render(" " + itoa(len(m.importHosts)) + " host(s) found in ~/.ssh/config"),
	}
	if len(m.importSkipped) > 0 {
		body = append(body, stl(t.Dim, t.Panel).Render(" "+itoa(len(m.importSkipped))+" wildcard pattern(s) skipped"))
	}
	body = append(body,
		"",
		stl(t.Dim, t.Panel).Render(" Apply? Existing manual hosts are never overwritten."),
		"",
		stl(t.Hi, t.Panel).Render(" y")+stl(t.Dim, t.Panel).Render("/")+stl(t.Hi, t.Panel).Render("enter")+
			stl(t.Dim, t.Panel).Render(" apply · ")+stl(t.Hi, t.Panel).Render("esc")+
			stl(t.Dim, t.Panel).Render("/")+stl(t.Hi, t.Panel).Render("n")+stl(t.Dim, t.Panel).Render(" cancel"))
	return m.modalBox(t, "import ssh config", "hi", body)
}

// --- keygen -----------------------------------------------------------------

func (m Model) keygenView(t theme.Theme) []string {
	labels := [3]string{"name", "comment", "passphrase"}
	var body []string
	for i := 0; i < 3; i++ {
		focused := i == m.kgFocus
		val := m.kgVals[i]
		if i == 2 { // passphrase is masked
			val = strings.Repeat("•", len([]rune(val)))
		}
		line := stl(t.Dim, t.Panel).Render(" "+padTo2(labels[i], 12)) + stl(t.Hi, t.Panel).Render(val)
		if i == 2 && m.kgVals[i] == "" && !focused {
			line = stl(t.Dim, t.Panel).Render(" "+padTo2(labels[i], 12)) + stl(t.Dim, t.Panel).Render("(optional)")
		}
		if focused {
			line += m.cur(t.Hi, t.Panel)
		}
		body = append(body, line)
	}
	if m.kgErr != "" {
		body = append(body, "", stl(t.Err, t.Panel).Render(" "+m.kgErr))
	}
	body = append(body, "",
		stl(t.Dim, t.Panel).Render(" Writes to ~/.ssh (0600). Never overwrites."),
		"",
		stl(t.Hi, t.Panel).Render(" tab")+stl(t.Dim, t.Panel).Render(" move · ")+
			stl(t.Hi, t.Panel).Render("enter")+stl(t.Dim, t.Panel).Render(" generate · ")+
			stl(t.Hi, t.Panel).Render("esc")+stl(t.Dim, t.Panel).Render(" cancel"))
	return m.modalBox(t, "generate ed25519 key", "hi", body)
}

// --- quit confirm -----------------------------------------------------------

func (m Model) quitConfirmView(t theme.Theme) []string {
	n := 0
	if m.mgr != nil {
		n = len(m.mgr.List())
	}
	body := []string{
		stl(t.Warn, t.Panel).Render(" " + itoa(n) + " live session(s) will be closed."),
		"",
		stl(t.Hi, t.Panel).Render(" y") + stl(t.Dim, t.Panel).Render("/") + stl(t.Hi, t.Panel).Render("enter") +
			stl(t.Dim, t.Panel).Render(" quit · ") + stl(t.Hi, t.Panel).Render("esc") +
			stl(t.Dim, t.Panel).Render("/") + stl(t.Hi, t.Panel).Render("n") + stl(t.Dim, t.Panel).Render(" cancel"),
	}
	return m.modalBox(t, "quit wharf", "err", body)
}

// --- prominent error --------------------------------------------------------

func (m Model) errorView(t theme.Theme) []string {
	var body []string
	for _, ln := range strings.Split(m.errBody, "\n") {
		body = append(body, stl(t.Err, t.Panel).Render(" "+ln))
	}
	body = append(body, "",
		stl(t.Hi, t.Panel).Render(" enter")+stl(t.Dim, t.Panel).Render(" dismiss"))
	return m.modalBox(t, m.errTitle, "err", body)
}
