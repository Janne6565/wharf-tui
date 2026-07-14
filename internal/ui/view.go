package ui

import (
	"strconv"
	"strings"

	"github.com/Janne6565/wharf-tui/internal/data"
	"github.com/Janne6565/wharf-tui/internal/theme"
	"github.com/charmbracelet/lipgloss"
)

// View renders the whole screen as exactly h lines of width w.
func (m Model) View() string {
	if !m.ready || m.w < 24 || m.h < 8 {
		return ""
	}
	t := m.th()
	var lines []string
	switch {
	case m.helpOpen:
		lines = m.helpView(t)
	case m.screen == scAuth:
		lines = m.authView(t)
	case m.inviteOpen:
		lines = m.inviteView(t)
	case m.screen == scMain:
		lines = m.mainView(t)
	case m.screen == scSession:
		lines = m.sessionView(t)
	}
	return strings.Join(vpad(lines, m.w, m.h, t.Bg, false), "\n")
}

// --- shared bits ------------------------------------------------------------

func colorFor(t theme.Theme, role string) lipgloss.Color {
	switch role {
	case "hi":
		return t.Hi
	case "dim":
		return t.Dim
	case "ok":
		return t.Ok
	case "warn":
		return t.Warn
	case "err":
		return t.Err
	case "mag":
		return t.Mag
	case "blue":
		return t.Blue
	default:
		return t.Fg
	}
}

func statusColor(t theme.Theme, s string) lipgloss.Color {
	switch s {
	case "online":
		return t.Ok
	case "offline":
		return t.Err
	default:
		return t.Dim
	}
}

// cur renders the blinking block cursor (or a bg-painted space when hidden).
func (m Model) cur(fg, bg lipgloss.Color) string {
	if m.cursorOn() {
		return stl(fg, bg).Render("▌")
	}
	return bgpad(1, bg)
}

// rowSeg renders text in a fixed-width, bg-painted column.
func rowSeg(text string, width int, fg, bg lipgloss.Color, right bool) string {
	if width > 0 {
		text = trunc(text, width)
		if right {
			text = padLeftPlain(text, width)
		} else {
			text = padTo2(text, width)
		}
	}
	return stl(fg, bg).Render(text)
}

func padLeftPlain(s string, w int) string {
	if d := w - len([]rune(s)); d > 0 {
		return strings.Repeat(" ", d) + s
	}
	return s
}

func itoa(n int) string { return strconv.Itoa(n) }

// barLine builds a full-width top/bottom bar with left and right styled groups.
func barLine(t theme.Theme, w int, left, right string) string {
	gap := w - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 0 {
		return padTo(left, w, t.Bg)
	}
	return left + bgpad(gap, t.Bg) + right
}

// centerInArea centers a block horizontally and vertically inside w×areaH.
func centerInArea(block []string, w, areaH int, bg lipgloss.Color) []string {
	return vpad(hcenter(block, w, bg), w, areaH, bg, true)
}

// --- auth / login -----------------------------------------------------------

func (m Model) authView(t theme.Theme) []string {
	logo := bold(t.Hi, t.Bg).Render("⌢ wharf") + m.cur(t.Hi, t.Bg)
	subtitle := stl(t.Dim, t.Bg).Render("your fleet, one terminal · v0.5.0")

	pw := 68
	if pw > m.w-6 {
		pw = m.w - 6
	}
	inner := pw - 2

	var body []string
	switch m.authStep {
	case 0:
		body = []string{
			stl(t.Fg, t.Panel).Render("Sign in to sync your vault across machines and use team projects."),
			stl(t.Dim, t.Panel).Render("Authentication happens in your browser — Google, GitHub or email."),
			"",
			stl(t.Hi, t.Panel).Render("enter") + stl(t.Dim, t.Panel).Render("  open browser & get a device code"),
			stl(t.Hi, t.Panel).Render("l") + stl(t.Dim, t.Panel).Render("      skip · use Wharf locally on this machine"),
		}
	case 1:
		body = []string{
			stl(t.Dim, t.Panel).Render("Browser opened at"),
			stl(t.Hi, t.Panel).Render("https://wharf.sh/device"),
			"",
			stl(t.Dim, t.Panel).Render("Finish signing in there, then type the 8-character code:"),
			m.codeLine(t),
			stl(t.Dim, t.Panel).Render("type code · ") + stl(t.Hi, t.Panel).Render("enter") +
				stl(t.Dim, t.Panel).Render(" confirm · ") + stl(t.Hi, t.Panel).Render("esc") +
				stl(t.Dim, t.Panel).Render(" back"),
		}
	case 2:
		body = []string{
			stl(t.Warn, t.Panel).Render(m.spinner() + " verifying device code…"),
			stl(t.Dim, t.Panel).Render("exchanging for session token · unlocking vault"),
		}
	}

	box := panel(t, "sign in", t.Hi, pw, len(body)+2, body)
	footer := stl(t.Dim, t.Bg).Render("api.wharf.sh · e2e-encrypted vault · ") + stl(t.Ok, t.Bg).Render("● service up")

	block := []string{logo, subtitle, ""}
	block = append(block, box...)
	block = append(block, "", footer)
	_ = inner
	return centerInArea(block, m.w, m.h, t.Bg)
}

// codeLine renders the device code as "TYPED▌rest" in XXXX-XXXX form.
func (m Model) codeLine(t theme.Theme) string {
	pad := m.code
	for len(pad) < 8 {
		pad += "·"
	}
	pad = pad[:8]
	disp := pad[:4] + "-" + pad[4:]
	cut := len(m.code)
	if len(m.code) > 4 {
		cut++
	}
	typed := disp[:cut]
	rest := disp[cut:]
	return stl(t.Hi, t.Panel).Render(typed) + m.cur(t.Hi, t.Panel) + stl(t.Dim, t.Panel).Render(rest)
}

// --- dashboard --------------------------------------------------------------

func (m Model) mainView(t theme.Theme) []string {
	header := m.header(t, m.dashTabs(t))
	hint := m.hintBar(t)
	contentH := m.h - len(header) - len(hint)
	if contentH < 3 {
		contentH = 3
	}
	var content []string
	switch m.tab {
	case 0:
		content = m.hostsTab(t, contentH)
	case 1:
		content = m.projectsTab(t, contentH)
	case 2:
		content = m.keysTab(t, contentH)
	case 3:
		content = m.settingsTab(t, contentH)
	}
	out := append([]string{}, header...)
	out = append(out, content...)
	out = append(out, hint...)
	return out
}

// header renders the two-line top bar (badge + tabs + account status).
func (m Model) header(t theme.Theme, tabs string) []string {
	badge := bold(t.Ink, t.Hi).Render(" ⌢ wharf ")
	left := badge + bgpad(1, t.Bg) + tabs
	var right string
	if m.signedIn {
		right = stl(t.Dim, t.Bg).Render(m.email+" · ") + stl(t.Ok, t.Bg).Render("● synced 12s ago")
	} else {
		right = stl(t.Dim, t.Bg).Render("○ local vault · ") + stl(t.Hi, t.Bg).Render("q") + stl(t.Dim, t.Bg).Render(" sign in")
	}
	return []string{barLine(t, m.w, " "+left, right+" "), rule(t, m.w)}
}

func (m Model) dashTabs(t theme.Theme) string {
	var b strings.Builder
	for i, name := range tabNames {
		label := " " + itoa(i+1) + ":" + name + " "
		if i == m.tab {
			b.WriteString(stl(t.Hi, t.Sel).Render(label))
		} else {
			b.WriteString(stl(t.Dim, t.Bg).Render(label))
		}
	}
	return b.String()
}

// twoPane lays out a list panel and a detail panel with 1-col margins/gap.
func (m Model) twoPane(t theme.Theme, contentH int, lTitle string, lBorder lipgloss.Color, lBody []string, lw int, rTitle string, rBorder lipgloss.Color, rBody []string, rw int) []string {
	avail := m.w - 3
	if avail < 10 {
		avail = 10
	}
	leftW := avail * lw / (lw + rw)
	rightW := avail - leftW
	left := panel(t, lTitle, lBorder, leftW, contentH, lBody)
	right := panel(t, rTitle, rBorder, rightW, contentH, rBody)
	return hjoin(col(1, contentH, t.Bg), left, col(1, contentH, t.Bg), right, col(1, contentH, t.Bg))
}

func (m Model) listBorder(t theme.Theme) lipgloss.Color {
	if m.focus == 0 {
		return t.Hi
	}
	return t.Border
}

func (m Model) detailBorder(t theme.Theme) lipgloss.Color {
	if m.focus == 1 {
		return t.Hi
	}
	return t.Border
}

// hostsTab renders the hosts list + host detail.
func (m Model) hostsTab(t theme.Theme, contentH int) []string {
	fh := m.filteredHosts()
	hIdx := clampIdx(m.hostIdx, len(fh))

	// list body: optional search line, then rows.
	var lBody []string
	if m.searchActive || m.query != "" {
		lBody = append(lBody, stl(t.Warn, t.Panel).Render(" /"+m.query)+m.cur(t.Warn, t.Panel))
	}
	innerW := m.hostsInnerW()
	for i, h := range fh {
		lBody = append(lBody, hostRow(t, h, i == hIdx, innerW))
	}
	if len(fh) == 0 {
		lBody = append(lBody, stl(t.Dim, t.Panel).Render(" no hosts match"))
	}

	// detail body.
	var rBody []string
	if len(fh) > 0 {
		h := fh[hIdx]
		rw := m.hostsDetailInnerW()
		rBody = []string{
			stl(t.Hi, t.Panel).Bold(true).Render(" " + h.Name),
			"",
			kv(t, " address", h.Conn(), t.Fg, rw),
			kv(t, " project", h.Project, t.Mag, rw),
			kv(t, " identity", h.Key, t.Fg, rw),
			kv(t, " tags", tagStr(h), t.Blue, rw),
			kv(t, " last", h.Last, t.Dim, rw),
			kv(t, " status", "● "+h.Status, statusColor(t, h.Status), rw),
			"",
			stl(t.Dim, t.Panel).Render(" ─────"),
			stl(t.Hi, t.Panel).Render(" enter") + stl(t.Dim, t.Panel).Render(" connect · detach keeps it alive"),
		}
	} else {
		rBody = []string{stl(t.Dim, t.Panel).Render(" no match")}
	}

	title := "hosts · " + itoa(len(fh)) + "/" + itoa(len(m.hosts))
	return m.twoPane(t, contentH, title, m.listBorder(t), lBody, 3, "host", m.detailBorder(t), rBody, 2)
}

func (m Model) hostsInnerW() int {
	avail := m.w - 3
	return avail*3/5 - 2
}
func (m Model) hostsDetailInnerW() int {
	avail := m.w - 3
	return avail - avail*3/5 - 2
}

func hostRow(t theme.Theme, h data.Host, sel bool, innerW int) string {
	bg := t.Panel
	if sel {
		bg = t.Sel
	}
	mark := " "
	nameFg := t.Fg
	if sel {
		mark = "▸"
		nameFg = t.Hi
	}
	tags := tagStr(h)
	status := "● " + h.Status
	tagW := len([]rune(tags))
	connW := innerW - (3 + 16 + 1 + 1 + tagW + 1 + 10)
	if connW < 6 {
		connW = 6
	}
	return stl(t.Hi, bg).Render(" "+mark+" ") +
		rowSeg(h.Name, 16, nameFg, bg, false) +
		bgpad(1, bg) +
		rowSeg(h.Conn(), connW, t.Dim, bg, false) +
		bgpad(1, bg) +
		rowSeg(tags, tagW, t.Blue, bg, false) +
		bgpad(1, bg) +
		rowSeg(status, 10, statusColor(t, h.Status), bg, true)
}

func tagStr(h data.Host) string {
	out := make([]string, len(h.Tags))
	for i, tg := range h.Tags {
		out[i] = "#" + tg
	}
	return strings.Join(out, " ")
}

// projectsTab renders the team-project list + detail, or the sign-in gate.
func (m Model) projectsTab(t theme.Theme, contentH int) []string {
	if !m.signedIn {
		return m.projectsGate(t, contentH)
	}
	pIdx := clampIdx(m.projIdx, len(m.projects))
	var lBody []string
	dw := m.w - 3
	lInner := dw*11/25 - 2
	for i, p := range m.projects {
		lBody = append(lBody, projRow(t, p, i == pIdx, lInner))
	}
	p := m.projects[pIdx]
	rw := dw - dw*11/25 - 2
	rBody := []string{
		stl(t.Hi, t.Panel).Bold(true).Render(" " + p.Name),
		stl(t.Dim, t.Panel).Render(" " + p.Desc),
		"",
		stl(t.Dim, t.Panel).Render(" members"),
	}
	for _, mem := range p.Members {
		rBody = append(rBody, stl(t.Fg, t.Panel).Render(" "+padTo2(mem.Name, 16))+stl(t.Dim, t.Panel).Render(mem.Role))
	}
	if len(p.Invites) > 0 {
		rBody = append(rBody, "", stl(t.Dim, t.Panel).Render(" pending invites"))
		for _, e := range p.Invites {
			rBody = append(rBody, stl(t.Warn, t.Panel).Render(" ○ "+padTo2(e, 20))+stl(t.Dim, t.Panel).Render("invited · awaiting accept"))
		}
	}
	rBody = append(rBody, "",
		stl(t.Hi, t.Panel).Render(" i")+stl(t.Dim, t.Panel).Render(" invite member · ")+
			stl(t.Hi, t.Panel).Render("enter")+stl(t.Dim, t.Panel).Render(" filter hosts to project"))
	_ = rw
	title := "projects · " + itoa(len(m.projects))
	return m.twoPane(t, contentH, title, m.listBorder(t), lBody, 11, "project", m.detailBorder(t), rBody, 14)
}

func projRow(t theme.Theme, p data.Project, sel bool, innerW int) string {
	bg := t.Panel
	mark := " "
	nameFg := t.Fg
	if sel {
		bg = t.Sel
		mark = "▸"
		nameFg = t.Hi
	}
	meta := itoa(p.Hosts) + " hosts · " + itoa(len(p.Members)) + " members"
	metaW := innerW - (3 + 18 + 1)
	if metaW < 4 {
		metaW = 4
	}
	return stl(t.Hi, bg).Render(" "+mark+" ") +
		rowSeg(p.Name, 18, nameFg, bg, false) +
		bgpad(1, bg) +
		rowSeg(meta, metaW, t.Dim, bg, false)
}

func (m Model) projectsGate(t theme.Theme, contentH int) []string {
	pw := 62
	if pw > m.w-6 {
		pw = m.w - 6
	}
	body := []string{
		stl(t.Fg, t.Panel).Render("Projects are a team feature."),
		"",
		stl(t.Dim, t.Panel).Render("Sign in to share a project's hosts with teammates, assign"),
		stl(t.Dim, t.Panel).Render("roles (owner / admin / member) and sync across machines."),
		stl(t.Dim, t.Panel).Render("Your private keys are never shared."),
		"",
		stl(t.Hi, t.Panel).Render("enter") + stl(t.Dim, t.Panel).Render(" sign in   ·   ") +
			stl(t.Dim, t.Panel).Render("you're using Wharf locally"),
	}
	box := panel(t, "projects · sign in required", t.Warn, pw, len(body)+2, body)
	return centerInArea(box, m.w, contentH, t.Bg)
}

// keysTab renders identities list + detail.
func (m Model) keysTab(t theme.Theme, contentH int) []string {
	kIdx := clampIdx(m.keyIdx, len(m.keys))
	dw := m.w - 3
	lInner := dw*11/25 - 2
	var lBody []string
	for i, k := range m.keys {
		lBody = append(lBody, keyRow(t, k, i == kIdx, lInner))
	}
	k := m.keys[kIdx]
	rw := dw - dw*11/25 - 2
	storage := "encrypted vault"
	storageC := t.Ok
	if k.Badge == "hardware" {
		storage = "security key (resident)"
		storageC = t.Warn
	}
	rBody := []string{
		stl(t.Hi, t.Panel).Bold(true).Render(" " + k.Name),
		"",
		kv(t, " type", k.Type, t.Fg, rw),
		kv(t, " fingerprint", k.Fp, t.Dim, rw),
		kv(t, " created", k.Created, t.Fg, rw),
		kv(t, " used by", itoa(k.Hosts)+" hosts", t.Fg, rw),
		kv(t, " storage", storage, storageC, rw),
		"",
		stl(t.Dim, t.Panel).Render(" private key never leaves the vault · agent signs in-memory"),
	}
	return m.twoPane(t, contentH, "identities · "+itoa(len(m.keys)), m.listBorder(t), lBody, 11, "identity", m.detailBorder(t), rBody, 14)
}

func keyRow(t theme.Theme, k data.Key, sel bool, innerW int) string {
	bg := t.Panel
	mark := " "
	nameFg := t.Fg
	if sel {
		bg = t.Sel
		mark = "▸"
		nameFg = t.Hi
	}
	badgeC := t.Dim
	switch k.Badge {
	case "default":
		badgeC = t.Ok
	case "hardware":
		badgeC = t.Warn
	}
	badgeW := len([]rune(k.Badge))
	typeW := innerW - (3 + 20 + 1 + badgeW + 1)
	if typeW < 4 {
		typeW = 4
	}
	return stl(t.Hi, bg).Render(" "+mark+" ") +
		rowSeg(k.Name, 20, nameFg, bg, false) +
		bgpad(1, bg) +
		rowSeg(k.Type, typeW, t.Dim, bg, false) +
		bgpad(1, bg) +
		rowSeg(k.Badge, badgeW, badgeC, bg, true)
}

// settingsTab renders the centered settings panel.
func (m Model) settingsTab(t theme.Theme, contentH int) []string {
	pw := 66
	if pw > m.w-6 {
		pw = m.w - 6
	}
	inner := pw - 2
	var body []string
	for i, d := range settingDefs {
		sel := i == m.setIdx
		bg := t.Panel
		mark := " "
		labelFg := t.Fg
		if sel {
			bg = t.Sel
			mark = "▸"
			labelFg = t.Hi
		}
		var val string
		var vc lipgloss.Color
		if d.key == "theme" {
			val = "‹ " + m.themeName + " ›"
			vc = t.Hi
		} else if m.settings[d.key] {
			val, vc = "[on]", t.Ok
		} else {
			val, vc = "[off]", t.Dim
		}
		row := stl(t.Hi, bg).Render(" "+mark+" ") +
			rowSeg(d.label, inner-3-12, labelFg, bg, false) +
			rowSeg(val, 12, vc, bg, true)
		body = append(body, row)
	}
	body = append(body, "",
		stl(t.Hi, t.Panel).Render(" enter")+stl(t.Dim, t.Panel).Render(" toggle / cycle · theme applies live"))
	box := panel(t, "settings", t.Hi, pw, len(body)+2, body)
	return centerInArea(box, m.w, contentH, t.Bg)
}

// --- session ----------------------------------------------------------------

func (m Model) sessionView(t theme.Theme) []string {
	// header with session tabs.
	badge := bold(t.Ink, t.Hi).Render(" ⌢ wharf ")
	var tabs strings.Builder
	for i, nm := range m.open {
		label := " " + itoa(i+1) + ":" + nm + " "
		if nm == m.active {
			tabs.WriteString(stl(t.Hi, t.Sel).Render(label))
		} else {
			tabs.WriteString(stl(t.Dim, t.Bg).Render(label))
		}
	}
	right := stl(t.Dim, t.Bg).Render(m.accountLabel())
	header := []string{
		barLine(t, m.w, " "+badge+bgpad(1, t.Bg)+tabs.String(), right+" "),
		rule(t, m.w),
	}

	hint := []string{
		rule(t, m.w),
		barLine(t, m.w,
			" "+stl(t.Hi, t.Bg).Render("type")+stl(t.Dim, t.Bg).Render(" remote shell   ")+
				stl(t.Hi, t.Bg).Render("alt+1..9")+stl(t.Dim, t.Bg).Render(" switch   ")+
				stl(t.Hi, t.Bg).Render("esc")+stl(t.Dim, t.Bg).Render(" detach (keeps running)"),
			stl(t.Ok, t.Bg).Render("● connected")+" "),
	}

	contentH := m.h - len(header) - len(hint)
	if contentH < 3 {
		contentH = 3
	}

	s := m.sessions[m.active]
	inner := m.w - 3 - 2
	var body []string
	if s != nil {
		start := 0
		if len(s.lines) > contentH-3 {
			start = len(s.lines) - (contentH - 3) // keep the tail visible
		}
		for _, ln := range s.lines[start:] {
			seg := ""
			if ln.prompt != "" {
				seg = stl(colorFor(t, ln.prole), t.Panel).Render(ln.prompt)
			}
			seg += stl(colorFor(t, ln.role), t.Panel).Render(trunc(ln.text, inner-lipgloss.Width(seg)))
			body = append(body, seg)
		}
		body = append(body, stl(t.Hi, t.Panel).Render(promptFor(m.active))+
			stl(t.Fg, t.Panel).Render(s.input)+m.cur(t.Hi, t.Panel))
	}

	title := "ssh"
	if s != nil {
		title = "ssh · " + s.host.Conn()
	}
	pane := hjoin(col(1, contentH, t.Bg), panel(t, title, t.Hi, m.w-3, contentH, body), col(1, contentH, t.Bg))

	out := append([]string{}, header...)
	out = append(out, pane...)
	out = append(out, hint...)
	return out
}

func (m Model) accountLabel() string {
	if m.signedIn {
		return m.email
	}
	return "local vault"
}

// --- hint bar (dashboard) ---------------------------------------------------

func (m Model) hintBar(t theme.Theme) []string {
	type hk struct{ k, l string }
	hints := []hk{{"j/k", "move"}}
	switch m.tab {
	case 0:
		hints = append(hints, hk{"enter", "connect"}, hk{"/", "filter"})
	case 1:
		if m.signedIn {
			hints = append(hints, hk{"enter", "view hosts"}, hk{"i", "invite"})
		} else {
			hints = append(hints, hk{"enter", "sign in"})
		}
	case 3:
		hints = append(hints, hk{"enter", "toggle"})
	}
	signLabel := "sign in"
	if m.signedIn {
		signLabel = "sign out"
	}
	hints = append(hints, hk{"1-4", "tabs"}, hk{"tab", "pane"}, hk{"q", signLabel})

	var b strings.Builder
	b.WriteString(" ")
	for i, h := range hints {
		if i > 0 {
			b.WriteString(bgpad(2, t.Bg))
		}
		b.WriteString(stl(t.Hi, t.Bg).Render(h.k) + stl(t.Dim, t.Bg).Render(" "+h.l))
	}
	right := stl(t.Hi, t.Bg).Render("?") + stl(t.Dim, t.Bg).Render(" help") + " "
	return []string{rule(t, m.w), barLine(t, m.w, b.String(), right)}
}

// --- overlays ---------------------------------------------------------------

func (m Model) inviteView(t theme.Theme) []string {
	pw := 60
	if pw > m.w-6 {
		pw = m.w - 6
	}
	p := m.projects[clampIdx(m.projIdx, len(m.projects))]
	body := []string{
		stl(t.Dim, t.Panel).Render("They get access to this project's hosts. Keys stay yours."),
		"",
		stl(t.Fg, t.Panel).Render("email: ") + stl(t.Hi, t.Panel).Render(m.inviteEmail) + m.cur(t.Hi, t.Panel),
		"",
		stl(t.Hi, t.Panel).Render("enter") + stl(t.Dim, t.Panel).Render(" send invite · ") +
			stl(t.Hi, t.Panel).Render("esc") + stl(t.Dim, t.Panel).Render(" cancel"),
	}
	box := panel(t, "invite to "+p.Name, t.Hi, pw, len(body)+2, body)
	return centerInArea(box, m.w, m.h, t.Bg)
}

func (m Model) helpView(t theme.Theme) []string {
	rows := [][2]string{
		{"j / k", "move selection"},
		{"1-4", "switch tab"},
		{"/", "filter hosts"},
		{"tab", "cycle pane focus"},
		{"enter", "connect / open / toggle"},
		{"i", "invite member (projects)"},
		{"esc", "back / clear / detach"},
		{"q", "sign in / out (login screen)"},
		{"l", "skip login · use local (on login screen)"},
		{"alt+1..9", "switch session tab"},
		{"?", "toggle this help"},
	}
	pw := 60
	if pw > m.w-6 {
		pw = m.w - 6
	}
	var body []string
	for _, r := range rows {
		body = append(body, stl(t.Hi, t.Panel).Render(padTo2(r[0], 12))+stl(t.Dim, t.Panel).Render(r[1]))
	}
	body = append(body, "",
		stl(t.Dim, t.Panel).Render("Wharf is local-first — sign in only to sync & use projects."))
	box := panel(t, "keybindings", t.Hi, pw, len(body)+2, body)
	return centerInArea(box, m.w, m.h, t.Bg)
}
