package ui

import (
	"strconv"
	"strings"
	"time"

	"github.com/Janne6565/wharf-tui/internal/api"
	"github.com/Janne6565/wharf-tui/internal/data"
	"github.com/Janne6565/wharf-tui/internal/keys"
	"github.com/Janne6565/wharf-tui/internal/probe"
	"github.com/Janne6565/wharf-tui/internal/store"
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
	case m.modal != modalNone:
		lines = m.modalView(t)
	case m.screen == scUnlock:
		lines = m.unlockView(t)
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

// probeStatusText maps an (optional) probe result to a status label and role.
func probeStatusText(res probe.Result, known bool) (string, string) {
	if !known {
		return "? unknown", "dim"
	}
	switch res.Status {
	case probe.StatusOnline:
		return "● online", "ok"
	case probe.StatusDegraded:
		return "● degraded", "warn"
	default:
		return "● offline", "err"
	}
}

// orDash renders "—" for an empty value.
func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// lastSeenStr renders a coarse "time ago" for a host's last connection.
func lastSeenStr(ts time.Time) string {
	if ts.IsZero() {
		return "never"
	}
	d := time.Since(ts)
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

// topInArea centers a block horizontally but pins it to the top of w×areaH.
func topInArea(block []string, w, areaH int, bg lipgloss.Color) []string {
	return vpad(hcenter(block, w, bg), w, areaH, bg, false)
}

// --- auth / login (simulated account) ---------------------------------------

func (m Model) authView(t theme.Theme) []string {
	logo := bold(t.Hi, t.Bg).Render("⚓ wharf") + m.cur(t.Hi, t.Bg)
	subtitle := stl(t.Dim, t.Bg).Render("your fleet, one terminal · v1.0.0")

	pw := 72
	if pw > m.w-6 {
		pw = m.w - 6
	}

	var body []string
	switch m.authStep {
	case 0:
		intro := stl(t.Fg, t.Panel).Render("Sign in to sync your vault across machines and use team projects.")
		body = []string{
			intro,
			stl(t.Dim, t.Panel).Render("Authentication happens in your browser — Google, GitHub or email."),
			"",
		}
		if m.demo {
			body = append(body,
				stl(t.Hi, t.Panel).Render("enter")+stl(t.Dim, t.Panel).Render("  open browser & get a device code"),
				stl(t.Hi, t.Panel).Render("l")+stl(t.Dim, t.Panel).Render("      skip · use Wharf locally on this machine"))
		} else {
			body = append(body,
				stl(t.Dim, t.Panel).Render("Open ")+stl(t.Hi, t.Panel).Render(stripScheme(m.deviceURL))+
					stl(t.Dim, t.Panel).Render(" in your browser, sign in,"),
				stl(t.Dim, t.Panel).Render("and it shows an 8-character pairing code."),
				"",
				stl(t.Hi, t.Panel).Render("enter")+stl(t.Dim, t.Panel).Render("  type the code"),
				stl(t.Hi, t.Panel).Render("esc")+stl(t.Dim, t.Panel).Render("    back to your local vault"))
		}
	case 1:
		if m.demo {
			body = []string{
				stl(t.Dim, t.Panel).Render("Browser opened at"),
				stl(t.Hi, t.Panel).Render("https://wharf.sh/device"),
				"",
				stl(t.Dim, t.Panel).Render("Finish signing in there, then type the 8-character code:"),
				m.codeLine(t),
			}
		} else {
			body = []string{
				stl(t.Dim, t.Panel).Render("In your browser, open"),
				stl(t.Hi, t.Panel).Render(stripScheme(m.deviceURL)),
				"",
				stl(t.Dim, t.Panel).Render("Sign in there, then type the pairing code it shows:"),
				m.codeLine(t),
			}
			if m.authErr != "" {
				body = append(body, stl(t.Err, t.Panel).Render(m.authErr))
			}
		}
		body = append(body,
			stl(t.Dim, t.Panel).Render("type code · ")+stl(t.Hi, t.Panel).Render("enter")+
				stl(t.Dim, t.Panel).Render(" confirm · ")+stl(t.Hi, t.Panel).Render("esc")+
				stl(t.Dim, t.Panel).Render(" back"))
	case 2:
		if m.demo {
			body = []string{
				stl(t.Warn, t.Panel).Render(m.spinner() + " verifying device code…"),
				stl(t.Dim, t.Panel).Render("exchanging for session token · unlocking sync"),
			}
		} else {
			body = []string{
				stl(t.Warn, t.Panel).Render(m.spinner() + " exchanging device code…"),
				stl(t.Dim, t.Panel).Render("pairing this device with your account"),
			}
		}
	}

	box := boxPanelAuto(t, "sign in", t.Hi, pw, body)
	var footer string
	if m.demo {
		footer = stl(t.Dim, t.Bg).Render("api.wharf.sh · e2e-encrypted vault · ") + stl(t.Ok, t.Bg).Render("● service up")
	} else {
		footer = stl(t.Dim, t.Bg).Render(stripScheme(apiBaseDisplay()) + " · e2e-encrypted vault · zero-knowledge sync")
	}

	block := []string{logo, subtitle, ""}
	block = append(block, box...)
	block = append(block, "", footer)
	return centerInArea(block, m.w, m.h, t.Bg)
}

// stripScheme drops http(s):// for display.
func stripScheme(u string) string {
	u = strings.TrimPrefix(u, "https://")
	return strings.TrimPrefix(u, "http://")
}

// apiBaseDisplay is the backend host shown on the sign-in footer.
func apiBaseDisplay() string { return api.BaseURL() }

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
	strip := m.sessionStrip(t)
	toast := m.toastLine(t)
	hint := m.hintBar(t)
	// One blank margin row between the header rule and the top of the panels
	// (design: content area padding-top ≈ 14px).
	contentH := m.h - len(header) - len(strip) - len(toast) - len(hint) - 1
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
	out = append(out, strip...)
	out = append(out, bgpad(m.w, t.Bg))
	out = append(out, content...)
	out = append(out, toast...)
	out = append(out, hint...)
	return out
}

// header renders the two-line top bar (badge + tabs + account/vault status).
func (m Model) header(t theme.Theme, tabs string) []string {
	badge := bold(t.Ink, t.Hi).Render(" ⚓ wharf ")
	left := badge + bgpad(1, t.Bg) + tabs
	var right string
	switch {
	case m.signedIn && !m.demo:
		right = stl(t.Dim, t.Bg).Render(m.email+" · ") + m.syncIndicator(t) +
			stl(t.Dim, t.Bg).Render(" · ") + stl(t.Hi, t.Bg).Render("q") + stl(t.Dim, t.Bg).Render(" lock")
	case m.signedIn:
		right = stl(t.Dim, t.Bg).Render(m.email+" · ") + stl(t.Ok, t.Bg).Render("● synced")
	case m.demo:
		right = stl(t.Dim, t.Bg).Render("○ local vault · ") + stl(t.Hi, t.Bg).Render("q") + stl(t.Dim, t.Bg).Render(" sign in")
	default:
		right = stl(t.Ok, t.Bg).Render("● vault open · ") + stl(t.Hi, t.Bg).Render("q") + stl(t.Dim, t.Bg).Render(" lock")
	}
	return []string{barLine(t, m.w, " "+left, right+" "), rule(t, m.w)}
}

// syncIndicator renders the account sync state for the header (design: the
// success-green "● synced" dot in the tab row).
func (m Model) syncIndicator(t theme.Theme) string {
	switch m.syncSt {
	case ssSyncing:
		return stl(t.Warn, t.Bg).Render(m.spinner() + " syncing")
	case ssSynced:
		return stl(t.Ok, t.Bg).Render("● synced")
	case ssOffline:
		return stl(t.Err, t.Bg).Render("● offline")
	case ssConflict:
		return stl(t.Warn, t.Bg).Render("● conflict")
	default:
		return stl(t.Dim, t.Bg).Render("○ not synced")
	}
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

// sessionStrip lists live SSH sessions (real mode only).
func (m Model) sessionStrip(t theme.Theme) []string {
	if m.demo || m.mgr == nil {
		return nil
	}
	sessions := m.mgr.List()
	if len(sessions) == 0 {
		return nil
	}
	left := " " + stl(t.Dim, t.Bg).Render("live ")
	for i, s := range sessions {
		if i >= 9 {
			break
		}
		label := " " + itoa(i+1) + ":" + s.Host().Name + " "
		left += stl(t.Hi, t.Sel).Render(label) + bgpad(1, t.Bg)
	}
	right := stl(t.Dim, t.Bg).Render("alt+# reattach") + " "
	return []string{barLine(t, m.w, left, right)}
}

// toastLine renders the transient status toast, or nothing.
func (m Model) toastLine(t theme.Theme) []string {
	if m.toast == "" {
		return nil
	}
	c := t.Ok
	if m.toastRole == "err" {
		c = t.Err
	}
	return []string{barLine(t, m.w, " "+stl(c, t.Bg).Render("› "+m.toast), "")}
}

// paneAvail is the total width available to the two panes (screen minus the
// outer margins and the inter-pane gap).
func (m Model) paneAvail() int {
	avail := m.w - 2*marginX - paneGap
	if avail < 10 {
		avail = 10
	}
	return avail
}

// paneSplit divides paneAvail into a left and right pane width in the ratio
// lw:rw.
func (m Model) paneSplit(lw, rw int) (int, int) {
	avail := m.paneAvail()
	leftW := avail * lw / (lw + rw)
	return leftW, avail - leftW
}

// twoPane lays out a list panel (full-width selection rows) and a detail panel
// (inset content) with outer margins and an inter-pane gap.
func (m Model) twoPane(t theme.Theme, contentH int, lTitle string, lBorder lipgloss.Color, lRows []string, lw int, rTitle string, rBorder lipgloss.Color, rBody []string, rw int) []string {
	leftW, rightW := m.paneSplit(lw, rw)
	left := listPanel(t, lTitle, lBorder, leftW, contentH, lRows)
	right := boxPanel(t, rTitle, rBorder, rightW, contentH, rBody)
	return hjoin(col(marginX, contentH, t.Bg), left, col(paneGap, contentH, t.Bg), right, col(marginX, contentH, t.Bg))
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

// hostLive reports whether a live session exists for the host.
func (m Model) hostLive(id string) bool {
	if m.mgr == nil {
		return false
	}
	s := m.mgr.Get(id)
	return s != nil && s.Alive()
}

// hostsTab renders the hosts list + host detail (or an empty state).
func (m Model) hostsTab(t theme.Theme, contentH int) []string {
	if len(m.storeHosts()) == 0 && m.query == "" {
		return m.hostsEmpty(t, contentH)
	}
	fh := m.filteredHosts()
	hIdx := clampIdx(m.hostIdx, len(fh))

	leftW, rightW := m.paneSplit(3, 2)
	innerW := leftW - 2
	pad := bgpad(padX, t.Panel)

	var lRows []string
	if m.searchActive || m.query != "" {
		lRows = append(lRows, pad+stl(t.Warn, t.Panel).Render("/"+m.query)+m.cur(t.Warn, t.Panel))
	}
	for i, h := range fh {
		res, ok := m.probes[h.ID]
		lRows = append(lRows, hostRow(t, h, res, ok, m.hostLive(h.ID), i == hIdx, innerW))
	}
	if len(fh) == 0 {
		lRows = append(lRows, pad+stl(t.Dim, t.Panel).Render("no hosts match"))
	}

	rw := boxContentW(rightW)
	var rBody []string
	if len(fh) > 0 {
		h := fh[hIdx]
		res, ok := m.probes[h.ID]
		statusTxt, statusRole := probeStatusText(res, ok)
		rtt := "—"
		if ok && res.Status != probe.StatusOffline && res.RTT > 0 {
			rtt = res.RTT.Round(time.Millisecond).String()
		}
		rBody = []string{
			stl(t.Hi, t.Panel).Bold(true).Render(h.Name),
			"",
			kv(t, "address", h.Conn(), t.Fg, rw),
			kv(t, "identity", orDash(h.KeyPath), t.Fg, rw),
			kv(t, "auth", authDetail(h), t.Fg, rw),
			kv(t, "tags", orDash(tagStr(h)), t.Blue, rw),
			kv(t, "source", h.Source, t.Dim, rw),
			kv(t, "last seen", lastSeenStr(h.LastSeen), t.Dim, rw),
			kv(t, "status", statusTxt, colorFor(t, statusRole), rw),
			kv(t, "rtt", rtt, t.Dim, rw),
		}
		if m.hostLive(h.ID) {
			rBody = append(rBody, "", stl(t.Ok, t.Panel).Render("● live session — enter reattaches"))
		}
		rBody = append(rBody, "",
			ruleIn(t, rw),
			"",
			stl(t.Hi, t.Panel).Render("enter")+stl(t.Dim, t.Panel).Render(" connect · ")+
				stl(t.Hi, t.Panel).Render("a/e/d")+stl(t.Dim, t.Panel).Render(" add/edit/del"))
	} else {
		rBody = []string{stl(t.Dim, t.Panel).Render("no match")}
	}

	title := "hosts · " + itoa(len(fh)) + "/" + itoa(len(m.storeHosts()))
	return m.twoPane(t, contentH, title, m.listBorder(t), lRows, 3, "host", m.detailBorder(t), rBody, 2)
}

// hostsEmpty renders the friendly empty state for a fresh vault.
func (m Model) hostsEmpty(t theme.Theme, contentH int) []string {
	pw := 60
	if pw > m.w-6 {
		pw = m.w - 6
	}
	body := []string{
		stl(t.Fg, t.Panel).Render("No hosts yet."),
		"",
		stl(t.Hi, t.Panel).Render("a") + stl(t.Dim, t.Panel).Render("   add a host"),
		stl(t.Hi, t.Panel).Render("m") + stl(t.Dim, t.Panel).Render("   import ~/.ssh/config"),
	}
	box := boxPanelAuto(t, "hosts", t.Hi, pw, body)
	return centerInArea(box, m.w, contentH, t.Bg)
}

func hostRow(t theme.Theme, h store.Host, res probe.Result, known, live, sel bool, innerW int) string {
	bg := t.Panel
	mark := " "
	nameFg := t.Fg
	if sel {
		bg = t.Sel
		mark = "▸"
		nameFg = t.Hi
	}
	avail := innerW - 2*padX
	if avail < 10 {
		avail = 10
	}
	liveSeg := bgpad(2, bg)
	if live {
		liveSeg = stl(t.Ok, bg).Render("● ")
	}
	tags := tagStr(h)
	statusTxt, statusRole := probeStatusText(res, known)
	tagW := len([]rune(tags))
	const (
		nameW   = 16
		statusW = 10
	)
	// mark(2) + live(2) + name + 3 single-space gaps + tags + status; conn flexes.
	connW := avail - (2 + 2 + nameW + 3 + tagW + statusW)
	if connW < 6 {
		connW = 6
	}
	mid := stl(t.Hi, bg).Render(mark+" ") +
		liveSeg +
		rowSeg(h.Name, nameW, nameFg, bg, false) +
		bgpad(1, bg) +
		rowSeg(h.Conn(), connW, t.Dim, bg, false) +
		bgpad(1, bg) +
		rowSeg(tags, tagW, t.Blue, bg, false) +
		bgpad(1, bg) +
		rowSeg(statusTxt, statusW, colorFor(t, statusRole), bg, true)
	return selRow(innerW, bg, mid)
}

func tagStr(h store.Host) string {
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
	leftW, rightW := m.paneSplit(11, 14)
	lInner := leftW - 2
	var lRows []string
	for i, p := range m.projects {
		lRows = append(lRows, projRow(t, p, i == pIdx, lInner))
	}
	p := m.projects[pIdx]
	rBody := []string{
		stl(t.Hi, t.Panel).Bold(true).Render(p.Name),
		stl(t.Dim, t.Panel).Render(p.Desc),
		"",
		stl(t.Dim, t.Panel).Render("members"),
	}
	for _, mem := range p.Members {
		rBody = append(rBody, stl(t.Fg, t.Panel).Render(padTo2(mem.Name, 16))+stl(t.Dim, t.Panel).Render(mem.Role))
	}
	if len(p.Invites) > 0 {
		rBody = append(rBody, "", stl(t.Dim, t.Panel).Render("pending invites"))
		for _, e := range p.Invites {
			rBody = append(rBody, stl(t.Warn, t.Panel).Render("○ "+padTo2(e, 20))+stl(t.Dim, t.Panel).Render("invited · awaiting accept"))
		}
	}
	rBody = append(rBody, "",
		stl(t.Hi, t.Panel).Render("i")+stl(t.Dim, t.Panel).Render(" invite member · ")+
			stl(t.Hi, t.Panel).Render("enter")+stl(t.Dim, t.Panel).Render(" filter hosts to project"))
	_ = rightW
	title := "projects · " + itoa(len(m.projects))
	return m.twoPane(t, contentH, title, m.listBorder(t), lRows, 11, "project", m.detailBorder(t), rBody, 14)
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
	avail := innerW - 2*padX
	if avail < 8 {
		avail = 8
	}
	const nameW = 18
	meta := itoa(p.Hosts) + " hosts · " + itoa(len(p.Members)) + " members"
	metaW := avail - (2 + nameW + 1)
	if metaW < 4 {
		metaW = 4
	}
	mid := stl(t.Hi, bg).Render(mark+" ") +
		rowSeg(p.Name, nameW, nameFg, bg, false) +
		bgpad(1, bg) +
		rowSeg(meta, metaW, t.Dim, bg, false)
	return selRow(innerW, bg, mid)
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
	box := boxPanelAuto(t, "projects · sign in required", t.Warn, pw, body)
	return centerInArea(box, m.w, contentH, t.Bg)
}

// keysTab renders identities scanned from ~/.ssh + detail.
func (m Model) keysTab(t theme.Theme, contentH int) []string {
	if len(m.keyInfos) == 0 {
		return m.keysEmpty(t, contentH)
	}
	kIdx := clampIdx(m.keyIdx, len(m.keyInfos))
	leftW, rightW := m.paneSplit(11, 14)
	lInner := leftW - 2
	var lRows []string
	for i, k := range m.keyInfos {
		lRows = append(lRows, keyRow(t, k, i == kIdx, lInner))
	}
	k := m.keyInfos[kIdx]
	rw := boxContentW(rightW)
	enc, encC := "no", t.Ok
	if k.Encrypted {
		enc, encC = "yes", t.Warn
	}
	rBody := []string{
		stl(t.Hi, t.Panel).Bold(true).Render(k.Name),
		"",
		kv(t, "type", orDash(k.Type), t.Fg, rw),
		kv(t, "fingerprint", orDash(k.Fingerprint), t.Dim, rw),
		kv(t, "path", orDash(k.Path), t.Fg, rw),
		kv(t, "encrypted", enc, encC, rw),
		"",
		stl(t.Hi, t.Panel).Render("g") + stl(t.Dim, t.Panel).Render(" generate a new ed25519 key"),
	}
	return m.twoPane(t, contentH, "identities · "+itoa(len(m.keyInfos)), m.listBorder(t), lRows, 11, "identity", m.detailBorder(t), rBody, 14)
}

func (m Model) keysEmpty(t theme.Theme, contentH int) []string {
	pw := 58
	if pw > m.w-6 {
		pw = m.w - 6
	}
	body := []string{
		stl(t.Fg, t.Panel).Render("No SSH keys found in ~/.ssh."),
		"",
		stl(t.Hi, t.Panel).Render("g") + stl(t.Dim, t.Panel).Render("   generate an ed25519 key"),
	}
	box := boxPanelAuto(t, "identities", t.Hi, pw, body)
	return centerInArea(box, m.w, contentH, t.Bg)
}

func keyRow(t theme.Theme, k keys.KeyInfo, sel bool, innerW int) string {
	bg := t.Panel
	mark := " "
	nameFg := t.Fg
	if sel {
		bg = t.Sel
		mark = "▸"
		nameFg = t.Hi
	}
	avail := innerW - 2*padX
	if avail < 8 {
		avail = 8
	}
	const nameW = 20
	badge := ""
	badgeC := t.Dim
	if k.Encrypted {
		badge, badgeC = "encrypted", t.Warn
	}
	badgeW := len([]rune(badge))
	typeW := avail - (2 + nameW + 1 + 1 + badgeW)
	if typeW < 4 {
		typeW = 4
	}
	mid := stl(t.Hi, bg).Render(mark+" ") +
		rowSeg(k.Name, nameW, nameFg, bg, false) +
		bgpad(1, bg) +
		rowSeg(orDash(k.Type), typeW, t.Dim, bg, false) +
		bgpad(1, bg) +
		rowSeg(badge, badgeW, badgeC, bg, true)
	return selRow(innerW, bg, mid)
}

// settingsTab renders the centered settings panel from store.Settings.
func (m Model) settingsTab(t theme.Theme, contentH int) []string {
	pw := 66
	if pw > m.w-6 {
		pw = m.w - 6
	}
	inner := pw - 2
	avail := inner - 2*padX
	if avail < 8 {
		avail = 8
	}
	const valW = 16
	pad := bgpad(padX, t.Panel)
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
		switch d.key {
		case "theme":
			val, vc = "‹ "+m.themeName+" ›", t.Hi
		case "account":
			if m.signedIn {
				val, vc = m.email, t.Ok
			} else {
				val, vc = "signed out", t.Dim
			}
		default:
			if m.settingOn(d.key) {
				val, vc = "[on]", t.Ok
			} else {
				val, vc = "[off]", t.Dim
			}
		}
		mid := stl(t.Hi, bg).Render(mark+" ") +
			rowSeg(d.label, avail-2-valW, labelFg, bg, false) +
			rowSeg(val, valW, vc, bg, true)
		body = append(body, selRow(inner, bg, mid))
	}
	body = append(body, "",
		pad+ruleIn(t, avail),
		"",
		pad+stl(t.Hi, t.Panel).Render("enter")+stl(t.Dim, t.Panel).Render(" toggle / cycle / sign in · theme applies live"))
	box := listPanel(t, "settings", t.Hi, pw, len(body)+4, body)
	return topInArea(box, m.w, contentH, t.Bg)
}

// settingOn reports the current boolean setting value.
func (m Model) settingOn(key string) bool {
	switch key {
	case "agent":
		return m.settings.Agent
	case "keepalive":
		return m.settings.Keepalive
	case "telemetry":
		return m.settings.Telemetry
	}
	return false
}

// --- session (simulated, demo only) -----------------------------------------

func (m Model) sessionView(t theme.Theme) []string {
	badge := bold(t.Ink, t.Hi).Render(" ⚓ wharf ")
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

	// One blank margin row between the header rule and the terminal panel.
	contentH := m.h - len(header) - len(hint) - 1
	if contentH < 3 {
		contentH = 3
	}

	paneW := m.w - 2*marginX
	if paneW < 4 {
		paneW = 4
	}
	inner := boxContentW(paneW)

	s := m.sessions[m.active]
	var body []string
	if s != nil {
		// Visible scrollback: interior minus borders, the two padding rows and
		// the live prompt line.
		maxLines := contentH - 4 - 1
		if maxLines < 1 {
			maxLines = 1
		}
		start := 0
		if len(s.lines) > maxLines {
			start = len(s.lines) - maxLines
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
	pane := hjoin(col(marginX, contentH, t.Bg), boxPanel(t, title, t.Hi, paneW, contentH, body), col(marginX, contentH, t.Bg))

	out := append([]string{}, header...)
	out = append(out, bgpad(m.w, t.Bg))
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
		if !m.demo {
			hints = append(hints, hk{"a/e/d", "add/edit/del"}, hk{"m", "import"}, hk{"R", "probe"})
		}
	case 1:
		if m.signedIn {
			hints = append(hints, hk{"enter", "view hosts"}, hk{"i", "invite"})
		} else {
			hints = append(hints, hk{"enter", "sign in"})
		}
	case 2:
		if !m.demo {
			hints = append(hints, hk{"g", "generate"})
		}
	case 3:
		hints = append(hints, hk{"enter", "toggle"})
		if m.signedIn && !m.demo {
			hints = append(hints, hk{"s", "sync now"})
		}
	}
	if m.demo {
		signLabel := "sign in"
		if m.signedIn {
			signLabel = "sign out"
		}
		hints = append(hints, hk{"1-4", "tabs"}, hk{"q", signLabel})
	} else {
		hints = append(hints, hk{"1-4", "tabs"}, hk{"q", "lock"}, hk{"⌃q", "quit"})
	}

	var b strings.Builder
	b.WriteString(" ")
	for i, h := range hints {
		if i > 0 {
			b.WriteString(bgpad(hintGap, t.Bg))
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
	box := boxPanelAuto(t, "invite to "+p.Name, t.Hi, pw, body)
	return centerInArea(box, m.w, m.h, t.Bg)
}

func (m Model) helpView(t theme.Theme) []string {
	rows := [][2]string{
		{"j / k", "move selection"},
		{"1-4", "switch tab"},
		{"/", "filter hosts"},
		{"tab", "cycle pane focus"},
		{"enter", "connect / open / toggle"},
		{"a / e / d", "add / edit / delete host"},
		{"m", "import ~/.ssh/config"},
		{"R", "re-probe all hosts"},
		{"g", "generate a key (keys tab)"},
		{"i", "invite member (projects)"},
		{"esc", "back / clear / detach / cancel"},
		{"ctrl+\\", "detach from a live session"},
		{"alt+1..9", "reattach a live session"},
		{"q", "lock vault (sign in/out in demo)"},
		{"ctrl+q", "quit wharf"},
		{"?", "toggle this help"},
	}
	pw := 96
	if pw > m.w-6 {
		pw = m.w - 6
	}
	cw := boxContentW(pw)
	const keyW = 10
	gap := hintGap
	cellW := (cw - gap) / 2
	if cellW < keyW+4 {
		cellW = keyW + 4
	}
	half := (len(rows) + 1) / 2
	var body []string
	for i := 0; i < half; i++ {
		left := helpCell(t, rows[i], keyW, cellW)
		right := ""
		if j := i + half; j < len(rows) {
			right = helpCell(t, rows[j], keyW, cellW)
		}
		body = append(body, left+bgpad(gap, t.Panel)+right)
	}
	body = append(body, "",
		ruleIn(t, cw),
		"",
		stl(t.Dim, t.Panel).Render("Wharf is local-first — sign in only to sync & use projects."))
	box := boxPanelAuto(t, "keybindings", t.Hi, pw, body)
	return centerInArea(box, m.w, m.h, t.Bg)
}

// helpCell renders one key/label pair padded to cellW for the help grid.
func helpCell(t theme.Theme, r [2]string, keyW, cellW int) string {
	key := stl(t.Hi, t.Panel).Render(padTo2(r[0], keyW))
	label := stl(t.Dim, t.Panel).Render(trunc(r[1], cellW-keyW))
	return padTo(key+label, cellW, t.Panel)
}
