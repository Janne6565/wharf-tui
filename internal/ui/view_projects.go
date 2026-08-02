package ui

import (
	"strings"

	"github.com/Janne6565/wharf-tui/internal/api"
	"github.com/Janne6565/wharf-tui/internal/theme"
	"github.com/charmbracelet/lipgloss"
)

// realProjectsTab renders the live projects master/detail: pinned received
// invites, the project list, and a detail pane with members/roles/invites (or an
// awaiting-access placeholder).
func (m Model) realProjectsTab(t theme.Theme, contentH int) []string {
	if m.projectRowCount() == 0 {
		if m.projectsPending() {
			what := "loading your projects…"
			if m.identityBooting {
				what = "setting up project encryption…"
			}
			return m.loadingPanel(t, contentH, "projects", what)
		}
		return m.realProjectsEmpty(t, contentH)
	}
	pIdx := clampIdx(m.projIdx, m.projectRowCount())
	leftW, rightW := m.paneSplit(11, 14)
	lInner := leftW - 2
	pad := bgpad(padX, t.Panel)

	var lRows []string
	// Pinned received invites at the top.
	for i, inv := range m.receivedInvites {
		lRows = append(lRows, inviteRow(t, inv, i == pIdx, lInner))
	}
	for i, p := range m.realProjects {
		idx := len(m.receivedInvites) + i
		lRows = append(lRows, m.realProjRow(t, p, idx == pIdx, lInner))
	}

	// Right pane: invite response prompt, awaiting placeholder, or project detail.
	var rBody []string
	if inv, ok := m.selectedInvite(); ok {
		rBody = []string{
			stl(t.Hi, t.Panel).Bold(true).Render("Invitation"),
			"",
			stl(t.Fg, t.Panel).Render(inv.InvitedByEmail) + stl(t.Dim, t.Panel).Render(" invited you to"),
			stl(t.Hi, t.Panel).Render(inv.ProjectName),
			"",
			stl(t.Hi, t.Panel).Render("enter") + stl(t.Dim, t.Panel).Render(" respond (accept / decline)"),
		}
	} else if p, ok := m.selectedProject(); ok {
		rBody = m.projectDetailBody(t, p, boxContentW(rightW))
	} else {
		rBody = []string{stl(t.Dim, t.Panel).Render("no project selected")}
	}
	if lines := m.identityNoticeLines(t, boxContentW(rightW)); lines != nil {
		rBody = append(rBody, "")
		rBody = append(rBody, lines...)
	}
	// The mismatch warning goes first: it outranks anything else on this tab, and
	// the detail pane clips from the bottom, so the top is the one spot that
	// cannot be pushed off screen.
	if lines := m.identityMismatchLines(t, boxContentW(rightW)); lines != nil {
		rBody = append(append(lines, ""), rBody...)
	}
	_ = pad

	title := "projects · " + itoa(len(m.realProjects))
	if len(m.receivedInvites) > 0 {
		title += " · " + itoa(len(m.receivedInvites)) + " invite(s)"
	}
	return m.twoPane(t, contentH, title, m.listBorder(t), lRows, 11, "project", m.detailBorder(t), rBody, 14)
}

// projectDetailBody renders the right-pane detail for a selected project.
func (m Model) projectDetailBody(t theme.Theme, p projectItem, rw int) []string {
	body := []string{
		stl(t.Hi, t.Panel).Bold(true).Render(p.Name),
		stl(t.Dim, t.Panel).Render(orDash(p.Description)),
		"",
	}
	if p.AwaitingKey {
		body = append(body,
			stl(t.Warn, t.Panel).Render("awaiting access"),
			stl(t.Dim, t.Panel).Render("an admin needs to grant your key"),
			"",
			kv(t, "role", strings.ToLower(p.Role), t.Fg, rw),
			kv(t, "members", itoa(p.MemberCount), t.Dim, rw))
		return body
	}
	body = append(body,
		kv(t, "role", strings.ToLower(p.Role), t.Fg, rw),
		"")

	body = append(body, m.projectHostLines(t, rw)...)
	body = append(body, "", stl(t.Dim, t.Panel).Render("members"))

	memberFocus := m.focus == pfMembers
	if d := m.projDetail; d != nil && d.ID == p.ID {
		for i, mem := range d.Members {
			marker := "  "
			nameFg := t.Fg
			if memberFocus && i == m.memberIdx {
				marker = "▸ "
				nameFg = t.Hi
			}
			label := mem.Email
			if mem.Email == m.email {
				label += " (you)"
			}
			body = append(body, stl(t.Hi, t.Panel).Render(marker)+
				rowSeg(label, detailNameW, nameFg, t.Panel, false)+
				stl(t.Dim, t.Panel).Render(strings.ToLower(mem.Role)))
		}
		if len(d.Invites) > 0 {
			body = append(body, "", stl(t.Dim, t.Panel).Render("pending invites"))
			for j, inv := range d.Invites {
				idx := len(d.Members) + j
				marker := "○ "
				emailFg := t.Warn
				if memberFocus && idx == m.memberIdx {
					marker = "▸ "
					emailFg = t.Hi
				}
				body = append(body, stl(emailFg, t.Panel).Render(marker)+
					rowSeg(inv.Email, detailNameW, emailFg, t.Panel, false)+
					stl(t.Dim, t.Panel).Render("invited · awaiting accept"))
			}
		}
	} else {
		body = append(body, stl(t.Dim, t.Panel).Render("  loading members…"))
	}

	body = append(body, "", m.projectDetailHints(t, p))
	return body
}

// projectHostCount is a project's live host count: read from the decrypted doc
// when it is loaded, so a host added or moved locally shows up immediately
// rather than at the next projects sync. Falls back to the sync snapshot for a
// project whose doc has not been fetched.
func (m Model) projectHostCount(p projectItem) int {
	if doc := m.projectDocs[p.ID]; doc != nil {
		return len(doc.HostList())
	}
	return p.HostCount
}

// detailNameW is the shared name column of the detail pane's host and member
// lists: fixed and truncating, so the two line up and a long address can never
// run into the status beside it.
const detailNameW = 26

// projectHostLines renders the selected project's own hosts inside the detail
// pane. Opening a project moves the cursor here rather than switching tabs, so
// this list is the tab's primary content, not a footnote under the members.
func (m Model) projectHostLines(t theme.Theme, rw int) []string {
	hosts := m.selectedProjectHosts()
	out := []string{stl(t.Dim, t.Panel).Render("hosts · " + itoa(len(hosts)))}
	if len(hosts) == 0 {
		return append(out, stl(t.Dim, t.Panel).Render("  none yet — ")+
			stl(t.Hi, t.Panel).Render("p")+stl(t.Dim, t.Panel).Render(" on a host moves one in"))
	}
	focused := m.focus == pfHosts
	cur := clampIdx(m.projHostIdx, len(hosts))
	for i, h := range hosts {
		marker, nameFg := "  ", t.Fg
		if focused && i == cur {
			marker, nameFg = "▸ ", t.Hi
		}
		// Width mirrors the members rows below so the two lists line up.
		res, known := m.probes[h.ID]
		label, role := probeStatusText(res, known)
		out = append(out, stl(t.Hi, t.Panel).Render(marker)+
			rowSeg(h.Name, detailNameW, nameFg, t.Panel, false)+
			stl(colorFor(t, role), t.Panel).Render(label))
	}
	return out
}

// projectDetailHints names what the keys do for the ring the cursor is in.
func (m Model) projectDetailHints(t theme.Theme, p projectItem) string {
	key := func(k, l string) string {
		return stl(t.Hi, t.Panel).Render(k) + stl(t.Dim, t.Panel).Render(" "+l)
	}
	sep := stl(t.Dim, t.Panel).Render(" · ")
	switch m.focus {
	case pfHosts:
		return key("enter", "connect") + sep + key("esc", "back") + sep + key("f", "in hosts tab")
	case pfMembers:
		if isAdmin(p.Role) {
			return key("d/x", "remove/revoke") + sep + key("i", "invite") + sep + key("esc", "back")
		}
		return key("esc", "back")
	default:
		hints := key("enter", "open hosts") + sep + key("f", "in hosts tab")
		if isAdmin(p.Role) {
			hints += sep + key("i", "invite") + sep + key("tab", "members")
		}
		return hints
	}
}

// realProjRow renders a project list row: name + "N hosts · N members".
func (m Model) realProjRow(t theme.Theme, p projectItem, sel bool, innerW int) string {
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
	var meta string
	if p.AwaitingKey {
		meta = "awaiting access"
	} else {
		meta = itoa(m.projectHostCount(p)) + " hosts · " + itoa(p.MemberCount) + " members"
	}
	metaW := avail - (2 + nameW + 1)
	if metaW < 4 {
		metaW = 4
	}
	metaFg := t.Dim
	if p.AwaitingKey {
		metaFg = t.Warn
	}
	mid := stl(t.Hi, bg).Render(mark+" ") +
		rowSeg(p.Name, nameW, nameFg, bg, false) +
		bgpad(1, bg) +
		rowSeg(meta, metaW, metaFg, bg, false)
	return selRow(innerW, bg, mid)
}

// inviteRow renders a pinned received-invite row at the top of the list.
func inviteRow(t theme.Theme, inv api.ReceivedInvite, sel bool, innerW int) string {
	bg := t.Panel
	mark := " "
	if sel {
		bg = t.Sel
		mark = "▸"
	}
	avail := innerW - 2*padX
	if avail < 8 {
		avail = 8
	}
	text := "✉ invited to " + inv.ProjectName
	mid := stl(t.Hi, bg).Render(mark+" ") + rowSeg(text, avail-2, t.Warn, bg, false)
	return selRow(innerW, bg, mid)
}

// realProjectsEmpty renders the empty state for a signed-in account with no
// projects and no invites.
func (m Model) realProjectsEmpty(t theme.Theme, contentH int) []string {
	pw := 62
	if pw > m.w-6 {
		pw = m.w - 6
	}
	body := []string{
		stl(t.Fg, t.Panel).Render("No projects yet."),
		"",
		stl(t.Dim, t.Panel).Render("A project is a shared set of hosts. Invite teammates by"),
		stl(t.Dim, t.Panel).Render("email; your private keys are never shared."),
		"",
		stl(t.Hi, t.Panel).Render("n") + stl(t.Dim, t.Panel).Render("   create a project"),
	}
	if lines := m.identityNoticeLines(t, pw-6); lines != nil {
		body = append(body, "")
		body = append(body, lines...)
	}
	if lines := m.identityMismatchLines(t, pw-6); lines != nil {
		body = append(append(lines, ""), body...)
	}
	box := boxPanelAuto(t, "projects", t.Hi, pw, body)
	return centerInArea(box, m.w, contentH, t.Bg)
}

// --- modals -------------------------------------------------------------------

func (m Model) createProjectView(t theme.Theme) []string {
	labels := [2]string{"name", "description"}
	hints := [2]string{"", "optional"}
	var body []string
	for i := 0; i < 2; i++ {
		focused := i == m.cpjFocus
		line := stl(t.Dim, t.Panel).Render(padTo2(labels[i], 12))
		if m.cpjVals[i] == "" && !focused && hints[i] != "" {
			line += stl(t.Dim, t.Panel).Render(hints[i])
		} else {
			line += stl(t.Hi, t.Panel).Render(m.cpjVals[i])
		}
		if focused {
			line += m.cur(t.Hi, t.Panel)
		}
		body = append(body, line)
	}
	if m.cpjErr != "" {
		body = append(body, "", stl(t.Err, t.Panel).Render(m.cpjErr))
	}
	body = append(body, "",
		stl(t.Dim, t.Panel).Render("Creates an encrypted shared vault you own."),
		"",
		stl(t.Hi, t.Panel).Render("tab")+stl(t.Dim, t.Panel).Render(" move · ")+
			stl(t.Hi, t.Panel).Render("enter")+stl(t.Dim, t.Panel).Render(" create · ")+
			stl(t.Hi, t.Panel).Render("esc")+stl(t.Dim, t.Panel).Render(" cancel"))
	return m.modalBox(t, "new project", "hi", body)
}

func (m Model) removeMemberView(t theme.Theme) []string {
	body := []string{
		stl(t.Fg, t.Panel).Render("Remove ") + stl(t.Hi, t.Panel).Render(m.rmName) + stl(t.Fg, t.Panel).Render(" ?"),
		"",
		stl(t.Dim, t.Panel).Render("The project key is rotated: a fresh DEK is generated,"),
		stl(t.Dim, t.Panel).Render("the vault re-sealed, and re-wrapped for the remaining"),
		stl(t.Dim, t.Panel).Render("members. The removed member loses all access."),
		"",
		stl(t.Hi, t.Panel).Render("y") + stl(t.Dim, t.Panel).Render("/") + stl(t.Hi, t.Panel).Render("enter") +
			stl(t.Dim, t.Panel).Render(" remove · ") + stl(t.Hi, t.Panel).Render("esc") +
			stl(t.Dim, t.Panel).Render("/") + stl(t.Hi, t.Panel).Render("n") + stl(t.Dim, t.Panel).Render(" cancel"),
	}
	return m.modalBox(t, "remove member", "err", body)
}

func (m Model) inviteResponseView(t theme.Theme) []string {
	body := []string{
		stl(t.Fg, t.Panel).Render("You were invited to ") + stl(t.Hi, t.Panel).Render(m.invRespName) + stl(t.Fg, t.Panel).Render("."),
		"",
		stl(t.Dim, t.Panel).Render("Accepting joins the project; an admin then grants your"),
		stl(t.Dim, t.Panel).Render("access key on their next sync."),
		"",
		stl(t.Hi, t.Panel).Render("a") + stl(t.Dim, t.Panel).Render("/") + stl(t.Hi, t.Panel).Render("enter") +
			stl(t.Dim, t.Panel).Render(" accept · ") + stl(t.Hi, t.Panel).Render("d") +
			stl(t.Dim, t.Panel).Render(" decline · ") + stl(t.Hi, t.Panel).Render("esc") + stl(t.Dim, t.Panel).Render(" later"),
	}
	return m.modalBox(t, "respond to invite", "hi", body)
}

func (m Model) resetIdentityView(t theme.Theme) []string {
	body := []string{
		stl(t.Warn, t.Panel).Render("Reset your project identity?"),
		"",
		stl(t.Dim, t.Panel).Render("Use this only if you have lost the device that created"),
		stl(t.Dim, t.Panel).Render("your identity. A brand-new key is minted here and your"),
		stl(t.Dim, t.Panel).Render("published one is replaced."),
		"",
		stl(t.Dim, t.Panel).Render("Every project re-enters awaiting-access until an admin"),
		stl(t.Dim, t.Panel).Render("re-grants your key. A project where you were the only"),
		stl(t.Dim, t.Panel).Render("member holding a key becomes unrecoverable."),
		"",
		stl(t.Hi, t.Panel).Render("y") + stl(t.Dim, t.Panel).Render("/") + stl(t.Hi, t.Panel).Render("enter") +
			stl(t.Dim, t.Panel).Render(" reset · ") + stl(t.Hi, t.Panel).Render("esc") +
			stl(t.Dim, t.Panel).Render("/") + stl(t.Hi, t.Panel).Render("n") + stl(t.Dim, t.Panel).Render(" cancel"),
	}
	return m.modalBox(t, "reset identity", "warn", body)
}

func (m Model) projectConflictView(t theme.Theme) []string {
	c := m.projConflict
	if c == nil {
		return m.mainView(t)
	}
	body := []string{
		stl(t.Warn, t.Panel).Render("Project “" + c.Name + "” changed on both sides."),
		stl(t.Dim, t.Panel).Render("Pick which one to keep — the other side is overwritten."),
		"",
		stl(t.Fg, t.Panel).Render("local   ") + stl(t.Hi, t.Panel).Render(itoa(c.LocalHosts)+" host(s)"),
		stl(t.Fg, t.Panel).Render("remote  ") + stl(t.Hi, t.Panel).Render(itoa(c.RemoteHosts)+" host(s)") +
			stl(t.Dim, t.Panel).Render("  v"+itoa(int(c.RemoteVersion))),
		"",
		stl(t.Hi, t.Panel).Render("l") + stl(t.Dim, t.Panel).Render("  keep local — overwrite the project vault"),
		stl(t.Hi, t.Panel).Render("r") + stl(t.Dim, t.Panel).Render("  take remote — discard this machine's changes"),
		stl(t.Hi, t.Panel).Render("esc") + stl(t.Dim, t.Panel).Render("  decide later"),
	}
	return m.modalBox(t, "project conflict", "warn", body)
}

// projectTag renders a dim inline project label for a merged host row.
func projectTag(t theme.Theme, name string, bg lipgloss.Color) string {
	return stl(t.Mag, bg).Render("⧉ " + name)
}

// identityNoticeLines renders the cross-device "sync first" notice, word-wrapped
// to width, plus the reset keybinding when the "I lost my old vault" reset is
// available (the needs-sync state). Returns nil when there is no notice.
func (m Model) identityNoticeLines(t theme.Theme, width int) []string {
	if m.identityNotice == "" {
		return nil
	}
	var out []string
	for _, ln := range wrapText(m.identityNotice, width) {
		out = append(out, stl(t.Warn, t.Panel).Render(ln))
	}
	if m.identityNeedsSync {
		out = append(out, stl(t.Hi, t.Panel).Render("R")+
			stl(t.Dim, t.Panel).Render(" reset identity — lost that device"))
	}
	return out
}

// identityMismatchLines renders the published-key mismatch warning: what is
// wrong, what it costs, and both fingerprints so the user can compare them
// against their other devices. Returns nil when no mismatch stands.
//
// Colors go through the theme's danger role (t.Err) rather than a literal, so a
// live theme switch recolors it like everything else.
func (m Model) identityMismatchLines(t theme.Theme, width int) []string {
	if !m.identityMismatch {
		return nil
	}
	const body = "The public key the server publishes for this account does not " +
		"match the one in this vault. Project keys shared with this account may be " +
		"going to someone else. Do not accept invites until this is resolved."

	out := []string{bold(t.Err, t.Panel).Render("⚠ public key mismatch")}
	for _, ln := range wrapText(body, width) {
		out = append(out, stl(t.Err, t.Panel).Render(ln))
	}
	out = append(out, "",
		fingerprintLine(t, "in this vault", m.identityLocalFP),
		fingerprintLine(t, "published by the server", m.identityServerFP),
		"",
		stl(t.Hi, t.Panel).Render("p")+
			stl(t.Dim, t.Panel).Render(" republish this vault's key to the server"))
	return out
}

// fingerprintLine renders one labelled fingerprint of the mismatch warning.
func fingerprintLine(t theme.Theme, label, fp string) string {
	return stl(t.Dim, t.Panel).Render(padTo2(label, 24)) + stl(t.Err, t.Panel).Render(fp)
}

// republishKeyView is the mismatch remediation confirm. It spells out the cost
// of the rotate, which is the whole reason this is not done automatically.
func (m Model) republishKeyView(t theme.Theme) []string {
	body := []string{
		stl(t.Err, t.Panel).Render("Republish this vault's public key?"),
		"",
		stl(t.Dim, t.Panel).Render("Your local key is kept — no new keypair is generated."),
		stl(t.Dim, t.Panel).Render("Only the server's copy is overwritten."),
		"",
		fingerprintLine(t, "in this vault", m.identityLocalFP),
		fingerprintLine(t, "published by the server", m.identityServerFP),
		"",
		stl(t.Dim, t.Panel).Render("Replacing a published key nulls every wrapped project"),
		stl(t.Dim, t.Panel).Render("DEK server-side: all your projects re-enter awaiting-"),
		stl(t.Dim, t.Panel).Render("access until an admin re-grants your access."),
		"",
		stl(t.Hi, t.Panel).Render("y") + stl(t.Dim, t.Panel).Render("/") + stl(t.Hi, t.Panel).Render("enter") +
			stl(t.Dim, t.Panel).Render(" republish · ") + stl(t.Hi, t.Panel).Render("esc") +
			stl(t.Dim, t.Panel).Render("/") + stl(t.Hi, t.Panel).Render("n") + stl(t.Dim, t.Panel).Render(" cancel"),
	}
	return m.modalBox(t, "republish public key", "err", body)
}

// wrapText breaks s into lines no wider than width runes, on word boundaries.
func wrapText(s string, width int) []string {
	if width < 1 {
		width = 1
	}
	var lines []string
	var cur string
	for _, word := range strings.Fields(s) {
		switch {
		case cur == "":
			cur = word
		case len([]rune(cur))+1+len([]rune(word)) <= width:
			cur += " " + word
		default:
			lines = append(lines, cur)
			cur = word
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// moveProjectView renders the move-to-project picker: the destinations a host
// can live in, with the one it is in now marked so the move is a deliberate
// change rather than a re-pick of the status quo.
func (m Model) moveProjectView(t theme.Theme) []string {
	opts := m.projectFormOptions()
	cur := clampIdx(m.mvIdx, len(opts))
	body := []string{
		stl(t.Dim, t.Panel).Render("Move ") + stl(t.Hi, t.Panel).Render(m.mvName) +
			stl(t.Dim, t.Panel).Render(" to:"),
		"",
	}
	for i, o := range opts {
		marker, fg := "  ", t.Fg
		if i == cur {
			marker, fg = "▸ ", t.Hi
		}
		label := o.ProjectName
		if o.ProjectID == "" {
			label = "personal vault"
		}
		row := stl(t.Hi, t.Panel).Render(marker) + stl(fg, t.Panel).Render(padTo2(label, 28))
		if o.ProjectID == m.mvSourceID {
			row += stl(t.Dim, t.Panel).Render("where it is now")
		} else if o.ProjectID != "" {
			row += stl(t.Dim, t.Panel).Render("shared with the project's members")
		}
		body = append(body, row)
	}
	body = append(body, "",
		stl(t.Dim, t.Panel).Render("A host in a project is readable by every member."),
		stl(t.Dim, t.Panel).Render("Saved passwords move with it; private keys never do."))
	if m.mvErr != "" {
		body = append(body, "", stl(t.Err, t.Panel).Render(" "+m.mvErr))
	}
	body = append(body, "",
		stl(t.Hi, t.Panel).Render("j/k")+stl(t.Dim, t.Panel).Render(" choose · ")+
			stl(t.Hi, t.Panel).Render("enter")+stl(t.Dim, t.Panel).Render(" move · ")+
			stl(t.Hi, t.Panel).Render("esc")+stl(t.Dim, t.Panel).Render(" cancel"))
	return m.modalBox(t, "move host", "hi", body)
}
