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
		lRows = append(lRows, realProjRow(t, p, idx == pIdx, lInner))
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
	if m.identityNotice != "" {
		rBody = append(rBody, "", stl(t.Warn, t.Panel).Render(m.identityNotice))
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
		kv(t, "hosts", itoa(p.HostCount), t.Dim, rw),
		"",
		stl(t.Dim, t.Panel).Render("members"))

	memberFocus := m.focus == 1
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
				stl(nameFg, t.Panel).Render(padTo2(label, 22))+stl(t.Dim, t.Panel).Render(strings.ToLower(mem.Role)))
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
				body = append(body, stl(emailFg, t.Panel).Render(marker+padTo2(inv.Email, 22))+
					stl(t.Dim, t.Panel).Render("invited · awaiting accept"))
			}
		}
	} else {
		body = append(body, stl(t.Dim, t.Panel).Render("  loading members…"))
	}

	body = append(body, "")
	hints := stl(t.Hi, t.Panel).Render("enter") + stl(t.Dim, t.Panel).Render(" filter hosts")
	if isAdmin(p.Role) {
		hints += stl(t.Dim, t.Panel).Render(" · ") + stl(t.Hi, t.Panel).Render("i") +
			stl(t.Dim, t.Panel).Render(" invite · ") + stl(t.Hi, t.Panel).Render("tab") +
			stl(t.Dim, t.Panel).Render(" members · ") + stl(t.Hi, t.Panel).Render("d/x") +
			stl(t.Dim, t.Panel).Render(" remove/revoke")
	}
	body = append(body, hints)
	return body
}

// realProjRow renders a project list row: name + "N hosts · N members".
func realProjRow(t theme.Theme, p projectItem, sel bool, innerW int) string {
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
		meta = itoa(p.HostCount) + " hosts · " + itoa(p.MemberCount) + " members"
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
	if m.identityNotice != "" {
		body = append(body, "", stl(t.Warn, t.Panel).Render(m.identityNotice))
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
