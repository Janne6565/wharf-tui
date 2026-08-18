package ui

import (
	"os"
	"strings"
	"time"

	"github.com/Janne6565/wharf-tui/internal/sshx"
	"github.com/Janne6565/wharf-tui/internal/store"
	"github.com/Janne6565/wharf-tui/internal/termius"
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
	case modalImportSource:
		return m.importSourceView(t)
	case modalImportSummary:
		return m.importSummaryView(t)
	case modalQuitConfirm:
		return m.quitConfirmView(t)
	case modalConnecting:
		return m.connectingView(t)
	case modalSessionHint:
		return m.sessionHintView(t)
	case modalSessionPicker:
		return m.sessionPickerView(t)
	case modalHostKey:
		return m.hostKeyView(t)
	case modalSecret:
		return m.secretView(t)
	case modalError:
		return m.errorView(t)
	case modalSyncConflict:
		return m.syncConflictView(t)
	case modalChangePassword:
		return m.changePasswordView(t)
	case modalCreateProject:
		return m.createProjectView(t)
	case modalRemoveMember:
		return m.removeMemberView(t)
	case modalInviteResponse:
		return m.inviteResponseView(t)
	case modalProjectConflict:
		return m.projectConflictView(t)
	case modalResetIdentity:
		return m.resetIdentityView(t)
	case modalRepublishKey:
		return m.republishKeyView(t)
	case modalForwardForm:
		return m.forwardFormView(t)
	case modalForwards:
		return m.forwardsView(t)
	case modalKeyUnsync:
		return m.keyUnsyncView(t)
	case modalSignOut:
		return m.signOutView(t)
	case modalMoveProject:
		return m.moveProjectView(t)
	case modalProxy:
		return m.proxyView(t)
	case modalDetachKey:
		return m.detachKeyView(t)
	case modalRemoteKey:
		return m.remoteKeyView(t)
	case modalRemoteAccess:
		return m.remoteAccessView(t)
	}
	return m.mainView(t)
}

// modalBox centers a titled panel over the full screen.
func (m Model) modalBox(t theme.Theme, title, border string, body []string) []string {
	pw := 66
	if pw > m.w-6 {
		pw = m.w - 6
	}
	box := boxPanelAuto(t, title, colorFor(t, border), pw, body)
	return centerInArea(box, m.w, m.h, t.Bg)
}

// --- host form --------------------------------------------------------------

func (m Model) hostFormView(t theme.Theme) []string {
	title := "add host"
	if m.formEditID != "" {
		title = "edit host"
	}
	labels := [fCount]string{"name", "user", "address", "port", "tags", "auth", "key path", "vault key", "password", "project"}
	hints := [fCount]string{"", "", "host or ip", "default 22", "comma-separated", "", "~/.ssh/id_…", "", "", ""}

	var body []string
	for i := 0; i < fCount; i++ {
		if !m.fieldVisible(i) {
			continue // hidden conditional field (key path / password / project)
		}
		focused := i == m.formFocus
		line := stl(t.Dim, t.Panel).Render(padTo2(labels[i], 10))
		switch i {
		case fAuth:
			line += m.authSelector(t, focused)
		case fVaultKey:
			line += m.vaultKeySelector(t, focused)
		case fProject:
			line += m.projectSelector(t, focused)
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
		body = append(body, "", stl(t.Err, t.Panel).Render(m.formErr))
	}
	body = append(body, "",
		stl(t.Hi, t.Panel).Render("tab/↑↓")+stl(t.Dim, t.Panel).Render(" move · ")+
			stl(t.Hi, t.Panel).Render("enter")+stl(t.Dim, t.Panel).Render(" save · ")+
			stl(t.Hi, t.Panel).Render("esc")+stl(t.Dim, t.Panel).Render(" cancel"))
	return m.modalBox(t, title, "hi", body)
}

// authSelector renders the two auth options inline with the active one lit.
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

// vaultKeySelector renders the bound-key selector: the key this host
// authenticates with, or "any" to keep offering the whole vault.
//
// The hint says why binding is worth doing rather than only what the control
// is: every key offered spends one of the server's few authentication tries, so
// on a vault of any size "any" is the slow option, not the neutral one.
func (m Model) vaultKeySelector(t theme.Theme, focused bool) string {
	label := m.vaultKeyLabel(m.formVals[fVaultKey])
	seg := stl(t.Hi, t.Sel).Render(" "+label+" ") + stl(t.Dim, t.Panel).Render("  ‹ › to change")
	if focused {
		seg += m.cur(t.Hi, t.Panel)
	}
	return seg
}

// projectSelector renders the destination selector: personal + writable
// projects, with the active one lit.
func (m Model) projectSelector(t theme.Theme, focused bool) string {
	cur := m.formVals[fProject]
	label := m.projectOptionLabel(cur)
	seg := stl(t.Hi, t.Sel).Render(" "+label+" ") + stl(t.Dim, t.Panel).Render("  ‹ › to change")
	if focused {
		seg += m.cur(t.Hi, t.Panel)
	}
	return seg
}

// passwordField renders the masked host-form password (bullets, like the unlock
// screen). It is only rendered in password mode (the key-mode field is hidden).
//
// The empty-field placeholder says what leaving it empty *does*, not merely
// that it is allowed: "(optional)" reads as a contradiction next to an auth
// mode called "password", when the truth is that the password is always
// required — the choice is only whether to store it now or be asked at connect.
func (m Model) passwordField(t theme.Theme, focused bool) string {
	var seg string
	switch {
	case m.formVals[fPassword] != "":
		seg = stl(t.Hi, t.Panel).Render(strings.Repeat("•", len([]rune(m.formVals[fPassword]))))
	case !focused:
		seg = stl(t.Dim, t.Panel).Render("asked at connect · ctrl+r there saves it")
	}
	if focused {
		seg += m.cur(t.Hi, t.Panel)
	}
	return seg
}

// authDetail describes a host's effective auth method for the detail pane.
// Only two modes exist; a legacy "" / "auto" host reads as key.
func authDetail(h store.Host) string {
	if h.AuthMethod == sshx.AuthPassword {
		if h.Password != "" {
			return "password (saved)"
		}
		return "password"
	}
	if h.KeyPath != "" {
		return "key " + h.KeyPath
	}
	return "key (agent)"
}

// hostAuthDetail is authDetail plus the bound vault key, which only the model
// can resolve to a name. A bound host says so: it is the difference between one
// key offered and the whole vault walked.
func (m Model) hostAuthDetail(h store.Host) string {
	base := authDetail(h)
	if h.AuthMethod == sshx.AuthPassword || h.KeyID == "" || m.st == nil {
		return base
	}
	if k, ok := m.st.KeyByID(h.KeyID); ok {
		if h.KeyPath == "" {
			return "key " + k.Name + " (vault)"
		}
		return base + " + " + k.Name + " (vault)"
	}
	return base
}

// --- change master password -------------------------------------------------

func (m Model) changePasswordView(t theme.Theme) []string {
	labels := [cpFields]string{"current", "new", "confirm"}
	var body []string
	for i := 0; i < cpFields; i++ {
		focused := i == m.cpFocus
		masked := strings.Repeat("•", len([]rune(m.cpVals[i])))
		line := stl(t.Dim, t.Panel).Render(padTo2(labels[i], 10)) + stl(t.Hi, t.Panel).Render(masked)
		if focused && !m.cpBusy {
			line += m.cur(t.Hi, t.Panel)
		}
		body = append(body, line)
	}
	if m.cpErr != "" {
		body = append(body, "", stl(t.Err, t.Panel).Render(m.cpErr))
	}
	body = append(body, "")
	if m.signedIn {
		body = append(body, stl(t.Dim, t.Panel).Render("Re-encrypts the vault and rotates the online key."))
	} else {
		body = append(body, stl(t.Dim, t.Panel).Render("Re-encrypts the local vault. Recovery code is unchanged."))
	}
	body = append(body, "")
	if m.cpBusy {
		body = append(body, stl(t.Warn, t.Panel).Render(m.spinner()+" changing password …"))
	} else {
		body = append(body,
			stl(t.Hi, t.Panel).Render("tab/↑↓")+stl(t.Dim, t.Panel).Render(" move · ")+
				stl(t.Hi, t.Panel).Render("enter")+stl(t.Dim, t.Panel).Render(" change · ")+
				stl(t.Hi, t.Panel).Render("esc")+stl(t.Dim, t.Panel).Render(" cancel"))
	}
	return m.modalBox(t, "change master password", "hi", body)
}

// --- delete confirm ---------------------------------------------------------

func (m Model) deleteConfirmView(t theme.Theme) []string {
	body := []string{
		stl(t.Fg, t.Panel).Render("Delete host ") + stl(t.Hi, t.Panel).Render(m.delName) + stl(t.Fg, t.Panel).Render(" ?"),
		"",
		stl(t.Dim, t.Panel).Render("This removes it from the vault permanently."),
		"",
		stl(t.Hi, t.Panel).Render("y") + stl(t.Dim, t.Panel).Render("/") + stl(t.Hi, t.Panel).Render("enter") +
			stl(t.Dim, t.Panel).Render(" delete · ") + stl(t.Hi, t.Panel).Render("esc") +
			stl(t.Dim, t.Panel).Render("/") + stl(t.Hi, t.Panel).Render("n") + stl(t.Dim, t.Panel).Render(" cancel"),
	}
	return m.modalBox(t, "delete host", "err", body)
}

// --- unsync key from vault --------------------------------------------------

func (m Model) keyUnsyncView(t theme.Theme) []string {
	body := []string{
		stl(t.Fg, t.Panel).Render("Remove key ") + stl(t.Hi, t.Panel).Render(m.unsyncKeyName) + stl(t.Fg, t.Panel).Render(" from the vault?"),
		"",
		stl(t.Dim, t.Panel).Render("The local key file is left untouched."),
		"",
		stl(t.Hi, t.Panel).Render("y") + stl(t.Dim, t.Panel).Render("/") + stl(t.Hi, t.Panel).Render("enter") +
			stl(t.Dim, t.Panel).Render(" remove · ") + stl(t.Hi, t.Panel).Render("esc") +
			stl(t.Dim, t.Panel).Render("/") + stl(t.Hi, t.Panel).Render("n") + stl(t.Dim, t.Panel).Render(" cancel"),
	}
	return m.modalBox(t, "remove from vault", "warn", body)
}

// --- sign out ---------------------------------------------------------------

// signOutView spells out what signing out does and does not touch: the whole
// point of the confirmation is that "sign out" reads like it might take the
// vault with it, and that getting back in is a browser round-trip.
func (m Model) signOutView(t theme.Theme) []string {
	who := m.email
	if who == "" {
		who = "this device"
	}
	body := []string{
		stl(t.Fg, t.Panel).Render("Stop syncing ") + stl(t.Hi, t.Panel).Render(who) + stl(t.Fg, t.Panel).Render("?"),
		"",
		stl(t.Ok, t.Panel).Render("·") + stl(t.Dim, t.Panel).Render(" your local vault, hosts and keys stay on this machine"),
		stl(t.Warn, t.Panel).Render("·") + stl(t.Dim, t.Panel).Render(" shared projects become unavailable until you sign in again"),
		stl(t.Warn, t.Panel).Render("·") + stl(t.Dim, t.Panel).Render(" signing back in needs a fresh browser pairing code"),
		"",
		stl(t.Hi, t.Panel).Render("y") + stl(t.Dim, t.Panel).Render("/") + stl(t.Hi, t.Panel).Render("enter") +
			stl(t.Dim, t.Panel).Render(" sign out · ") + stl(t.Hi, t.Panel).Render("esc") +
			stl(t.Dim, t.Panel).Render("/") + stl(t.Hi, t.Panel).Render("n") + stl(t.Dim, t.Panel).Render(" cancel"),
	}
	return m.modalBox(t, "sign out", "warn", body)
}

// --- connecting -------------------------------------------------------------

// sessionHintView is the first-connect primer: the session is up, and these are
// the keys that get you out of it and back into it.
func (m Model) sessionHintView(t theme.Theme) []string {
	key := func(k, rest string) string {
		return stl(t.Hi, t.Panel).Render(k) + stl(t.Dim, t.Panel).Render(rest)
	}
	body := []string{
		stl(t.Ok, t.Panel).Render("● connected to " + m.hostName(m.pendingAttachID)),
		"",
		stl(t.Fg, t.Panel).Render("Wharf hands your terminal to the session. To get back:"),
		"",
		key(m.detachName, strings.Repeat(" ", maxInt(1, 9-len(m.detachName)))+"detach — the session keeps running"),
		// The remote-access key earns a line in the primer for the same reason
		// the detach key does: it is only pressable from inside the session, so
		// the dashboard is the last place it can be advertised before the
		// terminal is handed over.
		key(m.remoteName, strings.Repeat(" ", maxInt(1, 9-len(m.remoteName)))+"grant/revoke remote access, without detaching"),
		key("S", "        list live sessions: reattach, kill, open another"),
		key("enter", "    reattach from a host row marked live"),
		key("alt+1..9", " reattach by number (needs Option-as-Meta)"),
		"",
		stl(t.Ok, t.Panel).Render(attachSurvivalNotice),
		"",
		key("enter", " attach now · ") + key("esc", " stay on the dashboard"),
	}
	return m.modalBox(t, "session", "ok", body)
}

func (m Model) connectingView(t theme.Theme) []string {
	name := m.hostName(m.dialHostID)
	verb, title := "connecting to ", "connecting"
	if m.fwdInFlight {
		// The forward's host may be a project host hostName can't resolve; the
		// form stashed the full host, so use its name directly.
		name = m.fwdHost.Name
		verb, title = "starting forward to ", "starting forward"
	}
	body := []string{
		stl(t.Warn, t.Panel).Render(m.spinner() + " " + verb + name + " …"),
		"",
		stl(t.Hi, t.Panel).Render("esc") + stl(t.Dim, t.Panel).Render(" cancel"),
	}
	return m.modalBox(t, title, "hi", body)
}

// --- host-key TOFU ----------------------------------------------------------

func (m Model) hostKeyView(t theme.Theme) []string {
	p := m.pendingHostKey
	if p == nil {
		return m.mainView(t)
	}
	rw := panelInner(m.w)
	body := []string{
		stl(t.Warn, t.Panel).Render("The authenticity of this host can't be established."),
		"",
		kv(t, "host", p.Host, t.Fg, rw),
		kv(t, "key type", p.KeyType, t.Fg, rw),
		kv(t, "fingerprint", p.Fingerprint, t.Hi, rw),
		"",
		stl(t.Dim, t.Panel).Render("Trusting appends the key to ~/.ssh/known_hosts."),
		"",
		stl(t.Hi, t.Panel).Render("y") + stl(t.Dim, t.Panel).Render("/") + stl(t.Hi, t.Panel).Render("enter") +
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
		stl(t.Fg, t.Panel).Render(p.Title),
	}
	if p.Detail != "" {
		body = append(body, stl(t.Dim, t.Panel).Render(p.Detail))
	}
	body = append(body,
		"",
		stl(t.Hi, t.Panel).Render(shown)+m.cur(t.Hi, t.Panel))
	// Offer to persist the secret only for interactive password prompts.
	if p.Title == "password" {
		mark := "[ ]"
		if m.secretRemember {
			mark = "[x]"
		}
		body = append(body, "",
			stl(t.Hi, t.Panel).Render(mark+" remember password")+stl(t.Dim, t.Panel).Render("  ctrl+r"))
	}
	body = append(body,
		"",
		stl(t.Hi, t.Panel).Render("enter")+stl(t.Dim, t.Panel).Render(" submit · ")+
			stl(t.Hi, t.Panel).Render("esc")+stl(t.Dim, t.Panel).Render(" cancel"))
	return m.modalBox(t, "authentication", "hi", body)
}

// --- import summary ---------------------------------------------------------

// importSourceView is the "import from where?" chooser.
func (m Model) importSourceView(t theme.Theme) []string {
	opt := func(key, label, detail string) string {
		return stl(t.Hi, t.Panel).Render(key) + stl(t.Fg, t.Panel).Render("  "+label) +
			stl(t.Dim, t.Panel).Render("  "+detail)
	}
	body := []string{
		opt("s", "ssh config", "~/.ssh/config, including Include"),
		opt("t", "Termius", "local profile, read-only"),
		"",
		stl(t.Dim, t.Panel).Render("Termius needs no export and no Pro plan, but its"),
		stl(t.Dim, t.Panel).Render("credential store will ask for authorization."),
		"",
		stl(t.Hi, t.Panel).Render("esc") + stl(t.Dim, t.Panel).Render(" cancel"),
	}
	return m.modalBox(t, "import hosts", "hi", body)
}

func (m Model) importSummaryView(t theme.Theme) []string {
	from := "~/.ssh/config"
	if m.importSource == termius.Source {
		from = "the Termius profile"
	}
	body := []string{
		stl(t.Fg, t.Panel).Render(itoa(len(m.importHosts)) + " host(s) found in " + from),
	}
	if m.importNote != "" {
		// Passwords ride along from Termius and land in the encrypted vault;
		// say so rather than importing credentials silently.
		body = append(body, stl(t.Dim, t.Panel).Render(m.importNote))
	}
	if len(m.importSkipped) > 0 {
		what := "wildcard pattern(s) skipped"
		if m.importSource == termius.Source {
			what = "host(s) skipped"
		}
		body = append(body, stl(t.Dim, t.Panel).Render(itoa(len(m.importSkipped))+" "+what))
	}
	body = append(body,
		"",
		stl(t.Dim, t.Panel).Render("Apply? Existing manual hosts are never overwritten."),
		"",
		stl(t.Hi, t.Panel).Render("y")+stl(t.Dim, t.Panel).Render("/")+stl(t.Hi, t.Panel).Render("enter")+
			stl(t.Dim, t.Panel).Render(" apply · ")+stl(t.Hi, t.Panel).Render("esc")+
			stl(t.Dim, t.Panel).Render("/")+stl(t.Hi, t.Panel).Render("n")+stl(t.Dim, t.Panel).Render(" cancel"))
	title := "import ssh config"
	if m.importSource == termius.Source {
		title = "import from termius"
	}
	return m.modalBox(t, title, "hi", body)
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
		line := stl(t.Dim, t.Panel).Render(padTo2(labels[i], 12)) + stl(t.Hi, t.Panel).Render(val)
		if i == 2 && m.kgVals[i] == "" && !focused {
			// Blank is not "skipped" — it writes an unencrypted private key.
			line = stl(t.Dim, t.Panel).Render(padTo2(labels[i], 12)) +
				stl(t.Dim, t.Panel).Render("empty = key stored unencrypted")
		}
		if focused {
			line += m.cur(t.Hi, t.Panel)
		}
		body = append(body, line)
	}
	// 4th focusable element: the "also sync to vault" toggle.
	mark := "[ ]"
	if m.kgSync {
		mark = "[x]"
	}
	labelC := t.Dim
	if m.kgFocus == kgSyncField {
		labelC = t.Hi
	}
	body = append(body, stl(labelC, t.Panel).Render(padTo2("sync", 12))+
		stl(t.Hi, t.Panel).Render(mark+" sync to vault"))
	if m.kgErr != "" {
		body = append(body, "", stl(t.Err, t.Panel).Render(m.kgErr))
	}
	body = append(body, "",
		stl(t.Dim, t.Panel).Render("Writes to ~/.ssh (0600). Never overwrites."),
		"",
		stl(t.Hi, t.Panel).Render("tab")+stl(t.Dim, t.Panel).Render(" move · ")+
			stl(t.Hi, t.Panel).Render("enter")+stl(t.Dim, t.Panel).Render(" generate · ")+
			stl(t.Hi, t.Panel).Render("esc")+stl(t.Dim, t.Panel).Render(" cancel"))
	return m.modalBox(t, "generate ed25519 key", "hi", body)
}

// --- quit confirm -----------------------------------------------------------

func (m Model) quitConfirmView(t theme.Theme) []string {
	ns, nf := m.liveSessions(), m.liveForwards()
	var body []string
	// Sessions and forwards part ways on quit where sessions outlive wharf:
	// they live in their own child processes and keep running, while forwards
	// are process-bound and close. On Windows both go — hence the tone shift.
	if ns > 0 {
		tone := t.Ok
		if !sessionsSurviveQuit {
			tone = t.Warn
		}
		body = append(body, stl(tone, t.Panel).Render(quitSessionNotice(ns)))
	}
	if nf > 0 {
		body = append(body, stl(t.Warn, t.Panel).Render(itoa(nf)+" active forward(s) will be closed."))
	}
	if g := m.raGrant(); g != nil {
		body = append(body, stl(t.Warn, t.Panel).Render(
			"remote access on "+g.HostName()+" will be revoked."))
	}
	if len(body) == 0 {
		body = append(body, stl(t.Dim, t.Panel).Render("Nothing is running."))
	}
	body = append(body, "")
	body = append(body,
		stl(t.Hi, t.Panel).Render("y")+stl(t.Dim, t.Panel).Render("/")+stl(t.Hi, t.Panel).Render("enter")+
			stl(t.Dim, t.Panel).Render(" quit · ")+stl(t.Hi, t.Panel).Render("esc")+
			stl(t.Dim, t.Panel).Render("/")+stl(t.Hi, t.Panel).Render("n")+stl(t.Dim, t.Panel).Render(" cancel"))
	return m.modalBox(t, "quit wharf", "err", body)
}

// --- sync conflict ------------------------------------------------------------

// syncConflictView asks the user to pick a side when the local vault and the
// remote vault both changed since the last sync. There is no silent merge.
func (m Model) syncConflictView(t theme.Theme) []string {
	c := m.conflict
	if c == nil {
		return m.mainView(t)
	}
	localMeta := "this machine"
	if ts := humanizeAgo(m.localVaultModTime()); ts != "" {
		localMeta += " · " + ts
	}
	remoteMeta := "account · v" + itoa(int(c.RemoteVersion))
	if ts := humanizeAgo(c.RemoteUpdatedAt); ts != "" {
		remoteMeta += " · " + ts
	}
	body := []string{
		stl(t.Warn, t.Panel).Render("This vault and the account vault both changed."),
		stl(t.Dim, t.Panel).Render("Pick which one to keep — the other side is overwritten."),
		"",
		stl(t.Fg, t.Panel).Render("local   ") + stl(t.Hi, t.Panel).Render(itoa(c.LocalHosts)+" host(s)") +
			stl(t.Dim, t.Panel).Render("  "+localMeta),
		stl(t.Fg, t.Panel).Render("remote  ") + stl(t.Hi, t.Panel).Render(itoa(c.RemoteHosts)+" host(s)") +
			stl(t.Dim, t.Panel).Render("  "+remoteMeta),
		"",
		stl(t.Hi, t.Panel).Render("l") + stl(t.Dim, t.Panel).Render("  keep local — overwrite the account vault"),
		stl(t.Hi, t.Panel).Render("r") + stl(t.Dim, t.Panel).Render("  take remote — discard this machine's changes"),
		stl(t.Hi, t.Panel).Render("esc") + stl(t.Dim, t.Panel).Render("  decide later (sync pauses)"),
	}
	return m.modalBox(t, "sync conflict", "warn", body)
}

// localVaultModTime is the vault file's last-modified time — a stand-in for
// "when this machine last changed the vault". Zero if it can't be stat'd (e.g.
// a fake vault in tests).
func (m Model) localVaultModTime() time.Time {
	fi, err := os.Stat(m.vaultPath)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

// humanizeAgo renders a coarse "time ago" label, or "" for the zero time (which
// means the timestamp is unknown, so it's simply omitted).
func humanizeAgo(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	d := time.Since(ts)
	switch {
	case d < 45*time.Second:
		return "just now"
	case d < 90*time.Second:
		return "1 min ago"
	case d < time.Hour:
		return itoa(int(d/time.Minute)) + " min ago"
	case d < 2*time.Hour:
		return "1 hour ago"
	case d < 24*time.Hour:
		return itoa(int(d/time.Hour)) + " hours ago"
	case d < 48*time.Hour:
		return "yesterday"
	default:
		return itoa(int(d/(24*time.Hour))) + " days ago"
	}
}

// --- prominent error --------------------------------------------------------

func (m Model) errorView(t theme.Theme) []string {
	var body []string
	for _, ln := range strings.Split(m.errBody, "\n") {
		body = append(body, stl(t.Err, t.Panel).Render(ln))
	}
	body = append(body, "",
		stl(t.Hi, t.Panel).Render("enter")+stl(t.Dim, t.Panel).Render(" dismiss"))
	return m.modalBox(t, m.errTitle, "err", body)
}
