package ui

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Janne6565/wharf-tui/internal/sshx"
	"github.com/Janne6565/wharf-tui/internal/store"
	tea "github.com/charmbracelet/bubbletea"
)

// authMethods is the toggle order for the host-form auth selector: key first
// (the default), then password.
var authMethods = []string{sshx.AuthKey, sshx.AuthPassword}

// authLabel is the human-readable name for an auth method value. Anything that
// is not password renders as key (legacy "" / "auto" included).
func authLabel(method string) string {
	if method == sshx.AuthPassword {
		return "password"
	}
	return "key"
}

// cycleAuth advances the auth selector by dir (+1 / -1), wrapping around.
func cycleAuth(cur string, dir int) string {
	idx := 0
	for i, a := range authMethods {
		if a == cur {
			idx = i
			break
		}
	}
	idx = (idx + dir + len(authMethods)) % len(authMethods)
	return authMethods[idx]
}

// fieldVisible reports whether host-form field i is currently shown. The two
// conditional fields (key path, password) toggle on the selected auth mode; the
// hidden one is skipped by navigation and never rendered.
func (m Model) fieldVisible(i int) bool {
	switch i {
	case fKey:
		return m.formVals[fAuth] != sshx.AuthPassword
	case fPassword:
		return m.formVals[fAuth] == sshx.AuthPassword
	case fProject:
		// The project selector only appears when the account can write to at
		// least one project; hidden (and skipped) in demo/signed-out mode so the
		// existing host form is unchanged.
		return m.realMode() && len(m.writableProjects()) > 0
	default:
		return true
	}
}

// nextField advances the host-form focus by dir (+1 / -1), skipping the hidden
// conditional field. fAuth is always visible, so this always terminates.
func (m Model) nextField(dir int) int {
	f := m.formFocus
	for {
		f = (f + dir + fCount) % fCount
		if m.fieldVisible(f) {
			return f
		}
	}
}

// modalKey routes a keypress to the active real-mode modal.
func (m Model) modalKey(k tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	switch m.modal {
	case modalHostForm:
		return m.hostFormKey(key)
	case modalDeleteConfirm:
		return m.deleteConfirmKey(key)
	case modalKeygen:
		return m.keygenKey(key)
	case modalImportSummary:
		return m.importSummaryKey(key)
	case modalQuitConfirm:
		return m.quitConfirmKey(key)
	case modalConnecting:
		return m.connectingKey(key)
	case modalHostKey:
		return m.hostKeyModalKey(key)
	case modalSecret:
		return m.secretModalKey(key)
	case modalError:
		return m.errorModalKey(key)
	case modalSyncConflict:
		return m.syncConflictKey(key)
	case modalChangePassword:
		return m.changePasswordKey(key)
	case modalCreateProject:
		return m.createProjectKey(key)
	case modalRemoveMember:
		return m.removeMemberConfirmKey(key)
	case modalInviteResponse:
		return m.inviteResponseKey(key)
	case modalProjectConflict:
		return m.projectConflictKey(key)
	}
	return m, nil
}

// --- host form --------------------------------------------------------------

// openHostForm prepares the add/edit modal. An empty id starts an add.
func (m Model) openHostForm(id string) Model {
	m.modal = modalHostForm
	m.formEditID = id
	m.formEditProjID = ""
	m.formFocus = 0
	m.formErr = ""
	m.formVals = [fCount]string{}
	m.formVals[fAuth] = sshx.AuthKey // default mode; editSelectedHost overrides
	if id == "" {
		m.formVals[fPort] = "22"
	}
	return m
}

func (m Model) editSelectedHost() (tea.Model, tea.Cmd) {
	mh, ok := m.selectedMergedHost()
	if !ok {
		return m, nil
	}
	h := mh.Host
	m = m.openHostForm(h.ID)
	m.formEditProjID = mh.ProjectID
	m.formVals[fProject] = mh.ProjectID
	m.formVals[fName] = h.Name
	m.formVals[fUser] = h.User
	m.formVals[fAddr] = h.Addr
	m.formVals[fPort] = strconv.Itoa(h.Port)
	m.formVals[fTags] = strings.Join(h.Tags, ", ")
	m.formVals[fKey] = h.KeyPath
	// Only two modes exist; a legacy "" / "auto" host edits as key.
	if h.AuthMethod == sshx.AuthPassword {
		m.formVals[fAuth] = sshx.AuthPassword
	} else {
		m.formVals[fAuth] = sshx.AuthKey
	}
	// Pre-fill the real password into the buffer; the view only ever renders it
	// as bullets, so the plaintext is never shown.
	m.formVals[fPassword] = h.Password
	return m, nil
}

func (m Model) hostFormKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.modal = modalNone
		return m, nil
	case "tab", "down":
		m.formFocus = m.nextField(+1)
		return m, nil
	case "shift+tab", "up":
		m.formFocus = m.nextField(-1)
		return m, nil
	case "enter":
		return m.submitHostForm()
	}
	// The auth field is a selector, not a text input: arrows/space cycle it and
	// every other key is inert.
	if m.formFocus == fAuth {
		switch key {
		case "left":
			m.formVals[fAuth] = cycleAuth(m.formVals[fAuth], -1)
		case "right", " ":
			m.formVals[fAuth] = cycleAuth(m.formVals[fAuth], +1)
		}
		return m, nil
	}
	// The project field is likewise a selector over personal + writable projects.
	if m.formFocus == fProject {
		switch key {
		case "left":
			m.formVals[fProject] = m.cycleProject(m.formVals[fProject], -1)
		case "right", " ":
			m.formVals[fProject] = m.cycleProject(m.formVals[fProject], +1)
		}
		return m, nil
	}
	switch key {
	case "backspace":
		if v := m.formVals[m.formFocus]; len(v) > 0 {
			m.formVals[m.formFocus] = v[:len(v)-1]
		}
	default:
		if isPrintable(key) {
			m.formVals[m.formFocus] += key
		}
	}
	return m, nil
}

func (m Model) submitHostForm() (tea.Model, tea.Cmd) {
	portStr := strings.TrimSpace(m.formVals[fPort])
	port := 22
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil {
			m.formErr = "port must be a number"
			return m, nil
		}
		port = p
	}
	h := store.Host{
		Name:    strings.TrimSpace(m.formVals[fName]),
		User:    strings.TrimSpace(m.formVals[fUser]),
		Addr:    strings.TrimSpace(m.formVals[fAddr]),
		Port:    port,
		Tags:    parseTags(m.formVals[fTags]),
		KeyPath: strings.TrimSpace(m.formVals[fKey]),
		// Always "key" or "password" now. Both KeyPath and Password are persisted
		// as typed even though only one is relevant to the selected mode: the
		// engine ignores the irrelevant one, so keeping both is lossless if the
		// user toggles the selector by accident and saves.
		AuthMethod: m.formVals[fAuth],
		Password:   m.formVals[fPassword],
	}

	target := m.formVals[fProject] // "" = personal
	if !m.fieldVisible(fProject) {
		target = m.formEditProjID // selector hidden → keep the source location
	}

	// --- add ---
	if m.formEditID == "" {
		if target == "" {
			stored, err := m.st.AddHost(h)
			if err != nil {
				m.formErr = cleanErr(err)
				return m, nil
			}
			m.modal = modalNone
			m, syncCmd := m.saveVault()
			return m.setToast("added "+stored.Name, "ok"), tea.Batch(m.probeCmds(), syncCmd)
		}
		mm, pushCmd, stored, err := m.addHostToProject(target, h)
		if err != nil {
			m.formErr = cleanErr(err)
			return m, nil
		}
		mm.modal = modalNone
		return mm.setToast("added "+stored.Name+" to "+mm.projectOptionLabel(target), "ok"), tea.Batch(mm.probeCmds(), pushCmd)
	}

	// --- update ---
	h.ID = m.formEditID
	h.Source = "manual"
	source := m.formEditProjID
	if source == "" {
		if ex, ok := m.st.HostByID(m.formEditID); ok {
			h.Source = ex.Source
			h.LastSeen = ex.LastSeen
		}
	}

	if source == target {
		return m.updateHostInPlace(target, h)
	}
	return m.moveHostBetween(source, target, h)
}

// updateHostInPlace updates a host within its current doc (personal or project).
func (m Model) updateHostInPlace(target string, h store.Host) (tea.Model, tea.Cmd) {
	if target == "" {
		if err := m.st.UpdateHost(h); err != nil {
			m.formErr = cleanErr(err)
			return m, nil
		}
		m.modal = modalNone
		m, syncCmd := m.saveVault()
		return m.setToast("updated "+h.Name, "ok"), tea.Batch(m.probeCmds(), syncCmd)
	}
	doc := m.projectDocs[target]
	if doc == nil {
		m.formErr = errNoProjectDoc.Error()
		return m, nil
	}
	if err := doc.UpdateHost(h); err != nil {
		m.formErr = cleanErr(err)
		return m, nil
	}
	m.modal = modalNone
	mm, pushCmd := m.scheduleProjectPush(target)
	return mm.setToast("updated "+h.Name, "ok"), tea.Batch(mm.probeCmds(), pushCmd)
}

// moveHostBetween moves a host between docs (personal ↔ project) by removing it
// from the source and adding it to the target, each side persisted via its own
// path.
func (m Model) moveHostBetween(source, target string, h store.Host) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	// Remove from the source.
	if source == "" {
		if err := m.st.DeleteHost(h.ID); err != nil {
			m.formErr = cleanErr(err)
			return m, nil
		}
		mm, c := m.saveVault()
		m = mm
		cmds = append(cmds, c)
	} else {
		mm, c, err := m.deleteHostFromProject(source, h.ID)
		if err != nil {
			m.formErr = cleanErr(err)
			return m, nil
		}
		m = mm
		cmds = append(cmds, c)
	}
	// Add to the target (drop the ID so the destination assigns a fresh one).
	h.ID = ""
	h.LastSeen = time.Time{}
	if target == "" {
		if _, err := m.st.AddHost(h); err != nil {
			m.formErr = cleanErr(err)
			return m, nil
		}
		mm, c := m.saveVault()
		m = mm
		cmds = append(cmds, c)
	} else {
		mm, c, _, err := m.addHostToProject(target, h)
		if err != nil {
			m.formErr = cleanErr(err)
			return m, nil
		}
		m = mm
		cmds = append(cmds, c)
	}
	m.modal = modalNone
	cmds = append(cmds, m.probeCmds())
	return m.setToast("moved "+h.Name+" to "+m.projectOptionLabel(target), "ok"), tea.Batch(cmds...)
}

// --- delete confirm ---------------------------------------------------------

func (m Model) deleteSelectedHost() (tea.Model, tea.Cmd) {
	mh, ok := m.selectedMergedHost()
	if !ok {
		return m, nil
	}
	m.delID = mh.Host.ID
	m.delName = mh.Host.Name
	m.delProjID = mh.ProjectID
	m.modal = modalDeleteConfirm
	return m, nil
}

func (m Model) deleteConfirmKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "y", "Y", "enter":
		if m.delProjID != "" {
			mm, pushCmd, err := m.deleteHostFromProject(m.delProjID, m.delID)
			if err != nil {
				m.modal = modalNone
				return m.setToast("delete failed: "+cleanErr(err), "err"), nil
			}
			delete(mm.probes, m.delID)
			mm.modal = modalNone
			mm.hostIdx = clampIdx(mm.hostIdx, len(mm.filteredMergedHosts()))
			return mm.setToast("deleted "+m.delName, "ok"), pushCmd
		}
		if err := m.st.DeleteHost(m.delID); err != nil {
			m.modal = modalNone
			return m.setToast("delete failed: "+cleanErr(err), "err"), nil
		}
		delete(m.probes, m.delID)
		m.modal = modalNone
		m.hostIdx = clampIdx(m.hostIdx, len(m.filteredMergedHosts()))
		m, syncCmd := m.saveVault()
		return m.setToast("deleted "+m.delName, "ok"), syncCmd
	case "n", "N", "esc":
		m.modal = modalNone
	}
	return m, nil
}

// --- keygen -----------------------------------------------------------------

func (m Model) openKeygenForm() Model {
	m.modal = modalKeygen
	m.kgFocus = 0
	m.kgErr = ""
	m.kgVals = [3]string{"id_ed25519_wharf", defaultKeyComment(), ""}
	return m
}

func (m Model) keygenKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.modal = modalNone
		return m, nil
	case "tab", "down":
		m.kgFocus = (m.kgFocus + 1) % 3
		return m, nil
	case "shift+tab", "up":
		m.kgFocus = (m.kgFocus + 2) % 3
		return m, nil
	case "enter":
		if strings.TrimSpace(m.kgVals[0]) == "" {
			m.kgErr = "name is required"
			return m, nil
		}
		m.kgErr = ""
		return m, m.generateKeyCmd(strings.TrimSpace(m.kgVals[0]), m.kgVals[1], m.kgVals[2])
	case "backspace":
		if v := m.kgVals[m.kgFocus]; len(v) > 0 {
			m.kgVals[m.kgFocus] = v[:len(v)-1]
		}
		return m, nil
	default:
		if isPrintable(key) {
			m.kgVals[m.kgFocus] += key
		}
		return m, nil
	}
}

func (m Model) handleKeyGenerated(msg keyGeneratedMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		m.kgErr = cleanErr(msg.err)
		m.modal = modalKeygen
		return m, nil
	}
	m.modal = modalNone
	return m.setToast("generated "+msg.info.Name, "ok"), m.scanKeysCmd()
}

// --- ssh_config import ------------------------------------------------------

func (m Model) handleImportDone(msg importDoneMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		if errors.Is(msg.err, os.ErrNotExist) {
			return m.setToast("no ~/.ssh/config found", "err"), nil
		}
		return m.setToast("import failed: "+msg.err.Error(), "err"), nil
	}
	m.importHosts = msg.hosts
	m.importSkipped = msg.skipped
	m.modal = modalImportSummary
	return m, nil
}

func (m Model) importSummaryKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "y", "Y", "enter":
		added, updated, skipped := m.st.UpsertImported(m.importHosts)
		m.modal = modalNone
		m, syncCmd := m.saveVault()
		summary := itoa(added) + " added · " + itoa(updated) + " updated · " + itoa(skipped) + " skipped"
		return m.setToast(summary, "ok"), tea.Batch(m.probeCmds(), syncCmd)
	case "n", "N", "esc":
		m.modal = modalNone
	}
	return m, nil
}

// --- quit -------------------------------------------------------------------

// requestQuit is triggered by ctrl+q. Demo quits directly; real mode confirms
// when live sessions would be closed.
func (m Model) requestQuit() (tea.Model, tea.Cmd) {
	if m.demo {
		return m, tea.Quit
	}
	if m.mgr != nil && len(m.mgr.List()) > 0 {
		m.modal = modalQuitConfirm
		return m, nil
	}
	return m.doQuit()
}

func (m Model) doQuit() (tea.Model, tea.Cmd) {
	if m.mgr != nil {
		m.mgr.CloseAll()
	}
	if m.st != nil {
		_ = m.st.Save()
	}
	if m.vault != nil {
		_ = m.vault.Close()
	}
	m = m.closeSync()
	return m, tea.Quit
}

func (m Model) quitConfirmKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "y", "Y", "enter":
		return m.doQuit()
	case "n", "N", "esc":
		m.modal = modalNone
	}
	return m, nil
}

// --- helpers ----------------------------------------------------------------

func parseTags(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// cleanErr strips the package prefix ("store: ", "keys: ") from an error for
// inline display.
func cleanErr(err error) string {
	s := err.Error()
	if i := strings.Index(s, ": "); i >= 0 && i < 8 {
		return s[i+2:]
	}
	return s
}

func defaultKeyComment() string {
	u := os.Getenv("USER")
	if u == "" {
		u = "wharf"
	}
	h, _ := os.Hostname()
	if h == "" {
		h = "local"
	}
	return u + "@" + h
}
