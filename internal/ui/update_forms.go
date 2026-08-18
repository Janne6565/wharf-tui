package ui

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Janne6565/wharf-tui/internal/sshx"
	"github.com/Janne6565/wharf-tui/internal/store"
	"github.com/Janne6565/wharf-tui/internal/termius"
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

// vaultKeyOptions is the bound-key selector's option list: "" (any key) first,
// then every synced vault key by ID, in the store's name-sorted order. It is
// always at least one entry long, so a vault with no keys renders no selector.
func (m Model) vaultKeyOptions() []string {
	opts := []string{""}
	if m.st == nil {
		return opts
	}
	for _, k := range m.st.Keys() {
		opts = append(opts, k.ID)
	}
	return opts
}

// vaultKeyLabel names a bound-key option for the form and the detail pane. A
// binding whose key is gone reads as unbound, which is how the engine treats it.
func (m Model) vaultKeyLabel(id string) string {
	if id == "" {
		return "any (all vault keys)"
	}
	if m.st != nil {
		if k, ok := m.st.KeyByID(id); ok {
			return k.Name
		}
	}
	return "any (all vault keys)"
}

// cycleVaultKey advances the bound-key selector by dir (+1 / -1), wrapping.
func (m Model) cycleVaultKey(cur string, dir int) string {
	opts := m.vaultKeyOptions()
	idx := 0
	for i, o := range opts {
		if o == cur {
			idx = i
			break
		}
	}
	return opts[(idx+dir+len(opts))%len(opts)]
}

// boundKeyID is the KeyID the host form saves: the selected key, or none when
// the selector is hidden or the selection no longer names a key in the vault.
// A hidden selector must not silently drop a binding made on another device, so
// it keeps whatever the form was opened with.
func (m Model) boundKeyID() string {
	id := m.formVals[fVaultKey]
	if id == "" || m.st == nil {
		return id
	}
	if _, ok := m.st.KeyByID(id); !ok {
		return ""
	}
	return id
}

// fieldVisible reports whether host-form field i is currently shown. The two
// conditional fields (key path, password) toggle on the selected auth mode; the
// hidden one is skipped by navigation and never rendered.
func (m Model) fieldVisible(i int) bool {
	switch i {
	case fKey:
		return m.formVals[fAuth] != sshx.AuthPassword
	case fVaultKey:
		// Nothing to pick from until the vault holds synced keys, and nothing to
		// pick for a password host. Not gated on being signed in the way the
		// project selector is: vault keys are local-first and exist without an
		// account.
		return m.formVals[fAuth] != sshx.AuthPassword && !m.demo && len(m.vaultKeyOptions()) > 1
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
	case modalImportSource:
		return m.importSourceKey(key)
	case modalImportSummary:
		return m.importSummaryKey(key)
	case modalQuitConfirm:
		return m.quitConfirmKey(key)
	case modalConnecting:
		return m.connectingKey(key)
	case modalSessionHint:
		return m.sessionHintKey(key)
	case modalSessionPicker:
		return m.sessionPickerKey(key)
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
	case modalResetIdentity:
		return m.resetIdentityConfirmKey(key)
	case modalRepublishKey:
		return m.republishKeyConfirmKey(key)
	case modalForwardForm:
		return m.forwardFormKey(key)
	case modalForwards:
		return m.forwardsKey(key)
	case modalKeyUnsync:
		return m.keyUnsyncConfirmKey(key)
	case modalSignOut:
		return m.signOutConfirmKey(key)
	case modalMoveProject:
		return m.moveProjectKey(key)
	case modalProxy:
		return m.proxyKey(key)
	case modalDetachKey:
		return m.detachKeyCapture(key)
	case modalRemoteKey:
		return m.remoteKeyCapture(key)
	case modalRemoteAccess:
		return m.remoteAccessKey(key)
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
	m.formVals[fVaultKey] = h.KeyID
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
	// The bound-key field is a selector over "any" plus every synced vault key.
	if m.formFocus == fVaultKey {
		switch key {
		case "left":
			m.formVals[fVaultKey] = m.cycleVaultKey(m.formVals[fVaultKey], -1)
		case "right", " ":
			m.formVals[fVaultKey] = m.cycleVaultKey(m.formVals[fVaultKey], +1)
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
		KeyID:   m.boundKeyID(),
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

// moveHostBetween moves a host between docs for the host form, reporting a
// failure inline on the form.
func (m Model) moveHostBetween(source, target string, h store.Host) (tea.Model, tea.Cmd) {
	mm, cmd, err := m.moveHostTo(source, target, h)
	if err != nil {
		m.formErr = cleanErr(err)
		return m, nil
	}
	return mm, cmd
}

// moveHostTo moves a host between docs (personal ↔ project) by removing it from
// the source and adding it to the target, each side persisted via its own path.
//
// The order is remove-then-add, and a failure on the add leaves the host
// nowhere — so the add is validated against the destination *first*: a name
// already taken there is rejected before anything is removed. The two sides
// cannot be made atomic (they are separate encrypted documents with separate
// optimistic-version pushes), so the cheap check is the safeguard.
func (m Model) moveHostTo(source, target string, h store.Host) (Model, tea.Cmd, error) {
	if source == target {
		return m, nil, nil
	}
	if err := m.destinationAccepts(target, h); err != nil {
		return m, nil, err
	}
	var cmds []tea.Cmd
	// Remove from the source.
	if source == "" {
		if err := m.st.DeleteHost(h.ID); err != nil {
			return m, nil, err
		}
		mm, c := m.saveVault()
		m = mm
		cmds = append(cmds, c)
	} else {
		mm, c, err := m.deleteHostFromProject(source, h.ID)
		if err != nil {
			return m, nil, err
		}
		m = mm
		cmds = append(cmds, c)
	}
	// Add to the target (drop the ID so the destination assigns a fresh one).
	h.ID = ""
	h.LastSeen = time.Time{}
	if target == "" {
		if _, err := m.st.AddHost(h); err != nil {
			return m, nil, err
		}
		mm, c := m.saveVault()
		m = mm
		cmds = append(cmds, c)
	} else {
		mm, c, _, err := m.addHostToProject(target, h)
		if err != nil {
			return m, nil, err
		}
		m = mm
		cmds = append(cmds, c)
	}
	m.modal = modalNone
	cmds = append(cmds, m.probeCmds())
	return m.setToast("moved "+h.Name+" to "+m.projectOptionLabel(target), "ok"), tea.Batch(cmds...), nil
}

// destinationAccepts reports whether target can take h — today, whether its
// name is free there. Checked before the source side is touched.
func (m Model) destinationAccepts(target string, h store.Host) error {
	name := strings.ToLower(strings.TrimSpace(h.Name))
	if target == "" {
		for _, ex := range m.storeHosts() {
			if strings.ToLower(strings.TrimSpace(ex.Name)) == name {
				return fmt.Errorf("a personal host named %q already exists", h.Name)
			}
		}
		return nil
	}
	doc := m.projectDocs[target]
	if doc == nil {
		return errNoProjectDoc
	}
	for _, ex := range doc.HostList() {
		if strings.ToLower(strings.TrimSpace(ex.Name)) == name {
			return fmt.Errorf("%s already has a host named %q", m.projectOptionLabel(target), h.Name)
		}
	}
	return nil
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

// kgFieldCount is the number of focusable keygen elements: name, comment,
// passphrase, and the "sync to vault" toggle (kgSyncField).
const (
	kgSyncField  = 3
	kgFieldCount = 4
)

func (m Model) openKeygenForm() Model {
	m.modal = modalKeygen
	m.kgFocus = 0
	m.kgErr = ""
	m.kgSync = false
	m.kgVals = [3]string{"id_ed25519_wharf", defaultKeyComment(), ""}
	return m
}

func (m Model) keygenKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.modal = modalNone
		return m, nil
	case "tab", "down":
		m.kgFocus = (m.kgFocus + 1) % kgFieldCount
		return m, nil
	case "shift+tab", "up":
		m.kgFocus = (m.kgFocus + kgFieldCount - 1) % kgFieldCount
		return m, nil
	case "enter":
		if strings.TrimSpace(m.kgVals[0]) == "" {
			m.kgErr = "name is required"
			return m, nil
		}
		m.kgErr = ""
		return m, m.generateKeyCmd(strings.TrimSpace(m.kgVals[0]), m.kgVals[1], m.kgVals[2])
	}
	// The sync toggle is a selector, not a text field.
	if m.kgFocus == kgSyncField {
		switch key {
		case "left", "right", " ":
			m.kgSync = !m.kgSync
		}
		return m, nil
	}
	switch key {
	case "backspace":
		if v := m.kgVals[m.kgFocus]; len(v) > 0 {
			m.kgVals[m.kgFocus] = v[:len(v)-1]
		}
	default:
		if isPrintable(key) {
			m.kgVals[m.kgFocus] += key
		}
	}
	return m, nil
}

func (m Model) handleKeyGenerated(msg keyGeneratedMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		m.kgErr = cleanErr(msg.err)
		m.modal = modalKeygen
		return m, nil
	}
	m.modal = modalNone
	doSync := m.kgSync
	m.kgSync = false
	cmds := []tea.Cmd{m.scanKeysCmd()}
	// "Also sync": the fresh key is unencrypted-or-not exactly as generated, so
	// the same sync path applies (keySyncedMsg then AddKey + saveVault).
	if doSync && !m.demo {
		cmds = append(cmds, m.syncKeyCmd(msg.info))
	}
	return m.setToast("generated "+msg.info.Name, "ok"), tea.Batch(cmds...)
}

// --- key sync / unsync (keys tab) -------------------------------------------

// syncSelectedKey copies the selected local key into the vault. The file read
// runs off the reducer via syncKeyCmd; AddKey + save happen in handleKeySynced.
func (m Model) syncSelectedKey() (tea.Model, tea.Cmd) {
	mk, ok := m.selectedMergedKey()
	if !ok || mk.local == nil {
		return m, nil
	}
	if mk.vault != nil {
		return m.setToast(mk.name+" is already in the vault", "ok"), nil
	}
	return m, m.syncKeyCmd(*mk.local)
}

func (m Model) handleKeySynced(msg keySyncedMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		return m.setToast("sync failed: "+cleanErr(msg.err), "err"), nil
	}
	stored, err := m.st.AddKey(msg.key)
	if err != nil {
		return m.setToast("sync failed: "+cleanErr(err), "err"), nil
	}
	m, syncCmd := m.saveVault()
	return m.setToast("synced "+stored.Name+" to vault", "ok"), syncCmd
}

// unsyncSelectedKey opens the confirm modal for removing the selected synced
// (or vault-only) key from the vault. The local key file is never touched.
func (m Model) unsyncSelectedKey() (tea.Model, tea.Cmd) {
	mk, ok := m.selectedMergedKey()
	if !ok || mk.vault == nil {
		return m, nil
	}
	m.unsyncKeyID = mk.vault.ID
	m.unsyncKeyName = mk.vault.Name
	m.modal = modalKeyUnsync
	return m, nil
}

func (m Model) keyUnsyncConfirmKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "y", "Y", "enter":
		name := m.unsyncKeyName
		if err := m.st.RemoveKey(m.unsyncKeyID); err != nil {
			m.modal = modalNone
			return m.setToast("unsync failed: "+cleanErr(err), "err"), nil
		}
		m.modal = modalNone
		m.keyIdx = clampIdx(m.keyIdx, len(m.mergedKeys()))
		m, syncCmd := m.saveVault()
		return m.setToast("removed "+name+" from vault", "ok"), syncCmd
	case "n", "N", "esc":
		m.modal = modalNone
	}
	return m, nil
}

// --- ssh_config import ------------------------------------------------------

func (m Model) handleImportDone(msg importDoneMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		if errors.Is(msg.err, os.ErrNotExist) && msg.source != termius.Source {
			return m.setToast("no ~/.ssh/config found", "err"), nil
		}
		// Termius failures carry multi-line guidance (which profiles were
		// searched, which keyring entries were tried), so they go to the error
		// modal rather than a one-line toast that would truncate them.
		if msg.source == termius.Source {
			m.modal = modalError
			m.errTitle = "termius import failed"
			m.errBody = msg.err.Error()
			return m, nil
		}
		return m.setToast("import failed: "+msg.err.Error(), "err"), nil
	}
	m.importHosts = msg.hosts
	m.importKeys = msg.keys
	m.importHostKeys = msg.hostKeys
	m.importSkipped = msg.skipped
	m.importSource = msg.source
	m.importNote = msg.note
	m.modal = modalImportSummary
	return m, nil
}

// openImportSource asks what to import from. ssh_config used to run straight
// off the keypress; the chooser exists because Termius is a second source, and
// a wrong guess there is expensive (it prompts the OS credential store).
func (m Model) openImportSource() (tea.Model, tea.Cmd) {
	m.modal = modalImportSource
	return m, nil
}

// applyImportedKeys adds the pending imported keys to the vault and returns how
// many were stored.
//
// A key whose name already exists is skipped rather than renamed again: the
// vault's own key is the user's, and a re-import should be idempotent instead
// of growing "name (2)", "name (3)" on every run.
func (m *Model) applyImportedKeys() int {
	added := 0
	existing := map[string]bool{}
	for _, k := range m.st.Keys() {
		existing[strings.ToLower(k.Name)] = true
	}
	for _, k := range m.importKeys {
		if existing[strings.ToLower(k.Name)] {
			continue
		}
		if _, err := m.st.AddKey(k); err != nil {
			continue
		}
		existing[strings.ToLower(k.Name)] = true
		added++
	}
	m.importKeys = nil
	return added
}

// bindImportedHosts turns the source's host→key-name mapping into KeyID
// bindings against the vault's keys.
//
// It resolves by name against the whole vault, not just the keys this import
// added: a re-import finds the key already there (applyImportedKeys skips a name
// that exists) and binds to it rather than leaving the host unbound. A name
// that resolves to nothing leaves the host unbound — better than a reference to
// a key the vault does not hold.
func (m *Model) bindImportedHosts() {
	if len(m.importHostKeys) == 0 || m.st == nil {
		return
	}
	byName := map[string]string{}
	for _, k := range m.st.Keys() {
		byName[strings.ToLower(strings.TrimSpace(k.Name))] = k.ID
	}
	for i, h := range m.importHosts {
		keyName, ok := m.importHostKeys[h.Name]
		if !ok {
			continue
		}
		if id := byName[strings.ToLower(strings.TrimSpace(keyName))]; id != "" {
			m.importHosts[i].KeyID = id
		}
	}
	m.importHostKeys = nil
}

// importSourceKey handles the "import from where?" chooser.
func (m Model) importSourceKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "s", "S":
		m.modal = modalNone
		return m.setToast("importing ~/.ssh/config…", "ok"), m.importCmd()
	case "t", "T":
		m.modal = modalNone
		// The credential store may prompt, and on macOS that dialog can end up
		// behind other windows, so the toast says to expect it.
		return m.setToast("reading Termius profile… (approve the keychain prompt)", "ok"), m.termiusImportCmd()
	case "esc", "n", "N", "q":
		m.modal = modalNone
	}
	return m, nil
}

func (m Model) importSummaryKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "y", "Y", "enter":
		// Keys land first: a host can only be bound to a key that already has
		// its vault ID.
		keysAdded := m.applyImportedKeys()
		m.bindImportedHosts()

		var added, updated, skipped int
		if m.importSource == termius.Source {
			// Only a Termius profile brings passwords with it.
			added, updated, skipped = m.st.UpsertImportedWithSecrets(m.importHosts)
		} else {
			added, updated, skipped = m.st.UpsertImported(m.importHosts)
		}
		m.modal = modalNone
		m, syncCmd := m.saveVault()
		summary := itoa(added) + " added · " + itoa(updated) + " updated · " + itoa(skipped) + " skipped"
		if keysAdded > 0 {
			summary += " · " + itoa(keysAdded) + " key(s)"
		}
		return m.setToast(summary, "ok"), tea.Batch(m.probeCmds(), syncCmd)
	case "n", "N", "esc":
		m.modal = modalNone
	}
	return m, nil
}

// --- quit -------------------------------------------------------------------

// requestQuit is triggered by ctrl+q. Demo quits directly; real mode confirms
// when live sessions or forwards would be closed.
func (m Model) requestQuit() (tea.Model, tea.Cmd) {
	if m.demo {
		return m, tea.Quit
	}
	if m.liveSessions() > 0 || m.liveForwards() > 0 || m.raGrant() != nil {
		m.modal = modalQuitConfirm
		return m, nil
	}
	return m.doQuit()
}

func (m Model) doQuit() (tea.Model, tea.Cmd) {
	// A grant is process-bound like a forward, but it is revoked explicitly
	// rather than left to the process exit: Close is synchronous, so quitting
	// cannot race a command that is starting as wharf goes away.
	m = m.revokeRemoteAccess()
	// Sessions are deliberately left running in their child processes; only the
	// control connections go away. Forwards are process-bound and do close.
	if m.pool != nil {
		m.pool.Detach()
	}
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
