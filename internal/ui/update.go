package ui

import (
	"strings"

	"github.com/Janne6565/wharf-tui/internal/probe"
	"github.com/Janne6565/wharf-tui/internal/sshx"
	"github.com/Janne6565/wharf-tui/internal/store"
	"github.com/Janne6565/wharf-tui/internal/theme"
	tea "github.com/charmbracelet/bubbletea"
)

// toastTTL is how many ticks (~120ms each) a status toast stays visible.
const toastTTL = 40

// Update is the Bubble Tea reducer: it routes messages to per-screen handlers.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		m.ready = true
		return m, nil
	case tickMsg:
		m.tick++
		if m.toast != "" && m.tick-m.toastAt > toastTTL {
			m.toast, m.toastRole = "", ""
		}
		// Suspend the ticker while the TTY is handed to a session so ticks don't
		// pile up during the takeover; detachedMsg restarts it.
		if m.attaching {
			return m, nil
		}
		return m, tickCmd()
	case authDoneMsg:
		// Demo-only: the simulated sign-in "verification" timer.
		if m.demo && m.screen == scAuth && m.authStep == 2 {
			m.signedIn = true
			m.email = "deniz@wharf.sh"
			m.screen = scMain
			m.tab = m.postAuthTab
			m.authStep = 0
			m.code = ""
		}
		return m, nil

	// vault gate results.
	case vaultCreatedMsg, vaultOpenedMsg, vaultRecoveredMsg, vaultResetMsg:
		return m.handleVaultMsg(msg)

	// sync engine results (real mode).
	case pairedMsg:
		return m.handlePaired(msg)
	case sessionResumedMsg:
		return m.handleSessionResumed(msg)
	case syncDoneMsg:
		return m.handleSyncDone(msg)
	case syncPushTimerMsg:
		return m.handleSyncPushTimer(msg)
	case changePasswordDoneMsg:
		return m.handleChangePasswordDone(msg)

	// projects (real mode).
	case identityReadyMsg:
		return m.handleIdentityReady(msg)
	case projectsSyncedMsg:
		return m.handleProjectsSynced(msg)
	case invitesFetchedMsg:
		return m.handleInvitesFetched(msg)
	case projectDetailMsg:
		return m.handleProjectDetail(msg)
	case projectCreatedMsg:
		return m.handleProjectCreated(msg)
	case projectOpMsg:
		return m.handleProjectOp(msg)
	case inviteSentMsg:
		return m.handleInviteSent(msg)
	case inviteRevokedMsg:
		return m.handleInviteRevoked(msg)
	case inviteRespondedMsg:
		return m.handleInviteResponded(msg)
	case finalizeDoneMsg:
		return m.handleFinalizeDone(msg)
	case projPushTimerMsg:
		return m.handleProjPushTimer(msg)

	// data-layer results.
	case probeResultMsg:
		if m.probes == nil {
			m.probes = map[string]probe.Result{}
		}
		m.probes[msg.HostID] = msg.Result
		return m, nil
	case keysScannedMsg:
		if msg.err != nil {
			return m.setToast("key scan failed: "+msg.err.Error(), "err"), nil
		}
		m.keyInfos = msg.keys
		m.keyIdx = clampIdx(m.keyIdx, len(m.mergedKeys()))
		return m, nil
	case keyGeneratedMsg:
		return m.handleKeyGenerated(msg)
	case keySyncedMsg:
		return m.handleKeySynced(msg)
	case importDoneMsg:
		return m.handleImportDone(msg)

	// session engine results and prompts.
	case dialDoneMsg:
		return m.handleDialDone(msg)
	case forwardDoneMsg:
		return m.handleForwardDone(msg)
	case detachedMsg:
		return m.handleDetached(msg)
	case sshx.HostKeyPromptMsg:
		return m.handleHostKeyPrompt(msg)
	case sshx.SecretPromptMsg:
		return m.handleSecretPrompt(msg)
	case sshx.SessionEndedMsg:
		return m.handleSessionEnded(msg)
	case sshx.ForwardEndedMsg:
		return m.handleForwardEnded(msg)

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m Model) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Fast typing and pastes arrive as one KeyMsg carrying several runes; split
	// them so every text input sees the same per-rune stream the handlers expect.
	if k.Type == tea.KeyRunes && len(k.Runes) > 1 {
		var cmds []tea.Cmd
		var tm tea.Model = m
		for _, r := range k.Runes {
			nk := k
			nk.Runes = []rune{r}
			var cmd tea.Cmd
			tm, cmd = tm.(Model).handleKey(nk)
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
		}
		return tm, tea.Batch(cmds...)
	}
	key := k.String()
	// ctrl+c is no longer a quit; while attached it's a byte to the remote, and
	// in the TUI it does nothing.
	if key == "ctrl+c" {
		return m, nil
	}
	if key == "ctrl+q" {
		return m.requestQuit()
	}
	// Help overlay swallows everything until dismissed.
	if m.helpOpen {
		if key == "?" || key == "esc" || key == "q" {
			m.helpOpen = false
		}
		return m, nil
	}
	// Real-mode modals take priority over the screen underneath.
	if m.modal != modalNone {
		return m.modalKey(k, key)
	}
	switch m.screen {
	case scUnlock:
		return m.unlockKey(key)
	case scAuth:
		return m.authKey(key)
	case scMain:
		if m.inviteOpen {
			return m.inviteKey(key)
		}
		return m.mainKey(k, key)
	case scSession:
		return m.sessionKey(key)
	}
	return m, nil
}

// authKey drives the account sign-in (device code). Demo mode simulates the
// exchange; real mode pairs against the backend via the sync engine. The
// code input accepts the displayed dash form (XXXX-XXXX): dashes are simply
// skipped, so pasting works.
func (m Model) authKey(key string) (tea.Model, tea.Cmd) {
	switch m.authStep {
	case 0:
		switch key {
		case "enter":
			m.authStep = 1
			m.code = ""
			m.authErr = ""
		case "l", "L": // demo: skip login — use the local sample vault
			if m.demo {
				m.screen = scMain
			}
		case "esc":
			// real mode: back out of an on-demand sign-in to the dashboard.
			if !m.demo {
				m.screen = scMain
				m.tab = m.postAuthTab
			}
		case "?":
			m.helpOpen = true
		}
	case 1:
		switch key {
		case "esc":
			m.authStep = 0
			m.code = ""
			m.authErr = ""
		case "backspace":
			if len(m.code) > 0 {
				m.code = m.code[:len(m.code)-1]
			}
		case "enter":
			if len(m.code) != 8 {
				return m, nil
			}
			if m.demo {
				m.authStep = 2
				return m, authDoneCmd()
			}
			if m.eng == nil {
				m.authErr = "sync unavailable this session"
				return m, nil
			}
			m.authStep = 2
			m.authErr = ""
			return m, m.pairCmd(m.code)
		default:
			if isAlnum(key) && len(m.code) < 8 {
				m.code += strings.ToUpper(key)
				m.authErr = ""
			}
		}
	case 2:
		// verifying / exchanging — input ignored
	}
	return m, nil
}

func (m Model) mainKey(k tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	// Search-as-you-type on the hosts tab.
	if m.searchActive {
		switch key {
		case "esc":
			m.searchActive = false
			m.query = ""
			m.hostIdx = 0
		case "enter":
			m.searchActive = false
		case "backspace":
			if len(m.query) > 0 {
				m.query = m.query[:len(m.query)-1]
				m.hostIdx = 0
			}
		case "down":
			m.move(1)
		case "up":
			m.move(-1)
		default:
			if isPrintable(key) {
				m.query += key
				m.hostIdx = 0
			}
		}
		return m, nil
	}

	switch key {
	case "?":
		m.helpOpen = true
		return m, nil
	case "q":
		if m.demo {
			// Demo: sign out back to the simulated login screen.
			m.signedIn = false
			m.email = ""
			m.screen = scAuth
			m.authStep = 0
			m.code = ""
			return m, nil
		}
		return m.lock()
	case "F":
		// Active-forwards overlay: works from any tab in real mode; inert with no
		// engine and in demo.
		if !m.demo && m.mgr != nil {
			return m.openForwards(), nil
		}
	}

	// alt+1..9 reattaches a live session from anywhere on the dashboard.
	if strings.HasPrefix(key, "alt+") && len(key) == 5 && key[4] >= '1' && key[4] <= '9' {
		return m.reattachByIndex(int(key[4] - '1'))
	}

	if key == "esc" && m.query != "" {
		m.query = ""
		m.hostIdx = 0
		return m, nil
	}
	if key == "esc" && m.tab == 0 && m.projFilterID != "" {
		m.projFilterID = ""
		m.projFilterName = ""
		m.hostIdx = 0
		return m, nil
	}

	// The real-mode projects tab has its own key map (member cursor, invites,
	// per-project actions); tab-switch numbers and help still work.
	if m.tab == 1 && m.realMode() {
		switch key {
		case "1":
			return m.switchTab(0)
		case "2":
			return m.switchTab(1)
		case "3":
			return m.switchTab(2)
		case "4":
			return m.switchTab(3)
		case "?":
			m.helpOpen = true
			return m, nil
		case "q":
			return m.lock()
		}
		return m.projectsKey(key)
	}

	switch key {
	case "1":
		return m.switchTab(0)
	case "2":
		return m.switchTab(1)
	case "3":
		return m.switchTab(2)
	case "4":
		return m.switchTab(3)
	case "tab":
		if m.focus == 0 {
			m.focus = 1
		} else {
			m.focus = 0
		}
	case "/":
		if m.tab == 0 {
			m.searchActive = true
			m.focus = 0
		}
	case "j", "down":
		m.move(1)
	case "k", "up":
		m.move(-1)
	case "i":
		if m.tab == 1 && m.signedIn {
			m.inviteOpen = true
			m.inviteEmail = ""
		}
	case "a":
		if m.tab == 0 && !m.demo {
			return m.openHostForm(""), nil
		}
	case "e":
		if m.tab == 0 && !m.demo {
			return m.editSelectedHost()
		}
	case "d":
		if m.tab == 0 && !m.demo {
			return m.deleteSelectedHost()
		}
	case "f":
		if m.tab == 0 && !m.demo {
			return m.startForwardForm()
		}
	case "m":
		if m.tab == 0 && !m.demo {
			return m.setToast("importing ~/.ssh/config…", "ok"), m.importCmd()
		}
	case "R":
		if m.tab == 0 && !m.demo {
			return m.setToast("re-probing hosts…", "ok"), m.probeCmds()
		}
	case "g":
		if m.tab == 2 && !m.demo {
			return m.openKeygenForm(), nil
		}
	case "s":
		// Keys tab: sync the selected local key to the vault.
		if m.tab == 2 && !m.demo {
			return m.syncSelectedKey()
		}
		// Manual sync from the settings (account) tab. A pending conflict
		// re-runs the pass, which reopens the resolve prompt.
		if m.tab == 3 && !m.demo && m.signedIn {
			if m.conflict != nil && m.modal == modalNone {
				m.modal = modalSyncConflict
				return m, nil
			}
			return m.startSync()
		}
	case "u":
		// Keys tab: remove the selected synced key from the vault.
		if m.tab == 2 && !m.demo {
			return m.unsyncSelectedKey()
		}
	case "enter", " ":
		return m.mainEnter()
	}
	return m, nil
}

// switchTab moves to tab i. Switching to the projects tab (1) in real mode
// bootstraps identity, fetches invites and runs a projects sync.
func (m Model) switchTab(i int) (tea.Model, tea.Cmd) {
	if i == 1 {
		return m.enterProjectsTab()
	}
	m.tab, m.focus = i, 0
	return m, nil
}

// mainEnter handles the primary action per tab.
func (m Model) mainEnter() (tea.Model, tea.Cmd) {
	switch m.tab {
	case 0: // hosts → connect
		mh, ok := m.selectedMergedHost()
		if !ok {
			return m, nil
		}
		if m.demo {
			return m.connect(mh.Host), nil
		}
		return m.startConnect(mh.Host)
	case 1: // projects
		if !m.signedIn {
			// Gate: projects are an online feature — enter starts sign-in.
			m.postAuthTab = 1
			m.screen = scAuth
			m.authStep = 0
			m.code = ""
			m.authErr = ""
			return m, nil
		}
		p := m.projects[clampIdx(m.projIdx, len(m.projects))]
		m.tab = 0
		m.query = p.Name
		m.searchActive = true
		m.hostIdx = 0
	case 3: // settings → toggle/cycle
		return m.toggleSetting()
	}
	return m, nil
}

func (m Model) inviteKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.inviteOpen = false
		m.inviteEmail = ""
	case "backspace":
		if len(m.inviteEmail) > 0 {
			m.inviteEmail = m.inviteEmail[:len(m.inviteEmail)-1]
		}
	case "enter":
		em := strings.TrimSpace(m.inviteEmail)
		if m.realMode() {
			m.inviteOpen = false
			m.inviteEmail = ""
			if em == "" {
				return m, nil
			}
			if p, ok := m.selectedProject(); ok {
				return m.setToast("sending invite…", "ok"), m.inviteCmd(p.ID, em)
			}
			return m, nil
		}
		// Demo mode: keep the in-memory append behavior.
		if em != "" {
			idx := clampIdx(m.projIdx, len(m.projects))
			m.projects[idx].Invites = append(m.projects[idx].Invites, em)
		}
		m.inviteOpen = false
		m.inviteEmail = ""
	default:
		if isPrintable(key) {
			m.inviteEmail += key
		}
	}
	return m, nil
}

func (m Model) sessionKey(key string) (tea.Model, tea.Cmd) {
	switch {
	case key == "esc":
		// Detach: the session keeps running, back to the dashboard.
		m.screen = scMain
		return m, nil
	case key == "tab":
		return m, nil
	case strings.HasPrefix(key, "alt+") && len(key) == 5 && key[4] >= '1' && key[4] <= '9':
		if idx := int(key[4] - '1'); idx < len(m.open) {
			m.active = m.open[idx]
		}
		return m, nil
	}
	s := m.sessions[m.active]
	if s == nil {
		return m, nil
	}
	switch key {
	case "backspace":
		if len(s.input) > 0 {
			s.input = s.input[:len(s.input)-1]
		}
	case "enter":
		m.exec()
	default:
		if isPrintable(key) {
			s.input += key
		}
	}
	return m, nil
}

// --- state transitions ------------------------------------------------------

func (m *Model) move(d int) {
	switch m.tab {
	case 0:
		m.hostIdx = clampIdx(m.hostIdx+d, len(m.filteredMergedHosts()))
	case 1:
		m.projIdx = clampIdx(m.projIdx+d, len(m.projects))
	case 2:
		m.keyIdx = clampIdx(m.keyIdx+d, len(m.mergedKeys()))
	case 3:
		m.setIdx = clampIdx(m.setIdx+d, len(settingDefs))
	}
}

// toggleSetting toggles or actions the selected settings row and persists.
func (m Model) toggleSetting() (tea.Model, tea.Cmd) {
	def := settingDefs[clampIdx(m.setIdx, len(settingDefs))]
	switch def.key {
	case "theme":
		next := theme.Next(m.themeName)
		m.themeName = next
		m.settings.Theme = next
		return m.persistSettings()
	case "account":
		if m.signedIn {
			if m.demo {
				m.signedIn = false
				m.email = ""
				return m, nil
			}
			return m.signOut(), nil
		}
		m.postAuthTab = 3
		m.screen = scAuth
		m.authStep = 0
		m.code = ""
		m.authErr = ""
		return m, nil
	case "password":
		if m.demo || m.vault == nil {
			return m.setToast("changing the master password needs a real vault", "err"), nil
		}
		return m.openChangePassword(), nil
	case "agent":
		m.settings.Agent = !m.settings.Agent
	case "keepalive":
		m.settings.Keepalive = !m.settings.Keepalive
	case "telemetry":
		m.settings.Telemetry = !m.settings.Telemetry
	}
	return m.persistSettings()
}

// persistSettings writes the working settings through the store and schedules
// a sync push (settings live in the synced payload too).
func (m Model) persistSettings() (Model, tea.Cmd) {
	if m.st != nil {
		m.st.SetSettings(m.settings)
	}
	return m.saveVault()
}

// setToast raises a transient status line.
func (m Model) setToast(text, role string) Model {
	m.toast = text
	m.toastRole = role
	m.toastAt = m.tick
	return m
}

// --- demo simulated session -------------------------------------------------

func (m Model) connect(h store.Host) Model {
	if m.sessions[h.Name] == nil {
		m.sessions[h.Name] = &session{host: h, lines: initLines(h)}
	}
	found := false
	for _, n := range m.open {
		if n == h.Name {
			found = true
		}
	}
	if !found {
		m.open = append(m.open, h.Name)
	}
	m.active = h.Name
	m.screen = scSession
	return m
}

// exec runs the simulated shell command in the active demo session.
func (m Model) exec() {
	s := m.sessions[m.active]
	if s == nil {
		return
	}
	cmd := s.input
	trimmed := strings.TrimSpace(cmd)
	if trimmed == "clear" {
		s.lines = nil
		s.input = ""
		return
	}
	var out []line
	switch trimmed {
	case "":
	case "ls":
		out = []line{{text: "app  deploy.sh  logs  node_modules  package.json  README.md", role: "fg"}}
	case "whoami":
		out = []line{{text: "deniz", role: "fg"}}
	case "uptime":
		out = []line{{text: " 14:32:07 up 84 days,  3:12,  2 users,  load average: 0.42, 0.38, 0.35", role: "fg"}}
	default:
		out = []line{{text: "bash: " + strings.Fields(trimmed)[0] + ": command not found", role: "err"}}
	}
	s.lines = append(s.lines, line{prompt: promptFor(m.active), prole: "hi", text: cmd, role: "fg"})
	s.lines = append(s.lines, out...)
	s.input = ""
}

func initLines(h store.Host) []line {
	return []line{
		{text: "Connecting to " + h.Conn() + " …", role: "dim"},
		{text: "✓ host key verified · agent authentication accepted", role: "ok"},
		{text: "Welcome to Ubuntu 24.04.2 LTS (" + h.Name + ")", role: "fg"},
		{text: "Last login: Fri Jul 10 09:12:44 2026 from 84.112.9.20", role: "dim"},
		{text: "", role: "fg"},
	}
}

func promptFor(name string) string { return "deniz@" + name + ":~$ " }

// --- input predicates -------------------------------------------------------

func isAlnum(s string) bool {
	if len([]rune(s)) != 1 {
		return false
	}
	r := []rune(s)[0]
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

func isPrintable(s string) bool {
	if len([]rune(s)) != 1 {
		return false
	}
	r := []rune(s)[0]
	return r >= 32 && r != 127
}
