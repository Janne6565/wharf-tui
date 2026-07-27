package ui

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Janne6565/wharf-tui/internal/probe"
	"github.com/Janne6565/wharf-tui/internal/store"
	"github.com/Janne6565/wharf-tui/internal/vault"
	tea "github.com/charmbracelet/bubbletea"
)

// unlockKey drives the real-mode vault gate (create / unlock / recovery / reset
// / show-code).
func (m Model) unlockKey(key string) (tea.Model, tea.Cmd) {
	switch m.unlockStep {
	case ulUnlock:
		return m.unlockEntryKey(key)
	case ulRecovery:
		return m.recoveryEntryKey(key)
	case ulCreate, ulReset:
		return m.pwPairKey(key)
	case ulShowCode:
		// The one-time code must be explicitly acknowledged.
		switch key {
		case "enter", "y", "Y":
			m.recoveryCode = ""
			m.unlockErr = ""
			return m.enterMain()
		}
		return m, nil
	case ulLocked:
		switch key {
		case "enter", "esc", "q":
			m.unlockStep = ulUnlock
			m.unlockErr = ""
		}
		return m, nil
	default:
		// ulUnlocking / ulCreating / ulRecoveryOpening / ulResetting: busy.
		return m, nil
	}
}

// unlockEntryKey handles master-password entry for an existing vault.
func (m Model) unlockEntryKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "enter":
		if m.pwInput == "" {
			m.unlockErr = "enter your master password"
			return m, nil
		}
		pw := m.pwInput
		m.unlockStep = ulUnlocking
		m.unlockErr = ""
		return m, m.openCmd(pw)
	case "backspace":
		if len(m.pwInput) > 0 {
			m.pwInput = m.pwInput[:len(m.pwInput)-1]
		}
	case "r":
		// Switch to recovery only from an empty field so a real password may
		// still contain 'r' (type any other character first).
		if m.pwInput == "" {
			m.unlockStep = ulRecovery
			m.recoveryInput = ""
			m.unlockErr = ""
			return m, nil
		}
		m.pwInput += key
	default:
		if isPrintable(key) {
			m.pwInput += key
		}
	}
	return m, nil
}

// recoveryEntryKey handles recovery-code entry (normalized at open time).
func (m Model) recoveryEntryKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.unlockStep = ulUnlock
		m.recoveryInput = ""
		m.unlockErr = ""
	case "enter":
		if strings.TrimSpace(m.recoveryInput) == "" {
			m.unlockErr = "enter your recovery code"
			return m, nil
		}
		code := m.recoveryInput
		m.unlockStep = ulRecoveryOpening
		m.unlockErr = ""
		return m, m.recoverCmd(code)
	case "backspace":
		if len(m.recoveryInput) > 0 {
			m.recoveryInput = m.recoveryInput[:len(m.recoveryInput)-1]
		}
	default:
		if isPrintable(key) {
			m.recoveryInput += key
		}
	}
	return m, nil
}

// pwPairKey handles the password + confirmation pair shared by the create and
// forced-reset flows.
func (m Model) pwPairKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "tab", "down", "shift+tab", "up":
		m.pwField = (m.pwField + 1) % 2
	case "enter":
		if m.pwInput == "" {
			m.unlockErr = "password cannot be empty"
			return m, nil
		}
		if m.pwInput != m.pwConfirm {
			m.unlockErr = "passwords do not match"
			return m, nil
		}
		pw := m.pwInput
		m.unlockErr = ""
		if m.unlockStep == ulCreate {
			m.unlockStep = ulCreating
			return m, m.createCmd(pw)
		}
		m.unlockStep = ulResetting
		return m, resetCmd(m.vault, pw)
	case "backspace":
		if m.pwField == 0 {
			if len(m.pwInput) > 0 {
				m.pwInput = m.pwInput[:len(m.pwInput)-1]
			}
		} else if len(m.pwConfirm) > 0 {
			m.pwConfirm = m.pwConfirm[:len(m.pwConfirm)-1]
		}
	default:
		if isPrintable(key) {
			if m.pwField == 0 {
				m.pwInput += key
			} else {
				m.pwConfirm += key
			}
		}
	}
	return m, nil
}

// handleVaultMsg processes the async results of the vault gate commands.
func (m Model) handleVaultMsg(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case vaultCreatedMsg:
		if msg.err != nil {
			m.unlockStep = ulCreate
			m.unlockErr = "could not create vault: " + msg.err.Error()
			return m, nil
		}
		m.vault = msg.v
		if err := m.openStoreFromVault(); err != nil {
			m.unlockStep = ulCreate
			m.unlockErr = err.Error()
			return m, nil
		}
		m = m.initSync(msg.pw)
		m.recoveryCode = msg.code
		m.pwInput, m.pwConfirm = "", ""
		m.unlockStep = ulShowCode
		return m, nil

	case vaultOpenedMsg:
		if msg.err != nil {
			return m.handleOpenErr(msg.err), nil
		}
		m.vault = msg.v
		if err := m.openStoreFromVault(); err != nil {
			m.unlockStep = ulUnlock
			m.unlockErr = err.Error()
			m.pwInput = ""
			return m, nil
		}
		m = m.initSync(msg.pw)
		m.pwInput = ""
		return m.enterMain()

	case vaultRecoveredMsg:
		if msg.err != nil {
			if errors.Is(msg.err, vault.ErrLocked) {
				m.unlockStep = ulLocked
				m.unlockErr = ""
				return m, nil
			}
			m.unlockStep = ulRecovery
			m.unlockErr = "recovery code not accepted"
			return m, nil
		}
		// Recovery unlock forces a fresh password + a new recovery code.
		m.vault = msg.v
		m.recoveryInput = ""
		m.pwInput, m.pwConfirm, m.pwField = "", "", 0
		m.unlockStep = ulReset
		return m, nil

	case vaultResetMsg:
		if msg.err != nil {
			m.unlockStep = ulReset
			m.unlockErr = "reset failed: " + msg.err.Error()
			return m, nil
		}
		if err := m.openStoreFromVault(); err != nil {
			m.unlockStep = ulReset
			m.unlockErr = err.Error()
			return m, nil
		}
		m = m.initSync(msg.pw)
		m.recoveryCode = msg.code
		m.unlockStep = ulShowCode
		return m, nil
	}
	return m, nil
}

// handleOpenErr maps a vault.Open failure onto the right gate state.
func (m Model) handleOpenErr(err error) Model {
	m.pwInput = ""
	switch {
	case errors.Is(err, vault.ErrWrongSecret):
		m.unlockStep = ulUnlock
		m.unlockErr = "wrong password"
	case errors.Is(err, vault.ErrLocked):
		m.unlockStep = ulLocked
		m.unlockErr = ""
	case errors.Is(err, vault.ErrCorrupt):
		m.unlockStep = ulUnlock
		m.unlockErr = "vault file is corrupt or tampered"
	default:
		m.unlockStep = ulUnlock
		m.unlockErr = "unlock failed: " + err.Error()
	}
	return m
}

// openStoreFromVault loads the store over the freshly opened vault and applies
// the persisted theme.
func (m *Model) openStoreFromVault() error {
	st, err := store.Open(m.vault)
	if err != nil {
		return err
	}
	m.st = st
	m.settings = st.Settings()
	if m.settings.Theme != "" {
		m.themeName = m.settings.Theme
	}
	m.applySSHSettings()
	return nil
}

// applySSHSettings pushes the persisted SSH preferences into the manager. The
// manager is built in main before there is a vault to read them from, so it
// starts on the defaults and is corrected here (on unlock) and again whenever
// one of the rows is toggled.
func (m Model) applySSHSettings() {
	if m.mgr == nil {
		return
	}
	m.mgr.SetKeepalive(m.settings.Keepalive)
	m.mgr.SetUseAgent(m.settings.Agent)
}

// afterUnlockCmds fans out probes, a key scan, and the sync-session resume
// once the vault is open. The tick loop keeps running from Init, so it is
// not restarted here.
func (m Model) afterUnlockCmds() tea.Cmd {
	return tea.Batch(m.probeCmds(), m.scanKeysCmd(), m.resumeSyncCmd())
}

// enterMain leaves the vault gate for the main screen, and consumes a host name
// given on the command line (`wharf prod-api-01`) by dialing it right away. A
// name that resolves to no host, or to several, only raises a toast — the user
// still lands on the hosts list rather than back at a shell.
func (m Model) enterMain() (tea.Model, tea.Cmd) {
	m.screen = scMain
	m.tab = 0
	cmds := m.afterUnlockCmds()
	name := m.connectTo
	m.connectTo = ""
	if name == "" {
		return m, cmds
	}
	h, err := m.hostByName(name)
	if err != nil {
		return m.setToast(err.Error(), "err"), cmds
	}
	next, cmd := m.startConnect(h)
	return next, tea.Batch(cmds, cmd)
}

// hostByName resolves a command-line host argument: an exact name first, else a
// unique name prefix, both case-insensitive. Personal hosts only — project
// hosts need a projects sync that has not run yet at unlock time.
func (m Model) hostByName(name string) (store.Host, error) {
	want := strings.ToLower(strings.TrimSpace(name))
	if m.st == nil || want == "" {
		return store.Host{}, fmt.Errorf("no saved host named %q", name)
	}
	hosts := m.st.Hosts()
	for _, h := range hosts {
		if strings.ToLower(h.Name) == want {
			return h, nil
		}
	}
	var matched []string
	var first store.Host
	for _, h := range hosts {
		if strings.HasPrefix(strings.ToLower(h.Name), want) {
			if len(matched) == 0 {
				first = h
			}
			matched = append(matched, h.Name)
		}
	}
	switch len(matched) {
	case 1:
		return first, nil
	case 0:
		return store.Host{}, fmt.Errorf("no saved host named %q", name)
	default:
		return store.Host{}, fmt.Errorf("%q matches %s", name, strings.Join(matched, ", "))
	}
}

// lock saves, closes the vault and the sync engine, wipes the in-memory
// data, and returns to the unlock screen. Best-effort: a save/close failure
// still locks the UI.
func (m Model) lock() (tea.Model, tea.Cmd) {
	if m.st != nil {
		_ = m.st.Save()
	}
	if m.vault != nil {
		_ = m.vault.Close()
	}
	m = m.closeSync()
	m.st = nil
	m.vault = nil
	m.probes = map[string]probe.Result{}
	m.keyInfos = nil
	m.screen = scUnlock
	m.unlockStep = ulUnlock
	m.pwInput = ""
	m.unlockErr = ""
	m.query = ""
	m.searchActive = false
	m.hostIdx = 0
	m.signedIn = false
	m.email = ""
	m.modal = modalNone
	return m, nil
}
