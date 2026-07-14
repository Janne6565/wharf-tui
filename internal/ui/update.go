package ui

import (
	"strings"

	"github.com/Janne6565/wharf-tui/internal/data"
	"github.com/Janne6565/wharf-tui/internal/theme"
	tea "github.com/charmbracelet/bubbletea"
)

// Update is the Bubble Tea reducer: it routes messages to per-screen handlers.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		m.ready = true
		return m, nil
	case tickMsg:
		m.tick++
		return m, tickCmd()
	case authDoneMsg:
		if m.screen == scAuth && m.authStep == 2 {
			m.signedIn = true
			m.email = "deniz@wharf.sh"
			m.screen = scMain
			m.authStep = 0
			m.code = ""
		}
		return m, nil
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m Model) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := k.String()
	if key == "ctrl+c" {
		return m, tea.Quit
	}
	// Help overlay swallows everything until dismissed.
	if m.helpOpen {
		if key == "?" || key == "esc" || key == "q" {
			m.helpOpen = false
		}
		return m, nil
	}
	switch m.screen {
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

// authKey drives the login screen: sign in, or skip to a local-only vault.
func (m Model) authKey(key string) (tea.Model, tea.Cmd) {
	switch m.authStep {
	case 0:
		switch key {
		case "enter":
			m.authStep = 1
			m.code = ""
		case "l", "L": // skip login — use the local vault on this machine only
			m.screen = scMain
		case "?":
			m.helpOpen = true
		}
	case 1:
		switch key {
		case "esc":
			m.authStep = 0
			m.code = ""
		case "backspace":
			if len(m.code) > 0 {
				m.code = m.code[:len(m.code)-1]
			}
		case "enter":
			if len(m.code) == 8 {
				m.authStep = 2
				return m, authDoneCmd()
			}
		default:
			if isAlnum(key) && len(m.code) < 8 {
				m.code += strings.ToUpper(key)
			}
		}
	case 2:
		// verifying — input ignored
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
		// Lock: return to the login screen. The local vault is untouched;
		// signing back in (or skipping again) resumes from here.
		m.signedIn = false
		m.email = ""
		m.screen = scAuth
		m.authStep = 0
		m.code = ""
		return m, nil
	}

	if key == "esc" && m.query != "" {
		m.query = ""
		m.hostIdx = 0
		return m, nil
	}

	switch key {
	case "1":
		m.tab, m.focus = 0, 0
	case "2":
		m.tab, m.focus = 1, 0
	case "3":
		m.tab, m.focus = 2, 0
	case "4":
		m.tab, m.focus = 3, 0
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
	case "enter", " ":
		return m.mainEnter()
	}
	return m, nil
}

// mainEnter handles the primary action per tab.
func (m Model) mainEnter() (tea.Model, tea.Cmd) {
	switch m.tab {
	case 0: // hosts → connect
		fh := m.filteredHosts()
		if len(fh) == 0 {
			return m, nil
		}
		h := fh[clampIdx(m.hostIdx, len(fh))]
		if h.Status != "offline" {
			m = m.connect(h)
		}
	case 1: // projects
		if !m.signedIn {
			// Gate: projects are an online feature — enter starts sign-in.
			m.screen = scAuth
			m.authStep = 0
			m.code = ""
			return m, nil
		}
		p := m.projects[clampIdx(m.projIdx, len(m.projects))]
		m.tab = 0
		m.query = p.Name
		m.searchActive = true
		m.hostIdx = 0
	case 3: // settings → toggle/cycle
		m = m.toggleSetting()
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
		if em := strings.TrimSpace(m.inviteEmail); em != "" {
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
		m.hostIdx = clampIdx(m.hostIdx+d, len(m.filteredHosts()))
	case 1:
		m.projIdx = clampIdx(m.projIdx+d, len(m.projects))
	case 2:
		m.keyIdx = clampIdx(m.keyIdx+d, len(m.keys))
	case 3:
		m.setIdx = clampIdx(m.setIdx+d, len(settingDefs))
	}
}

func (m Model) toggleSetting() Model {
	def := settingDefs[clampIdx(m.setIdx, len(settingDefs))]
	if def.key == "theme" {
		m.themeName = theme.Next(m.themeName)
	} else {
		m.settings[def.key] = !m.settings[def.key]
	}
	return m
}

func (m Model) connect(h data.Host) Model {
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

// exec runs the (simulated) shell command in the active session. This is the
// seam where a real x/crypto/ssh channel will replace the canned responses.
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

func initLines(h data.Host) []line {
	return []line{
		{text: "Connecting to " + h.Conn() + " …", role: "dim"},
		{text: "✓ " + h.Key + " accepted · host key verified", role: "ok"},
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
