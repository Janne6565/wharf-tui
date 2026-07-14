package ui

import (
	"strings"
	"time"

	"github.com/Janne6565/wharf-tui/internal/data"
	"github.com/Janne6565/wharf-tui/internal/theme"
	tea "github.com/charmbracelet/bubbletea"
)

type screen int

const (
	scAuth    screen = iota // login screen (entry point) — can sign in or skip to local
	scMain                  // dashboard: hosts / projects / keys / settings
	scSession               // active SSH session view
)

// line is one rendered terminal row: an optional prompt plus text. Colors are
// stored as theme roles (resolved at render time) so a live theme switch
// recolors existing scrollback correctly.
type line struct {
	prompt string
	text   string
	prole  string // color role for the prompt segment
	role   string // color role for the text segment
}

// session is a single (simulated) SSH connection kept alive across detaches.
type session struct {
	host  data.Host
	lines []line
	input string
}

// settingDef describes one row on the settings screen.
type settingDef struct {
	key   string
	label string
}

var settingDefs = []settingDef{
	{"agent", "SSH agent forwarding"},
	{"keepalive", "Keep-alive packets (30s)"},
	{"mosh", "Mosh fallback on flaky links"},
	{"telemetry", "Anonymous usage telemetry"},
	{"theme", "Theme"},
}

var tabNames = []string{"hosts", "projects", "keys", "settings"}

// Model is the root Bubble Tea model for the whole TUI.
type Model struct {
	w, h  int
	ready bool

	screen   screen
	authStep int    // 0 intro · 1 enter code · 2 verifying
	code     string // typed device code (up to 8 chars)

	// Account state. Wharf is local-first: everything below works signed out;
	// signing in only adds cross-machine sync and the Projects tab.
	signedIn bool
	email    string

	tab   int // active dashboard tab
	focus int // 0 list pane · 1 detail pane

	hostIdx, projIdx, keyIdx, setIdx int

	searchActive bool
	query        string

	inviteOpen  bool
	inviteEmail string
	helpOpen    bool

	themeName string
	settings  map[string]bool

	hosts    []data.Host
	projects []data.Project
	keys     []data.Key

	sessions map[string]*session
	open     []string // ordered open session names
	active   string   // currently focused session

	tick int // animation counter (blink + spinner)
}

// New builds the initial model: local-first, opening on the login screen.
func New() Model {
	return Model{
		screen:    scAuth,
		themeName: "abyss",
		settings: map[string]bool{
			"agent": true, "keepalive": true, "mosh": false, "telemetry": false,
		},
		hosts:    data.Hosts(),
		projects: data.Projects(),
		keys:     data.Keys(),
		sessions: map[string]*session{},
	}
}

// --- animation --------------------------------------------------------------

type tickMsg struct{}
type authDoneMsg struct{}

func tickCmd() tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return tickMsg{} })
}

func authDoneCmd() tea.Cmd {
	return tea.Tick(1300*time.Millisecond, func(time.Time) tea.Msg { return authDoneMsg{} })
}

// cursorOn reports whether the blinking block cursor is currently visible.
func (m Model) cursorOn() bool { return (m.tick/4)%2 == 0 }

var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"}

func (m Model) spinner() string { return spinFrames[m.tick%len(spinFrames)] }

// Init starts the animation ticker.
func (m Model) Init() tea.Cmd { return tickCmd() }

// --- small helpers ----------------------------------------------------------

func clampIdx(i, n int) int {
	if i < 0 || n == 0 {
		return 0
	}
	if i > n-1 {
		return n - 1
	}
	return i
}

// filteredHosts applies the current search query.
func (m Model) filteredHosts() []data.Host {
	if m.query == "" {
		return m.hosts
	}
	q := strings.ToLower(m.query)
	out := make([]data.Host, 0, len(m.hosts))
	for _, h := range m.hosts {
		hay := strings.ToLower(h.Name + " " + h.Addr + " " + h.User + " " + strings.Join(h.Tags, " ") + " " + h.Project)
		if strings.Contains(hay, q) {
			out = append(out, h)
		}
	}
	return out
}

// th returns the active theme.
func (m Model) th() theme.Theme { return theme.Get(m.themeName) }
