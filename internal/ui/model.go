package ui

import (
	"context"
	"strings"
	"time"

	"github.com/Janne6565/wharf-tui/internal/data"
	"github.com/Janne6565/wharf-tui/internal/keys"
	"github.com/Janne6565/wharf-tui/internal/probe"
	"github.com/Janne6565/wharf-tui/internal/sshx"
	"github.com/Janne6565/wharf-tui/internal/store"
	"github.com/Janne6565/wharf-tui/internal/theme"
	tea "github.com/charmbracelet/bubbletea"
)

type screen int

const (
	scAuth    screen = iota // simulated account sign-in (device code) — demo boot + on-demand
	scMain                  // dashboard: hosts / projects / keys / settings
	scSession               // simulated SSH session view (demo only)
	scUnlock                // real-mode vault gate: create / unlock / recovery / show-code
)

// unlock sub-steps for the real-mode vault gate (scUnlock).
const (
	ulUnlock          = iota // existing vault: master-password entry
	ulUnlocking              // spinner while vault.Open runs
	ulCreate                 // fresh vault: new password + confirm
	ulCreating               // spinner while vault.Create runs
	ulRecovery               // recovery-code entry
	ulRecoveryOpening        // spinner while OpenWithRecovery runs
	ulReset                  // forced new password + confirm after recovery unlock
	ulResetting              // spinner while ChangePassword+RegenerateRecovery run
	ulShowCode               // one-time recovery-code display (after create or reset)
	ulLocked                 // dedicated "another wharf instance is running" state
)

// modalKind is the active real-mode overlay (mutually exclusive).
type modalKind int

const (
	modalNone modalKind = iota
	modalHostForm
	modalDeleteConfirm
	modalConnecting
	modalHostKey
	modalSecret
	modalImportSummary
	modalKeygen
	modalQuitConfirm
	modalError
)

// host-form field indices.
const (
	fName = iota
	fUser
	fAddr
	fPort
	fTags
	fKey
	fAuth     // auth-method selector (auto | key | password)
	fPassword // masked; meaningful for auto/password auth
	fCount
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

// session is a single simulated SSH connection kept alive across detaches.
// Real-mode sessions live in the sshx.Manager, not here; this drives the demo
// takeover screen only.
type session struct {
	host  store.Host
	lines []line
	input string
}

// settingDef describes one row on the settings screen.
type settingDef struct {
	key   string
	label string
}

// settingDefs drives the settings screen. The mosh row was dropped (port
// forwarding / mosh are roadmap); an "account" action row was added.
var settingDefs = []settingDef{
	{"agent", "SSH agent forwarding"},
	{"keepalive", "Keep-alive packets (30s)"},
	{"telemetry", "Anonymous usage telemetry"},
	{"account", "Account"},
	{"theme", "Theme"},
}

var tabNames = []string{"hosts", "projects", "keys", "settings"}

// vaultHandle is the slice of *vault.Vault the UI depends on, behind an
// interface so headless tests can inject a fast fake (real argon2 Create is too
// slow for unit tests). It is unexported: main.go relies on the default hooks.
type vaultHandle interface {
	Payload() []byte
	Save([]byte) error
	ChangePassword([]byte) error
	RegenerateRecovery() (string, error)
	Close() error
}

// Model is the root Bubble Tea model for the whole TUI.
type Model struct {
	w, h  int
	ready bool
	demo  bool // demo mode: sample data, simulated session, no disk I/O, no real SSH

	screen      screen
	authStep    int    // 0 intro · 1 enter code · 2 verifying
	code        string // typed device code (up to 8 chars)
	postAuthTab int    // tab to return to after a simulated sign-in

	// Account state (simulated). Wharf is local-first: everything below works
	// signed out; signing in only adds cross-machine sync and the Projects tab.
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

	// --- real data layer (nil/empty in demo before seeding) ---
	vaultPath string
	mgr       *sshx.Manager
	vault     vaultHandle
	st        *store.Store
	settings  store.Settings
	probes    map[string]probe.Result // ephemeral reachability, keyed by host ID
	keyInfos  []keys.KeyInfo          // live ~/.ssh scan

	// vault hooks (injectable for tests; default to the real vault package).
	vaultExists  func(string) bool
	openVault    func(string, []byte) (vaultHandle, error)
	createVault  func(string, []byte) (vaultHandle, string, error)
	openRecovery func(string, string) (vaultHandle, error)

	// --- vault gate state ---
	unlockStep    int
	pwInput       string
	pwConfirm     string
	pwField       int // 0 password · 1 confirm (create/reset)
	recoveryInput string
	recoveryCode  string // code to display on ulShowCode
	unlockErr     string

	// projects are a simulated team feature (data fixtures in both modes).
	projects []data.Project

	// demo simulated sessions.
	sessions map[string]*session
	open     []string // ordered open session names
	active   string   // currently focused session

	// --- real-mode modals ---
	modal modalKind

	formEditID string         // "" = add, else the ID being edited
	formVals   [fCount]string // Name, User, Addr, Port, Tags, KeyPath, AuthMethod, Password
	formFocus  int
	formErr    string

	delID   string
	delName string

	kgVals  [3]string // name, comment, passphrase
	kgFocus int
	kgErr   string

	dialHostID string
	dialCancel context.CancelFunc
	attaching  bool // TTY handed to a session: suspend the tick loop

	importHosts   []store.Host
	importSkipped []string

	pendingHostKey *sshx.HostKeyPromptMsg
	pendingSecret  *sshx.SecretPromptMsg
	secretInput    string
	secretRemember bool // "remember password" toggle in the secret modal

	// pendingPW holds a typed password captured with "remember" on, kept until
	// the matching dial succeeds so it can be written to the vault.
	pendingPW *rememberedPassword

	errTitle string
	errBody  string

	toast     string
	toastRole string // "ok" | "err"
	toastAt   int    // tick at which the toast was raised

	tick int // animation counter (blink + spinner)
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

// storeHosts returns all stored hosts (stable-sorted by the store).
func (m Model) storeHosts() []store.Host {
	if m.st == nil {
		return nil
	}
	return m.st.Hosts()
}

// filteredHosts applies the current search query.
func (m Model) filteredHosts() []store.Host {
	hs := m.storeHosts()
	if m.query == "" {
		return hs
	}
	q := strings.ToLower(m.query)
	out := make([]store.Host, 0, len(hs))
	for _, h := range hs {
		hay := strings.ToLower(h.Name + " " + h.Addr + " " + h.User + " " + strings.Join(h.Tags, " "))
		if strings.Contains(hay, q) {
			out = append(out, h)
		}
	}
	return out
}

// th returns the active theme.
func (m Model) th() theme.Theme { return theme.Get(m.themeName) }
