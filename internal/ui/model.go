package ui

import (
	"context"
	"strings"
	"time"

	"github.com/Janne6565/wharf-tui/internal/api"
	"github.com/Janne6565/wharf-tui/internal/data"
	"github.com/Janne6565/wharf-tui/internal/keys"
	"github.com/Janne6565/wharf-tui/internal/probe"
	"github.com/Janne6565/wharf-tui/internal/sshx"
	"github.com/Janne6565/wharf-tui/internal/store"
	syncx "github.com/Janne6565/wharf-tui/internal/sync"
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
	modalSyncConflict
	modalChangePassword
	modalCreateProject   // new-project form (name + description)
	modalRemoveMember    // confirm client-side rotation-with-removal
	modalInviteResponse  // accept / decline a received invite
	modalProjectConflict // per-project sync conflict (queued)
	modalResetIdentity   // confirm "I lost my old vault" identity reset (pubkey rotate)
	modalForwardForm     // -L/-R/-D port-forward form (real mode; k9s-style, never persisted)
	modalForwards        // active-forwards overlay (F)
	modalKeyUnsync       // confirm removing a synced key from the vault (keys tab)
)

// syncState is the rendered sync status (header indicator). It is pure
// display state: the truth lives in the sync engine and arrives as messages.
type syncState int

const (
	ssNone     syncState = iota // signed out / no sync yet
	ssSyncing                   // a sync pass is in flight
	ssSynced                    // in agreement with the remote
	ssOffline                   // last pass failed (network/backend)
	ssConflict                  // both sides changed; user must resolve
)

// host-form field indices. fAuth is the two-way selector; fKey and fPassword
// are conditional — only the one matching the selected mode is shown and
// navigable (key path in key mode, masked password in password mode).
const (
	fName = iota
	fUser
	fAddr
	fPort
	fTags
	fAuth     // auth-method selector (key | password)
	fKey      // key path — shown in key mode only
	fPassword // masked password — shown in password mode only
	fProject  // project selector (personal | writable projects) — real mode only
	fCount
)

// forward-form field indices. ffKind is the kind selector; the two target
// fields are conditional — shown and navigable only for local/remote (a dynamic
// SOCKS5 forward resolves its target per-connection, so it has none).
const (
	ffKind = iota
	ffBindAddr
	ffBindPort
	ffTargetAddr
	ffTargetPort
	ffCount
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
	{"password", "Master password"},
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
	// DeriveKey returns a 32-byte HKDF subkey of the vault DEK bound to info
	// (used to seal the device-local sync session file).
	DeriveKey(info string) ([]byte, error)
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
	authErr     string // pairing failure shown on the code screen (real mode)
	postAuthTab int    // tab to return to after a sign-in

	// Account state. Wharf is local-first: everything below works signed
	// out; signing in only adds cross-machine sync and the Projects tab.
	// Real mode pairs against the backend; demo mode stays simulated.
	signedIn bool
	email    string

	// --- vault sync (real mode) ---
	// The engine owns the paired session and bookkeeping; the Model only
	// renders the state it reports via messages.
	eng       *syncx.Engine
	syncSt    syncState
	conflict  *syncx.Conflict
	syncGen   int    // debounce generation for post-save pushes
	deviceURL string // pairing page shown on the sign-in screen

	// sync hooks (injectable for tests; defaults wired in initSync).
	syncAPI           syncx.API
	syncReadBlob      func() ([]byte, error)
	syncOpenBlob      func(blob, password []byte) ([]byte, error)
	syncProjectCrypto syncx.ProjectCrypto
	genIdentity       func() (pub, priv []byte, err error)

	// --- real projects (real signed-in mode; demo keeps m.projects fixtures) ---
	realProjects      []projectItem                // ordered, from the engine's sync pass
	projectDocs       map[string]*store.ProjectDoc // decrypted docs keyed by project ID
	projDetail        *api.ProjectDetail           // members/invites of the selected project
	receivedInvites   []api.ReceivedInvite         // pending invites addressed to the account
	projConflicts     []syncx.ProjectConflict      // queued per-project conflicts
	projConflict      *syncx.ProjectConflict       // the one being resolved
	projFilterID      string                       // hosts-tab filter by project ID ("" = none)
	projFilterName    string                       // display name for the filter chip
	identityReady     bool                         // identity loaded into the engine this session
	identityBooting   bool                         // a bootstrap attempt is in flight
	identityNotice    string                       // cross-device "sync first" notice
	identityNeedsSync bool                         // needs-sync state: offer the "R" identity reset

	// create-project form (name, description).
	cpjVals  [2]string
	cpjFocus int
	cpjErr   string

	// remove-member confirm (client-side rotation).
	rmUserID string
	rmName   string
	rmProjID string

	// invite-response modal (accept/decline a received invite).
	invRespID   string
	invRespName string

	// member cursor in the projects detail pane (focus == 1): indexes the
	// combined members-then-invites list for d (remove) / x (revoke).
	memberIdx int

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

	formEditID     string         // "" = add, else the ID being edited
	formEditProjID string         // source project of the host being edited ("" personal)
	formVals       [fCount]string // Name, User, Addr, Port, Tags, AuthMethod, KeyPath, Password, ProjectID
	formFocus      int
	formErr        string

	delID     string
	delName   string
	delProjID string // "" personal, else the project to delete the host from

	kgVals  [3]string // name, comment, passphrase
	kgFocus int       // 0..2 text fields, kgSyncField the "sync to vault" toggle
	kgErr   string
	kgSync  bool // "also sync to vault" toggle (keygen modal)

	// unsync-from-vault confirm (keys tab).
	unsyncKeyID   string
	unsyncKeyName string

	// change-master-password modal: current, new, confirm.
	cpVals  [3]string
	cpFocus int
	cpErr   string
	cpBusy  bool // async re-key + upload in flight (blocks input, shows spinner)

	dialHostID string
	dialCancel context.CancelFunc
	attaching  bool // TTY handed to a session: suspend the tick loop

	// --- port forwards (real mode; k9s-style, nothing persisted) ---
	fwdVals     [ffCount]string             // forward-form buffers (see ff* indices)
	fwdFocus    int                         // forward-form focused field
	fwdErr      string                      // inline forward-form validation/engine error
	fwdHost     store.Host                  // the host the form/start operates on
	fwdInFlight bool                        // connecting modal shows "starting forward…"
	fwdIdx      int                         // cursor in the active-forwards overlay
	fwdPrefill  map[string]sshx.ForwardSpec // last submitted spec per host ID (ephemeral prefill)

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

// projectItem is a rendered real-project row: metadata from the engine's sync
// snapshot plus the live host count derived from the decrypted doc.
type projectItem struct {
	ID          string
	Name        string
	Description string
	Role        string
	AwaitingKey bool
	Version     int64
	MemberCount int
	HostCount   int
}

// realMode reports whether the UI is on the real (non-demo) signed-in path where
// projects, invites and the merged hosts tab are live.
func (m Model) realMode() bool { return !m.demo && m.signedIn }

// projectRowCount is the number of navigable rows on the projects tab: the
// pinned received-invite rows followed by the project rows.
func (m Model) projectRowCount() int {
	return len(m.receivedInvites) + len(m.realProjects)
}

// selectedInvite returns the received invite under the cursor, if the cursor is
// on a pinned invite row.
func (m Model) selectedInvite() (api.ReceivedInvite, bool) {
	if m.projIdx < len(m.receivedInvites) {
		return m.receivedInvites[m.projIdx], true
	}
	return api.ReceivedInvite{}, false
}

// selectedProject returns the project under the cursor, if the cursor is on a
// project row (past the pinned invites).
func (m Model) selectedProject() (projectItem, bool) {
	i := m.projIdx - len(m.receivedInvites)
	if i >= 0 && i < len(m.realProjects) {
		return m.realProjects[i], true
	}
	return projectItem{}, false
}

// writableProjects returns the real projects the account can push hosts to
// (keyed member/admin/owner, not awaiting-key).
func (m Model) writableProjects() []projectItem {
	var out []projectItem
	for _, p := range m.realProjects {
		if !p.AwaitingKey {
			out = append(out, p)
		}
	}
	return out
}

// projectHostsPayloads captures the current decrypted payload of every project
// doc, keyed by project ID, for a sync pass.
func (m Model) projectHostsPayloads() map[string][]byte {
	if len(m.projectDocs) == 0 {
		return nil
	}
	out := make(map[string][]byte, len(m.projectDocs))
	for id, doc := range m.projectDocs {
		if doc == nil {
			continue
		}
		if b, err := doc.Marshal(); err == nil {
			out[id] = b
		}
	}
	return out
}
