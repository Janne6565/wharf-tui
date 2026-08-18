package ui

import (
	"context"
	"strings"
	"time"

	"github.com/Janne6565/wharf-tui/internal/api"
	"github.com/Janne6565/wharf-tui/internal/data"
	"github.com/Janne6565/wharf-tui/internal/keys"
	"github.com/Janne6565/wharf-tui/internal/probe"
	"github.com/Janne6565/wharf-tui/internal/proxydial"
	"github.com/Janne6565/wharf-tui/internal/remoteaccess"
	"github.com/Janne6565/wharf-tui/internal/sessd"
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
	ulChoose                 // first run: local-only vault vs. sign in to an account
	ulCreate                 // fresh vault: new password + confirm
	ulCreating               // spinner while vault.Create runs
	ulRecovery               // recovery-code entry
	ulRecoveryOpening        // spinner while OpenWithRecovery runs
	ulReset                  // forced new password + confirm after recovery unlock
	ulResetting              // spinner while ChangePassword+RegenerateRecovery run
	ulShowCode               // one-time recovery-code display (after create or reset)
	ulLocked                 // dedicated "another wharf instance is running" state

	// Account sign-in at the gate: pair in the browser, then install the
	// account's own vault blob as this machine's vault (see update_signin.go).
	ulSignInCode     // device-code entry
	ulSignInPairing  // spinner while the code is exchanged and the vault fetched
	ulSignInPassword // account master-password entry
	ulSignInOpening  // spinner while the account vault is opened and installed
	ulSignInSetup    // dead end: the account has no vault yet (finish in browser)
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
	modalRepublishKey    // confirm re-publishing the local pubkey over a mismatched server key
	modalForwardForm     // -L/-R/-D port-forward form (real mode; k9s-style, never persisted)
	modalForwards        // active-forwards overlay (F)
	modalKeyUnsync       // confirm removing a synced key from the vault (keys tab)
	modalSignOut         // confirm unpairing this device (settings tab)
	modalSessionHint     // first-connect primer on detach / reattach keys
	modalSessionPicker   // choose among a host's open sessions, or start another
	modalMoveProject     // move the selected host between personal and a project
	modalProxy           // edit the machine-local egress proxy (settings tab)
	modalDetachKey       // capture a new detach key (settings tab)
	modalImportSource    // choose what to import hosts from (ssh_config / Termius)
	modalRemoteKey       // capture a new remote-access key (settings tab)
	modalRemoteAccess    // remote-access grant: command line, expiry, live audit log (A)
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

// host-form field indices. fAuth is the two-way selector; fKey, fVaultKey and
// fPassword are conditional — only those matching the selected mode are shown
// and navigable (key path + vault key in key mode, masked password in password
// mode).
const (
	fName = iota
	fUser
	fAddr
	fPort
	fTags
	fAuth     // auth-method selector (key | password)
	fKey      // key path — shown in key mode only
	fVaultKey // bound vault key selector — key mode, and only with synced keys
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

// settingDef describes one row on the settings screen. A row with act unset is
// status only: the cursor skips it, so enter is never a no-op.
type settingDef struct {
	key   string
	label string
	act   bool
}

// settingRows drives the settings screen for the current account state. The
// mosh row was dropped (port forwarding / mosh are roadmap), as was the
// "Anonymous usage telemetry" row: wharf collects and sends nothing, so the
// row claimed a feature that does not exist and let people believe they had
// switched something off. store.Settings keeps the field so the committed
// cross-implementation vault fixtures stay byte-identical. Signing in and
// signing out are deliberately *different rows*: while signed in, "Account" is
// a status row showing the address and a separate "Sign out" row carries the
// action, so enter on the account line can never unpair the device by
// surprise. Signed out there is nothing to show, so the one row signs in.
func (m Model) settingRows() []settingDef {
	rows := []settingDef{
		{key: "agent", label: "Use SSH agent keys", act: true},
		{key: "keepalive", label: "Keep-alive packets (30s)", act: true},
		{key: "proxy", label: "Egress proxy", act: true},
		{key: "detachkey", label: "Detach key", act: true},
		{key: "remotekey", label: "Remote-access key", act: true},
	}
	if m.signedIn {
		rows = append(rows,
			settingDef{key: "account", label: "Account"},
			settingDef{key: "signout", label: "Sign out", act: true})
	} else {
		rows = append(rows, settingDef{key: "account", label: "Account", act: true})
	}
	return append(rows,
		settingDef{key: "password", label: "Master password", act: true},
		settingDef{key: "theme", label: "Theme", act: true})
}

// settingIdx is the effective settings cursor: clamped into range and nudged
// off a status-only row. Signing in or out changes the row set underneath a
// stored index, so this is resolved at use rather than written back.
func (m Model) settingIdx() int {
	rows := m.settingRows()
	i := clampIdx(m.setIdx, len(rows))
	for i+1 < len(rows) && !rows[i].act {
		i++
	}
	return i
}

// settingCursor returns the index d actionable rows away, skipping status rows.
func (m Model) settingCursor(d int) int {
	rows := m.settingRows()
	start := m.settingIdx()
	i := start
	for {
		n := clampIdx(i+d, len(rows))
		if n == i {
			return start // ran into the edge with nothing actionable ahead
		}
		i = n
		if rows[i].act {
			return i
		}
	}
}

// Focus rings on the projects tab. Opening a project keeps you on the tab —
// it moves the cursor into that project's own host list in the detail pane —
// so the three rings are the project list, its hosts, and its members.
const (
	pfList = iota
	pfHosts
	pfMembers
	pfCount
)

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

	// Auto-opening the pairing page. openBrowser is injectable for tests and
	// nil when opening would be pointless (demo mode, or no reachable
	// display — see internal/browser.Available).
	openBrowser   func(string) error
	browserOpened bool // the pairing page was handed to a browser

	// copyToClipboard puts a string on the terminal's clipboard (OSC 52). It is
	// injectable for the same reason openBrowser is: a headless test must never
	// emit an escape sequence into the test runner's terminal. Nil means "no
	// clipboard at all", which is a supported state — the remote-access overlay
	// always shows the command as selectable text regardless.
	copyToClipboard func(string) error

	// --- egress proxy (machine-local, never synced) ---
	// proxyStored is the value the settings row edits, as saved on this
	// machine. What is actually in effect lives in the shared proxydial.Setting
	// that the engine, the session pool and the probes all read — the Model
	// holds the same pointer rather than a copy, so the screen cannot disagree
	// with what the next dial will do. applyProxy persists an edit and updates
	// that setting; nil disables editing.
	proxyStored string
	proxy       *proxydial.Setting
	applyProxy  func(setting string) error
	pxVal       string // proxy-edit modal buffer
	pxErr       string // inline validation error in that modal

	// --- detach key (machine-local, never synced) ---
	// detachName is the key that leaves an attached session running, by the
	// name bubbletea reports for it. It is resolved to a byte at attach time,
	// so a change applies to sessions that are already open. applyDetachKey
	// persists an edit; nil disables editing (demo mode, tests).
	detachName     string
	applyDetachKey func(name string) error
	dkErr          string // rejected-key message in the capture modal

	// --- remote-access key (machine-local, never synced) ---
	// remoteName is the key that toggles the remote-access grant from inside an
	// attached session, by the name bubbletea reports for it. It is the twin of
	// detachName in every respect — resolved to a byte per attach, persisted by
	// applyRemoteKey, nil disables editing — and the two are kept apart because
	// whichever byte the attach loop swallows for one is a byte the other can
	// never see. Each capture modal validates against the other's binding.
	remoteName     string
	applyRemoteKey func(name string) error
	rkErr          string // rejected-key message in that capture modal

	// sync hooks (injectable for tests; defaults wired in initSync).
	syncAPI           syncx.API
	syncReadBlob      func() ([]byte, error)
	syncOpenBlob      func(blob, password []byte) ([]byte, error)
	syncProjectCrypto syncx.ProjectCrypto
	genIdentity       func() (pub, priv []byte, err error)
	// identityHybridUpgraded records that this session added the ML-KEM half to a
	// pre-existing classical identity, so the publish that follows must replace
	// the server's copy (PublishUpgrade) instead of no-opping on 409.
	identityHybridUpgraded bool

	// --- real projects (real signed-in mode; demo keeps m.projects fixtures) ---
	realProjects      []projectItem                // ordered, from the engine's sync pass
	projectDocs       map[string]*store.ProjectDoc // decrypted docs keyed by project ID
	projDetail        *api.ProjectDetail           // members/invites of the selected project
	receivedInvites   []api.ReceivedInvite         // pending invites addressed to the account
	projConflicts     []syncx.ProjectConflict      // queued per-project conflicts
	projConflict      *syncx.ProjectConflict       // the one being resolved
	projFilterID      string                       // hosts-tab filter by project ID ("" = none)
	projFilterName    string                       // display name for the filter chip
	projectsLoaded    bool                         // a projects sync has landed this session
	identityReady     bool                         // identity loaded into the engine this session
	identityBooting   bool                         // a bootstrap attempt is in flight
	identityNotice    string                       // cross-device "sync first" notice
	identityNeedsSync bool                         // needs-sync state: offer the "R" identity reset

	// Published-key mismatch: the server hands out a public key for this very
	// account that is not the one in this vault, i.e. the key directory cannot be
	// trusted. Both fingerprints are kept so the user can compare them against
	// their other devices.
	identityMismatch bool
	identityLocalFP  string // fingerprint of the key in this vault
	identityServerFP string // fingerprint of the key the server publishes

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

	// member cursor in the projects detail pane (focus == pfMembers): indexes
	// the combined members-then-invites list for d (remove) / x (revoke).
	memberIdx int
	// host cursor in the projects detail pane (focus == pfHosts): indexes the
	// selected project's own hosts.
	projHostIdx int

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
	// connectTo is the host named on the command line, consumed once the vault
	// opens (see handleVaultMsg) and then cleared.
	connectTo string
	// mgr owns port forwards, which are documented as ephemeral and die with
	// the process. Interactive sessions live in pool instead, one child process
	// each, so they survive a quit.
	mgr      *sshx.Manager
	pool     *sessd.Pool
	vault    vaultHandle
	st       *store.Store
	settings store.Settings
	probes   map[string]probe.Result // ephemeral reachability, keyed by host ID
	keyInfos []keys.KeyInfo          // live ~/.ssh scan
	// keysScanned marks the ~/.ssh scan as having returned (it runs async at
	// unlock), so an empty keys tab can tell "none" from "not yet".
	keysScanned bool

	// vault hooks (injectable for tests; default to the real vault package).
	vaultExists  func(string) bool
	openVault    func(string, []byte) (vaultHandle, error)
	createVault  func(string, []byte) (vaultHandle, string, error)
	openRecovery func(string, string) (vaultHandle, error)
	installVault func(path string, blob, password []byte) (vaultHandle, error)

	// boot carries an account sign-in that is mid-flight: the pairing is
	// established but the account's vault has not been installed yet. Nil
	// outside the sign-in flow.
	boot *bootstrapState

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
	formVals       [fCount]string // Name, User, Addr, Port, Tags, AuthMethod, KeyPath, KeyID, Password, ProjectID
	formFocus      int
	formErr        string

	// move-to-project picker (hosts tab): the host being moved, where it lives
	// now, and the cursor over the destination options.
	mvHostID   string
	mvSourceID string
	mvName     string
	mvIdx      int
	mvErr      string

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

	// Session-hint modal: shown once per run after the first successful dial, so
	// the detach/reattach keys are learned before the terminal is handed over.
	// Deliberately not persisted — a UI hint has no business in the synced,
	// zero-knowledge vault payload, and the settings doc is a cross-implementation
	// contract (web, mobile) that a preference like this should not widen.
	sessionHintSeen bool
	pendingAttachID string // session the hint is gating (session ID, not host)

	// Session picker: shown when connecting to a host that already has one or
	// more sessions open. pickHost is the host being connected to, pickIdx the
	// highlighted row (len(sessions) is the "new session" row) and pickKill the
	// *session* armed for a kill, so x never terminates a shell on one keypress.
	// It is an ID, not a row: sessions end on their own while the picker is
	// open, and an index would silently come to mean a different shell.
	pickHost store.Host
	pickIdx  int
	pickKill string

	// --- port forwards (real mode; k9s-style, nothing persisted) ---
	fwdVals     [ffCount]string             // forward-form buffers (see ff* indices)
	fwdFocus    int                         // forward-form focused field
	fwdErr      string                      // inline forward-form validation/engine error
	fwdHost     store.Host                  // the host the form/start operates on
	fwdInFlight bool                        // connecting modal shows "starting forward…"
	fwdIdx      int                         // cursor in the active-forwards overlay
	fwdPrefill  map[string]sshx.ForwardSpec // last submitted spec per host ID (ephemeral prefill)

	// --- remote access ---
	// A grant hands one local process — in practice an AI coding agent — an
	// exec-only capability on exactly one host, riding a connection wharf
	// already holds. None of this is ever persisted: not the token, not the
	// audit log, not the fact that a grant existed. There is no field here that
	// reaches the vault, the store or localcfg, and that is deliberate — a
	// grant dies with wharf, so a restart is itself a revocation, and a token
	// that only ever lived in this process cannot be lifted off a disk.
	//
	// The grant and its audit log are *not* Model state. They live in a
	// remoteaccess.Holder the Model only points at, because the in-session
	// hotkey toggles the grant from the attach byte scanner — a goroutine
	// running while Bubble Tea is suspended, which may not touch a Model that
	// is copied on every update and written only by Update. The Model holds a
	// stable pointer and reads through it, so a grant minted while attached is
	// simply *there* the next time anything renders, with no message to deliver
	// and nothing to synchronise. See internal/remoteaccess.Holder.
	ra *remoteaccess.Holder
	// raCopy is the one piece of grant-adjacent state the Holder does not own:
	// whether the clipboard actually took the command line. It is behind a
	// pointer and its own mutex for the same reason the Holder is — the attach
	// callback records a copy result from its own goroutine — and it is keyed
	// to the grant it describes, so a stale "copied" can never be shown against
	// a grant that was never copied.
	raCopy *raCopyStatus
	// raSel is the overlay cursor, held as the Entry.ID of the selected row
	// rather than as an index: the log grows at the front, so an index-keyed
	// cursor slides onto a different command every time a new one starts. Zero
	// means "the newest row", which is where the overlay opens.
	raSel uint64
	// raErr is an inline error about the last attempt (no live session,
	// unix-only, open failed); raEnded says how a grant that is no longer there
	// ended, for a reader who was in the overlay when it happened and never saw
	// the toast the panel was covering.
	raErr   string
	raEnded string

	importHosts   []store.Host
	importKeys    []store.VaultKey
	importSkipped []string
	// importHostKeys maps host name → vault key name for the pending import,
	// turned into store.Host.KeyID bindings once the keys are in the vault.
	importHostKeys map[string]string
	// importSource is which importer produced importHosts ("ssh_config" or
	// termius.Source). It selects the summary wording and, because only a
	// Termius profile carries passwords, the upsert path.
	importSource string
	// importNote is a source-specific line for the summary, e.g. how many
	// imported hosts brought a saved password with them.
	importNote string

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

// Init starts the animation ticker, and the single consumer of the Holder's
// re-render nudge.
//
// The nudge is armed exactly once, here, and re-armed only by its own message
// handler, because Holder.Changed is a depth-1 channel with one consumer: a
// second waiter would take turns with the first and each would see half the
// nudges. Losing one costs nothing anyway — the nudge carries no data and the
// UI re-reads the whole Holder when it renders — but two consumers would also
// mean two re-arming chains growing without bound.
func (m Model) Init() tea.Cmd {
	return tea.Batch(tickCmd(), waitRemoteAccessChangedCmd(m.ra))
}

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
