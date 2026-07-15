package ui

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/Janne6565/wharf-tui/internal/api"
	syncx "github.com/Janne6565/wharf-tui/internal/sync"
	"github.com/Janne6565/wharf-tui/internal/vault"
	tea "github.com/charmbracelet/bubbletea"
)

// pushDebounce is how long after the last vault save a push is triggered, so
// a burst of edits becomes one upload.
const pushDebounce = 3 * time.Second

// syncTimeout bounds one full sync pass (network + argon2 on a remote blob).
const syncTimeout = 60 * time.Second

// --- messages -----------------------------------------------------------------

// pairedMsg is the result of a device-code exchange.
type pairedMsg struct {
	email string
	err   error
}

// sessionResumedMsg reports whether a stored session was restored at unlock.
type sessionResumedMsg struct {
	email string
	ok    bool
}

// syncDoneMsg carries the outcome of one engine pass (Sync or Resolve).
type syncDoneMsg struct {
	res syncx.Result
}

// syncPushTimerMsg fires after the push debounce; stale generations are
// dropped so only the last save in a burst triggers a sync.
type syncPushTimerMsg struct {
	gen int
}

// --- engine lifecycle ---------------------------------------------------------

// initSync builds the sync engine for a freshly unlocked vault. pw is the
// master password that just opened (or re-keyed) the vault; the engine
// retains it in memory for remote-blob unlocks and zeroes it on Close. Demo
// mode never gets an engine.
func (m Model) initSync(pw string) Model {
	if m.demo || m.vault == nil {
		return m
	}
	key, err := m.vault.DeriveKey(syncx.SessionKeyInfo)
	if err != nil {
		return m // closed vault — no sync this session
	}
	apiClient := m.syncAPI
	if apiClient == nil {
		apiClient = api.New(api.BaseURL())
	}
	readBlob := m.syncReadBlob
	if readBlob == nil {
		path := m.vaultPath
		readBlob = func() ([]byte, error) { return os.ReadFile(path) }
	}
	openBlob := m.syncOpenBlob
	if openBlob == nil {
		openBlob = vault.OpenPayload
	}
	host, _ := os.Hostname()
	m.eng = syncx.New(syncx.Config{
		API:         apiClient,
		SessionPath: syncx.SessionPath(m.vaultPath),
		Key:         key,
		Password:    []byte(pw),
		DeviceName:  host,
		ReadBlob:    readBlob,
		OpenBlob:    openBlob,
	})
	return m
}

// closeSync tears the engine down (lock/quit), zeroing its secrets.
func (m Model) closeSync() Model {
	if m.eng != nil {
		m.eng.Close()
		m.eng = nil
	}
	m.syncSt = ssNone
	m.conflict = nil
	return m
}

// --- commands -----------------------------------------------------------------

// resumeSyncCmd restores a stored pairing after unlock.
func (m Model) resumeSyncCmd() tea.Cmd {
	eng := m.eng
	if eng == nil {
		return nil
	}
	return func() tea.Msg {
		email, ok := eng.Resume()
		return sessionResumedMsg{email: email, ok: ok}
	}
}

// pairCmd exchanges the typed device code for a session.
func (m Model) pairCmd(code string) tea.Cmd {
	eng := m.eng
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), syncTimeout)
		defer cancel()
		email, err := eng.Pair(ctx, code)
		return pairedMsg{email: email, err: err}
	}
}

// syncNowCmd runs one full sync pass against the current saved payload. The
// payload is captured here, on the UI goroutine, so the engine never touches
// the live vault handle.
func (m Model) syncNowCmd() tea.Cmd {
	if m.eng == nil || m.vault == nil {
		return nil
	}
	eng, payload := m.eng, m.vault.Payload()
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), syncTimeout)
		defer cancel()
		return syncDoneMsg{res: eng.Sync(ctx, payload)}
	}
}

// resolveCmd settles the pending conflict with the user's choice.
func (m Model) resolveCmd(keepLocal bool) tea.Cmd {
	if m.eng == nil || m.vault == nil {
		return nil
	}
	eng, payload := m.eng, m.vault.Payload()
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), syncTimeout)
		defer cancel()
		return syncDoneMsg{res: eng.Resolve(ctx, keepLocal, payload)}
	}
}

// startSync flips the indicator and fires a pass (used by every trigger).
func (m Model) startSync() (Model, tea.Cmd) {
	cmd := m.syncNowCmd()
	if cmd == nil {
		return m, nil
	}
	m.syncSt = ssSyncing
	return m, cmd
}

// saveVault persists the store and, when signed in, schedules a debounced
// push. It replaces bare st.Save() calls on every data mutation.
func (m Model) saveVault() (Model, tea.Cmd) {
	if m.st != nil {
		_ = m.st.Save()
	}
	return m.schedulePush()
}

// schedulePush arms (or re-arms) the push debounce timer.
func (m Model) schedulePush() (Model, tea.Cmd) {
	if m.eng == nil || !m.signedIn {
		return m, nil
	}
	m.syncGen++
	gen := m.syncGen
	return m, tea.Tick(pushDebounce, func(time.Time) tea.Msg { return syncPushTimerMsg{gen: gen} })
}

// --- message handlers ---------------------------------------------------------

func (m Model) handlePaired(msg pairedMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		// Only surface the failure if the user is still on the code screen.
		if m.screen == scAuth {
			m.authStep = 1
			m.authErr = pairErrText(msg.err)
		}
		return m, nil
	}
	m.signedIn = true
	m.email = msg.email
	m.authErr = ""
	m.code = ""
	m.authStep = 0
	if m.screen == scAuth {
		m.screen = scMain
		m.tab = m.postAuthTab
	}
	m = m.setToast("signed in as "+msg.email, "ok")
	return m.startSync()
}

// pairErrText renders a pairing failure for the code screen.
func pairErrText(err error) string {
	var ae *api.Error
	if errors.As(err, &ae) {
		switch ae.Status {
		case 404:
			return "code not found — check for typos"
		case 410:
			return "code expired or already used — get a fresh one"
		}
		return ae.Error()
	}
	return "could not reach the server: " + err.Error()
}

func (m Model) handleSessionResumed(msg sessionResumedMsg) (tea.Model, tea.Cmd) {
	if !msg.ok {
		return m, nil
	}
	m.signedIn = true
	m.email = msg.email
	return m.startSync()
}

func (m Model) handleSyncDone(msg syncDoneMsg) (tea.Model, tea.Cmd) {
	if m.eng == nil {
		// The vault was locked while a pass was in flight; the result is
		// stale (the engine already zeroed its secrets under its own lock).
		return m, nil
	}
	res := msg.res
	switch {
	case res.SignedOut:
		m.syncSt = ssNone
		return m, nil

	case res.SessionDead:
		m.signedIn = false
		m.email = ""
		m.syncSt = ssNone
		m.conflict = nil
		return m.setToast("sync session expired — sign in again to re-pair", "err"), nil

	case res.Err != nil:
		m.syncSt = ssOffline
		if errors.Is(res.Err, vault.ErrWrongSecret) {
			return m.setToast("remote vault uses a different master password — cannot sync", "err"), nil
		}
		return m, nil

	case res.Conflict != nil:
		m.conflict = res.Conflict
		m.syncSt = ssConflict
		if m.modal == modalNone {
			m.modal = modalSyncConflict
		}
		return m, nil

	case res.Adopt != nil:
		return m.adoptRemote(res)

	default:
		m.syncSt = ssSynced
		m.conflict = nil
		if res.Pushed {
			return m.setToast("synced — changes uploaded", "ok"), nil
		}
		return m, nil
	}
}

// adoptRemote writes a pulled payload into the local vault (re-encrypting
// under the local DEK via the normal save path), reloads the store, and
// confirms the pull to the engine.
func (m Model) adoptRemote(res syncx.Result) (tea.Model, tea.Cmd) {
	if m.vault == nil {
		m.syncSt = ssOffline
		return m, nil
	}
	if err := m.vault.Save(res.Adopt); err != nil {
		m.syncSt = ssOffline
		return m.setToast("could not write synced vault: "+err.Error(), "err"), nil
	}
	if err := m.openStoreFromVault(); err != nil {
		m.syncSt = ssOffline
		return m.setToast("synced vault unreadable: "+err.Error(), "err"), nil
	}
	if m.eng != nil {
		_ = m.eng.CommitAdopt(res.AdoptVersion, res.Adopt)
	}
	m.hostIdx = clampIdx(m.hostIdx, len(m.filteredHosts()))
	m.syncSt = ssSynced
	m.conflict = nil
	m = m.setToast("synced — pulled remote changes", "ok")
	return m, m.probeCmds()
}

func (m Model) handleSyncPushTimer(msg syncPushTimerMsg) (tea.Model, tea.Cmd) {
	if msg.gen != m.syncGen || m.eng == nil || !m.signedIn {
		return m, nil // superseded by a later save, or signed out meanwhile
	}
	if m.syncSt == ssSyncing || m.syncSt == ssConflict {
		// A pass is running (its result covers this save) or a conflict is
		// pending (pushing would be resolved by the user's choice anyway).
		return m, nil
	}
	return m.startSync()
}

// signOut deletes the device pairing; the local vault is untouched.
func (m Model) signOut() Model {
	if m.eng != nil {
		m.eng.SignOut()
	}
	m.signedIn = false
	m.email = ""
	m.syncSt = ssNone
	m.conflict = nil
	return m.setToast("signed out — local vault kept", "ok")
}

// --- conflict modal -----------------------------------------------------------

func (m Model) syncConflictKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "l", "L":
		m.modal = modalNone
		m.conflict = nil
		m.syncSt = ssSyncing
		return m, m.resolveCmd(true)
	case "r", "R":
		m.modal = modalNone
		m.conflict = nil
		m.syncSt = ssSyncing
		return m, m.resolveCmd(false)
	case "esc":
		// Decide later: the header keeps showing the conflict; a manual sync
		// reopens the prompt.
		m.modal = modalNone
	}
	return m, nil
}
