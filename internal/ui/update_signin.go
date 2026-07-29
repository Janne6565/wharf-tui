package ui

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/Janne6565/wharf-tui/internal/api"
	"github.com/Janne6565/wharf-tui/internal/store"
	syncx "github.com/Janne6565/wharf-tui/internal/sync"
	"github.com/Janne6565/wharf-tui/internal/vault"
	tea "github.com/charmbracelet/bubbletea"
)

// Signing in to an account and having a local vault are not two independent
// facts about a machine — they used to be, and that was a bug.
//
// A vault blob carries its own password slot and its own recovery slot. An
// account, created in the browser, additionally has server-side credentials
// derived from the *same* password and the *same* recovery code (see the
// zero-knowledge contract in the wharf-backend README). A vault created here,
// offline, has neither: its password and its recovery code are known only to
// this file. Pairing a device used to leave those two worlds side by side,
// which produced two failures. Sync would wedge forever the moment the two
// passwords differed (the remote blob simply cannot be opened), and — worse —
// when they happened to match, the first push replaced the account's blob, and
// with it the recovery slot the browser's reset flow decrypts with. The server
// still expected the account's recovery code, the blob now answered to the
// local one, and neither half worked alone.
//
// So sign-in does not merely pair: it makes the account's vault *be* this
// machine's vault. The blob is installed verbatim (vault.InstallBlob), and
// whatever was in the local vault is merged into it (store.Merge) and pushed
// on the next pass. Afterwards there is exactly one master password and one
// recovery code, valid here, in the browser and on every other device.

// bootstrapState is a sign-in between the pairing and the install.
type bootstrapState struct {
	refresh string
	email   string
	userID  string
	// blob/version are the account's vault as fetched right after pairing.
	blob    []byte
	version int64
	// merge is the payload of the vault this machine had *before* signing in.
	// Non-nil marks the "signed in later" case: those hosts and keys are folded
	// into the account vault rather than dropped. Nil is a first-run sign-in,
	// where there is nothing to keep.
	merge []byte
	// fromGate marks a sign-in started at the first-run gate, so cancelling
	// returns to the local-or-account choice instead of the dashboard.
	fromGate bool
	// skipRetained suppresses the silent attempt with the password the engine
	// holds, for the one caller that already knows it does not open the
	// account vault (a sync that failed on exactly that).
	skipRetained bool
}

// --- messages -----------------------------------------------------------------

// accountFetchedMsg is the result of pairing (first run) or of inspecting the
// account right after pairing (signed in later): the profile plus the account's
// vault blob, or the reason there is none.
type accountFetchedMsg struct {
	boot    *bootstrapState
	noVault bool // the account exists but has never had a master password set
	err     error
}

// vaultInstalledMsg is the result of installing the account vault locally.
type vaultInstalledMsg struct {
	v vaultHandle
	// remote is the payload as downloaded, before the local merge — the
	// content the device is in agreement with at boot.version.
	remote []byte
	// merged reports that local data was folded in, so a push is owed.
	merged store.MergeResult
	pw     string
	// auto marks an attempt made with the password the engine already held,
	// without asking. A rejection then means the account uses a different
	// password, not that the user mistyped one.
	auto bool
	err  error
}

// --- gate: the first-run choice -------------------------------------------------

// chooseKey drives the first-run "local vault or account?" screen. It is shown
// only when no vault file exists; every later run goes straight to the unlock
// prompt (or, once signed in, to the account's own vault).
func (m Model) chooseKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "1", "l", "L":
		m.unlockStep = ulCreate
		m.unlockErr = ""
		m.pwInput, m.pwConfirm, m.pwField = "", "", 0
	case "2", "s", "S":
		m.unlockStep = ulSignInCode
		m.unlockErr = ""
		m.code = ""
	case "q", "ctrl+c":
		return m, tea.Quit
	}
	return m, nil
}

// signInCodeKey drives device-code entry at the gate. The displayed dash form
// (XXXX-XXXX) pastes fine: non-alphanumerics are skipped.
func (m Model) signInCodeKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.unlockStep = ulChoose
		m.code = ""
		m.unlockErr = ""
	case "backspace":
		if len(m.code) > 0 {
			m.code = m.code[:len(m.code)-1]
		}
	case "enter":
		if len(m.code) != 8 {
			return m, nil
		}
		m.unlockStep = ulSignInPairing
		m.unlockErr = ""
		return m.pairAccountCmd(m.code)
	default:
		if isAlnum(key) && len(m.code) < 8 {
			m.code += strings.ToUpper(key)
			m.unlockErr = ""
		}
	}
	return m, nil
}

// signInPasswordKey drives account-master-password entry (shared by both
// sign-in paths — the gate one and the adoption after a later pairing).
func (m Model) signInPasswordKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		return m.cancelSignIn(), nil
	case "backspace":
		if len(m.pwInput) > 0 {
			m.pwInput = m.pwInput[:len(m.pwInput)-1]
		}
	case "enter":
		if m.pwInput == "" {
			m.unlockErr = "enter your account's master password"
			return m, nil
		}
		pw := m.pwInput
		m.unlockStep = ulSignInOpening
		m.unlockErr = ""
		return m, m.installAccountVaultCmd(pw, false)
	default:
		if isPrintable(key) {
			m.pwInput += key
		}
	}
	return m, nil
}

// signInSetupKey acknowledges the "no account vault yet" dead end.
func (m Model) signInSetupKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "enter", "esc", "q":
		return m.cancelSignIn(), nil
	}
	return m, nil
}

// cancelSignIn abandons an in-flight sign-in. A gate sign-in returns to the
// first-run choice; an adoption started from an already unlocked vault returns
// to the dashboard, still paired but not yet synced — the next sync pass
// re-runs the adoption check.
func (m Model) cancelSignIn() Model {
	boot := m.boot
	m.boot = nil
	m.pwInput = ""
	m.code = ""
	m.unlockErr = ""
	if boot != nil && !boot.fromGate {
		m.screen = scMain
		m.tab = m.postAuthTab
		m.syncSt = ssOffline
		return m.setToast("signed in — sync paused until the account vault is unlocked", "err")
	}
	m.unlockStep = ulChoose
	return m
}

// --- commands -------------------------------------------------------------------

// apiClient memoizes the backend client on the model so the gate sign-in, the
// engine built afterwards and every later call share one client — and with it
// the tokens the device-code exchange installed.
func (m *Model) apiClient() syncx.API {
	if m.syncAPI == nil {
		m.syncAPI = api.New(api.BaseURL())
	}
	return m.syncAPI
}

// pairAccountCmd exchanges a device code and fetches the account's vault. It
// runs at the gate, before any vault exists, so it cannot go through the sync
// engine (which needs an unlocked vault to seal its session file) and talks to
// the API client directly. Nothing is persisted until the vault is installed.
func (m Model) pairAccountCmd(code string) (tea.Model, tea.Cmd) {
	client := m.apiClient()
	host, _ := os.Hostname()
	return m, func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), syncTimeout)
		defer cancel()
		sess, err := client.ExchangeDeviceCode(ctx, code, host)
		if err != nil {
			return accountFetchedMsg{err: err}
		}
		boot := &bootstrapState{
			refresh:  sess.RefreshToken,
			email:    sess.Email,
			userID:   sess.UserID,
			fromGate: true,
		}
		return fetchAccountVault(ctx, client, boot)
	}
}

// adoptAccountVaultCmd is the same inspection for a device that paired the
// normal way, with an unlocked local vault already open. The pairing lives in
// the engine by then, so only the vault has to be fetched.
func (m Model) adoptAccountVaultCmd(tryRetained bool) tea.Cmd {
	client := m.apiClient()
	eng := m.eng
	local := append([]byte(nil), m.vault.Payload()...)
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), syncTimeout)
		defer cancel()
		boot := &bootstrapState{email: eng.Email(), merge: local, skipRetained: !tryRetained}
		return fetchAccountVault(ctx, client, boot)
	}
}

// fetchAccountVault fills boot with the account's vault, or reports why there
// is none. An account without a vault has never had a master password set
// (it was created through OAuth): the TUI deliberately does not offer to set
// one, because doing so means re-implementing the browser's account-credential
// derivation, and a second implementation of that is exactly how the two sides
// drift apart again.
func fetchAccountVault(ctx context.Context, client syncx.API, boot *bootstrapState) accountFetchedMsg {
	// HasPassword is checked alongside HasVault because the two are set
	// together, by the browser, in one atomic step: an account missing either
	// has no password credentials on the server, and pushing this machine's
	// vault into it is precisely the split-brain this flow exists to prevent.
	if prof, err := client.Me(ctx); err != nil {
		return accountFetchedMsg{boot: boot, err: err}
	} else if !prof.HasVault || !prof.HasPassword {
		return accountFetchedMsg{boot: boot, noVault: true}
	}
	rv, err := client.GetVault(ctx)
	if errors.Is(err, api.ErrNoVault) {
		return accountFetchedMsg{boot: boot, noVault: true}
	}
	if err != nil {
		return accountFetchedMsg{boot: boot, err: err}
	}
	boot.blob = rv.Blob
	boot.version = rv.Version
	return accountFetchedMsg{boot: boot}
}

// installAccountVaultCmd opens the account blob with pw and makes it this
// machine's vault file, folding in whatever the local vault held.
//
// The order matters. The password is checked against the downloaded blob
// first, while the old vault is still open and untouched, so a typo costs
// nothing. Only then is the old vault closed (releasing its lock) and the blob
// written. The write itself is atomic, so a failure past that point leaves a
// readable vault file on disk — the old one or the new one, never a mixture.
func (m Model) installAccountVaultCmd(pw string, auto bool) tea.Cmd {
	boot := m.boot
	path := m.vaultPath
	openBlob := m.blobOpener()
	install := m.installVault
	old := m.vault
	return func() tea.Msg {
		fail := func(err error) tea.Msg {
			return vaultInstalledMsg{err: err, pw: pw, auto: auto}
		}
		remote, err := openBlob(boot.blob, []byte(pw))
		if err != nil {
			return fail(err)
		}
		merged, res := remote, store.MergeResult{}
		if boot.merge != nil {
			merged, res, err = store.Merge(remote, boot.merge)
			if err != nil {
				return fail(err)
			}
		}
		if old != nil {
			_ = old.Close()
		}
		v, err := install(path, boot.blob, []byte(pw))
		if err != nil {
			return fail(err)
		}
		if res.Any() {
			if err := v.Save(merged); err != nil {
				return fail(err)
			}
		}
		return vaultInstalledMsg{v: v, remote: remote, merged: res, pw: pw}
	}
}

// --- message handlers -------------------------------------------------------------

func (m Model) handleAccountFetched(msg accountFetchedMsg) (tea.Model, tea.Cmd) {
	if msg.boot != nil {
		m.boot = msg.boot
	}
	switch {
	case msg.err != nil:
		return m.signInFailed(msg.err)

	case msg.noVault:
		if m.boot != nil && !m.boot.fromGate {
			// Paired from a running session: keep the pairing (the account is
			// real, it is just unfinished) but do not push this machine's vault
			// into it — that is what used to strand the account's recovery code.
			m.syncSt = ssOffline
			m.screen = scMain
			m.tab = m.postAuthTab
			m.boot = nil
			return m.setToast("no account vault yet — set a master password at "+
				stripScheme(api.SetPasswordURL(apiBaseDisplay())), "err"), nil
		}
		m.screen = scUnlock
		m.unlockStep = ulSignInSetup
		return m, nil

	default:
		// A device that already had an unlocked vault has its master password
		// in the engine, and it is usually the account's too. Try it before
		// asking — but in the command, not here: this is an argon2id
		// derivation at the pinned cost, and the UI goroutine must not stall
		// on it.
		if pw := m.retainedPassword(); pw != "" && !m.boot.skipRetained {
			m.screen = scUnlock
			m.unlockStep = ulSignInOpening
			m.unlockErr = ""
			return m, m.installAccountVaultCmd(pw, true)
		}
		m.screen = scUnlock
		m.unlockStep = ulSignInPassword
		m.pwInput = ""
		m.unlockErr = ""
		return m, nil
	}
}

// signInFailed reports a pairing/fetch failure on whichever screen the user is
// looking at.
func (m Model) signInFailed(err error) (tea.Model, tea.Cmd) {
	fromGate := m.boot == nil || m.boot.fromGate
	m.boot = nil
	if fromGate {
		m.screen = scUnlock
		m.unlockStep = ulSignInCode
		m.unlockErr = pairErrText(err)
		return m, nil
	}
	// Already paired and on the dashboard: the account is reachable enough to
	// have paired, so this is a transient failure. Stay signed in and let the
	// next sync pass retry the adoption.
	m.syncSt = ssOffline
	m.screen = scMain
	m.tab = m.postAuthTab
	return m.setToast("signed in — could not read the account vault yet", "err"), nil
}

func (m Model) handleVaultInstalled(msg vaultInstalledMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		if errors.Is(msg.err, vault.ErrWrongSecret) {
			m.unlockStep = ulSignInPassword
			m.pwInput = ""
			if msg.auto {
				m.unlockErr = "this account's vault uses a different master password"
			} else {
				m.unlockErr = "wrong master password for " + m.bootEmail()
			}
			return m, nil
		}
		if m.vault == nil {
			// The old vault was closed before the failure: there is nothing to
			// go back to but the unlock prompt.
			m.st = nil
			m = m.closeSync()
			m.signedIn = false
			m.unlockStep = ulUnlock
			m.unlockErr = "sign-in failed: " + msg.err.Error()
			m.boot = nil
			return m, nil
		}
		m.unlockStep = ulSignInPassword
		m.unlockErr = "sign-in failed: " + msg.err.Error()
		return m, nil
	}

	boot := m.boot
	m.boot = nil
	m.pwInput, m.code = "", ""
	m.vault = msg.v
	// The old engine was keyed to the old vault's DEK; the session file it
	// wrote is unreadable under the new one and is replaced by Attach below.
	m = m.closeSync()
	if err := m.openStoreFromVault(); err != nil {
		m.unlockStep = ulUnlock
		m.unlockErr = err.Error()
		return m, nil
	}
	m = m.initSync(msg.pw)
	if m.eng == nil {
		m.unlockStep = ulUnlock
		m.unlockErr = "could not start sync for the account vault"
		return m, nil
	}
	if err := m.eng.Attach(syncx.Pairing{
		RefreshToken: m.bootRefresh(boot),
		Email:        boot.email,
		UserID:       boot.userID,
		Version:      boot.version,
		Payload:      msg.remote,
	}); err != nil {
		m.unlockStep = ulUnlock
		m.unlockErr = "could not store the account session: " + err.Error()
		return m, nil
	}
	m.signedIn = true
	m.email = boot.email

	var cmd tea.Cmd
	if boot.fromGate {
		var next tea.Model
		next, cmd = m.enterMain()
		m = next.(Model)
	} else {
		// Adoption from a running session: the dashboard is already up, so only
		// the state that the swapped-out vault invalidated is refreshed.
		m.screen = scMain
		m.tab = m.postAuthTab
		m.authStep = 0
		m.hostIdx = clampIdx(m.hostIdx, len(m.filteredHosts()))
		cmd = m.afterUnlockCmds()
	}
	m = m.setToast(installedToast(boot, msg.merged), "ok")
	// A merge is a local change against the version just adopted, so the sync
	// pass this starts pushes it.
	m, sync := m.startSync()
	m, projects := m.bootstrapProjects()
	return m, tea.Batch(cmd, sync, projects)
}

// installedToast summarizes what the sign-in did to this machine's vault.
func installedToast(boot *bootstrapState, res store.MergeResult) string {
	msg := "signed in as " + boot.email
	if boot.merge == nil {
		return msg + " — this vault now uses your account password and recovery code"
	}
	msg += " — account vault adopted"
	if res.HostsAdded > 0 {
		msg += ", " + plural(res.HostsAdded, "local host") + " kept"
	}
	if res.HostsSkipped > 0 {
		msg += ", " + plural(res.HostsSkipped, "name clash") + " skipped"
	}
	return msg
}

// bootEmail is the account address of the sign-in in flight ("" if none).
func (m Model) bootEmail() string {
	if m.boot == nil {
		return "this account"
	}
	return m.boot.email
}

// bootRefresh is the refresh token for the pairing: the gate flow carries its
// own, while an adoption reuses the one the engine already stored.
func (m Model) bootRefresh(boot *bootstrapState) string {
	if boot.refresh != "" {
		return boot.refresh
	}
	return m.syncAPI.RefreshToken()
}

// retainedPassword returns the master password the engine holds for the
// currently unlocked vault ("" when signed out or locked).
func (m Model) retainedPassword() string {
	if m.eng == nil {
		return ""
	}
	pw := m.eng.MasterPassword()
	defer func() {
		for i := range pw {
			pw[i] = 0
		}
	}()
	return string(pw)
}
