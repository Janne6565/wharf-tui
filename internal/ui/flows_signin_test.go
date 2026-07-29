package ui

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Janne6565/wharf-tui/internal/store"
	syncx "github.com/Janne6565/wharf-tui/internal/sync"
	"github.com/Janne6565/wharf-tui/internal/vault"
	tea "github.com/charmbracelet/bubbletea"
)

// accountVaultWith renders an account vault payload holding the named hosts.
func accountVaultWith(t *testing.T, names ...string) []byte {
	t.Helper()
	hosts := make([]store.Host, 0, len(names))
	for i, n := range names {
		hosts = append(hosts, store.Host{
			ID: "acct" + itoa(i), Name: n, User: "root",
			Addr: n + ".example.com", Port: 22, Source: "manual",
		})
	}
	doc := map[string]any{
		"schema":   3,
		"hosts":    hosts,
		"settings": store.DefaultSettings(),
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal account vault: %v", err)
	}
	return b
}

// addHost drives the host form on the hosts tab.
func addHost(t *testing.T, tm tea.Model, name, addr string) tea.Model {
	t.Helper()
	tm = send(tm, runes("1")) // hosts tab
	tm = send(tm, runes("a")) // add
	tm = typeStr(tm, name)
	tm = send(tm, special(tea.KeyTab)) // → user
	tm = send(tm, special(tea.KeyTab)) // → address
	tm = typeStr(tm, addr)
	tm, _ = step(tm, special(tea.KeyEnter))
	return tm
}

// freshModel is a first-run model (no vault file) wired to a fake backend.
func freshModel(t *testing.T, fb *fakeBackend) (tea.Model, *fakeVault) {
	t.Helper()
	fv := &fakeVault{}
	created := false
	m := New(Config{
		VaultPath:   filepath.Join(t.TempDir(), "vault.enc"),
		VaultExists: func(string) bool { return false },
		CreateVault: func(string, []byte) (vaultHandle, string, error) {
			created = true
			return fv, code40, nil
		},
		SyncAPI: fb,
		// Blob == payload for tests, but only the right password opens it.
		SyncReadBlob: func() ([]byte, error) { return fv.Payload(), nil },
		SyncOpenBlob: func(blob, pw []byte) ([]byte, error) {
			if string(pw) != "account-pw" {
				return nil, vault.ErrWrongSecret
			}
			return blob, nil
		},
		InstallVault: func(_ string, blob, pw []byte) (vaultHandle, error) {
			if string(pw) != "account-pw" {
				return nil, vault.ErrWrongSecret
			}
			fv.payload = append([]byte(nil), blob...)
			fv.installs++
			fv.closed = false
			return fv, nil
		},
	})
	var tm tea.Model = m
	tm = send(tm, tea.WindowSizeMsg{Width: 100, Height: 32})
	t.Cleanup(func() {
		if created && fv.installs > 0 {
			t.Error("signing in must not also create a local vault")
		}
	})
	return tm, fv
}

// signInAtGate drives the first-run gate through "2 → code → password".
func signInAtGate(t *testing.T, tm tea.Model, pw string) tea.Model {
	t.Helper()
	tm = send(tm, runes("2")) // sign in to an account
	if !strings.Contains(tm.View(), "pairing code") {
		t.Fatalf("choosing an account should ask for a pairing code:\n%s", tm.View())
	}
	tm = typeStr(tm, "K7PQ-M2XR")
	tm, cmd := step(tm, special(tea.KeyEnter))
	if cmd == nil {
		t.Fatal("the code submit should pair")
	}
	tm, _ = step(tm, cmd()) // accountFetchedMsg
	if !strings.Contains(tm.View(), "account master password") {
		return tm // caller is testing a non-password outcome
	}
	tm = typeStr(tm, pw)
	tm, cmd = step(tm, special(tea.KeyEnter))
	if cmd == nil {
		t.Fatal("the password submit should install the account vault")
	}
	return drainCmd(t, tm, cmd)
}

// The first run offers the choice, and it is the *only* time it is offered:
// a machine with a vault goes straight to the unlock prompt.
func TestFirstRunOffersAccountChoice(t *testing.T) {
	tm, _ := freshModel(t, &fakeBackend{})
	v := tm.View()
	if !strings.Contains(v, "Use Wharf on this machine only") || !strings.Contains(v, "Sign in to a Wharf account") {
		t.Fatalf("first run should offer both options:\n%s", v)
	}

	existing := New(Config{VaultPath: "/tmp/none", VaultExists: func(string) bool { return true }})
	var em tea.Model = existing
	em = send(em, tea.WindowSizeMsg{Width: 100, Height: 32})
	if strings.Contains(em.View(), "get started") {
		t.Fatalf("an existing vault must not re-ask the first-run question:\n%s", em.View())
	}
}

// Signing in at the gate installs the account's own vault rather than creating
// a second one, so the account's master password and recovery code are the
// only ones this machine has.
func TestFirstRunSignInInstallsAccountVault(t *testing.T) {
	fb := &fakeBackend{vault: accountVaultWith(t, "prod-api"), version: 4}
	tm, fv := freshModel(t, fb)
	tm = signInAtGate(t, tm, "account-pw")

	m := tm.(Model)
	if !m.signedIn || m.email != "deniz@example.com" {
		t.Fatalf("gate sign-in should sign in, got signedIn=%v email=%q", m.signedIn, m.email)
	}
	if fv.installs != 1 {
		t.Fatalf("the account vault should be installed once, got %d", fv.installs)
	}
	if !strings.Contains(tm.View(), "prod-api") {
		t.Fatalf("the account's hosts should be on the dashboard:\n%s", tm.View())
	}
	// Agreement was recorded at the fetched version, so nothing is pushed back.
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if fb.version != 4 {
		t.Fatalf("a fresh sign-in should not rewrite the account vault, version = %d", fb.version)
	}
}

func TestFirstRunSignInWrongPassword(t *testing.T) {
	fb := &fakeBackend{vault: accountVaultWith(t, "prod-api"), version: 1}
	tm, fv := freshModel(t, fb)
	tm = signInAtGate(t, tm, "nope")

	if fv.installs != 0 {
		t.Fatal("a wrong password must not install anything")
	}
	if !strings.Contains(tm.View(), "wrong master password") {
		t.Fatalf("the wrong password should be reported:\n%s", tm.View())
	}
	if tm.(Model).signedIn {
		t.Fatal("a wrong password must not reach the dashboard")
	}
}

// An account created through OAuth has no vault: the browser has to set the
// master password, because that is the one step that mints the account's
// server-side credentials alongside the vault blob.
func TestFirstRunSignInWithoutAccountVault(t *testing.T) {
	tm, fv := freshModel(t, &fakeBackend{noVault: true})
	tm = signInAtGate(t, tm, "account-pw")

	v := tm.View()
	if !strings.Contains(v, "no vault yet") || !strings.Contains(v, "set-password") {
		t.Fatalf("the browser hand-off should be explained:\n%s", v)
	}
	if fv.installs != 0 || tm.(Model).signedIn {
		t.Fatal("an unfinished account must not become this machine's vault")
	}
	// Enter goes back to the choice, so local-only is still reachable.
	tm, _ = step(tm, special(tea.KeyEnter))
	if !strings.Contains(tm.View(), "get started") {
		t.Fatalf("acknowledging should return to the first-run choice:\n%s", tm.View())
	}
}

func TestFirstRunSignInBadCode(t *testing.T) {
	tm, _ := freshModel(t, &fakeBackend{badCode: true})
	tm = signInAtGate(t, tm, "account-pw")
	if !strings.Contains(tm.View(), "code not found") {
		t.Fatalf("a rejected code should be reported at the gate:\n%s", tm.View())
	}
	// esc returns to the choice rather than stranding the user.
	tm, _ = step(tm, special(tea.KeyEsc))
	if !strings.Contains(tm.View(), "get started") {
		t.Fatalf("esc should return to the first-run choice:\n%s", tm.View())
	}
}

func TestFirstRunLocalChoiceStillCreatesAVault(t *testing.T) {
	tm, _ := freshModel(t, &fakeBackend{})
	tm = send(tm, runes("1"))
	if !strings.Contains(tm.View(), "create vault") {
		t.Fatalf("the local choice should lead to vault creation:\n%s", tm.View())
	}
}

// The reason this flow exists: a machine that used wharf locally and signs in
// later adopts the account vault, keeping its own hosts, instead of pushing a
// blob whose recovery slot the account has never seen.
func TestLaterSignInAdoptsAccountVaultAndKeepsLocalHosts(t *testing.T) {
	tm, fv, fb := syncedModel(t)
	fb.mu.Lock()
	fb.vault = accountVaultWith(t, "prod-api")
	fb.version = 9
	fb.mu.Unlock()

	// A host added before signing in.
	tm = addHost(t, tm, "homelab", "10.0.0.5")

	tm = gotoSettingRow(t, tm, "account")
	tm, _ = step(tm, special(tea.KeyEnter)) // sign-in intro
	tm, _ = step(tm, special(tea.KeyEnter)) // → code entry
	tm = typeStr(tm, "K7PQM2XR")
	tm, cmd := step(tm, special(tea.KeyEnter))
	tm, adopt := step(tm, cmd()) // pairedMsg → fetch the account vault
	if adopt == nil {
		t.Fatal("pairing should fetch the account vault, not push the local one")
	}
	tm, install := step(tm, adopt()) // accountFetchedMsg → install (password matches)
	if install == nil {
		t.Fatalf("the retained master password should install without prompting:\n%s", tm.View())
	}
	tm = drainCmd(t, tm, install)

	if fv.installs != 1 {
		t.Fatalf("the account vault should replace the local one, installs = %d", fv.installs)
	}
	var doc struct {
		Hosts []store.Host `json:"hosts"`
	}
	if err := json.Unmarshal(fv.Payload(), &doc); err != nil {
		t.Fatalf("unmarshal merged payload: %v", err)
	}
	names := map[string]bool{}
	for _, h := range doc.Hosts {
		names[h.Name] = true
	}
	if !names["prod-api"] || !names["homelab"] {
		t.Fatalf("both sides should survive the adoption, got %v", names)
	}
	// The merge is a local change against the adopted version, so it is pushed.
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if fb.version != 10 {
		t.Fatalf("the merge should be pushed once, version = %d", fb.version)
	}
}

// Pairing with an account that never finished setup keeps the pairing but
// refuses to push: uploading this machine's blob is what used to strand the
// account's recovery code.
func TestLaterSignInWithoutAccountVaultDoesNotPush(t *testing.T) {
	tm, _, fb := syncedModel(t)
	fb.mu.Lock()
	fb.noVault = true
	fb.vault = nil
	fb.version = 0
	fb.mu.Unlock()
	tm = addHost(t, tm, "homelab", "10.0.0.5")

	tm = gotoSettingRow(t, tm, "account")
	tm, _ = step(tm, special(tea.KeyEnter))
	tm, _ = step(tm, special(tea.KeyEnter))
	tm = typeStr(tm, "K7PQM2XR")
	tm, cmd := step(tm, special(tea.KeyEnter))
	tm, adopt := step(tm, cmd())
	tm = drainCmd(t, tm, adopt)

	if !strings.Contains(tm.View(), "set-password") {
		t.Fatalf("the browser hand-off should be surfaced:\n%s", tm.View())
	}
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if !fb.noVault {
		t.Fatal("an account with no vault must not be given this machine's blob")
	}
}

// A sync that cannot open the account vault is not terminal any more: it
// offers the adoption, which asks for the account's password and merges this
// machine's hosts into it.
func TestWedgedSyncOffersAdoption(t *testing.T) {
	tm, fv, fb := syncedModel(t)
	// The account vault opens only with "account-pw"; this machine unlocked
	// with "pw", so the engine's retained password is the wrong one.
	m := tm.(Model)
	m.syncOpenBlob = func(blob, pw []byte) ([]byte, error) {
		if string(pw) != "account-pw" {
			return nil, vault.ErrWrongSecret
		}
		return blob, nil
	}
	m.installVault = func(_ string, blob, pw []byte) (vaultHandle, error) {
		if string(pw) != "account-pw" {
			return nil, vault.ErrWrongSecret
		}
		fv.payload = append([]byte(nil), blob...)
		fv.installs++
		fv.closed = false
		return fv, nil
	}
	tm = m

	fb.mu.Lock()
	fb.vault = accountVaultWith(t, "prod-api")
	fb.version = 3
	fb.mu.Unlock()

	tm, next := step(tm, syncDoneMsg{res: syncx.Result{Err: vault.ErrWrongSecret}})
	if next == nil {
		t.Fatal("a password mismatch should offer the adoption instead of wedging")
	}
	tm = drainCmd(t, tm, next) // fetch → auto attempt skipped → prompt
	if !strings.Contains(tm.View(), "account master password") {
		t.Fatalf("the adoption should ask for the account password:\n%s", tm.View())
	}

	tm = typeStr(tm, "account-pw")
	tm, cmd := step(tm, special(tea.KeyEnter))
	tm = drainCmd(t, tm, cmd)
	if fv.installs != 1 {
		t.Fatalf("the account vault should be installed, installs = %d", fv.installs)
	}
	if !strings.Contains(tm.View(), "prod-api") {
		t.Fatalf("the account's hosts should be on the dashboard:\n%s", tm.View())
	}
}

// The engine's API client holds the session tokens, and the adoption calls
// Me/GetVault outside the engine. Both must be the same client, or every
// adoption after a resumed session authenticates as nobody.
func TestSyncEngineAndSignInShareOneAPIClient(t *testing.T) {
	fv := &fakeVault{}
	m := New(Config{
		VaultPath:   filepath.Join(t.TempDir(), "vault.enc"),
		VaultExists: func(string) bool { return true },
		OpenVault:   func(string, []byte) (vaultHandle, error) { return fv, nil },
	})
	var tm tea.Model = m
	tm = send(tm, tea.WindowSizeMsg{Width: 100, Height: 32})
	tm = typeStr(tm, "pw")
	tm, cmd := step(tm, special(tea.KeyEnter))
	tm, _ = step(tm, cmd()) // vaultOpenedMsg → initSync

	got := tm.(Model)
	if got.eng == nil {
		t.Fatal("unlock should build a sync engine")
	}
	if got.syncAPI == nil {
		t.Fatal("initSync must memoize its API client on the model")
	}
	// apiClient() must hand back that very client rather than minting another.
	if got.apiClient() != got.syncAPI {
		t.Fatal("the sign-in flow must reuse the engine's client, tokens and all")
	}
}
