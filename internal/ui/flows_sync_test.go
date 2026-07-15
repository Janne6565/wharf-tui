package ui

import (
	"context"
	"path/filepath"
	"strings"
	stdsync "sync"
	"testing"

	"github.com/Janne6565/wharf-tui/internal/api"
	syncx "github.com/Janne6565/wharf-tui/internal/sync"
	tea "github.com/charmbracelet/bubbletea"
)

// fakeBackend is an in-memory sync backend for UI tests: one vault slot with
// optimistic versioning. Blobs are the payload bytes verbatim (the fake
// OpenBlob is the identity), so tests reason in payloads only.
type fakeBackend struct {
	mu      stdsync.Mutex
	vault   []byte
	version int64
	noVault bool
	badCode bool
}

func (f *fakeBackend) ExchangeDeviceCode(_ context.Context, code, _ string) (api.Session, error) {
	if f.badCode || api.NormalizeCode(code) != "K7PQM2XR" {
		return api.Session{}, &api.Error{Status: 404, Detail: "unknown code"}
	}
	return api.Session{UserID: "u1", Email: "deniz@example.com", AccessToken: "acc", RefreshToken: "ref"}, nil
}

func (f *fakeBackend) GetVault(context.Context) (api.Vault, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.noVault {
		return api.Vault{}, api.ErrNoVault
	}
	return api.Vault{Blob: append([]byte(nil), f.vault...), Version: f.version}, nil
}

func (f *fakeBackend) PutVault(_ context.Context, blob []byte, expectedVersion int64) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.noVault && expectedVersion != f.version {
		return 0, api.ErrVaultConflict
	}
	f.noVault = false
	f.vault = append([]byte(nil), blob...)
	f.version++
	return f.version, nil
}

func (f *fakeBackend) SetTokens(string, string) {}
func (f *fakeBackend) RefreshToken() string     { return "ref" }

// syncedModel returns a real-mode model unlocked over a fake vault and wired
// to a fake backend, plus both fakes.
func syncedModel(t *testing.T) (tea.Model, *fakeVault, *fakeBackend) {
	t.Helper()
	fv := &fakeVault{}
	fb := &fakeBackend{noVault: true}
	m := New(Config{
		VaultPath:   filepath.Join(t.TempDir(), "vault.enc"),
		VaultExists: func(string) bool { return true },
		OpenVault:   func(string, []byte) (vaultHandle, error) { return fv, nil },
		SyncAPI:     fb,
		// Blob == payload for tests; OpenBlob is the identity.
		SyncReadBlob: func() ([]byte, error) { return fv.Payload(), nil },
		SyncOpenBlob: func(blob, _ []byte) ([]byte, error) { return blob, nil },
	})
	var tm tea.Model = m
	tm = send(tm, tea.WindowSizeMsg{Width: 100, Height: 32})
	tm = typeStr(tm, "pw")
	tm, cmd := step(tm, special(tea.KeyEnter))
	if cmd == nil {
		t.Fatal("unlock submit produced no command")
	}
	tm, _ = step(tm, cmd()) // vaultOpenedMsg → scMain (engine created)
	if tm.(Model).eng == nil {
		t.Fatal("real-mode unlock should build a sync engine")
	}
	return tm, fv, fb
}

// pairModel drives syncedModel through the device-code pairing.
func pairModel(t *testing.T) (tea.Model, *fakeVault, *fakeBackend) {
	t.Helper()
	tm, fv, fb := syncedModel(t)
	// settings → account row → enter opens the sign-in screen.
	tm = send(tm, runes("4"))
	tm = send(tm, runes("j"))
	tm = send(tm, runes("j"))
	tm = send(tm, runes("j")) // land on Account
	tm, _ = step(tm, special(tea.KeyEnter))
	if !strings.Contains(tm.View(), "pairing code") {
		t.Fatalf("account row should open the real sign-in screen:\n%s", tm.View())
	}
	tm, _ = step(tm, special(tea.KeyEnter)) // intro → code entry
	tm = typeStr(tm, "K7PQ-M2XR")           // dash form accepted (dash skipped)
	tm, cmd := step(tm, special(tea.KeyEnter))
	if cmd == nil {
		t.Fatal("code submit should produce the pair command")
	}
	tm, syncCmd := step(tm, cmd()) // pairedMsg → signed in + initial sync
	m := tm.(Model)
	if !m.signedIn || m.email != "deniz@example.com" {
		t.Fatalf("pairing should sign in, got signedIn=%v email=%q", m.signedIn, m.email)
	}
	if syncCmd == nil {
		t.Fatal("pairing should trigger the initial sync")
	}
	tm, _ = step(tm, syncCmd()) // syncDoneMsg
	return tm, fv, fb
}

func TestRealPairFlow(t *testing.T) {
	tm, _, _ := pairModel(t)
	v := tm.View()
	if !strings.Contains(v, "deniz@example.com") {
		t.Fatalf("header should show the account email:\n%s", v)
	}
	if !strings.Contains(v, "● synced") {
		t.Fatalf("header should show the synced indicator:\n%s", v)
	}
}

func TestRealPairBadCode(t *testing.T) {
	tm, _, fb := syncedModel(t)
	fb.badCode = true
	tm = send(tm, runes("2"))               // projects gate
	tm, _ = step(tm, special(tea.KeyEnter)) // → sign-in
	tm, _ = step(tm, special(tea.KeyEnter)) // → code entry
	tm = typeStr(tm, "K7PQM2XR")
	tm, cmd := step(tm, special(tea.KeyEnter))
	tm, _ = step(tm, cmd()) // pairedMsg{err}
	m := tm.(Model)
	if m.signedIn {
		t.Fatal("a rejected code must not sign in")
	}
	if !strings.Contains(tm.View(), "code not found") {
		t.Fatalf("the backend rejection should be shown:\n%s", tm.View())
	}
}

func TestSaveSchedulesDebouncedPush(t *testing.T) {
	tm, _, fb := pairModel(t)

	// Add a host: the save must schedule a push timer, and the timer a sync.
	tm = send(tm, runes("1"))
	tm = send(tm, runes("a"))
	tm = typeStr(tm, "web1")
	tm = send(tm, special(tea.KeyTab))
	tm = send(tm, special(tea.KeyTab))
	tm = typeStr(tm, "example.com")
	tm, cmd := step(tm, special(tea.KeyEnter))
	if cmd == nil {
		t.Fatal("host save should emit commands")
	}
	gen := tm.(Model).syncGen
	if gen == 0 {
		t.Fatal("saving while signed in should arm the push debounce")
	}
	// Fire the debounce timer directly (skipping the 3s tick).
	tm, syncCmd := step(tm, syncPushTimerMsg{gen: gen})
	if syncCmd == nil {
		t.Fatal("the armed timer should trigger a sync")
	}
	tm, _ = step(tm, syncCmd()) // syncDoneMsg{Pushed}
	if !strings.Contains(tm.View(), "changes uploaded") {
		t.Fatalf("push should confirm via toast:\n%s", tm.View())
	}
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if !strings.Contains(string(fb.vault), "web1") {
		t.Fatal("the pushed blob should contain the new host")
	}
	// A stale generation must be dropped.
	if _, c := step(tm, syncPushTimerMsg{gen: gen - 1}); c != nil {
		t.Fatal("stale debounce generations must not sync")
	}
}

func TestAdoptRemoteReloadsStore(t *testing.T) {
	tm, fv, fb := pairModel(t)

	// The remote grows a host (payload == blob in tests, store-shaped JSON).
	remote := []byte(`{"schema":1,"hosts":[{"id":"aaaabbbbccccdddd","name":"from-remote","user":"u","addr":"r.example.com","port":22,"source":"manual"}],"settings":{"theme":"abyss","agent":true,"keepalive":true,"telemetry":false}}`)
	fb.mu.Lock()
	fb.noVault = false
	fb.vault = remote
	fb.version++
	fb.mu.Unlock()

	// Manual sync from the settings tab.
	tm = send(tm, runes("4"))
	tm, cmd := step(tm, runes("s"))
	if cmd == nil {
		t.Fatal("manual sync should emit a command")
	}
	tm, _ = step(tm, cmd()) // syncDoneMsg{Adopt}
	if !strings.Contains(string(fv.payload), "from-remote") {
		t.Fatal("adopting should write the remote payload into the local vault")
	}
	tm = send(tm, runes("1"))
	if !strings.Contains(tm.View(), "from-remote") {
		t.Fatalf("the pulled host should appear on the hosts tab:\n%s", tm.View())
	}
}

func TestConflictPromptAndResolve(t *testing.T) {
	tm, _, fb := pairModel(t)

	// Local change (host add), remote change → both sides moved.
	tm = send(tm, runes("1"))
	tm = send(tm, runes("a"))
	tm = typeStr(tm, "local-host")
	tm = send(tm, special(tea.KeyTab))
	tm = send(tm, special(tea.KeyTab))
	tm = typeStr(tm, "l.example.com")
	tm, _ = step(tm, special(tea.KeyEnter))

	remote := []byte(`{"schema":1,"hosts":[{"id":"eeeeffff00001111","name":"remote-host","user":"u","addr":"r.example.com","port":22,"source":"manual"}],"settings":{"theme":"abyss","agent":true,"keepalive":true,"telemetry":false}}`)
	fb.mu.Lock()
	fb.noVault = false
	fb.vault = remote
	fb.version++
	fb.mu.Unlock()

	tm = send(tm, runes("4"))
	tm, cmd := step(tm, runes("s"))
	tm, _ = step(tm, cmd()) // syncDoneMsg{Conflict}
	v := tm.View()
	if !strings.Contains(v, "sync conflict") {
		t.Fatalf("both-changed should open the conflict prompt:\n%s", v)
	}
	if !strings.Contains(v, "keep local") || !strings.Contains(v, "take remote") {
		t.Fatalf("the prompt should offer both choices:\n%s", v)
	}

	// Keep local → push overwrites the remote.
	tm, cmd = step(tm, runes("l"))
	if cmd == nil {
		t.Fatal("choosing a side should emit the resolve command")
	}
	tm, _ = step(tm, cmd())
	if !strings.Contains(tm.View(), "changes uploaded") && !strings.Contains(tm.View(), "● synced") {
		t.Fatalf("keep-local should converge:\n%s", tm.View())
	}
	fb.mu.Lock()
	defer fb.mu.Unlock()
	if !strings.Contains(string(fb.vault), "local-host") {
		t.Fatal("keep-local must overwrite the remote with the local blob")
	}
}

func TestSignOutKeepsVault(t *testing.T) {
	tm, fv, _ := pairModel(t)
	tm = send(tm, runes("4"))
	for i := 0; i < len(settingDefs); i++ { // to the top…
		tm = send(tm, runes("k"))
	}
	tm = send(tm, runes("j"))
	tm = send(tm, runes("j"))
	tm = send(tm, runes("j")) // …then down to the Account row
	tm, _ = step(tm, special(tea.KeyEnter))
	m := tm.(Model)
	if m.signedIn {
		t.Fatal("enter on the account row should sign out")
	}
	if !strings.Contains(tm.View(), "signed out") {
		t.Fatalf("sign-out should confirm via toast:\n%s", tm.View())
	}
	if fv.closed {
		t.Fatal("sign-out must not close the local vault")
	}
	if !strings.Contains(tm.View(), "● vault open") {
		t.Fatalf("header should fall back to the local-vault state:\n%s", tm.View())
	}
}

func TestSessionDeadSignsOutUI(t *testing.T) {
	tm, _, _ := pairModel(t)
	tm, _ = step(tm, syncDoneMsg{res: syncx.Result{SessionDead: true}})
	m := tm.(Model)
	if m.signedIn {
		t.Fatal("a dead session should sign the UI out")
	}
	if !strings.Contains(tm.View(), "session expired") {
		t.Fatalf("the user should be told to re-pair:\n%s", tm.View())
	}
}
