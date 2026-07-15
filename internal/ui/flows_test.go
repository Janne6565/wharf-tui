package ui

import (
	"strings"
	"testing"

	"github.com/Janne6565/wharf-tui/internal/sshx"
	"github.com/Janne6565/wharf-tui/internal/store"
	"github.com/Janne6565/wharf-tui/internal/vault"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// fakeVault is a fast in-memory vaultHandle so UI tests avoid argon2's cost.
type fakeVault struct {
	payload       []byte
	saves         int
	closed        bool
	changePwCalls int
	lastPw        string
}

func (f *fakeVault) Payload() []byte { return f.payload }
func (f *fakeVault) Save(p []byte) error {
	f.payload = append([]byte(nil), p...)
	f.saves++
	return nil
}
func (f *fakeVault) ChangePassword(pw []byte) error {
	f.changePwCalls++
	f.lastPw = string(pw)
	return nil
}
func (f *fakeVault) RegenerateRecovery() (string, error) { return code40, nil }
func (f *fakeVault) DeriveKey(string) ([]byte, error)    { return make([]byte, 32), nil }
func (f *fakeVault) Close() error                        { f.closed = true; return nil }

const code40 = "ABCDEFGHJKMNPQRSTVWXYZ012345670189ABCDEF"

func init() { lipgloss.SetColorProfile(termenv.Ascii) }

// step runs one Update and returns the concrete model plus the emitted command.
func step(m tea.Model, msg tea.Msg) (tea.Model, tea.Cmd) { return m.Update(msg) }

// typeStr feeds each rune of s as a key message.
func typeStr(m tea.Model, s string) tea.Model {
	for _, r := range s {
		m = send(m, runes(string(r)))
	}
	return m
}

// openedModel returns a real-mode model unlocked to the dashboard over a fake
// vault.
func openedModel(t *testing.T) (tea.Model, *fakeVault) {
	t.Helper()
	fv := &fakeVault{}
	m := New(Config{
		VaultPath:   "/tmp/none",
		VaultExists: func(string) bool { return true },
		OpenVault:   func(string, []byte) (vaultHandle, error) { return fv, nil },
	})
	var tm tea.Model = m
	tm = send(tm, tea.WindowSizeMsg{Width: 100, Height: 32})
	tm = typeStr(tm, "pw")
	tm, cmd := step(tm, special(tea.KeyEnter)) // → openCmd
	if cmd == nil {
		t.Fatal("unlock submit produced no command")
	}
	tm, _ = step(tm, cmd()) // vaultOpenedMsg → scMain
	if !strings.Contains(tm.View(), "No hosts yet") {
		t.Fatalf("expected empty dashboard after unlock, got:\n%s", tm.View())
	}
	return tm, fv
}

func TestCreateFlow(t *testing.T) {
	fv := &fakeVault{}
	m := New(Config{
		VaultPath:   "/tmp/none",
		VaultExists: func(string) bool { return false },
		CreateVault: func(string, []byte) (vaultHandle, string, error) { return fv, code40, nil },
	})
	var tm tea.Model = m
	tm = send(tm, tea.WindowSizeMsg{Width: 100, Height: 32})

	if !strings.Contains(tm.View(), "create vault") {
		t.Fatalf("fresh vault should show create screen:\n%s", tm.View())
	}
	tm = typeStr(tm, "hunter2")        // password field
	tm = send(tm, special(tea.KeyTab)) // → confirm field
	tm = typeStr(tm, "hunter2")
	tm, cmd := step(tm, special(tea.KeyEnter)) // → createCmd
	if cmd == nil {
		t.Fatal("create submit produced no command")
	}
	tm, _ = step(tm, cmd()) // vaultCreatedMsg → ulShowCode

	if !strings.Contains(tm.View(), "ABCDE-FGHJK") {
		t.Fatalf("recovery code should be shown grouped:\n%s", tm.View())
	}
	tm = send(tm, runes("y")) // acknowledge
	if !strings.Contains(tm.View(), "No hosts yet") {
		t.Fatalf("after acknowledging code we should reach the empty dashboard:\n%s", tm.View())
	}
}

func TestCreatePasswordMismatch(t *testing.T) {
	m := New(Config{
		VaultPath:   "/tmp/none",
		VaultExists: func(string) bool { return false },
	})
	var tm tea.Model = m
	tm = send(tm, tea.WindowSizeMsg{Width: 100, Height: 32})
	tm = typeStr(tm, "abc")
	tm = send(tm, special(tea.KeyTab))
	tm = typeStr(tm, "xyz")
	tm, _ = step(tm, special(tea.KeyEnter))
	if !strings.Contains(tm.View(), "do not match") {
		t.Fatalf("mismatched confirmation should show an inline error:\n%s", tm.View())
	}
}

func TestUnlockWrongPassword(t *testing.T) {
	m := New(Config{
		VaultPath:   "/tmp/none",
		VaultExists: func(string) bool { return true },
		OpenVault:   func(string, []byte) (vaultHandle, error) { return nil, vault.ErrWrongSecret },
	})
	var tm tea.Model = m
	tm = send(tm, tea.WindowSizeMsg{Width: 100, Height: 32})
	tm = typeStr(tm, "nope")
	tm, cmd := step(tm, special(tea.KeyEnter))
	tm, _ = step(tm, cmd()) // vaultOpenedMsg{err}
	if !strings.Contains(tm.View(), "wrong password") {
		t.Fatalf("wrong password should stay on unlock with an error:\n%s", tm.View())
	}
}

func TestLockReturnsToUnlock(t *testing.T) {
	tm, fv := openedModel(t)
	tm = send(tm, runes("q")) // lock
	if !strings.Contains(tm.View(), "unlock vault") {
		t.Fatalf("q on the dashboard should lock back to the unlock screen:\n%s", tm.View())
	}
	if !fv.closed {
		t.Fatal("locking should close the vault")
	}
}

func TestHostAddAppearsAndSaves(t *testing.T) {
	tm, fv := openedModel(t)
	before := fv.saves

	tm = send(tm, runes("a")) // open add form
	if !strings.Contains(tm.View(), "add host") {
		t.Fatalf("a should open the add-host form:\n%s", tm.View())
	}
	tm = typeStr(tm, "web1")
	tm = send(tm, special(tea.KeyTab))
	tm = typeStr(tm, "deploy")
	tm = send(tm, special(tea.KeyTab))
	tm = typeStr(tm, "example.com")
	tm, _ = step(tm, special(tea.KeyEnter)) // submit (port defaults to 22)

	if !strings.Contains(tm.View(), "web1") {
		t.Fatalf("added host should appear in the list:\n%s", tm.View())
	}
	if fv.saves <= before {
		t.Fatal("adding a host should persist via Save")
	}
}

func TestHostDeleteConfirm(t *testing.T) {
	tm, _ := openedModel(t)
	tm = send(tm, runes("a"))
	tm = typeStr(tm, "web1")
	tm = send(tm, special(tea.KeyTab))
	tm = send(tm, special(tea.KeyTab))
	tm = typeStr(tm, "example.com")
	tm, _ = step(tm, special(tea.KeyEnter))

	tm = send(tm, runes("d")) // delete confirm
	if !strings.Contains(tm.View(), "Delete host") {
		t.Fatalf("d should open the delete confirm:\n%s", tm.View())
	}
	tm = send(tm, runes("y"))
	if !strings.Contains(tm.View(), "No hosts yet") {
		t.Fatalf("host should be gone after confirming delete:\n%s", tm.View())
	}
}

func TestTOFUModalReplyOnce(t *testing.T) {
	tm, _ := openedModel(t)
	reply := make(chan bool, 1) // buffered(1), matching the engine contract
	msg := sshx.HostKeyPromptMsg{
		HostID:      "h1",
		Host:        "example.com:22",
		KeyType:     "ssh-ed25519",
		Fingerprint: "SHA256:abc123XYZ",
		Reply:       reply,
	}
	tm, _ = step(tm, msg)
	if !strings.Contains(tm.View(), "SHA256:abc123XYZ") {
		t.Fatalf("TOFU modal should render the fingerprint:\n%s", tm.View())
	}
	tm, _ = step(tm, special(tea.KeyEnter)) // accept
	select {
	case v := <-reply:
		if !v {
			t.Fatal("accepting should send true")
		}
	default:
		t.Fatal("accepting should send exactly one reply")
	}
	// A second keypress must not attempt another send on the drained channel.
	tm, _ = step(tm, special(tea.KeyEnter))
	if len(reply) != 0 {
		t.Fatal("reply channel should not receive a second value")
	}
}

func TestSecretModalSendsBytes(t *testing.T) {
	tm, _ := openedModel(t)
	reply := make(chan []byte, 1)
	tm, _ = step(tm, sshx.SecretPromptMsg{
		HostID: "h1",
		Title:  "password",
		Detail: "deploy@example.com",
		Reply:  reply,
	})
	tm = typeStr(tm, "s3cret")
	tm, _ = step(tm, special(tea.KeyEnter))
	select {
	case got := <-reply:
		if string(got) != "s3cret" {
			t.Fatalf("secret modal should send typed bytes, got %q", got)
		}
	default:
		t.Fatal("secret modal should send a reply on enter")
	}
}

// hostByName looks a stored host up by name, failing the test if absent.
func hostByName(t *testing.T, m tea.Model, name string) store.Host {
	t.Helper()
	for _, h := range m.(Model).st.Hosts() {
		if h.Name == name {
			return h
		}
	}
	t.Fatalf("host %q not found in store", name)
	return store.Host{}
}

func TestHostAddPasswordAuth(t *testing.T) {
	tm, _ := openedModel(t)

	tm = send(tm, runes("a")) // open add form
	tm = typeStr(tm, "web1")
	tm = send(tm, special(tea.KeyTab)) // → user
	tm = typeStr(tm, "deploy")
	tm = send(tm, special(tea.KeyTab)) // → address
	tm = typeStr(tm, "example.com")
	// Navigate to the auth selector: port, tags, auth.
	tm = send(tm, special(tea.KeyTab)) // → port
	tm = send(tm, special(tea.KeyTab)) // → tags
	tm = send(tm, special(tea.KeyTab)) // → auth
	// Toggle key → password with space.
	tm = send(tm, runes(" "))
	tm = send(tm, special(tea.KeyTab)) // → password field
	tm = typeStr(tm, "s3cr3t")
	tm, _ = step(tm, special(tea.KeyEnter)) // submit

	h := hostByName(t, tm, "web1")
	if h.AuthMethod != sshx.AuthPassword {
		t.Fatalf("auth method should be %q, got %q", sshx.AuthPassword, h.AuthMethod)
	}
	if h.Password != "s3cr3t" {
		t.Fatalf("stored password should be s3cr3t, got %q", h.Password)
	}
	if strings.Contains(tm.View(), "s3cr3t") {
		t.Fatalf("plaintext password must never render:\n%s", tm.View())
	}
}

func TestHostEditPasswordMasked(t *testing.T) {
	tm, _ := openedModel(t)

	// Seed a password-auth host through the add form.
	tm = send(tm, runes("a"))
	tm = typeStr(tm, "web1")
	tm = send(tm, special(tea.KeyTab)) // → user
	tm = send(tm, special(tea.KeyTab)) // → address
	tm = typeStr(tm, "example.com")
	tm = send(tm, special(tea.KeyTab)) // → port
	tm = send(tm, special(tea.KeyTab)) // → tags
	tm = send(tm, special(tea.KeyTab)) // → auth
	tm = send(tm, runes(" "))          // key → password
	tm = send(tm, special(tea.KeyTab)) // → password field
	tm = typeStr(tm, "s3cr3t")
	tm, _ = step(tm, special(tea.KeyEnter))

	// Reopen for edit: the password must render as bullets, never plaintext.
	tm = send(tm, runes("e"))
	if !strings.Contains(tm.View(), "edit host") {
		t.Fatalf("e should open the edit form:\n%s", tm.View())
	}
	if !strings.Contains(tm.View(), "••••••") {
		t.Fatalf("edit form should mask the stored password as bullets:\n%s", tm.View())
	}
	if strings.Contains(tm.View(), "s3cr3t") {
		t.Fatalf("edit form must not render the plaintext password:\n%s", tm.View())
	}

	// Change nothing, submit → values preserved.
	tm, _ = step(tm, special(tea.KeyEnter))
	h := hostByName(t, tm, "web1")
	if h.AuthMethod != sshx.AuthPassword || h.Password != "s3cr3t" {
		t.Fatalf("edit with no changes should preserve auth=%q pw=%q, got auth=%q pw=%q",
			sshx.AuthPassword, "s3cr3t", h.AuthMethod, h.Password)
	}
}

func TestHostAddDefaultsToKey(t *testing.T) {
	tm, _ := openedModel(t)
	tm = send(tm, runes("a")) // open add form
	tm = typeStr(tm, "web1")
	tm = send(tm, special(tea.KeyTab)) // → user
	tm = send(tm, special(tea.KeyTab)) // → address
	tm = typeStr(tm, "example.com")
	tm, _ = step(tm, special(tea.KeyEnter)) // submit, no auth changes

	h := hostByName(t, tm, "web1")
	if h.AuthMethod != sshx.AuthKey {
		t.Fatalf("a new host should default to key auth, got %q", h.AuthMethod)
	}
}

// TestHostFormConditionalFields asserts only the field matching the selected
// mode renders: key path in key mode, masked password in password mode. The
// word "password" also appears once as the selector option, so the password
// FIELD is detected by a second occurrence.
func TestHostFormConditionalFields(t *testing.T) {
	tm, _ := openedModel(t)
	tm = send(tm, runes("a")) // add form — defaults to key mode

	v := tm.View()
	if !strings.Contains(v, "key path") {
		t.Fatalf("key mode should render the key path field:\n%s", v)
	}
	if n := strings.Count(v, "password"); n != 1 {
		t.Fatalf("key mode should not render a password field (want 1 selector option, got %d):\n%s", n, v)
	}

	// Move to the auth selector (name→user→addr→port→tags→auth) and toggle.
	for i := 0; i < 5; i++ {
		tm = send(tm, special(tea.KeyTab))
	}
	tm = send(tm, runes(" ")) // key → password

	v = tm.View()
	if strings.Contains(v, "key path") {
		t.Fatalf("password mode should hide the key path field:\n%s", v)
	}
	if n := strings.Count(v, "password"); n != 2 {
		t.Fatalf("password mode should render the password field plus the selector option (want 2, got %d):\n%s", n, v)
	}
}

// TestHostFormTogglePreservesBuffers types into both conditional fields and
// toggles between modes; both buffers must survive and both persist on submit.
func TestHostFormTogglePreservesBuffers(t *testing.T) {
	tm, _ := openedModel(t)
	tm = send(tm, runes("a"))
	tm = typeStr(tm, "web1")
	tm = send(tm, special(tea.KeyTab)) // → user
	tm = send(tm, special(tea.KeyTab)) // → address
	tm = typeStr(tm, "example.com")
	// To the key path field (addr→port→tags→auth→key) and type a path.
	for i := 0; i < 4; i++ {
		tm = send(tm, special(tea.KeyTab))
	}
	tm = typeStr(tm, "/tmp/id_key")
	// Back to auth, toggle to password, tab to the password field, type a secret.
	tm = send(tm, special(tea.KeyShiftTab)) // → auth
	tm = send(tm, runes(" "))               // key → password
	tm = send(tm, special(tea.KeyTab))      // → password field
	tm = typeStr(tm, "s3cr3t")
	// Toggle back to key and submit.
	tm = send(tm, special(tea.KeyShiftTab)) // → auth
	tm = send(tm, runes(" "))               // password → key
	tm, _ = step(tm, special(tea.KeyEnter))

	h := hostByName(t, tm, "web1")
	if h.AuthMethod != sshx.AuthKey {
		t.Fatalf("final auth mode = %q, want key", h.AuthMethod)
	}
	if h.KeyPath != "/tmp/id_key" {
		t.Fatalf("key path buffer lost across toggle, got %q", h.KeyPath)
	}
	if h.Password != "s3cr3t" {
		t.Fatalf("password buffer lost across toggle, got %q", h.Password)
	}
}

// TestHostEditLegacyAutoShowsKey injects a host carrying the retired "auto"
// AuthMethod (as a legacy vault would) and checks the edit form opens on key.
func TestHostEditLegacyAutoShowsKey(t *testing.T) {
	tm, _ := openedModel(t)
	mm := tm.(Model)
	mm.st = store.NewMemory([]store.Host{
		{ID: "leg0000000000000", Name: "legacy", Addr: "a.com", Port: 22, AuthMethod: "auto", Source: "manual"},
	}, mm.settings)
	var tm2 tea.Model = mm

	tm2 = send(tm2, runes("e")) // edit the selected (legacy) host
	v := tm2.View()
	if !strings.Contains(v, "edit host") {
		t.Fatalf("e should open the edit form:\n%s", v)
	}
	if !strings.Contains(v, "key path") {
		t.Fatalf("a legacy auto host should edit in key mode (key path field shown):\n%s", v)
	}
	if n := strings.Count(v, "password"); n != 1 {
		t.Fatalf("a legacy auto host must not show the password field (want 1 selector option, got %d):\n%s", n, v)
	}
}

func TestRememberPasswordPersists(t *testing.T) {
	tm, fv := openedModel(t)

	// A host must exist so the remembered password has somewhere to land.
	tm = send(tm, runes("a"))
	tm = typeStr(tm, "web1")
	tm = send(tm, special(tea.KeyTab))
	tm = send(tm, special(tea.KeyTab))
	tm = typeStr(tm, "example.com")
	tm, _ = step(tm, special(tea.KeyEnter))
	id := hostByName(t, tm, "web1").ID
	saves := fv.saves

	reply := make(chan []byte, 1)
	tm, _ = step(tm, sshx.SecretPromptMsg{
		HostID: id,
		Title:  "password",
		Detail: "deploy@example.com",
		Reply:  reply,
	})
	tm = typeStr(tm, "hunter2")
	tm, _ = step(tm, special(tea.KeyCtrlR)) // flip remember on
	if !strings.Contains(tm.View(), "[x] remember password") {
		t.Fatalf("ctrl+r should toggle the remember checkbox on:\n%s", tm.View())
	}
	tm, _ = step(tm, special(tea.KeyEnter)) // submit secret
	select {
	case got := <-reply:
		if string(got) != "hunter2" {
			t.Fatalf("secret modal should send typed bytes, got %q", got)
		}
	default:
		t.Fatal("secret modal should send exactly one reply")
	}
	if len(reply) != 0 {
		t.Fatal("secret modal must not send a second reply")
	}

	// The dial for this host succeeds → the password is written to the vault.
	tm, _ = step(tm, dialDoneMsg{hostID: id})
	if h := hostByName(t, tm, "web1"); h.Password != "hunter2" {
		t.Fatalf("remembered password should be persisted, got %q", h.Password)
	}
	if fv.saves <= saves {
		t.Fatal("persisting the password should Save the vault")
	}
	if !strings.Contains(tm.View(), "password saved to vault") {
		t.Fatalf("a confirming toast should be shown:\n%s", tm.View())
	}
}

func TestQuitNoSessions(t *testing.T) {
	tm, _ := openedModel(t)
	_, cmd := step(tm, special(tea.KeyCtrlQ))
	if cmd == nil {
		t.Fatal("ctrl+q with no live sessions should quit")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatal("ctrl+q should emit tea.Quit when there is nothing to close")
	}
}

func TestMultiRuneKeyMsgFillsInput(t *testing.T) {
	// Fast typing and bracketed paste deliver several runes in ONE KeyMsg;
	// the input handlers must not drop them (regression: E2E via expect).
	m := New(Config{
		VaultPath:   "/tmp/none",
		VaultExists: func(string) bool { return true },
		OpenVault:   func(string, []byte) (vaultHandle, error) { return nil, vault.ErrWrongSecret },
	})
	var tm tea.Model = m
	tm = send(tm, tea.WindowSizeMsg{Width: 100, Height: 32})
	tm = send(tm, runes("hunter2")) // one msg, seven runes
	if !strings.Contains(tm.View(), "•••••••") {
		t.Fatalf("a multi-rune KeyMsg should fill the password field:\n%s", tm.View())
	}
}
