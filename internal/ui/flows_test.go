package ui

import (
	"strings"
	"testing"

	"github.com/Janne6565/wharf-tui/internal/sshx"
	"github.com/Janne6565/wharf-tui/internal/vault"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// fakeVault is a fast in-memory vaultHandle so UI tests avoid argon2's cost.
type fakeVault struct {
	payload []byte
	saves   int
	closed  bool
}

func (f *fakeVault) Payload() []byte { return f.payload }
func (f *fakeVault) Save(p []byte) error {
	f.payload = append([]byte(nil), p...)
	f.saves++
	return nil
}
func (f *fakeVault) ChangePassword([]byte) error         { return nil }
func (f *fakeVault) RegenerateRecovery() (string, error) { return code40, nil }
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
