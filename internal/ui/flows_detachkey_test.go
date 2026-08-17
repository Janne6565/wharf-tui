package ui

import (
	"errors"
	"strings"
	"testing"

	"github.com/Janne6565/wharf-tui/internal/detachkey"
	tea "github.com/charmbracelet/bubbletea"
)

// detachKeyModel returns an unlocked real-mode model parked on the detach-key
// settings row, with the persistence hook wired to a recorder.
func detachKeyModel(t *testing.T, applyErr error) (tea.Model, *[]string) {
	return hotkeyRowModel(t, "detachkey", applyErr)
}

// remoteKeyModel is detachKeyModel for the remote-access binding.
func remoteKeyModel(t *testing.T, applyErr error) (tea.Model, *[]string) {
	return hotkeyRowModel(t, "remotekey", applyErr)
}

// hotkeyRowModel returns an unlocked real-mode model parked on one of the two
// hotkey settings rows, with that binding's persistence hook wired to a
// recorder. Both bindings are captured by the same modal shape, so they are
// driven by the same fixture.
func hotkeyRowModel(t *testing.T, row string, applyErr error) (tea.Model, *[]string) {
	t.Helper()
	saved := &[]string{}
	apply := func(name string) error {
		if applyErr != nil {
			return applyErr
		}
		*saved = append(*saved, name)
		return nil
	}

	tm, _ := openedModel(t)
	mm := tm.(Model)
	if row == "detachkey" {
		mm.applyDetachKey = apply
	} else {
		mm.applyRemoteKey = apply
	}
	tm = mm

	tm = send(tm, runes("4")) // settings tab
	return selectSettingRow(t, tm, row), saved
}

// ctrlKey builds the KeyMsg for a ctrl combination, matching what a terminal
// delivers: bubbletea reports these by type, not as runes.
func ctrlKey(name string) tea.KeyMsg {
	for _, k := range []tea.KeyType{
		tea.KeyCtrlA, tea.KeyCtrlB, tea.KeyCtrlC, tea.KeyCtrlD, tea.KeyCtrlZ,
		tea.KeyCtrlBackslash, tea.KeyCtrlCloseBracket, tea.KeyCtrlOpenBracket,
		tea.KeyCtrlO, tea.KeyCtrlUnderscore,
	} {
		if (tea.KeyMsg{Type: k}).String() == name {
			return tea.KeyMsg{Type: k}
		}
	}
	panic("no key type for " + name)
}

func TestDetachKeyRowShowsCurrentBindingAndOpensCapture(t *testing.T) {
	tm, _ := detachKeyModel(t, nil)
	v := tm.View()
	if !strings.Contains(v, "Detach key") || !strings.Contains(v, detachkey.DefaultName) {
		t.Fatalf("settings should list the detach key row with its binding:\n%s", v)
	}
	tm = send(tm, special(tea.KeyEnter))
	if v := tm.View(); !strings.Contains(v, "Press the key") {
		t.Fatalf("enter should open the capture modal:\n%s", v)
	}
}

func TestCapturingAKeyRebindsAndPersists(t *testing.T) {
	tm, saved := detachKeyModel(t, nil)
	tm = send(tm, special(tea.KeyEnter))
	tm = send(tm, ctrlKey("ctrl+o"))

	mm := tm.(Model)
	if mm.modal != modalNone {
		t.Fatal("a captured key should close the modal")
	}
	if mm.detachName != "ctrl+o" {
		t.Fatalf("detachName = %q, want ctrl+o", mm.detachName)
	}
	if mm.detachByte() != 0x0F {
		t.Fatalf("detachByte = %#x, want 0x0f — this is what the attach loop watches for", mm.detachByte())
	}
	if len(*saved) != 1 || (*saved)[0] != "ctrl+o" {
		t.Fatalf("persisted %v, want the captured key once", *saved)
	}
	// The rebinding has to reach the places that tell people how to get out.
	if v := tm.View(); !strings.Contains(v, "ctrl+o") {
		t.Fatalf("the settings row should show the new key:\n%s", v)
	}
}

// A key the remote needs is refused in place, with the modal still open so the
// next attempt does not cost a reopen.
func TestCapturingAReservedKeyKeepsTheModalOpen(t *testing.T) {
	tm, saved := detachKeyModel(t, nil)
	tm = send(tm, special(tea.KeyEnter))
	tm = send(tm, ctrlKey("ctrl+d"))

	mm := tm.(Model)
	if mm.modal != modalDetachKey {
		t.Fatal("a refused key must leave the capture modal open")
	}
	if mm.detachName != detachkey.DefaultName {
		t.Fatalf("detachName = %q, want the binding to be unchanged", mm.detachName)
	}
	if len(*saved) != 0 {
		t.Fatalf("a refused key must not be persisted, got %v", *saved)
	}
	if v := tm.View(); !strings.Contains(v, "end of input") {
		t.Fatalf("the modal should say why the key is refused:\n%s", v)
	}
}

func TestEscCancelsTheCapture(t *testing.T) {
	tm, saved := detachKeyModel(t, nil)
	tm = send(tm, special(tea.KeyEnter))
	tm = send(tm, special(tea.KeyEsc))

	mm := tm.(Model)
	if mm.modal != modalNone {
		t.Fatal("esc should close the capture modal")
	}
	if mm.detachName != detachkey.DefaultName || len(*saved) != 0 {
		t.Fatalf("esc must change nothing: name %q, saved %v", mm.detachName, *saved)
	}
}

func TestFailedPersistLeavesTheBindingAlone(t *testing.T) {
	tm, _ := detachKeyModel(t, errors.New("permission denied"))
	tm = send(tm, special(tea.KeyEnter))
	tm = send(tm, ctrlKey("ctrl+o"))

	mm := tm.(Model)
	if mm.detachName != detachkey.DefaultName {
		t.Fatalf("detachName = %q, want it unchanged when the write fails", mm.detachName)
	}
	if v := tm.View(); !strings.Contains(v, "permission denied") {
		t.Fatalf("the write error should be shown in place:\n%s", v)
	}
}

// The session primer and the help overlay are where people look for the way
// out, so both have to name the key that is actually bound.
func TestRebindingReachesTheHelpOverlay(t *testing.T) {
	tm, _ := detachKeyModel(t, nil)
	tm = send(tm, special(tea.KeyEnter))
	tm = send(tm, ctrlKey("ctrl+o"))

	tm = send(tm, runes("?"))
	v := tm.View()
	if !strings.Contains(v, "ctrl+o") {
		t.Fatalf("help should list the bound detach key:\n%s", v)
	}
	if strings.Contains(v, `ctrl+\`) {
		t.Fatalf("help still advertises the old default:\n%s", v)
	}
}

// --- the two bindings must not collide --------------------------------------

// The collision has to be refused from both sides. Whichever byte the attach
// loop swallows first, the other binding never sees — so a shared key silently
// disables one of them, and which one is decided by a tie-break inside the
// attach loop that no user could be expected to reason about. Guarding only the
// newer binding would leave the hole open from the older one's modal.
func TestTheCaptureModalRefusesTheOtherBindingsKeyFromTheDetachSide(t *testing.T) {
	tm, saved := detachKeyModel(t, nil)
	tm = send(tm, special(tea.KeyEnter))
	tm = send(tm, ctrlKey("ctrl+]")) // the remote-access default

	mm := tm.(Model)
	if mm.modal != modalDetachKey {
		t.Fatal("a colliding key must leave the capture modal open")
	}
	if mm.detachName != detachkey.DefaultName {
		t.Fatalf("detachName = %q, want the binding unchanged", mm.detachName)
	}
	if len(*saved) != 0 {
		t.Fatalf("a colliding key must not be persisted, got %v", *saved)
	}
	if v := tm.View(); !strings.Contains(v, "already the remote-access key") {
		t.Fatalf("the modal must name the conflict, not merely refuse:\n%s", v)
	}
}

func TestTheCaptureModalRefusesTheOtherBindingsKeyFromTheRemoteSide(t *testing.T) {
	tm, saved := remoteKeyModel(t, nil)
	tm = send(tm, special(tea.KeyEnter))
	tm = send(tm, ctrlKey(`ctrl+\`)) // the detach default

	mm := tm.(Model)
	if mm.modal != modalRemoteKey {
		t.Fatal("a colliding key must leave the capture modal open")
	}
	if mm.remoteName != detachkey.RemoteAccess.DefaultName() {
		t.Fatalf("remoteName = %q, want the binding unchanged", mm.remoteName)
	}
	if len(*saved) != 0 {
		t.Fatalf("a colliding key must not be persisted, got %v", *saved)
	}
	if v := tm.View(); !strings.Contains(v, "already the detach key") {
		t.Fatalf("the modal must name the conflict, not merely refuse:\n%s", v)
	}
}

// --- the remote-access binding ----------------------------------------------

func TestRemoteKeyRowShowsCurrentBindingAndOpensCapture(t *testing.T) {
	tm, _ := remoteKeyModel(t, nil)
	v := tm.View()
	if !strings.Contains(v, "Remote-access key") || !strings.Contains(v, detachkey.RemoteAccess.DefaultName()) {
		t.Fatalf("settings should list the remote-access key row with its binding:\n%s", v)
	}
	tm = send(tm, special(tea.KeyEnter))
	if v := tm.View(); !strings.Contains(v, "Press the key") {
		t.Fatalf("enter should open the capture modal:\n%s", v)
	}
}

func TestCapturingARemoteAccessKeyRebindsAndPersists(t *testing.T) {
	tm, saved := remoteKeyModel(t, nil)
	tm = send(tm, special(tea.KeyEnter))
	tm = send(tm, ctrlKey("ctrl+o"))

	mm := tm.(Model)
	if mm.modal != modalNone {
		t.Fatal("a captured key should close the modal")
	}
	if mm.remoteName != "ctrl+o" {
		t.Fatalf("remoteName = %q, want ctrl+o", mm.remoteName)
	}
	if mm.remoteByte() != 0x0F {
		t.Fatalf("remoteByte = %#x, want 0x0f — this is what the attach loop watches for", mm.remoteByte())
	}
	if len(*saved) != 1 || (*saved)[0] != "ctrl+o" {
		t.Fatalf("persisted %v, want the captured key once", *saved)
	}
	// The primer and the help overlay are where the key is advertised, and the
	// only place it can be advertised before the terminal is handed over.
	if v := send(tm, runes("?")).View(); !strings.Contains(v, "ctrl+o") {
		t.Fatalf("help should list the bound remote-access key:\n%s", v)
	}
}

func TestARemoteAccessKeyTheRemoteNeedsIsRefusedInPlace(t *testing.T) {
	tm, saved := remoteKeyModel(t, nil)
	tm = send(tm, special(tea.KeyEnter))
	tm = send(tm, ctrlKey("ctrl+d"))

	mm := tm.(Model)
	if mm.modal != modalRemoteKey {
		t.Fatal("a refused key must leave the capture modal open")
	}
	if len(*saved) != 0 {
		t.Fatalf("a refused key must not be persisted, got %v", *saved)
	}
	if v := tm.View(); !strings.Contains(v, "end of input") {
		t.Fatalf("the modal should say why the key is refused:\n%s", v)
	}
}
