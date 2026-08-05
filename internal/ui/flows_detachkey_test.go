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
	t.Helper()
	saved := &[]string{}

	tm, _ := openedModel(t)
	mm := tm.(Model)
	mm.applyDetachKey = func(name string) error {
		if applyErr != nil {
			return applyErr
		}
		*saved = append(*saved, name)
		return nil
	}
	tm = mm

	tm = send(tm, runes("4")) // settings tab
	return selectSettingRow(t, tm, "detachkey"), saved
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
	tm = send(tm, ctrlKey("ctrl+]"))

	mm := tm.(Model)
	if mm.modal != modalNone {
		t.Fatal("a captured key should close the modal")
	}
	if mm.detachName != "ctrl+]" {
		t.Fatalf("detachName = %q, want ctrl+]", mm.detachName)
	}
	if mm.detachByte() != 0x1D {
		t.Fatalf("detachByte = %#x, want 0x1D — this is what the attach loop watches for", mm.detachByte())
	}
	if len(*saved) != 1 || (*saved)[0] != "ctrl+]" {
		t.Fatalf("persisted %v, want the captured key once", *saved)
	}
	// The rebinding has to reach the places that tell people how to get out.
	if v := tm.View(); !strings.Contains(v, "ctrl+]") {
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
	tm = send(tm, ctrlKey("ctrl+]"))

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
	tm = send(tm, ctrlKey("ctrl+]"))

	tm = send(tm, runes("?"))
	v := tm.View()
	if !strings.Contains(v, "ctrl+]") {
		t.Fatalf("help should list the bound detach key:\n%s", v)
	}
	if strings.Contains(v, `ctrl+\`) {
		t.Fatalf("help still advertises the old default:\n%s", v)
	}
}
