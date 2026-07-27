package ui

import (
	"strings"
	"testing"

	"github.com/Janne6565/wharf-tui/internal/theme"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

// The "·" placeholder is a multi-byte rune; codeLine must slice by rune so it
// never emits a U+FFFD replacement character mid-code.
func TestCodeLineNeverGarblesPlaceholder(t *testing.T) {
	th := theme.Get("abyss")
	for _, code := range []string{"", "T", "T4H", "T4HE", "T4HEF", "T4HEF5", "T4HEF5GH", "T4HEF5GHX"} {
		m := Model{code: code}
		out := m.codeLine(th)
		if strings.ContainsRune(out, '�') {
			t.Fatalf("code %q produced a replacement char: %q", code, out)
		}
		// The typed characters must all survive intact.
		want := code
		if len(want) > 8 {
			want = want[:8]
		}
		stripped := strings.NewReplacer("·", "", "-", "", "▌", "", " ", "").Replace(out)
		if !strings.HasPrefix(stripped, want) {
			t.Fatalf("code %q: expected typed prefix %q in %q", code, want, out)
		}
	}
}

// Typed characters must land on exactly the columns their placeholders
// occupied: the line stays 8 slots + dash wide at every input length, with the
// dash pinned to column 4 and the cursor sitting on a slot rather than between
// two.
func TestCodeLineKeepsSlotColumns(t *testing.T) {
	th := theme.Get("abyss")
	for _, code := range []string{"", "T", "T4", "T4H", "T4HE", "T4HEF", "T4HEF5", "T4HEF5G", "T4HEF5GH"} {
		for _, tick := range []int{0, 4} { // cursor visible / blinked off
			m := Model{code: code, tick: tick}
			plain := []rune(ansi.Strip(m.codeLine(th)))
			if len(plain) != 9 {
				t.Fatalf("code %q tick %d: want width 9, got %d (%q)", code, tick, len(plain), string(plain))
			}
			if plain[4] != '-' {
				t.Fatalf("code %q tick %d: dash moved off column 4: %q", code, tick, string(plain))
			}
			for i, r := range []rune(code) {
				col := i
				if i >= 4 {
					col++
				}
				if plain[col] != r {
					t.Fatalf("code %q tick %d: char %q expected at column %d, got %q in %q",
						code, tick, r, col, plain[col], string(plain))
				}
			}
		}
	}
}

// A pairing code pasted into the terminal arrives as a single bracketed-paste
// KeyMsg whose String() is wrapped in "[...]"; handleKey must split it into
// plain per-rune keys, skipping the display dash, so pasting works as well as
// typing.
func TestPastedPairingCodeIsAccepted(t *testing.T) {
	for _, pasted := range []string{"T4HEF5GH", "T4HE-F5GH", "T"} {
		m := Model{screen: scAuth, authStep: 1}
		tm, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(pasted), Paste: true})
		want := strings.ToUpper(strings.ReplaceAll(pasted, "-", ""))
		if got := tm.(Model).code; got != want {
			t.Fatalf("paste %q: got code %q, want %q", pasted, got, want)
		}
	}
}
