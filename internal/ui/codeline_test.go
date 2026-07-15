package ui

import (
	"strings"
	"testing"

	"github.com/Janne6565/wharf-tui/internal/theme"
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
