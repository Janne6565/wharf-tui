package detachkey

import (
	"strings"
	"testing"
)

func TestParseKnownKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		want byte
	}{
		{`ctrl+\`, 0x1C},
		{"ctrl+]", 0x1D},
		{"CTRL+A", 0x01}, // a hand-edited config may shout
		{" ctrl+o ", 0x0F},
		{"", DefaultByte}, // unset means the default
	} {
		got, err := Parse(tc.name)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.name, err)
		}
		if got != tc.want {
			t.Fatalf("Parse(%q) = %#x, want %#x", tc.name, got, tc.want)
		}
	}
}

// The reserved keys are the point of the package: binding one would cost the
// remote shell a key it cannot do without, so each is refused with a reason.
func TestParseRefusesReservedKeys(t *testing.T) {
	for _, name := range []string{"ctrl+c", "ctrl+d", "ctrl+z", "esc", "ctrl+[", "enter", "tab", "backspace", "ctrl+q", "ctrl+s"} {
		_, err := Parse(name)
		if err == nil {
			t.Fatalf("Parse(%q) must fail: it is needed as itself", name)
		}
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("Parse(%q) error %q should name the key", name, err)
		}
	}
}

func TestParseRefusesNonControlKeys(t *testing.T) {
	for _, name := range []string{"j", "alt+1", "f5", "shift+left", "nonsense"} {
		if _, err := Parse(name); err == nil {
			t.Fatalf("Parse(%q) must fail: only ctrl combinations reach the attach loop", name)
		}
	}
}

func TestNameRoundTripsEveryBindableKey(t *testing.T) {
	for _, name := range Names() {
		b, err := Parse(name)
		if err != nil {
			t.Fatalf("Names() lists %q, which Parse rejects: %v", name, err)
		}
		if got := Name(b); got != name {
			t.Fatalf("Name(Parse(%q)) = %q", name, got)
		}
	}
}

// A config that no longer parses must never leave someone attached with no way
// out, so the byte resolution falls back rather than failing.
func TestByteFallsBackToTheDefault(t *testing.T) {
	for _, name := range []string{"ctrl+c", "f5", "", "ctrl+"} {
		if got := Byte(name); got != DefaultByte {
			t.Fatalf("Byte(%q) = %#x, want the default %#x", name, got, DefaultByte)
		}
	}
	if got := Name(0); got != DefaultName {
		t.Fatalf("Name(0) = %q, want %q — zero is how callers spell unset", got, DefaultName)
	}
}

func TestDefaultIsCtrlBackslash(t *testing.T) {
	b, err := Parse(DefaultName)
	if err != nil || b != DefaultByte {
		t.Fatalf("Parse(DefaultName) = %#x, %v; want %#x", b, err, DefaultByte)
	}
}
