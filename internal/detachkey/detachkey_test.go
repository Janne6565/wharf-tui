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

// The package-level functions are the detach binding, and the attach paths call
// them by those names, so the two spellings must not drift apart.
func TestPackageLevelFunctionsAreTheDetachBinding(t *testing.T) {
	if DefaultName != Detach.DefaultName() || DefaultByte != Detach.DefaultByte() {
		t.Fatalf("the package defaults (%q/%#x) are not Detach's (%q/%#x)",
			DefaultName, byte(DefaultByte), Detach.DefaultName(), Detach.DefaultByte())
	}
	if Byte("ctrl+c") != Detach.Byte("ctrl+c") || Name(0) != Detach.Name(0) {
		t.Fatal("the package-level fallbacks disagree with Detach's")
	}
}

func TestRemoteAccessDefaultIsCtrlRightBracket(t *testing.T) {
	if RemoteAccess.DefaultByte() != 0x1D {
		t.Fatalf("remote-access default byte = %#x, want 0x1D", RemoteAccess.DefaultByte())
	}
	b, err := RemoteAccess.Parse(RemoteAccess.DefaultName())
	if err != nil || b != 0x1D {
		t.Fatalf("Parse(%q) = %#x, %v; want 0x1D", RemoteAccess.DefaultName(), b, err)
	}
	if got := RemoteAccess.Name(b); got != RemoteAccess.DefaultName() {
		t.Fatalf("Name(%#x) = %q, want %q — the name must round-trip through the byte", b, got, RemoteAccess.DefaultName())
	}
	// Unset and unparseable both mean the default, as for the detach key: a
	// stale config must not leave the hotkey silently dead.
	for _, name := range []string{"", "ctrl+c", "f5", "ctrl+"} {
		if got := RemoteAccess.Byte(name); got != RemoteAccess.DefaultByte() {
			t.Fatalf("RemoteAccess.Byte(%q) = %#x, want the default %#x", name, got, RemoteAccess.DefaultByte())
		}
	}
	if got := RemoteAccess.Name(0); got != RemoteAccess.DefaultName() {
		t.Fatalf("RemoteAccess.Name(0) = %q, want %q — zero is how callers spell unset", got, RemoteAccess.DefaultName())
	}
}

// Both bindings live in the same raw byte stream, so a key the remote shell
// needs is refused whichever hotkey asked for it — with the same reason.
func TestBothBindingsRefuseReservedKeys(t *testing.T) {
	for _, b := range []Binding{Detach, RemoteAccess} {
		for name, why := range reserved {
			_, err := b.Parse(name)
			if err == nil {
				t.Fatalf("%s: Parse(%q) must fail: it is needed as itself", b.Label(), name)
			}
			if !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), why) {
				t.Fatalf("%s: Parse(%q) error %q should name the key and say what it is needed for", b.Label(), name, err)
			}
		}
		if _, err := b.Parse("f5"); err == nil || !strings.Contains(err.Error(), b.Label()) {
			t.Fatalf("%s: Parse(\"f5\") error %v should name the binding it is refusing", b.Label(), err)
		}
	}
}

// The whole point of ParseAgainst: one byte cannot serve two hotkeys, because
// the attach loop swallows it for the first and the second never sees it.
func TestTheTwoBindingsCannotShareAKey(t *testing.T) {
	// Remote access asking for the detach key, both on their defaults.
	_, err := RemoteAccess.ParseAgainst(Detach.DefaultName(), "")
	if err == nil {
		t.Fatal("binding remote access to the detach key succeeded, want a refusal")
	}
	if want := `ctrl+\ is already the detach key`; err.Error() != want {
		t.Fatalf("error = %q, want %q — the modal shows this verbatim", err, want)
	}

	// And the other way round, against a *configured* other key rather than a
	// default, shouted and padded the way a hand-edited config may be.
	_, err = Detach.ParseAgainst("ctrl+u", " CTRL+U ")
	if err == nil {
		t.Fatal("binding the detach key to the configured remote-access key succeeded, want a refusal")
	}
	if want := "ctrl+u is already the remote-access key"; err.Error() != want {
		t.Fatalf("error = %q, want %q", err, want)
	}

	// A free key is still free, and still resolves to its byte.
	got, err := RemoteAccess.ParseAgainst("ctrl+g", "")
	if err != nil || got != 0x07 {
		t.Fatalf("ParseAgainst(\"ctrl+g\", \"\") = %#x, %v; want 0x07 and no error", got, err)
	}
	// Reserved keys are refused with their own reason, not with a collision.
	if _, err := RemoteAccess.ParseAgainst("ctrl+c", ""); err == nil || strings.Contains(err.Error(), "already") {
		t.Fatalf("ParseAgainst(\"ctrl+c\", \"\") = %v, want the reserved explanation", err)
	}
}

// The defaults ship as a working pair; if someone changes one to collide with
// the other, every fresh install is broken and no user action caused it.
func TestTheShippedDefaultsDoNotCollide(t *testing.T) {
	if Detach.DefaultByte() == RemoteAccess.DefaultByte() {
		t.Fatalf("both bindings default to %#x", Detach.DefaultByte())
	}
	if _, err := RemoteAccess.ParseAgainst(RemoteAccess.DefaultName(), Detach.DefaultName()); err != nil {
		t.Fatalf("the shipped defaults refuse each other: %v", err)
	}
}

// Both bindings draw from the same curated set, and every key in it is
// bindable by either.
func TestEveryBindableKeyServesBothBindings(t *testing.T) {
	for _, name := range Names() {
		for _, b := range []Binding{Detach, RemoteAccess} {
			v, err := b.Parse(name)
			if err != nil {
				t.Fatalf("Names() lists %q, which %s rejects: %v", name, b.Label(), err)
			}
			if got := b.Name(v); got != name {
				t.Fatalf("%s: Name(Parse(%q)) = %q", b.Label(), name, got)
			}
		}
	}
}
