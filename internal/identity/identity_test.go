package identity

import "testing"

// TestFingerprintVectors pins the cross-client contract. These vectors are
// shared with the web and mobile clients: if one of them fails, the TUI is
// showing a fingerprint the user cannot compare against their other devices.
func TestFingerprintVectors(t *testing.T) {
	zeros := make([]byte, 32)
	ones := make([]byte, 32)
	for i := range ones {
		ones[i] = 1
	}
	asc := make([]byte, 32)
	for i := range asc {
		asc[i] = byte(i)
	}
	cases := []struct {
		name string
		pub  []byte
		want string
	}{
		{"all zero", zeros, "Zmh6 rfhi vXds j8GL"},
		{"all one", ones, "cs1u hCLE B/tt CYaQ"},
		{"ascending", asc, "Yw3N KWbE M2aR ElRI"},
	}
	for _, c := range cases {
		if got := Fingerprint(c.pub); got != c.want {
			t.Errorf("%s: Fingerprint = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestFingerprintShape guards the rendering itself: four groups of four, single
// spaces, nothing else.
func TestFingerprintShape(t *testing.T) {
	fp := Fingerprint(make([]byte, 32))
	if len(fp) != 19 {
		t.Fatalf("fingerprint should be 19 characters (16 + 3 spaces), got %d: %q", len(fp), fp)
	}
	for _, i := range []int{4, 9, 14} {
		if fp[i] != ' ' {
			t.Fatalf("expected a space at index %d of %q", i, fp)
		}
	}
}

// TestFingerprintDiffers is the property the mismatch check relies on: a
// different key must render a different fingerprint.
func TestFingerprintDiffers(t *testing.T) {
	a := make([]byte, 32)
	b := make([]byte, 32)
	b[31] = 1
	if Fingerprint(a) == Fingerprint(b) {
		t.Fatal("distinct keys must not share a fingerprint")
	}
}
