package termius

import (
	"testing"
)

// enc builds a serialized value the way Chromium writes one: a leading varint
// the IndexedDB layer prepends, then the versioned structured clone.
func enc(body ...byte) []byte {
	out := []byte{0x10, tagVersion, 20, tagVersion, 15}
	return append(out, body...)
}

func str(s string) []byte {
	out := []byte{tagOneByteStr, byte(len(s))}
	return append(out, []byte(s)...)
}

func TestDecodeObject(t *testing.T) {
	raw := enc(tagObject)
	raw = append(raw, str("id")...)
	raw = append(raw, tagInt32, 0x08)
	raw = append(raw, tagObjectEnd, 1)

	v, err := decodeValue(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("got %T, want map", v)
	}
	if m["id"] != int64(4) { // zigzag: 0x08 -> 4
		t.Errorf("id = %v (%T), want 4", m["id"], m["id"])
	}
}

// Padding is emitted before two-byte strings so their payload lands on an even
// offset. A reader that does not skip it misreads the rest of the record, which
// is how the first pass over a real profile lost 45 of 69 host rows.
func TestDecodeSkipsPadding(t *testing.T) {
	raw := enc(tagObject)
	raw = append(raw, str("k")...)
	raw = append(raw, tagPadding, tagTwoByteStr, 4, 'h', 0, 'i', 0)
	raw = append(raw, tagObjectEnd, 1)

	v, err := decodeValue(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := v.(map[string]any)["k"]; got != "hi" {
		t.Errorf("k = %q, want %q", got, "hi")
	}
}

func TestDecodeNestedAndRefs(t *testing.T) {
	// {"a": {"n": 1}, "b": <ref to the same object>}
	raw := enc(tagObject)
	raw = append(raw, str("a")...)
	raw = append(raw, tagObject)
	raw = append(raw, str("n")...)
	raw = append(raw, tagInt32, 0x02, tagObjectEnd, 1)
	raw = append(raw, str("b")...)
	raw = append(raw, tagObjectRef, 1) // object 0 is the outer map
	raw = append(raw, tagObjectEnd, 2)

	v, err := decodeValue(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	m := v.(map[string]any)
	inner, ok := m["a"].(map[string]any)
	if !ok || inner["n"] != int64(1) {
		t.Fatalf("a = %#v, want {n:1}", m["a"])
	}
	if b, ok := m["b"].(map[string]any); !ok || b["n"] != int64(1) {
		t.Errorf("b = %#v, want the same object as a", m["b"])
	}
}

func TestDecodeScalars(t *testing.T) {
	raw := enc(tagObject)
	raw = append(raw, str("t")...)
	raw = append(raw, tagTrue)
	raw = append(raw, str("f")...)
	raw = append(raw, tagFalse)
	raw = append(raw, str("z")...)
	raw = append(raw, tagNull)
	raw = append(raw, str("u")...)
	raw = append(raw, tagUndefined)
	raw = append(raw, tagObjectEnd, 4)

	v, err := decodeValue(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	m := v.(map[string]any)
	if m["t"] != true || m["f"] != false || m["z"] != nil || m["u"] != nil {
		t.Errorf("scalars decoded as %#v", m)
	}
}

// An unknown tag must be an error: past that point the cursor is misaligned, so
// every value the reader would go on to report is fiction.
func TestDecodeUnknownTagFails(t *testing.T) {
	raw := enc(tagObject)
	raw = append(raw, str("k")...)
	raw = append(raw, 'Q') // not a tag we implement
	raw = append(raw, tagObjectEnd, 1)

	if _, err := decodeValue(raw); err == nil {
		t.Fatal("want an error for an unknown tag, got nil")
	}
}

func TestDecodeTruncatedFails(t *testing.T) {
	raw := enc(tagObject)
	raw = append(raw, str("k")...)
	if _, err := decodeValue(raw); err == nil {
		t.Fatal("want an error for a truncated value, got nil")
	}
}
