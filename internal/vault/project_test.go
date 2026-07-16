package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func mustDEK(t *testing.T) []byte {
	t.Helper()
	dek := make([]byte, dekLen)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return dek
}

func TestProjectRoundtrip(t *testing.T) {
	dek := mustDEK(t)
	payload := []byte(`{"schema":1,"hosts":[{"id":"deadbeefdeadbeef","name":"prod"}]}`)

	blob, err := SealProject(dek, payload)
	if err != nil {
		t.Fatalf("SealProject: %v", err)
	}
	got, err := OpenProject(dek, blob)
	if err != nil {
		t.Fatalf("OpenProject: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("roundtrip payload = %q, want %q", got, payload)
	}
}

func TestProjectHeaderLayout(t *testing.T) {
	dek := mustDEK(t)
	blob, err := SealProject(dek, []byte("{}"))
	if err != nil {
		t.Fatalf("SealProject: %v", err)
	}
	if got := string(blob[0:6]); got != "WHARFP" {
		t.Fatalf("magic = %q, want WHARFP", got)
	}
	if got := binary.LittleEndian.Uint16(blob[6:8]); got != 1 {
		t.Fatalf("version = %d, want 1", got)
	}
	if len(blob) <= projectHeaderLen {
		t.Fatalf("blob length = %d, want > %d", len(blob), projectHeaderLen)
	}
	if projectHeaderLen != 32 {
		t.Fatalf("projectHeaderLen = %d, want 32", projectHeaderLen)
	}
}

func TestProjectFreshNonce(t *testing.T) {
	dek := mustDEK(t)
	payload := []byte("same payload")
	a, err := SealProject(dek, payload)
	if err != nil {
		t.Fatalf("SealProject: %v", err)
	}
	b, err := SealProject(dek, payload)
	if err != nil {
		t.Fatalf("SealProject: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same payload produced identical blobs (nonce reuse)")
	}
}

func TestProjectWrongDEK(t *testing.T) {
	dek := mustDEK(t)
	blob, err := SealProject(dek, []byte("secret"))
	if err != nil {
		t.Fatalf("SealProject: %v", err)
	}
	if _, err := OpenProject(mustDEK(t), blob); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("wrong DEK: err = %v, want ErrCorrupt", err)
	}
}

func TestProjectTamperCiphertext(t *testing.T) {
	dek := mustDEK(t)
	blob, err := SealProject(dek, []byte("secret payload"))
	if err != nil {
		t.Fatalf("SealProject: %v", err)
	}
	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := OpenProject(dek, tampered); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tampered ciphertext: err = %v, want ErrCorrupt", err)
	}
}

func TestProjectTamperHeaderAAD(t *testing.T) {
	dek := mustDEK(t)
	blob, err := SealProject(dek, []byte("secret payload"))
	if err != nil {
		t.Fatalf("SealProject: %v", err)
	}
	// Flip a byte inside the body nonce, which is AAD-covered but structurally
	// still valid magic/version — it must fail the AEAD check.
	tampered := append([]byte(nil), blob...)
	tampered[offProjectBodyNonce] ^= 0xFF
	if _, err := OpenProject(dek, tampered); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tampered header nonce: err = %v, want ErrCorrupt", err)
	}
}

func TestProjectBadMagicVersionTruncated(t *testing.T) {
	dek := mustDEK(t)
	blob, err := SealProject(dek, []byte("payload"))
	if err != nil {
		t.Fatalf("SealProject: %v", err)
	}

	badMagic := append([]byte(nil), blob...)
	copy(badMagic[0:6], []byte("XXXXXX"))
	if _, err := OpenProject(dek, badMagic); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("bad magic: err = %v, want ErrCorrupt", err)
	}

	badVersion := append([]byte(nil), blob...)
	binary.LittleEndian.PutUint16(badVersion[6:8], 2)
	if _, err := OpenProject(dek, badVersion); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("bad version: err = %v, want ErrCorrupt", err)
	}

	if _, err := OpenProject(dek, blob[:projectHeaderLen-1]); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("truncated blob: err = %v, want ErrCorrupt", err)
	}
}

func TestProjectCorruptionSweep(t *testing.T) {
	dek := mustDEK(t)
	blob, err := SealProject(dek, []byte(`{"k":"v"}`))
	if err != nil {
		t.Fatalf("SealProject: %v", err)
	}
	for i := range blob {
		mutated := append([]byte(nil), blob...)
		mutated[i] ^= 0xFF
		if _, err := OpenProject(dek, mutated); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("flipping byte %d: err = %v, want ErrCorrupt", i, err)
		}
	}
}

func TestWrapUnwrapRoundtrip(t *testing.T) {
	pub, priv, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	dek := mustDEK(t)

	wrapped, err := WrapProjectDEK(dek, pub)
	if err != nil {
		t.Fatalf("WrapProjectDEK: %v", err)
	}
	if len(wrapped) != 80 {
		t.Fatalf("wrapped length = %d, want 80", len(wrapped))
	}
	got, err := UnwrapProjectDEK(wrapped, pub, priv)
	if err != nil {
		t.Fatalf("UnwrapProjectDEK: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("unwrapped DEK mismatch")
	}
}

func TestWrapFreshEphemeral(t *testing.T) {
	pub, _, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	dek := mustDEK(t)
	a, err := WrapProjectDEK(dek, pub)
	if err != nil {
		t.Fatalf("WrapProjectDEK: %v", err)
	}
	b, err := WrapProjectDEK(dek, pub)
	if err != nil {
		t.Fatalf("WrapProjectDEK: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two wraps produced identical bytes (ephemeral key reuse)")
	}
}

func TestUnwrapWrongRecipient(t *testing.T) {
	pub, _, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	otherPub, otherPriv, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	wrapped, err := WrapProjectDEK(mustDEK(t), pub)
	if err != nil {
		t.Fatalf("WrapProjectDEK: %v", err)
	}
	if _, err := UnwrapProjectDEK(wrapped, otherPub, otherPriv); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("wrong recipient: err = %v, want ErrWrongSecret", err)
	}
}

func TestWrapBadKeyLengths(t *testing.T) {
	dek := mustDEK(t)
	if _, err := WrapProjectDEK(dek, make([]byte, 31)); !errors.Is(err, ErrBadKeyLength) {
		t.Fatalf("short pub: err = %v, want ErrBadKeyLength", err)
	}
	if _, err := WrapProjectDEK(make([]byte, 31), make([]byte, 32)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("short dek: err = %v, want ErrCorrupt", err)
	}
	if _, err := UnwrapProjectDEK(make([]byte, 80), make([]byte, 31), make([]byte, 32)); !errors.Is(err, ErrBadKeyLength) {
		t.Fatalf("short pub on unwrap: err = %v, want ErrBadKeyLength", err)
	}
	if _, err := UnwrapProjectDEK(make([]byte, 79), make([]byte, 32), make([]byte, 32)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("short wrapped: err = %v, want ErrCorrupt", err)
	}
}

// TestWriteProjectFixture is the cross-language fixture generator. It is skipped
// unless WHARF_WRITE_FIXTURE names a destination path; when set, it writes a
// JSON fixture that the TypeScript side loads to prove byte compatibility of
// both the sealed-box DEK wrapping and the WHARFP project blob. Regenerate with:
//
//	WHARF_WRITE_FIXTURE=/path/to/project-fixture.json go test ./internal/vault/ -run TestWriteProjectFixture
func TestWriteProjectFixture(t *testing.T) {
	dest := os.Getenv("WHARF_WRITE_FIXTURE")
	if dest == "" {
		t.Skip("set WHARF_WRITE_FIXTURE=<path> to regenerate the project fixture")
	}

	pub, priv, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	dek := mustDEK(t)

	wrapped, err := WrapProjectDEK(dek, pub)
	if err != nil {
		t.Fatalf("WrapProjectDEK: %v", err)
	}

	// A representative host object matching store.Host JSON (all fields the
	// crypto contract must survive round-tripping, including the vault-only
	// password field).
	payload := []byte(`{"schema":1,"hosts":[{"id":"a1b2c3d4e5f60718","name":"prod-web-01","user":"deploy","addr":"10.0.4.12","port":22,"tags":["prod","web"],"keyPath":"~/.ssh/id_ed25519","authMethod":"password","password":"s3cr3t-p@ss","source":"manual","lastSeen":"2026-07-16T09:30:00Z"}]}`)

	blob, err := SealProject(dek, payload)
	if err != nil {
		t.Fatalf("SealProject: %v", err)
	}

	b64 := base64.StdEncoding.EncodeToString
	fixture := map[string]string{
		"description":       "Generated by wharf-tui internal/vault TestWriteProjectFixture. Do not edit.",
		"privateKeyBase64":  b64(priv),
		"publicKeyBase64":   b64(pub),
		"dekBase64":         b64(dek),
		"wrappedDekBase64":  b64(wrapped),
		"payloadUtf8":       string(payload),
		"projectBlobBase64": b64(blob),
	}
	out, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	out = append(out, '\n')
	if err := os.WriteFile(dest, out, 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Logf("wrote project fixture to %s", dest)
}
