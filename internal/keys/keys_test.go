package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/crypto/ssh"
)

// writeEncrypted writes a passphrase-protected ed25519 private key at path and,
// when withPub is true, its sibling .pub. Used to seed Scan fixtures.
func writeEncrypted(t *testing.T, dir, name string, withPub bool) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "enc", []byte("secret"))
	if err != nil {
		t.Fatalf("marshal encrypted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("write priv: %v", err)
	}
	if withPub {
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatalf("new pubkey: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".pub"), ssh.MarshalAuthorizedKey(sshPub), 0644); err != nil {
			t.Fatalf("write pub: %v", err)
		}
	}
}

func TestGenerateRoundTrip(t *testing.T) {
	dir := t.TempDir()

	info, err := Generate(dir, "id_ed25519", "me@host", nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if info.Type != "ED25519" || !info.HasPub || info.Encrypted {
		t.Fatalf("unexpected info: %+v", info)
	}

	// Private key must parse and its public half must match the reported
	// fingerprint, proving the pair is coherent.
	privData, err := os.ReadFile(filepath.Join(dir, "id_ed25519"))
	if err != nil {
		t.Fatalf("read priv: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(privData)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}

	pubData, err := os.ReadFile(filepath.Join(dir, "id_ed25519.pub"))
	if err != nil {
		t.Fatalf("read pub: %v", err)
	}
	pk, comment, _, _, err := ssh.ParseAuthorizedKey(pubData)
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	if comment != "me@host" {
		t.Errorf("pub comment = %q, want %q", comment, "me@host")
	}
	if got := ssh.FingerprintSHA256(pk); got != info.Fingerprint {
		t.Errorf("pub fingerprint = %q, info = %q", got, info.Fingerprint)
	}
	if got := ssh.FingerprintSHA256(signer.PublicKey()); got != info.Fingerprint {
		t.Errorf("priv fingerprint = %q, info = %q", got, info.Fingerprint)
	}
}

func TestGenerateFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file modes")
	}
	dir := t.TempDir()
	if _, err := Generate(dir, "id_ed25519", "", nil); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	privStat, err := os.Stat(filepath.Join(dir, "id_ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	if got := privStat.Mode().Perm(); got != 0600 {
		t.Errorf("priv mode = %o, want 0600", got)
	}
	pubStat, err := os.Stat(filepath.Join(dir, "id_ed25519.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if got := pubStat.Mode().Perm(); got != 0644 {
		t.Errorf("pub mode = %o, want 0644", got)
	}
}

func TestGenerateNoClobber(t *testing.T) {
	dir := t.TempDir()
	if _, err := Generate(dir, "id_ed25519", "first", nil); err != nil {
		t.Fatalf("first Generate: %v", err)
	}
	orig, err := os.ReadFile(filepath.Join(dir, "id_ed25519"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Generate(dir, "id_ed25519", "second", nil); err == nil {
		t.Fatal("second Generate: expected error, got nil")
	}

	// The existing key must be byte-for-byte untouched.
	after, err := os.ReadFile(filepath.Join(dir, "id_ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	if string(orig) != string(after) {
		t.Error("existing private key was clobbered")
	}
}

func TestGenerateRefusesExistingPub(t *testing.T) {
	dir := t.TempDir()
	// A stray .pub with no private key must still block generation, and must
	// not be overwritten.
	if err := os.WriteFile(filepath.Join(dir, "id_ed25519.pub"), []byte("stray\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(dir, "id_ed25519", "", nil); err == nil {
		t.Fatal("expected error when .pub exists")
	}
	if _, err := os.Stat(filepath.Join(dir, "id_ed25519")); !errors.Is(err, os.ErrNotExist) {
		t.Error("private key should not have been written")
	}
	data, _ := os.ReadFile(filepath.Join(dir, "id_ed25519.pub"))
	if string(data) != "stray\n" {
		t.Error("existing .pub was clobbered")
	}
}

func TestGenerateEncrypted(t *testing.T) {
	dir := t.TempDir()
	info, err := Generate(dir, "id_ed25519", "me", []byte("hunter2"))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !info.Encrypted {
		t.Error("info.Encrypted = false, want true")
	}

	privData, err := os.ReadFile(filepath.Join(dir, "id_ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	// Without the passphrase it must report PassphraseMissingError.
	_, err = ssh.ParsePrivateKey(privData)
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		t.Errorf("ParsePrivateKey err = %v, want PassphraseMissingError", err)
	}
	// With the passphrase it must parse.
	if _, err := ssh.ParsePrivateKeyWithPassphrase(privData, []byte("hunter2")); err != nil {
		t.Errorf("ParsePrivateKeyWithPassphrase: %v", err)
	}
}

func TestGenerateInvalidName(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"", "sub/key", "..", "."} {
		if _, err := Generate(dir, name, "", nil); err == nil {
			t.Errorf("Generate(name=%q): expected error", name)
		}
	}
}

func TestScanClassification(t *testing.T) {
	dir := t.TempDir()

	// Plain key (with its .pub).
	plain, err := Generate(dir, "id_plain", "plain", nil)
	if err != nil {
		t.Fatalf("Generate plain: %v", err)
	}
	// Encrypted key with a sibling .pub.
	writeEncrypted(t, dir, "id_enc_pub", true)
	// Encrypted key without a .pub.
	writeEncrypted(t, dir, "id_enc_nopub", false)
	// Junk that is not a key at all.
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("just notes\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// A .pub-only entry (no private key) — must be skipped by suffix.
	if err := os.WriteFile(filepath.Join(dir, "orphan.pub"), []byte("ssh-ed25519 AAAA orphan\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Standard non-key files that must never appear.
	for _, n := range []string{"config", "known_hosts", "authorized_keys"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	byName := make(map[string]KeyInfo, len(got))
	for _, k := range got {
		byName[k.Name] = k
	}
	if len(byName) != 3 {
		var names []string
		for _, k := range got {
			names = append(names, k.Name)
		}
		t.Fatalf("scanned %d keys %v, want 3 (id_plain, id_enc_pub, id_enc_nopub)", len(got), names)
	}

	// Sorted by name.
	if got[0].Name != "id_enc_nopub" || got[1].Name != "id_enc_pub" || got[2].Name != "id_plain" {
		t.Errorf("not sorted by name: %v %v %v", got[0].Name, got[1].Name, got[2].Name)
	}

	if p := byName["id_plain"]; p.Encrypted || !p.HasPub || p.Type != "ED25519" || p.Fingerprint != plain.Fingerprint {
		t.Errorf("id_plain wrong: %+v", p)
	}
	if e := byName["id_enc_pub"]; !e.Encrypted || !e.HasPub || e.Type != "ED25519" || e.Fingerprint == "" {
		t.Errorf("id_enc_pub wrong: %+v", e)
	}
	if e := byName["id_enc_nopub"]; !e.Encrypted || e.HasPub || e.Type != "?" || e.Fingerprint != "" {
		t.Errorf("id_enc_nopub wrong: %+v", e)
	}
}

func TestScanMissingDir(t *testing.T) {
	got, err := Scan(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Errorf("err = %v, want nil for missing dir", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d keys, want 0", len(got))
	}
}
