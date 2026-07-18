package store

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Fixed, deterministic OpenSSH key material for the cross-language keys-document
// fixture. Both keys were generated once with ssh-keygen (ed25519); the second is
// passphrase-protected with "wharf-fixture". They are embedded VERBATIM so the
// fixture regenerates byte-for-byte. `material` in the vault stores the base64 of
// exactly these bytes (the keyfile as written to disk, trailing newline included),
// so a passphrase-encrypted file stays encrypted inside the vault.
const (
	fixtureUnencryptedPEM = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBBEzV60/rSdwP0+2qBzAXU6uIEBMjZ7uEMZPLPvhA0PgAAAKCwbdhZsG3Y
WQAAAAtzc2gtZWQyNTUxOQAAACBBEzV60/rSdwP0+2qBzAXU6uIEBMjZ7uEMZPLPvhA0Pg
AAAEA1BAgykyxKPhRv/meVo+KKyMKhlgPYwPbkxI2CmzdDj0ETNXrT+tJ3A/T7aoHMBdTq
4gQEyNnu4Qxk8s++EDQ+AAAAGXdoYXJmLWZpeHR1cmUtdW5lbmNyeXB0ZWQBAgME
-----END OPENSSH PRIVATE KEY-----
`
	fixtureUnencryptedPub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEETNXrT+tJ3A/T7aoHMBdTq4gQEyNnu4Qxk8s++EDQ+ wharf-fixture-unencrypted"

	fixtureEncryptedPEM = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBG+aXCAj
uGe0LA0IzjpBX7AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIL+SDO+stsvTfwZS
YX4MrKmvrnRH1jA8kZ+cWuAqLzL1AAAAoELIflCTkkM8wW2v4dzDmFW/kVm5AXJuN34KsX
96j/G2jHq29izIVg62FZPriEHVPq9yO7g4an1t1x+i+Sax4d28RpnS39JsK6e6Bk1zaIQ2
xMSi3LAM41qj6Jkor/+oKy19kc14QHTTWpN5GzRnVFsxl1fL+BzBq193UU0Z/ASGIKPY8o
rSMgo9FzVfK85PB/VkCV55q5vx55+VhPDQrX0=
-----END OPENSSH PRIVATE KEY-----
`
	fixtureEncryptedPub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL+SDO+stsvTfwZSYX4MrKmvrnRH1jA8kZ+cWuAqLzL1 wharf-fixture-encrypted"
)

// captureBackend is a minimal Backend that records the last Saved payload, so a
// test can read back the exact document string store.Save wrote (NewMemory's
// noopBackend discards it).
type captureBackend struct{ saved []byte }

func (b *captureBackend) Payload() []byte     { return b.saved }
func (b *captureBackend) Save(p []byte) error { b.saved = append([]byte(nil), p...); return nil }

// buildKeysFixtureStore builds a store with one key-mode host, a vault identity,
// and two vault keys (an unencrypted and a passphrase-encrypted ed25519), all with
// FIXED ids/timestamps so the Saved document is byte-stable. It returns the backend
// (holding the Saved document) after a Save.
func buildKeysFixtureStore(t *testing.T) *captureBackend {
	t.Helper()
	backend := &captureBackend{}
	st, err := Open(backend)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if _, err := st.AddHost(Host{
		ID:         "a1b2c3d4e5f60718",
		Name:       "prod-web-01",
		User:       "deploy",
		Addr:       "10.0.4.12",
		Port:       22,
		Tags:       []string{"prod", "web"},
		KeyPath:    "~/.ssh/id_ed25519",
		AuthMethod: "key",
		Source:     "manual",
		LastSeen:   time.Date(2026, 7, 16, 9, 30, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("AddHost: %v", err)
	}

	st.SetIdentity(&Identity{
		X25519Priv: "cHJpdmF0ZS1rZXktMzItYnl0ZXMtZml4dHVyZS1zZWVkISE=",
		X25519Pub:  "cHVibGljLWtleS0zMi1ieXRlcy1maXh0dXJlLXNlZWQhISEh",
		CreatedAt:  time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC),
	})

	// Added in name-sorted order so the on-disk `keys` order matches Keys() and the
	// TS extractVaultKeyRefs order — the fixture's expect arrays follow it too.
	if _, err := st.AddKey(VaultKey{
		ID:         "1111111111111111",
		Name:       "personal-laptop",
		Type:       "ED25519",
		Material:   base64.StdEncoding.EncodeToString([]byte(fixtureUnencryptedPEM)),
		PublicKey:  fixtureUnencryptedPub,
		SourcePath: "~/.ssh/id_ed25519",
		AddedAt:    time.Date(2026, 7, 18, 8, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("AddKey unencrypted: %v", err)
	}
	if _, err := st.AddKey(VaultKey{
		ID:        "2222222222222222",
		Name:      "prod-bastion",
		Type:      "ED25519",
		Material:  base64.StdEncoding.EncodeToString([]byte(fixtureEncryptedPEM)),
		PublicKey: fixtureEncryptedPub,
		AddedAt:   time.Date(2026, 7, 18, 8, 5, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("AddKey encrypted: %v", err)
	}

	if err := st.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return backend
}

// TestKeysDocumentRoundtrip is the always-run guard for the schema-3 keys fixture:
// the document store.Save writes must reopen with both vault keys intact
// (material + public key verbatim), independent of whether the fixture is
// regenerated. This is what keeps the committed fixture honest.
func TestKeysDocumentRoundtrip(t *testing.T) {
	backend := buildKeysFixtureStore(t)

	reopened, err := Open(backend)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	keys := reopened.Keys()
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	// Keys() is name-sorted: personal-laptop, then prod-bastion.
	if keys[0].Name != "personal-laptop" || keys[1].Name != "prod-bastion" {
		t.Fatalf("unexpected key order: %q, %q", keys[0].Name, keys[1].Name)
	}
	wantMaterial := map[string]string{
		"personal-laptop": base64.StdEncoding.EncodeToString([]byte(fixtureUnencryptedPEM)),
		"prod-bastion":    base64.StdEncoding.EncodeToString([]byte(fixtureEncryptedPEM)),
	}
	wantPub := map[string]string{
		"personal-laptop": fixtureUnencryptedPub,
		"prod-bastion":    fixtureEncryptedPub,
	}
	for _, k := range keys {
		if k.Material != wantMaterial[k.Name] {
			t.Errorf("%s: material not round-tripped verbatim", k.Name)
		}
		if k.PublicKey != wantPub[k.Name] {
			t.Errorf("%s: publicKey = %q, want %q", k.Name, k.PublicKey, wantPub[k.Name])
		}
	}

	// The unencrypted key's material must still parse as a real private key, and
	// its fingerprint must equal the one derived from the public line.
	signer, err := ssh.ParsePrivateKey([]byte(fixtureUnencryptedPEM))
	if err != nil {
		t.Fatalf("ParsePrivateKey(unencrypted): %v", err)
	}
	if got, want := ssh.FingerprintSHA256(signer.PublicKey()), fingerprintOf(t, fixtureUnencryptedPub); got != want {
		t.Errorf("unencrypted fingerprint mismatch: %q vs %q", got, want)
	}
	// The encrypted key's material must NOT parse without the passphrase (it stays
	// protected inside the vault), and must parse with it.
	if _, err := ssh.ParsePrivateKey([]byte(fixtureEncryptedPEM)); err == nil {
		t.Errorf("encrypted key parsed without passphrase — fixture is not actually encrypted")
	}
	if _, err := ssh.ParsePrivateKeyWithPassphrase([]byte(fixtureEncryptedPEM), []byte("wharf-fixture")); err != nil {
		t.Errorf("ParsePrivateKeyWithPassphrase(encrypted): %v", err)
	}
}

// fingerprintOf parses an authorized_keys line and returns its SHA256 fingerprint.
func fingerprintOf(t *testing.T, authorizedKeyLine string) string {
	t.Helper()
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKeyLine))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey(%q): %v", authorizedKeyLine, err)
	}
	return ssh.FingerprintSHA256(pub)
}

// keysDocumentFixture is the JSON shape written for the cross-language keys parity
// test. payloadUtf8 is the exact store.Save document; expect is what every client
// must derive from it.
type keysDocumentFixture struct {
	Description string `json:"description"`
	PayloadUtf8 string `json:"payloadUtf8"`
	Expect      struct {
		Schema       int      `json:"schema"`
		KeyNames     []string `json:"keyNames"`
		KeyTypes     []string `json:"keyTypes"`
		Fingerprints []string `json:"fingerprints"`
		PublicKeys   []string `json:"publicKeys"`
	} `json:"expect"`
}

// TestWriteKeysDocumentFixture is the cross-language fixture generator for the
// schema-3 synced-SSH-keys document. It is skipped unless WHARF_WRITE_FIXTURE
// names a destination path; when set, it writes a JSON fixture the TypeScript
// clients load to prove they parse a schema-3 `keys` array, strip the secret
// `material` from typed metadata, and derive OpenSSH SHA256 fingerprints identical
// to Go's ssh.FingerprintSHA256. Regenerate with:
//
//	WHARF_WRITE_FIXTURE=/path/to/keys-document-fixture.json \
//	  go test ./internal/store/ -run TestWriteKeysDocumentFixture
func TestWriteKeysDocumentFixture(t *testing.T) {
	dest := os.Getenv("WHARF_WRITE_FIXTURE")
	if dest == "" {
		t.Skip("set WHARF_WRITE_FIXTURE=<path> to regenerate the keys document fixture")
	}

	backend := buildKeysFixtureStore(t)

	var fixture keysDocumentFixture
	fixture.Description = "Generated by wharf-tui internal/store TestWriteKeysDocumentFixture. " +
		"Do not edit. Regenerate with: WHARF_WRITE_FIXTURE=<path> go test ./internal/store/ -run TestWriteKeysDocumentFixture"
	fixture.PayloadUtf8 = string(backend.saved)
	fixture.Expect.Schema = schemaVersion
	fixture.Expect.KeyNames = []string{"personal-laptop", "prod-bastion"}
	fixture.Expect.KeyTypes = []string{"ED25519", "ED25519"}
	fixture.Expect.Fingerprints = []string{
		fingerprintOf(t, fixtureUnencryptedPub),
		fingerprintOf(t, fixtureEncryptedPub),
	}
	fixture.Expect.PublicKeys = []string{fixtureUnencryptedPub, fixtureEncryptedPub}

	out, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	out = append(out, '\n')
	if err := os.WriteFile(dest, out, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Logf("wrote keys document fixture to %s", dest)
}
