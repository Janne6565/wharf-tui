package termius

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// writePPK builds a .ppk the way PuTTY does, so the parser is tested against
// the real container layout rather than against its own assumptions.
func writePPK(t *testing.T, algo, comment string, public, private []byte) []byte {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "PuTTY-User-Key-File-3: %s\n", algo)
	b.WriteString("Encryption: none\n")
	fmt.Fprintf(&b, "Comment: %s\n", comment)
	writeLines := func(name string, blob []byte) {
		enc := base64.StdEncoding.EncodeToString(blob)
		var lines []string
		for len(enc) > 64 {
			lines = append(lines, enc[:64])
			enc = enc[64:]
		}
		lines = append(lines, enc)
		fmt.Fprintf(&b, "%s: %d\n", name, len(lines))
		for _, l := range lines {
			b.WriteString(l + "\n")
		}
	}
	writeLines("Public-Lines", public)
	writeLines("Private-Lines", private)
	b.WriteString("Private-MAC: 00\n")
	return []byte(b.String())
}

// sshString encodes one length-prefixed field of the SSH wire format.
func sshString(b []byte) []byte {
	out := []byte{byte(len(b) >> 24), byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}
	return append(out, b...)
}

// sshMPInt encodes a big integer the way PuTTY blobs do.
func sshMPInt(i *big.Int) []byte {
	b := i.Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return sshString(b)
}

// checkConverts asserts that a .ppk converts into a private key the SSH engine
// can load, whose public half matches the original.
func checkConverts(t *testing.T, ppk []byte, want ssh.PublicKey) {
	t.Helper()
	pemBytes, line, err := ppkToOpenSSH(ppk)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("converted key does not parse: %v", err)
	}
	if !bytes.Equal(signer.PublicKey().Marshal(), want.Marshal()) {
		t.Error("converted key has a different public key than the original")
	}
	if !strings.Contains(line, want.Type()) {
		t.Errorf("public line %q does not name the key type %q", line, want.Type())
	}
}

func TestPPKConvertsRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	public := append(sshString([]byte(ssh.KeyAlgoRSA)),
		append(sshMPInt(big.NewInt(int64(key.E))), sshMPInt(key.N)...)...)
	// PuTTY order: d, p, q, iqmp.
	iqmp := new(big.Int).ModInverse(key.Primes[1], key.Primes[0])
	private := append(sshMPInt(key.D),
		append(sshMPInt(key.Primes[0]),
			append(sshMPInt(key.Primes[1]), sshMPInt(iqmp)...)...)...)

	checkConverts(t, writePPK(t, ssh.KeyAlgoRSA, "rsa-key", public, private), pub)
}

func TestPPKConvertsEd25519(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}

	public := append(sshString([]byte(ssh.KeyAlgoED25519)), sshString(pubKey)...)
	private := sshString(privKey.Seed())

	checkConverts(t, writePPK(t, ssh.KeyAlgoED25519, "ed-key", public, private), sshPub)
}

func TestPPKConvertsECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	point := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	public := append(sshString([]byte(ssh.KeyAlgoECDSA256)),
		append(sshString([]byte("nistp256")), sshString(point)...)...)
	private := sshMPInt(key.D)

	checkConverts(t, writePPK(t, ssh.KeyAlgoECDSA256, "ec-key", public, private), pub)
}

// A passphrase-protected key cannot be converted unattended; it must be
// reported rather than imported half-built.
func TestPPKEncryptedIsReported(t *testing.T) {
	ppk := []byte("PuTTY-User-Key-File-3: ssh-rsa\nEncryption: aes256-cbc\nComment: x\n")
	if _, _, err := ppkToOpenSSH(ppk); err != errPPKEncrypted {
		t.Fatalf("got %v, want errPPKEncrypted", err)
	}
}

// A .ppk whose private half does not belong to its public half must fail the
// verification rather than yield a subtly wrong key.
func TestPPKMismatchedHalvesFails(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	public := append(sshString([]byte(ssh.KeyAlgoED25519)), sshString(otherPub)...)
	private := sshString(privKey.Seed())

	if _, _, err := ppkToOpenSSH(writePPK(t, ssh.KeyAlgoED25519, "bad", public, private)); err == nil {
		t.Fatal("want an error when the halves do not match, got nil")
	}
}

func TestIsPPK(t *testing.T) {
	if !isPPK([]byte("PuTTY-User-Key-File-3: ssh-rsa\n")) {
		t.Error("v3 header not recognised")
	}
	if !isPPK([]byte("PuTTY-User-Key-File-2: ssh-rsa\n")) {
		t.Error("v2 header not recognised")
	}
	if isPPK([]byte("-----BEGIN OPENSSH PRIVATE KEY-----\n")) {
		t.Error("PEM key misidentified as PuTTY")
	}
}

// Termius allows duplicate key labels; the vault namespace is unique and
// case-insensitive, so collisions must be renamed rather than dropped.
func TestUniqueName(t *testing.T) {
	used := map[string]bool{}
	if got := uniqueName("key", used); got != "key" {
		t.Errorf("first = %q, want key", got)
	}
	if got := uniqueName("key", used); got != "key (2)" {
		t.Errorf("second = %q, want key (2)", got)
	}
	if got := uniqueName("KEY", used); got != "KEY (3)" {
		t.Errorf("case-insensitive collision = %q, want KEY (3)", got)
	}
}
