package vault

import (
	"bytes"
	"crypto/mlkem"
	"testing"
)

func TestHybridRoundTrip(t *testing.T) {
	pub, priv, err := GenerateHybridIdentity()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !IsHybridPub(pub) {
		t.Fatalf("generated pub is not v2: len=%d", len(pub))
	}
	if len(priv) != hybridPrivLen || priv[0] != identityV2 {
		t.Fatalf("generated priv is not v2: len=%d", len(priv))
	}

	dek := bytes.Repeat([]byte{7}, dekLen)
	wrapped, err := WrapProjectDEK(dek, pub)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if !IsHybridWrapped(wrapped) {
		t.Fatalf("wrapped is not v2: len=%d", len(wrapped))
	}

	got, err := UnwrapProjectDEK(wrapped, pub, priv)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("unwrapped DEK differs")
	}
}

// TestUpgradePreservesLegacyWrapped is the property the whole migration rests
// on: upgrading an identity keeps its X25519 half, so DEKs sealed before the
// upgrade still open afterwards and no project re-enters awaiting-access.
func TestUpgradePreservesLegacyWrapped(t *testing.T) {
	v1Pub, v1Priv, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("generate v1: %v", err)
	}
	dek := bytes.Repeat([]byte{3}, dekLen)
	legacy, err := WrapProjectDEK(dek, v1Pub)
	if err != nil {
		t.Fatalf("wrap v1: %v", err)
	}
	if len(legacy) != wrappedDEKLen {
		t.Fatalf("v1 wrap length = %d, want %d", len(legacy), wrappedDEKLen)
	}

	pub, priv, err := UpgradeIdentity(v1Pub, v1Priv)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if !bytes.Equal(pub[1:1+x25519KeyLen], v1Pub) {
		t.Fatal("upgrade changed the X25519 public half")
	}

	got, err := UnwrapProjectDEK(legacy, pub, priv)
	if err != nil {
		t.Fatalf("unwrap legacy with upgraded identity: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("legacy DEK differs")
	}
}

// TestWrapFollowsRecipientVersion: an upgraded client must still be able to key
// a member who has not upgraded, and that member must still be able to open it.
func TestWrapFollowsRecipientVersion(t *testing.T) {
	v1Pub, v1Priv, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("generate v1: %v", err)
	}
	dek := bytes.Repeat([]byte{9}, dekLen)

	wrapped, err := WrapProjectDEK(dek, v1Pub)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if len(wrapped) != wrappedDEKLen {
		t.Fatalf("wrap to v1 recipient produced %d bytes, want %d", len(wrapped), wrappedDEKLen)
	}
	got, err := UnwrapProjectDEK(wrapped, v1Pub, v1Priv)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("DEK differs")
	}
}

// TestHybridNeedsBothHalves pins the AND-composition: neither half alone opens a
// v2 blob.
func TestHybridNeedsBothHalves(t *testing.T) {
	pub, priv, err := GenerateHybridIdentity()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	wrapped, err := WrapProjectDEK(bytes.Repeat([]byte{1}, dekLen), pub)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	// X25519 half only (a v1 identity holding the same X25519 key).
	if _, err := UnwrapProjectDEK(wrapped, pub[1:1+x25519KeyLen], priv[1:1+x25519KeyLen]); err == nil {
		t.Fatal("v2 blob opened with the X25519 half alone")
	}

	// ML-KEM half only: keep the real seed, substitute a foreign X25519 key.
	otherPub, otherPriv, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("generate other: %v", err)
	}
	forgedPub := append(append([]byte{identityV2}, otherPub...), pub[1+x25519KeyLen:]...)
	forgedPriv := append(append([]byte{identityV2}, otherPriv...), priv[1+x25519KeyLen:]...)
	if _, err := UnwrapProjectDEK(wrapped, forgedPub, forgedPriv); err == nil {
		t.Fatal("v2 blob opened with the ML-KEM half alone")
	}
}

func TestHybridRejectsTamper(t *testing.T) {
	pub, priv, err := GenerateHybridIdentity()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	wrapped, err := WrapProjectDEK(bytes.Repeat([]byte{5}, dekLen), pub)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	for _, tc := range []struct {
		name string
		at   int
	}{
		{"version", 0},
		{"mlkem ciphertext", 1},
		{"nonce", 1 + mlkem.CiphertextSize768},
		{"body", hybridWrappedLen - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := bytes.Clone(wrapped)
			bad[tc.at] ^= 0xff
			if _, err := UnwrapProjectDEK(bad, pub, priv); err == nil {
				t.Fatal("tampered blob opened")
			}
		})
	}
}

func TestHybridSizes(t *testing.T) {
	if hybridPubLen != 1217 {
		t.Fatalf("hybridPubLen = %d, want 1217", hybridPubLen)
	}
	if hybridPrivLen != 97 {
		t.Fatalf("hybridPrivLen = %d, want 97", hybridPrivLen)
	}
	if hybridWrappedLen != 1209 {
		t.Fatalf("hybridWrappedLen = %d, want 1209", hybridWrappedLen)
	}
}
