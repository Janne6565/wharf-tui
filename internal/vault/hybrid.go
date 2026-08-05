// Hybrid post-quantum wrapping of a project DEK.
//
// A v1 identity is a bare X25519 keypair and a v1 wrapped DEK is a bare 80-byte
// crypto_box_seal (see box.go). Both are classical: an attacker who records the
// server's copy of a wrapped DEK today can decrypt it once a cryptographically
// relevant quantum computer exists, since the whole point of the zero-knowledge
// model is that the server stores those bytes forever. v2 closes that by adding
// ML-KEM-768 (FIPS 203) *around* the existing sealed box rather than replacing
// it:
//
//	v2 identity pub  = 0x02 || X25519 pub (32) || ML-KEM-768 ek (1184)
//	v2 identity priv = 0x02 || X25519 priv (32) || ML-KEM-768 seed (64)
//	v2 wrapped DEK   = 0x02 || ML-KEM ct (1088) || nonce (24) ||
//	                   XChaCha20-Poly1305(key = HKDF(ss), aad = 0x02 || ct,
//	                                      plaintext = v1 sealed box (80))
//
// The composition is deliberately a nesting, not a key-combiner: opening a v2
// blob needs the ML-KEM decapsulation key AND the X25519 private key, so it is
// secure if *either* primitive survives, and it reuses the sealed-box code that
// is already fixture-proven byte-identical across the Go, TypeScript and mobile
// clients. Nothing about the inner 80 bytes changes.
//
// The ML-KEM private half is stored as its 64-byte FIPS 203 (d, z) seed and
// expanded on use, so every implementation derives the same decapsulation key
// from the same vault bytes.
package vault

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	// identityV2 is the version byte prefixing every v2 identity key and wrapped
	// DEK. v1 values carry no prefix and are recognised by their exact length.
	identityV2 = 0x02

	// hybridPubLen is the length of a v2 identity public key.
	hybridPubLen = 1 + x25519KeyLen + mlkem.EncapsulationKeySize768
	// hybridPrivLen is the length of a v2 identity private key.
	hybridPrivLen = 1 + x25519KeyLen + mlkem.SeedSize
	// hybridWrappedLen is the length of a v2 wrapped DEK.
	hybridWrappedLen = 1 + mlkem.CiphertextSize768 + chacha20poly1305.NonceSizeX +
		wrappedDEKLen + chacha20poly1305.Overhead

	// dekWrapInfo domain-separates the HKDF that turns the ML-KEM shared secret
	// into the outer AEAD key.
	dekWrapInfo = "wharf/dek-wrap/v2"
)

// IsHybridPub reports whether pub is a v2 (post-quantum) identity public key.
// Callers use it to tell a member who has upgraded from one who has not.
func IsHybridPub(pub []byte) bool {
	return len(pub) == hybridPubLen && pub[0] == identityV2
}

// IsIdentityPub reports whether b is a well-formed identity public key of
// either version — the check the UI applies to a key the *server* hands out,
// where anything else is garbage rather than someone's key.
func IsIdentityPub(b []byte) bool {
	return len(b) == x25519KeyLen || IsHybridPub(b)
}

// IsHybridWrapped reports whether a wrapped DEK is v2.
func IsHybridWrapped(wrapped []byte) bool {
	return len(wrapped) == hybridWrappedLen && wrapped[0] == identityV2
}

// GenerateHybridIdentity creates a fresh v2 identity: an X25519 keypair and an
// ML-KEM-768 keypair, returned in the encoded forms above.
func GenerateHybridIdentity() (pub, priv []byte, err error) {
	xPub, xPriv, err := GenerateIdentity()
	if err != nil {
		return nil, nil, err
	}
	return UpgradeIdentity(xPub, xPriv)
}

// UpgradeIdentity lifts an existing v1 X25519 keypair to v2 by generating an
// ML-KEM-768 keypair alongside it. The X25519 half is preserved deliberately:
// every DEK already sealed to it stays openable, so an account can publish its
// hybrid key without any project re-entering the awaiting-access state.
func UpgradeIdentity(x25519Pub, x25519Priv []byte) (pub, priv []byte, err error) {
	seed, err := NewMLKEMSeed()
	if err != nil {
		return nil, nil, err
	}
	return EncodeIdentity(x25519Pub, x25519Priv, seed)
}

// NewMLKEMSeed generates the 64-byte FIPS 203 seed for a fresh ML-KEM-768
// keypair. The seed — not the expanded decapsulation key — is what the personal
// vault stores, so every client derives the same keypair from the same bytes.
func NewMLKEMSeed() ([]byte, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return dk.Bytes(), nil
}

// EncodeIdentity assembles the wire forms of an identity from its stored parts.
// An empty seed yields the v1 forms (the bare X25519 keys) so a vault written
// before the hybrid upgrade round-trips unchanged.
func EncodeIdentity(x25519Pub, x25519Priv, mlkemSeed []byte) (pub, priv []byte, err error) {
	if len(x25519Pub) != x25519KeyLen || len(x25519Priv) != x25519KeyLen {
		return nil, nil, ErrBadKeyLength
	}
	if len(mlkemSeed) == 0 {
		return bytes.Clone(x25519Pub), bytes.Clone(x25519Priv), nil
	}
	if len(mlkemSeed) != mlkem.SeedSize {
		return nil, nil, ErrBadKeyLength
	}
	dk, err := mlkem.NewDecapsulationKey768(mlkemSeed)
	if err != nil {
		return nil, nil, ErrCorrupt
	}

	pub = make([]byte, 0, hybridPubLen)
	pub = append(pub, identityV2)
	pub = append(pub, x25519Pub...)
	pub = append(pub, dk.EncapsulationKey().Bytes()...)

	priv = make([]byte, 0, hybridPrivLen)
	priv = append(priv, identityV2)
	priv = append(priv, x25519Priv...)
	priv = append(priv, mlkemSeed...)

	return pub, priv, nil
}

// splitPub splits an identity public key into its X25519 half and, for v2, its
// ML-KEM encapsulation key. A v1 key yields a nil encapsulation key.
func splitPub(pub []byte) (x25519 []byte, ek *mlkem.EncapsulationKey768, err error) {
	switch {
	case len(pub) == x25519KeyLen:
		return pub, nil, nil
	case IsHybridPub(pub):
		ek, err := mlkem.NewEncapsulationKey768(pub[1+x25519KeyLen:])
		if err != nil {
			return nil, nil, ErrCorrupt
		}
		return pub[1 : 1+x25519KeyLen], ek, nil
	default:
		return nil, nil, ErrBadKeyLength
	}
}

// splitPriv splits an identity private key into its X25519 half and, for v2,
// its ML-KEM decapsulation key expanded from the stored seed.
func splitPriv(priv []byte) (x25519 []byte, dk *mlkem.DecapsulationKey768, err error) {
	switch {
	case len(priv) == x25519KeyLen:
		return priv, nil, nil
	case len(priv) == hybridPrivLen && priv[0] == identityV2:
		dk, err := mlkem.NewDecapsulationKey768(priv[1+x25519KeyLen:])
		if err != nil {
			return nil, nil, ErrCorrupt
		}
		return priv[1 : 1+x25519KeyLen], dk, nil
	default:
		return nil, nil, ErrBadKeyLength
	}
}

// wrapHybrid seals an already-sealed (v1) DEK under a fresh ML-KEM-768
// encapsulation to ek.
func wrapHybrid(inner []byte, ek *mlkem.EncapsulationKey768) ([]byte, error) {
	sharedKey, ct := ek.Encapsulate()

	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, sharedKey, nil, []byte(dekWrapInfo)), key); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, hybridWrappedLen)
	out = append(out, identityV2)
	out = append(out, ct...)

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	// AAD binds the ciphertext to the encapsulation it was derived from, so a
	// ML-KEM ciphertext cannot be swapped between two wrapped DEKs.
	aad := out[:1+mlkem.CiphertextSize768]
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, inner, aad)

	if len(out) != hybridWrappedLen {
		return nil, ErrCorrupt
	}
	return out, nil
}

// unwrapHybrid strips the ML-KEM layer, returning the inner v1 sealed box.
func unwrapHybrid(wrapped []byte, dk *mlkem.DecapsulationKey768) ([]byte, error) {
	if dk == nil {
		// A v2 blob against a v1 identity: the recipient simply cannot open it.
		return nil, ErrWrongSecret
	}
	ct := wrapped[1 : 1+mlkem.CiphertextSize768]
	sharedKey, err := dk.Decapsulate(ct)
	if err != nil {
		return nil, ErrWrongSecret
	}

	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, sharedKey, nil, []byte(dekWrapInfo)), key); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	off := 1 + mlkem.CiphertextSize768
	nonce := wrapped[off : off+chacha20poly1305.NonceSizeX]
	body := wrapped[off+chacha20poly1305.NonceSizeX:]
	inner, err := aead.Open(nil, nonce, body, wrapped[:off])
	if err != nil {
		return nil, ErrWrongSecret
	}
	return inner, nil
}
