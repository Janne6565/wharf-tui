// X25519 sealed-box wrapping of a project DEK. A project's DEK is shared with a
// recipient by sealing it to their X25519 public key: the sender needs no
// long-term key of their own (an ephemeral keypair is generated per seal), and
// only the recipient's private key can open it. This is wire-compatible with
// libsodium's crypto_box_seal / crypto_box_seal_open (and NaCl's box.Seal
// Anonymous), so the TypeScript client (wharf-web/src/crypto/x25519.ts) wraps
// and unwraps the identical bytes.
package vault

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/nacl/box"
)

const (
	// x25519KeyLen is the length of an X25519 public or private key.
	x25519KeyLen = 32
	// wrappedDEKLen is the exact length of a sealed project DEK:
	// 32 ephemeral public key + 32 DEK + 16 Poly1305 tag.
	wrappedDEKLen = x25519KeyLen + dekLen + box.Overhead
)

// ErrBadKeyLength is returned when a key argument is not 32 bytes.
var ErrBadKeyLength = errors.New("vault: key must be 32 bytes")

// GenerateIdentity creates a fresh X25519 keypair. The private key stays inside
// the owner's personal vault; the public key is published so others can wrap
// project DEKs to it.
func GenerateIdentity() (pub, priv []byte, err error) {
	pubArr, privArr, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pubArr[:], privArr[:], nil
}

// WrapProjectDEK seals the 32-byte project DEK to recipientPub. Against a v1
// (bare X25519) recipient it returns exactly wrappedDEKLen (80) bytes, crypto_box_seal
// compatible: an ephemeral keypair is generated internally and its public key is
// prepended to the ciphertext. Against a v2 recipient the sealed box is wrapped
// again under a fresh ML-KEM-768 encapsulation (see hybrid.go), so the result is
// hybridWrappedLen bytes and is not decryptable by a future quantum attacker.
//
// The version follows the *recipient*, never a local preference: an upgraded
// client must still be able to key a member who has not upgraded yet.
func WrapProjectDEK(dek []byte, recipientPub []byte) ([]byte, error) {
	if len(dek) != dekLen {
		return nil, ErrCorrupt
	}
	x25519Pub, ek, err := splitPub(recipientPub)
	if err != nil {
		return nil, err
	}
	var pub [x25519KeyLen]byte
	copy(pub[:], x25519Pub)
	wrapped, err := box.SealAnonymous(nil, dek, &pub, rand.Reader)
	if err != nil {
		return nil, err
	}
	if ek == nil {
		return wrapped, nil
	}
	return wrapHybrid(wrapped, ek)
}

// UnwrapProjectDEK opens a sealed project DEK with the recipient's keypair. A
// failure to open (wrong recipient or tampering — indistinguishable) maps to
// ErrWrongSecret, matching the vault's wrap-open discipline.
// It accepts both versions independently of the identity's own version: a v2
// identity keeps its X25519 half, so every DEK sealed to it before the upgrade
// still opens.
func UnwrapProjectDEK(wrapped, pub, priv []byte) ([]byte, error) {
	x25519Pub, _, err := splitPub(pub)
	if err != nil {
		return nil, err
	}
	x25519Priv, dk, err := splitPriv(priv)
	if err != nil {
		return nil, err
	}
	switch {
	case IsHybridWrapped(wrapped):
		inner, err := unwrapHybrid(wrapped, dk)
		if err != nil {
			return nil, err
		}
		wrapped = inner
	case len(wrapped) != wrappedDEKLen:
		return nil, ErrCorrupt
	}
	var pubArr, privArr [x25519KeyLen]byte
	copy(pubArr[:], x25519Pub)
	copy(privArr[:], x25519Priv)
	dek, ok := box.OpenAnonymous(nil, wrapped, &pubArr, &privArr)
	if !ok {
		return nil, ErrWrongSecret
	}
	return dek, nil
}
