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

// WrapProjectDEK seals the 32-byte project DEK to recipientPub, returning
// exactly wrappedDEKLen (80) bytes. It is crypto_box_seal compatible: an
// ephemeral keypair is generated internally and its public key is prepended to
// the ciphertext.
func WrapProjectDEK(dek []byte, recipientPub []byte) ([]byte, error) {
	if len(dek) != dekLen {
		return nil, ErrCorrupt
	}
	if len(recipientPub) != x25519KeyLen {
		return nil, ErrBadKeyLength
	}
	var pub [x25519KeyLen]byte
	copy(pub[:], recipientPub)
	wrapped, err := box.SealAnonymous(nil, dek, &pub, rand.Reader)
	if err != nil {
		return nil, err
	}
	return wrapped, nil
}

// UnwrapProjectDEK opens a sealed project DEK with the recipient's keypair. A
// failure to open (wrong recipient or tampering — indistinguishable) maps to
// ErrWrongSecret, matching the vault's wrap-open discipline.
func UnwrapProjectDEK(wrapped, pub, priv []byte) ([]byte, error) {
	if len(pub) != x25519KeyLen || len(priv) != x25519KeyLen {
		return nil, ErrBadKeyLength
	}
	if len(wrapped) != wrappedDEKLen {
		return nil, ErrCorrupt
	}
	var pubArr, privArr [x25519KeyLen]byte
	copy(pubArr[:], pub)
	copy(privArr[:], priv)
	dek, ok := box.OpenAnonymous(nil, wrapped, &pubArr, &privArr)
	if !ok {
		return nil, ErrWrongSecret
	}
	return dek, nil
}
