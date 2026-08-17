package termius

import (
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/nacl/secretbox"
)

// Cipher format (reverse-engineered):
//
//	base64( 0x04 0x01 | nonce[24] | XSalsa20-Poly1305(plaintext) )
//
// which is a plain NaCl secretbox with a two-byte version header in front. The
// key is the base64-decoded localKey from the OS credential store.
var cipherHeader = [2]byte{0x04, 0x01}

const (
	nonceSize   = 24
	keySize     = 32
	minEnvelope = len(cipherHeader) + nonceSize + secretbox.Overhead
)

// ErrUnknownCipherVersion means a field is shaped like an envelope but carries a
// header we do not know — Termius changed its encryption and the export must not
// be trusted.
type ErrUnknownCipherVersion struct{ Header []byte }

func (e ErrUnknownCipherVersion) Error() string {
	return fmt.Sprintf("unknown cipher version header %x (only %x is known); "+
		"Termius may have changed its encryption scheme", e.Header, cipherHeader)
}

// ErrWrongKey means the header matched but Poly1305 rejected the ciphertext, so
// the key belongs to a different profile. Distinct from "no key found": the fix
// is to pick a different keyring entry, not to install or unlock anything.
var ErrWrongKey = fmt.Errorf("localKey does not decrypt this profile")

// decryptor unseals individual fields and counts what it saw, so an import can
// refuse to report success when nothing actually decrypted.
type decryptor struct {
	key                      [keySize]byte
	decrypted, plain, failed int
}

func newDecryptor(key []byte) (*decryptor, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("localKey must be %d bytes, got %d", keySize, len(key))
	}
	d := &decryptor{}
	copy(d.key[:], key)
	return d, nil
}

// isEnvelope reports whether a value is an encrypted field at all.
//
// Identification is by version header, never by a "looks like base64"
// heuristic: heuristics misfire in both directions, treating ordinary base64
// payloads as ciphertext and a successfully decrypted empty string as failure.
func isEnvelope(raw []byte) bool {
	return len(raw) >= minEnvelope && raw[0] == cipherHeader[0] && raw[1] == cipherHeader[1]
}

// field decrypts one value. Values that are not envelopes pass through
// unchanged — plenty of Termius columns (os_name, status, ip_version) are
// stored in the clear.
func (d *decryptor) field(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		d.plain++
		return v, nil
	}
	if !isEnvelope(raw) {
		// Long enough to be an envelope but with a foreign header: that is a
		// format change, not a plaintext field, and guessing would corrupt the
		// import silently.
		if len(raw) >= minEnvelope && raw[0] != cipherHeader[0] {
			return "", ErrUnknownCipherVersion{Header: raw[:2]}
		}
		d.plain++
		return v, nil
	}

	var nonce [nonceSize]byte
	copy(nonce[:], raw[len(cipherHeader):len(cipherHeader)+nonceSize])
	out, ok := secretbox.Open(nil, raw[len(cipherHeader)+nonceSize:], &nonce, &d.key)
	if !ok {
		d.failed++
		return "", ErrWrongKey
	}
	d.decrypted++
	// May legitimately be empty — an unnamed host has an encrypted empty label.
	return string(out), nil
}

// str decrypts a field read out of a decoded record, tolerating absent and
// non-string values.
func (d *decryptor) str(rec map[string]any, key string) (string, error) {
	v, ok := rec[key].(string)
	if !ok {
		return "", nil
	}
	return d.field(v)
}

// validates reports whether a candidate key decrypts a known-encrypted sample.
// Used to pick between multiple keyring entries: a machine that has run both
// the DMG and App Store builds carries two, holding different keys, and no
// fixed order is right for both. Poly1305 answers the question outright.
func validates(key []byte, sample string) bool {
	d, err := newDecryptor(key)
	if err != nil {
		return false
	}
	_, err = d.field(sample)
	return err == nil && d.decrypted == 1
}

// decodeBase64 is the envelope-detection decode, kept here so callers do not
// need to know the encoding.
func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
