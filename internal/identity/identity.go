// Package identity renders the human-comparable fingerprint of an account's
// X25519 project identity key.
//
// The fingerprint exists so a user can read their key aloud on one device and
// check it against another — including the web and mobile clients. That makes
// its exact shape a cross-client contract: all clients derive it byte-for-byte
// the same way. Changing the digest, the encoding, the truncation length or the
// grouping here silently breaks the comparison it exists for, so any change must
// land in every client at once.
package identity

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

const (
	// fpChars is how many base64 characters of the digest the fingerprint keeps.
	// 16 characters ≈ 96 bits — far past what a substitution attack could grind
	// out, and still short enough to read over the phone.
	fpChars = 16
	// fpGroup is the block size the characters are grouped into for reading.
	fpGroup = 4
)

// Fingerprint renders pub as the shared cross-client fingerprint: SHA-256 over
// the raw public key bytes, standard base64 with padding stripped, truncated to
// the first 16 characters, grouped into four blocks of four separated by single
// spaces (e.g. "Zmh6 rfhi vXds j8GL").
func Fingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	enc := strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
	if len(enc) > fpChars {
		enc = enc[:fpChars]
	}
	var b strings.Builder
	for i := 0; i < len(enc); i += fpGroup {
		if i > 0 {
			b.WriteByte(' ')
		}
		end := i + fpGroup
		if end > len(enc) {
			end = len(enc)
		}
		b.WriteString(enc[i:end])
	}
	return b.String()
}
