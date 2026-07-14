package vault

import (
	"crypto/rand"
	"errors"
	"strings"
)

// crockford is the Crockford base32 alphabet (no I, L, O, U). 25 secret bytes
// encode to exactly 40 characters (200 bits / 5 bits per char).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

const (
	recoverySecretLen = 25
	recoveryCodeLen   = 40
)

var errBadRecovery = errors.New("vault: malformed recovery code")

// newRecoveryCode returns a fresh 40-char code and the raw secret bytes it
// decodes to. The secret — never the string — feeds argon2, so OpenWithRecovery
// reconstructs the identical KEK input from user-typed input.
func newRecoveryCode() (code string, secret []byte, err error) {
	secret = make([]byte, recoverySecretLen)
	if _, err = rand.Read(secret); err != nil {
		return "", nil, err
	}
	return encodeCrockford(secret), secret, nil
}

func encodeCrockford(b []byte) string {
	var sb strings.Builder
	var buf uint64
	var bits uint
	for _, c := range b {
		buf = buf<<8 | uint64(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			sb.WriteByte(crockford[(buf>>bits)&0x1f])
		}
	}
	// 200 bits is divisible by 5, so no partial group remains.
	return sb.String()
}

func decodeCrockford(s string) ([]byte, error) {
	out := make([]byte, 0, recoverySecretLen)
	var buf uint64
	var bits uint
	for _, r := range s {
		v := strings.IndexByte(crockford, byte(r))
		if v < 0 || r > 127 {
			return nil, errBadRecovery
		}
		buf = buf<<5 | uint64(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(buf>>bits))
		}
	}
	return out, nil
}

// normalizeRecovery makes user input canonical: upper-case, strip separators,
// and fold the Crockford look-alikes (I/L→1, O→0) to their digit forms.
func normalizeRecovery(code string) string {
	code = strings.ToUpper(code)
	var sb strings.Builder
	for _, r := range code {
		switch r {
		case '-', ' ':
			continue
		case 'I', 'L':
			sb.WriteByte('1')
		case 'O':
			sb.WriteByte('0')
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// recoverySecret turns arbitrary user input into the 25-byte secret, or an
// error if it is not a well-formed code.
func recoverySecret(code string) ([]byte, error) {
	secret, err := decodeCrockford(normalizeRecovery(code))
	if err != nil {
		return nil, err
	}
	if len(secret) != recoverySecretLen {
		return nil, errBadRecovery
	}
	return secret, nil
}
