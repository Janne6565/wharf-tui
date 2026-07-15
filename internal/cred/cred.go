// Package cred derives the account authentication key from the master password,
// exactly matching wharf-backend's zero-knowledge contract (and wharf-web's
// TypeScript port). The TUI normally never needs this — device pairing means no
// password is ever sent to the server — but changing the master password must
// re-derive and upload the new authKey so a browser (or any password login) can
// still authenticate.
//
// Contract (wharf-backend README):
//
//	masterKey = argon2id(password,
//	                     salt = SHA-256(lowercased, trimmed email)[0:16],
//	                     t=3, m=64 MiB, p=4, 32-byte output)
//	authKey   = base64(HKDF-SHA256(masterKey, salt="", info="wharf/auth/v1", 32))
//
// Note the salt here is derived from the email, unlike the vault's random
// per-slot salts: the two derivations are independent by design.
package cred

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// authInfo is the HKDF info string binding the derived key to its purpose.
const authInfo = "wharf/auth/v1"

// Argon2 cost parameters for the master key. These mirror vault.DefaultParams
// and wharf-web's MASTER_KEY_PARAMS; they are part of the wire contract (the
// server stores a bcrypt hash of the resulting key), so they must not drift.
const (
	argonTime    uint32 = 3
	argonMemKiB  uint32 = 64 * 1024
	argonThreads uint8  = 4
	masterKeyLen uint32 = 32
)

// NormalizeEmail lowercases and trims the email, matching the salt derivation
// on the backend and web.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// MasterKey derives the 32-byte master key from the password and email.
func MasterKey(password, email string) []byte {
	sum := sha256.Sum256([]byte(NormalizeEmail(email)))
	salt := sum[:16]
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemKiB, argonThreads, masterKeyLen)
}

// AuthKey derives the base64 authentication key sent to the server, from the
// master password and account email.
func AuthKey(password, email string) (string, error) {
	mk := MasterKey(password, email)
	defer zero(mk)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, mk, nil, []byte(authInfo)), key); err != nil {
		return "", err
	}
	out := base64.StdEncoding.EncodeToString(key)
	zero(key)
	return out, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
