// Package vault implements Wharf's local encrypted vault: a single binary
// file sealed with XChaCha20-Poly1305 under a data-encryption key (DEK) that
// is wrapped twice — once by a key derived from the master password and once
// by a key derived from a 40-character recovery code (argon2id in both
// cases). The file is designed to be uploaded verbatim later as an opaque
// zero-knowledge blob by the sync layer.
//
// File layout (v1, little-endian):
//
//	off  len  field
//	0    6    magic "WHARFV"
//	6    2    version uint16 = 1
//	8    1    kdf id = 1 (argon2id)
//	9    4    argon2 time
//	13   4    argon2 memory (KiB)
//	17   1    argon2 parallelism
//	18   16   salt (password slot)
//	34   24   nonce (password slot)
//	58   48   DEK wrapped by password KEK (32B key + 16B tag)
//	106  16   salt (recovery slot)
//	122  24   nonce (recovery slot)
//	146  48   DEK wrapped by recovery KEK
//	194  24   body nonce
//	218  ...  XChaCha20-Poly1305(body nonce, DEK, payload JSON, AAD = bytes[0:218])
package vault

import "errors"

// Params are the argon2id cost parameters recorded in the vault header.
type Params struct {
	Time        uint32
	MemoryKiB   uint32
	Parallelism uint8
}

// DefaultParams balances unlock latency (~100-300ms on a laptop) against
// brute-force cost.
var DefaultParams = Params{Time: 3, MemoryKiB: 64 * 1024, Parallelism: 4}

var (
	// ErrWrongSecret is returned when the password or recovery code fails to
	// unwrap the DEK. Indistinguishable by design from "wrong slot".
	ErrWrongSecret = errors.New("vault: wrong password or recovery code")
	// ErrNotFound is returned by Open when no vault file exists at the path.
	ErrNotFound = errors.New("vault: no vault file")
	// ErrLocked is returned when another wharf process holds the vault lock.
	ErrLocked = errors.New("vault: another wharf instance is running")
	// ErrCorrupt is returned when the file is malformed or fails AEAD
	// authentication (tampering, truncation, bit rot).
	ErrCorrupt = errors.New("vault: file corrupt or tampered")
)

// DefaultPath resolves ${XDG_DATA_HOME:-~/.local/share}/wharf/vault.enc.
func DefaultPath() (string, error) {
	panic("vault: unimplemented")
}

// Exists reports whether a vault file exists at path.
func Exists(path string) bool {
	panic("vault: unimplemented")
}

// Create initializes a new vault at path with an empty payload, protected by
// password. It returns the open vault and the one-time recovery code
// (40 chars Crockford base32, formatted XXXXX-XXXXX-... in the UI). The code
// is never stored anywhere.
func Create(path string, password []byte) (v *Vault, recoveryCode string, err error) {
	panic("vault: unimplemented")
}

// Open unlocks the vault at path with the master password.
func Open(path string, password []byte) (*Vault, error) {
	panic("vault: unimplemented")
}

// OpenWithRecovery unlocks the vault with the recovery code (case- and
// dash-insensitive). Callers must follow up with ChangePassword and
// RegenerateRecovery to complete the reset flow.
func OpenWithRecovery(path, code string) (*Vault, error) {
	panic("vault: unimplemented")
}

// Vault is an unlocked vault holding the DEK in memory and an exclusive
// flock for the process lifetime.
type Vault struct {
	// implemented in WP1
}

// Payload returns the current decrypted payload (JSON document owned by
// internal/store).
func (v *Vault) Payload() []byte { panic("vault: unimplemented") }

// Save re-seals the payload with a fresh body nonce and atomically rewrites
// the file (tmp + fsync + rename + fsync dir).
func (v *Vault) Save(payload []byte) error { panic("vault: unimplemented") }

// ChangePassword rewrites the password slot; the recovery slot stays valid.
func (v *Vault) ChangePassword(newPassword []byte) error { panic("vault: unimplemented") }

// RegenerateRecovery replaces the recovery slot with a new code and returns
// it; the old code is invalid from that moment.
func (v *Vault) RegenerateRecovery() (string, error) { panic("vault: unimplemented") }

// Close zeroes the DEK and releases the lock file.
func (v *Vault) Close() error { panic("vault: unimplemented") }
