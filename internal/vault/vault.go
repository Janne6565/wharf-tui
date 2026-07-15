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

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/hkdf"
)

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
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "wharf", "vault.enc"), nil
}

// Exists reports whether a vault file exists at path.
func Exists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

// Create initializes a new vault at path with an empty payload, protected by
// password. It returns the open vault and the one-time recovery code
// (40 chars Crockford base32, formatted XXXXX-XXXXX-... in the UI). The code
// is never stored anywhere.
func Create(path string, password []byte) (v *Vault, recoveryCode string, err error) {
	return CreateWithParams(path, password, DefaultParams)
}

// CreateWithParams is Create with explicit cost parameters. Production code
// uses Create (pinned DefaultParams); tests and fixture tooling that need
// cheap argon2 (e.g. constructing sync blobs) pass tiny params here.
func CreateWithParams(path string, password []byte, params Params) (*Vault, string, error) {
	if !validParams(params) {
		return nil, "", errors.New("vault: invalid argon2 parameters")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, "", err
	}
	lock, err := acquireLock(path)
	if err != nil {
		return nil, "", err
	}

	dek := make([]byte, dekLen)
	if _, err := rand.Read(dek); err != nil {
		lock.Close()
		return nil, "", err
	}

	h := header{version: fileVersion, kdf: kdfArgon2id, params: params}
	if _, err := rand.Read(h.pwSalt[:]); err != nil {
		lock.Close()
		return nil, "", err
	}
	if _, err := rand.Read(h.pwNonce[:]); err != nil {
		lock.Close()
		return nil, "", err
	}
	pwWrap, err := wrapDEK(deriveKEK(password, h.pwSalt[:], params), h.pwNonce[:], dek)
	if err != nil {
		lock.Close()
		return nil, "", err
	}
	copy(h.pwWrap[:], pwWrap)

	code, secret, err := newRecoveryCode()
	if err != nil {
		lock.Close()
		return nil, "", err
	}
	if _, err := rand.Read(h.recSalt[:]); err != nil {
		lock.Close()
		return nil, "", err
	}
	if _, err := rand.Read(h.recNonce[:]); err != nil {
		lock.Close()
		return nil, "", err
	}
	recWrap, err := wrapDEK(deriveKEK(secret, h.recSalt[:], params), h.recNonce[:], dek)
	if err != nil {
		lock.Close()
		return nil, "", err
	}
	copy(h.recWrap[:], recWrap)

	v := &Vault{path: path, hdr: h, dek: dek, payload: []byte{}, lock: lock}
	if err := v.save(v.payload); err != nil {
		lock.Close()
		return nil, "", err
	}
	return v, code, nil
}

// Open unlocks the vault at path with the master password.
func Open(path string, password []byte) (*Vault, error) {
	return openVault(path, func(h header) ([]byte, error) {
		kek := deriveKEK(password, h.pwSalt[:], h.params)
		return unwrapDEK(kek, h.pwNonce[:], h.pwWrap[:])
	})
}

// OpenWithRecovery unlocks the vault with the recovery code (case- and
// dash-insensitive). Callers must follow up with ChangePassword and
// RegenerateRecovery to complete the reset flow.
func OpenWithRecovery(path, code string) (*Vault, error) {
	return openVault(path, func(h header) ([]byte, error) {
		secret, err := recoverySecret(code)
		if err != nil {
			return nil, err
		}
		kek := deriveKEK(secret, h.recSalt[:], h.params)
		return unwrapDEK(kek, h.recNonce[:], h.recWrap[:])
	})
}

// OpenPayload decrypts a WHARFV blob held in memory (e.g. fetched by the sync
// layer from the server) with the master password and returns its payload. It
// takes no file lock and keeps nothing: the DEK is derived, used and zeroed.
// A remote blob has its own random slot salts and its own DEK, so only the
// master password — never a local vault's DEK — can open it.
func OpenPayload(blob, password []byte) ([]byte, error) {
	h, body, err := parseHeader(blob)
	if err != nil {
		return nil, err
	}
	kek := deriveKEK(password, h.pwSalt[:], h.params)
	dek, err := unwrapDEK(kek, h.pwNonce[:], h.pwWrap[:])
	zero(kek)
	if err != nil {
		return nil, ErrWrongSecret
	}
	payload, err := openBody(dek, h.bodyNonce[:], body, blob[:headerLen])
	zero(dek)
	if err != nil {
		return nil, ErrCorrupt
	}
	return payload, nil
}

// openVault is the shared unlock path: it enforces existence, takes the lock,
// reads and validates the header, then delegates DEK recovery to unwrap.
func openVault(path string, unwrap func(header) ([]byte, error)) (*Vault, error) {
	if !Exists(path) {
		return nil, ErrNotFound
	}
	lock, err := acquireLock(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		lock.Close()
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	h, body, err := parseHeader(data)
	if err != nil {
		lock.Close()
		return nil, err
	}
	dek, err := unwrap(h)
	if err != nil {
		lock.Close()
		// Any wrap-open failure is indistinguishable "wrong secret".
		return nil, ErrWrongSecret
	}
	payload, err := openBody(dek, h.bodyNonce[:], body, data[:headerLen])
	if err != nil {
		zero(dek)
		lock.Close()
		return nil, ErrCorrupt
	}
	return &Vault{path: path, hdr: h, dek: dek, payload: payload, lock: lock}, nil
}

// Vault is an unlocked vault holding the DEK in memory and an exclusive
// flock for the process lifetime.
type Vault struct {
	path    string
	hdr     header
	dek     []byte
	payload []byte
	lock    *os.File
}

// Payload returns the current decrypted payload (JSON document owned by
// internal/store).
func (v *Vault) Payload() []byte { return v.payload }

// DeriveKey returns a 32-byte subkey of the DEK bound to info via
// HKDF-SHA256. Device-local secrets that must not live inside the synced
// payload (e.g. the sync session file) are encrypted under such a subkey: the
// raw DEK never leaves the vault, and each purpose gets an independent key.
// The subkey shares the DEK's lifetime — a re-created vault (new DEK) makes
// previously derived keys useless, which callers must treat as "start over".
func (v *Vault) DeriveKey(info string) ([]byte, error) {
	if v.dek == nil {
		return nil, errors.New("vault: closed")
	}
	key := make([]byte, dekLen)
	if _, err := io.ReadFull(hkdf.New(sha256.New, v.dek, nil, []byte(info)), key); err != nil {
		return nil, err
	}
	return key, nil
}

// Save re-seals the payload with a fresh body nonce and atomically rewrites
// the file (tmp + fsync + rename + fsync dir).
func (v *Vault) Save(payload []byte) error { return v.save(payload) }

// save re-seals under a fresh body nonce and atomically replaces the file. A
// fresh nonce is mandatory: it never repeats under the same DEK, and because it
// lives inside the AAD-protected header the whole file must be rewritten.
func (v *Vault) save(payload []byte) error {
	if _, err := rand.Read(v.hdr.bodyNonce[:]); err != nil {
		return err
	}
	hdrBytes := v.hdr.marshal()
	body, err := sealBody(v.dek, v.hdr.bodyNonce[:], payload, hdrBytes)
	if err != nil {
		return err
	}
	fileBytes := make([]byte, 0, len(hdrBytes)+len(body))
	fileBytes = append(fileBytes, hdrBytes...)
	fileBytes = append(fileBytes, body...)

	if err := writeFileAtomic(v.path, fileBytes); err != nil {
		return err
	}
	v.payload = append([]byte(nil), payload...)
	return nil
}

// writeFileAtomic writes data to <path>.tmp, fsyncs it, renames it onto path,
// then fsyncs the directory so the rename is durable.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmpPath := path + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// ChangePassword rewrites the password slot; the recovery slot stays valid.
func (v *Vault) ChangePassword(newPassword []byte) error {
	var salt [saltLen]byte
	var nonce [nonceLen]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return err
	}
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	wrapped, err := wrapDEK(deriveKEK(newPassword, salt[:], v.hdr.params), nonce[:], v.dek)
	if err != nil {
		return err
	}
	v.hdr.pwSalt = salt
	v.hdr.pwNonce = nonce
	copy(v.hdr.pwWrap[:], wrapped)
	return v.save(v.payload)
}

// RegenerateRecovery replaces the recovery slot with a new code and returns
// it; the old code is invalid from that moment.
func (v *Vault) RegenerateRecovery() (string, error) {
	code, secret, err := newRecoveryCode()
	if err != nil {
		return "", err
	}
	var salt [saltLen]byte
	var nonce [nonceLen]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", err
	}
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	wrapped, err := wrapDEK(deriveKEK(secret, salt[:], v.hdr.params), nonce[:], v.dek)
	if err != nil {
		return "", err
	}
	v.hdr.recSalt = salt
	v.hdr.recNonce = nonce
	copy(v.hdr.recWrap[:], wrapped)
	if err := v.save(v.payload); err != nil {
		return "", err
	}
	return code, nil
}

// Close zeroes the DEK and releases the lock file.
func (v *Vault) Close() error {
	if v.dek != nil {
		zero(v.dek)
		v.dek = nil
	}
	if v.lock == nil {
		return nil
	}
	err := v.lock.Close()
	v.lock = nil
	return err
}
