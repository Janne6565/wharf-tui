// Package sync implements Wharf's vault sync client: device pairing state and
// a full-blob sync engine with optimistic versioning against wharf-backend.
//
// Pairing produces a device-local session file stored NEXT TO the vault file
// (never inside the synced payload — the payload replicates to other devices,
// the session must not). The file is sealed with XChaCha20-Poly1305 under a
// subkey derived from the unlocked vault's DEK (vault.DeriveKey), so:
//
//   - it is never plaintext on disk,
//   - sync only works while the vault is unlocked (correct for a
//     zero-knowledge client), and
//   - if the vault is re-created (new DEK) the session file becomes
//     unreadable, which the engine treats as signed-out → re-pair.
package sync

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/crypto/chacha20poly1305"
)

// sessionMagic prefixes the session file and doubles as the AEAD's AAD.
const sessionMagic = "WHARFS1"

// SessionKeyInfo is the HKDF info string for the vault subkey that seals the
// session file (see vault.DeriveKey).
const SessionKeyInfo = "wharf/session-file/v1"

// sessionFileName sits in the same directory as the vault file.
const sessionFileName = "session.enc"

// errNoSession distinguishes "never paired" from a broken file.
var errNoSession = errors.New("sync: no session file")

// SessionPath resolves the session file for a given vault path.
func SessionPath(vaultPath string) string {
	return filepath.Join(filepath.Dir(vaultPath), sessionFileName)
}

// session is the decrypted session-file document: the long-lived credential
// plus the sync bookkeeping. The short-lived access token is memory-only.
type session struct {
	RefreshToken string `json:"refreshToken"`
	Email        string `json:"email"`
	UserID       string `json:"userId"`
	// LastSyncedVersion is the remote vault version this device last agreed
	// with; LastSyncedFingerprint is the SHA-256 (hex) of the payload JSON at
	// that moment. Together they classify local vs. remote drift.
	LastSyncedVersion     int64  `json:"lastSyncedVersion"`
	LastSyncedFingerprint string `json:"lastSyncedFingerprint"`
}

// saveSession seals s under key and writes it atomically with mode 0600.
func saveSession(path string, key []byte, s *session) error {
	plain, err := json.Marshal(s)
	if err != nil {
		return err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	out := make([]byte, 0, len(sessionMagic)+len(nonce)+len(plain)+aead.Overhead())
	out = append(out, sessionMagic...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plain, []byte(sessionMagic))

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// loadSession reads and opens the session file. Any structural or AEAD
// failure (tampering, or a vault re-created with a new DEK) is an error
// distinct from errNoSession; callers treat it as signed-out.
func loadSession(path string, key []byte) (*session, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errNoSession
		}
		return nil, err
	}
	if len(data) < len(sessionMagic)+chacha20poly1305.NonceSizeX ||
		string(data[:len(sessionMagic)]) != sessionMagic {
		return nil, errors.New("sync: session file corrupt")
	}
	nonce := data[len(sessionMagic) : len(sessionMagic)+chacha20poly1305.NonceSizeX]
	body := data[len(sessionMagic)+chacha20poly1305.NonceSizeX:]
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, body, []byte(sessionMagic))
	if err != nil {
		return nil, errors.New("sync: session file unreadable (vault key changed?)")
	}
	var s session
	if err := json.Unmarshal(plain, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
