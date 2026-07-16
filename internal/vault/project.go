// WHARFP is the project-blob format: a single opaque blob holding one Wharf
// project's payload (JSON) sealed with XChaCha20-Poly1305 under a per-project
// data-encryption key (the project DEK). Unlike WHARFV, WHARFP carries no key
// slots — the DEK is delivered out of band, wrapped per-recipient with the
// sealed-box scheme in box.go. The format is a byte-for-byte contract shared
// with the TypeScript client (wharf-web/src/crypto/wharfp.ts).
//
// Blob layout (v1, little-endian):
//
//	off  len  field
//	0    6    magic "WHARFP"
//	6    2    version uint16 = 1
//	8    24   body nonce (XChaCha20-Poly1305)
//	32   ...  XChaCha20-Poly1305(body nonce, projectDEK, payload JSON, AAD = bytes[0:32])
package vault

import (
	"crypto/rand"
	"encoding/binary"
)

// v1 project-blob layout constants. The offsets mirror the byte map above and
// are the single source of truth for (un)marshalling.
const (
	projectMagic       = "WHARFP"
	projectFileVersion = 1

	projectHeaderLen = 32 // AAD covers exactly this prefix

	offProjectVersion   = 6
	offProjectBodyNonce = 8
)

// SealProject seals payload under the project DEK, binding the fixed header
// (magic + version + body nonce) as AAD. A fresh random nonce is drawn on every
// call, so the same (dek, payload) never produces the same blob twice.
func SealProject(dek []byte, payload []byte) ([]byte, error) {
	if len(dek) != dekLen {
		return nil, ErrCorrupt
	}
	header := make([]byte, projectHeaderLen)
	copy(header[0:offProjectVersion], projectMagic)
	binary.LittleEndian.PutUint16(header[offProjectVersion:offProjectBodyNonce], projectFileVersion)
	if _, err := rand.Read(header[offProjectBodyNonce:projectHeaderLen]); err != nil {
		return nil, err
	}
	body, err := sealBody(dek, header[offProjectBodyNonce:projectHeaderLen], payload, header)
	if err != nil {
		return nil, err
	}
	blob := make([]byte, 0, len(header)+len(body))
	blob = append(blob, header...)
	blob = append(blob, body...)
	return blob, nil
}

// OpenProject reverses SealProject. It strictly validates the magic, version
// and length before attempting decryption; a structural problem maps to
// ErrCorrupt, and an AEAD failure (wrong DEK or tampering — indistinguishable)
// also maps to ErrCorrupt, matching the WHARFV body-open discipline.
func OpenProject(dek []byte, blob []byte) ([]byte, error) {
	if len(dek) != dekLen {
		return nil, ErrCorrupt
	}
	if len(blob) < projectHeaderLen {
		return nil, ErrCorrupt
	}
	if string(blob[0:offProjectVersion]) != projectMagic {
		return nil, ErrCorrupt
	}
	if binary.LittleEndian.Uint16(blob[offProjectVersion:offProjectBodyNonce]) != projectFileVersion {
		return nil, ErrCorrupt
	}
	nonce := blob[offProjectBodyNonce:projectHeaderLen]
	body := blob[projectHeaderLen:]
	payload, err := openBody(dek, nonce, body, blob[:projectHeaderLen])
	if err != nil {
		return nil, ErrCorrupt
	}
	return payload, nil
}
