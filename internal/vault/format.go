package vault

import (
	"encoding/binary"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// v1 on-disk layout constants. See the package comment for the byte map; the
// offsets here mirror it and are the single source of truth for (un)marshalling.
const (
	magic       = "WHARFV"
	fileVersion = 1
	kdfArgon2id = 1

	saltLen      = 16
	nonceLen     = 24 // XChaCha20-Poly1305 nonce
	wrapLen      = 48 // wrapped DEK: 32B key + 16B Poly1305 tag
	bodyNonceLen = 24
	dekLen       = 32
	headerLen    = 218 // AAD covers exactly this prefix

	offVersion   = 6
	offKDF       = 8
	offTime      = 9
	offMemory    = 13
	offParallel  = 17
	offPwSalt    = 18
	offPwNonce   = 34
	offPwWrap    = 58
	offRecSalt   = 106
	offRecNonce  = 122
	offRecWrap   = 146
	offBodyNonce = 194
)

// Corrupted headers can carry absurd argon2 cost parameters. Since the KEK must
// be derived (running argon2) before the AAD-authenticated body can reveal the
// tampering, unbounded params would let a malformed file exhaust memory or CPU.
// These caps are generous relative to DefaultParams yet reject such files early.
const (
	maxMemoryKiB uint32 = 2 << 20 // 2 GiB
	maxTime      uint32 = 1 << 10 // 1024 passes
)

// header is the parsed, mutable view of the fixed-size file prefix.
type header struct {
	version   uint16
	kdf       byte
	params    Params
	pwSalt    [saltLen]byte
	pwNonce   [nonceLen]byte
	pwWrap    [wrapLen]byte
	recSalt   [saltLen]byte
	recNonce  [nonceLen]byte
	recWrap   [wrapLen]byte
	bodyNonce [bodyNonceLen]byte
}

func (h *header) marshal() []byte {
	b := make([]byte, headerLen)
	copy(b[0:offVersion], magic)
	binary.LittleEndian.PutUint16(b[offVersion:offKDF], h.version)
	b[offKDF] = h.kdf
	binary.LittleEndian.PutUint32(b[offTime:offMemory], h.params.Time)
	binary.LittleEndian.PutUint32(b[offMemory:offParallel], h.params.MemoryKiB)
	b[offParallel] = h.params.Parallelism
	copy(b[offPwSalt:offPwNonce], h.pwSalt[:])
	copy(b[offPwNonce:offPwWrap], h.pwNonce[:])
	copy(b[offPwWrap:offRecSalt], h.pwWrap[:])
	copy(b[offRecSalt:offRecNonce], h.recSalt[:])
	copy(b[offRecNonce:offRecWrap], h.recNonce[:])
	copy(b[offRecWrap:offBodyNonce], h.recWrap[:])
	copy(b[offBodyNonce:headerLen], h.bodyNonce[:])
	return b
}

// parseHeader validates the fixed prefix and returns the header plus the
// remaining sealed body. Any structural problem maps to ErrCorrupt.
func parseHeader(data []byte) (header, []byte, error) {
	if len(data) < headerLen {
		return header{}, nil, ErrCorrupt
	}
	if string(data[0:offVersion]) != magic {
		return header{}, nil, ErrCorrupt
	}
	var h header
	h.version = binary.LittleEndian.Uint16(data[offVersion:offKDF])
	if h.version != fileVersion {
		return header{}, nil, ErrCorrupt
	}
	h.kdf = data[offKDF]
	if h.kdf != kdfArgon2id {
		return header{}, nil, ErrCorrupt
	}
	h.params.Time = binary.LittleEndian.Uint32(data[offTime:offMemory])
	h.params.MemoryKiB = binary.LittleEndian.Uint32(data[offMemory:offParallel])
	h.params.Parallelism = data[offParallel]
	if !validParams(h.params) {
		return header{}, nil, ErrCorrupt
	}
	copy(h.pwSalt[:], data[offPwSalt:offPwNonce])
	copy(h.pwNonce[:], data[offPwNonce:offPwWrap])
	copy(h.pwWrap[:], data[offPwWrap:offRecSalt])
	copy(h.recSalt[:], data[offRecSalt:offRecNonce])
	copy(h.recNonce[:], data[offRecNonce:offRecWrap])
	copy(h.recWrap[:], data[offRecWrap:offBodyNonce])
	copy(h.bodyNonce[:], data[offBodyNonce:headerLen])
	return h, data[headerLen:], nil
}

// validParams rejects the zero/absurd values that would either panic argon2
// (time or parallelism < 1) or turn a corrupt file into a resource-exhaustion
// vector.
func validParams(p Params) bool {
	return p.Time >= 1 && p.Time <= maxTime &&
		p.MemoryKiB >= 1 && p.MemoryKiB <= maxMemoryKiB &&
		p.Parallelism >= 1
}

func deriveKEK(secret, salt []byte, p Params) []byte {
	return argon2.IDKey(secret, salt, p.Time, p.MemoryKiB, p.Parallelism, dekLen)
}

// wrapDEK seals the DEK under a KEK with a per-slot nonce, no AAD. Output is
// wrapLen bytes (key + tag).
func wrapDEK(kek, nonce, dek []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, dek, nil), nil
}

// unwrapDEK reverses wrapDEK; an AEAD failure here means the secret was wrong.
func unwrapDEK(kek, nonce, wrapped []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, wrapped, nil)
}

// sealBody encrypts the payload under the DEK, binding the whole header as AAD.
func sealBody(dek, nonce, payload, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, payload, aad), nil
}

// openBody reverses sealBody; failure means the header/body was tampered with.
func openBody(dek, nonce, body, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, body, aad)
}
