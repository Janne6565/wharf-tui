package termius

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// PuTTY .ppk keys have to be converted rather than imported verbatim.
//
// Termius accepts PuTTY keys and stores them in their original format —
// measured on a real profile, 10 of 17 keys were .ppk — but x/crypto/ssh (and
// therefore Wharf's SSH engine) cannot parse one. Importing the bytes as-is
// would produce keys that look fine in the list and fail at connect time, so
// they are rebuilt as OpenSSH private keys here or not imported at all.
//
// Every conversion is checked by deriving the public key from the rebuilt
// private key and comparing it to the public blob the .ppk itself carries. A
// mismatch fails the conversion instead of writing a subtly wrong key.

// errPPKEncrypted marks a passphrase-protected .ppk. Decrypting one needs the
// passphrase (v3 derives the key with argon2), which an unattended import has
// no way to ask for, so these are reported and skipped.
var errPPKEncrypted = fmt.Errorf("passphrase-protected PuTTY key")

// isPPK reports whether data looks like a PuTTY private key file.
func isPPK(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(data), []byte("PuTTY-User-Key-File-"))
}

// ppkFile is the parsed header/body of a .ppk.
type ppkFile struct {
	algorithm  string
	encryption string
	comment    string
	public     []byte
	private    []byte
}

// parsePPK reads the line-oriented .ppk container. Both v2 and v3 share this
// layout; they differ only in the key-derivation headers, which matter solely
// for encrypted keys.
func parsePPK(data []byte) (ppkFile, error) {
	var f ppkFile
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		name, value, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)

		switch {
		case strings.HasPrefix(name, "PuTTY-User-Key-File-"):
			f.algorithm = value
		case name == "Encryption":
			f.encryption = value
		case name == "Comment":
			f.comment = value
		case name == "Public-Lines", name == "Private-Lines":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || i+n >= len(lines) {
				return ppkFile{}, fmt.Errorf("bad %s count %q", name, value)
			}
			blob, err := base64.StdEncoding.DecodeString(strings.Join(lines[i+1:i+1+n], ""))
			if err != nil {
				return ppkFile{}, fmt.Errorf("%s: %w", name, err)
			}
			if name == "Public-Lines" {
				f.public = blob
			} else {
				f.private = blob
			}
			i += n
		}
	}

	if f.algorithm == "" {
		return ppkFile{}, fmt.Errorf("not a PuTTY key file")
	}
	if f.encryption != "" && f.encryption != "none" {
		return ppkFile{}, errPPKEncrypted
	}
	if len(f.public) == 0 || len(f.private) == 0 {
		return ppkFile{}, fmt.Errorf("PuTTY key is missing its public or private section")
	}
	return f, nil
}

// ppkReader reads the SSH wire encoding the .ppk blobs use.
type ppkReader struct{ b []byte }

func (r *ppkReader) bytes() ([]byte, error) {
	if len(r.b) < 4 {
		return nil, fmt.Errorf("truncated blob")
	}
	n := int(r.b[0])<<24 | int(r.b[1])<<16 | int(r.b[2])<<8 | int(r.b[3])
	if n < 0 || 4+n > len(r.b) {
		return nil, fmt.Errorf("blob length %d exceeds %d remaining", n, len(r.b)-4)
	}
	out := r.b[4 : 4+n]
	r.b = r.b[4+n:]
	return out, nil
}

func (r *ppkReader) string() (string, error) {
	b, err := r.bytes()
	return string(b), err
}

// mpint reads a PuTTY multi-precision integer (big-endian, signed, but key
// material is always positive).
func (r *ppkReader) mpint() (*big.Int, error) {
	b, err := r.bytes()
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// ppkToOpenSSH converts an unencrypted .ppk into OpenSSH private key PEM bytes,
// returning the PEM and the authorized_keys-style public line.
func ppkToOpenSSH(data []byte) (pemBytes []byte, publicLine string, err error) {
	f, err := parsePPK(data)
	if err != nil {
		return nil, "", err
	}

	key, err := f.privateKey()
	if err != nil {
		return nil, "", err
	}

	// The rebuilt key must produce exactly the public key the file declares.
	// Anything else means the reconstruction was wrong, and a wrong key is
	// worse than a missing one.
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("rebuilt key is unusable: %w", err)
	}
	if !bytes.Equal(signer.PublicKey().Marshal(), f.public) {
		return nil, "", fmt.Errorf("converted key does not match the public key in the file")
	}

	block, err := ssh.MarshalPrivateKey(key, f.comment)
	if err != nil {
		return nil, "", fmt.Errorf("marshal: %w", err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if f.comment != "" {
		line += " " + f.comment
	}
	return pem.EncodeToMemory(block), line, nil
}

// privateKey rebuilds the Go private key from the .ppk's two blobs.
func (f ppkFile) privateKey() (crypto.PrivateKey, error) {
	pub := &ppkReader{b: f.public}
	algo, err := pub.string()
	if err != nil {
		return nil, err
	}
	if algo != f.algorithm {
		return nil, fmt.Errorf("header says %q but the public blob says %q", f.algorithm, algo)
	}
	priv := &ppkReader{b: f.private}

	switch algo {
	case ssh.KeyAlgoRSA:
		e, err := pub.mpint()
		if err != nil {
			return nil, err
		}
		n, err := pub.mpint()
		if err != nil {
			return nil, err
		}
		d, err := priv.mpint()
		if err != nil {
			return nil, err
		}
		p, err := priv.mpint()
		if err != nil {
			return nil, err
		}
		q, err := priv.mpint()
		if err != nil {
			return nil, err
		}
		// PuTTY also stores iqmp, but Go recomputes the CRT values itself.
		key := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: n, E: int(e.Int64())},
			D:         d,
			Primes:    []*big.Int{p, q},
		}
		key.Precompute()
		if err := key.Validate(); err != nil {
			return nil, fmt.Errorf("rebuilt RSA key is invalid: %w", err)
		}
		return key, nil

	case ssh.KeyAlgoED25519:
		pubBytes, err := pub.bytes()
		if err != nil {
			return nil, err
		}
		seed, err := priv.bytes()
		if err != nil {
			return nil, err
		}
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("ed25519 seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
		}
		key := ed25519.NewKeyFromSeed(seed)
		if !bytes.Equal(key.Public().(ed25519.PublicKey), pubBytes) {
			return nil, fmt.Errorf("ed25519 seed does not match the public key")
		}
		return key, nil

	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		if _, err := pub.string(); err != nil { // curve name, implied by algo
			return nil, err
		}
		point, err := pub.bytes()
		if err != nil {
			return nil, err
		}
		d, err := priv.mpint()
		if err != nil {
			return nil, err
		}
		curve, err := ecdsaCurve(algo)
		if err != nil {
			return nil, err
		}
		x, y := elliptic.Unmarshal(curve, point)
		if x == nil {
			return nil, fmt.Errorf("invalid ecdsa public point")
		}
		return &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
			D:         d,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported PuTTY key algorithm %q", algo)
	}
}

func ecdsaCurve(algo string) (elliptic.Curve, error) {
	switch algo {
	case ssh.KeyAlgoECDSA256:
		return elliptic.P256(), nil
	case ssh.KeyAlgoECDSA384:
		return elliptic.P384(), nil
	case ssh.KeyAlgoECDSA521:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported ecdsa algorithm %q", algo)
	}
}
