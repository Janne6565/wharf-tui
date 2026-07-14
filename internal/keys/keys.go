// Package keys scans and generates SSH identities on disk. Wharf references
// private keys by path (they never enter the vault); the Keys tab is a live
// view over ~/.ssh.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
)

// KeyInfo describes one private key found on disk.
type KeyInfo struct {
	Name        string // file base name, e.g. "id_ed25519"
	Path        string // absolute private-key path
	Type        string // "ED25519", "RSA", ...; "?" while encrypted without pub
	Fingerprint string // SHA256:... (from the .pub when encrypted)
	Encrypted   bool   // private key needs a passphrase
	HasPub      bool   // a sibling .pub exists
}

// Scan lists private keys in dir (typically ~/.ssh), skipping known
// non-keys (config, known_hosts, *.pub, authorized_keys). Encrypted keys
// are detected via ssh.PassphraseMissingError.
func Scan(dir string) ([]KeyInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		// A fresh machine simply has no ~/.ssh yet; that is not an error, an
		// empty key list is the correct answer.
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var out []KeyInfo
	for _, e := range entries {
		// Only regular files can be private keys; this also drops the agent
		// socket and any sub-directories in one check.
		if !e.Type().IsRegular() {
			continue
		}
		name := e.Name()
		if skipName(name) {
			continue
		}

		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		info, ok := classify(dir, name, path, data)
		if !ok {
			continue
		}
		out = append(out, info)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// skipName rejects file names that are never private keys, so we do not waste
// a parse attempt (and, more importantly, never surface config/known_hosts as
// "unparseable keys").
func skipName(name string) bool {
	if strings.HasSuffix(name, ".pub") {
		return true
	}
	for _, prefix := range []string{"known_hosts", "authorized_keys", "config", "agent"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// classify turns one candidate file into a KeyInfo, or reports ok=false when
// the bytes are not a private key at all (random text, a stray .pub, ...).
func classify(dir, name, path string, data []byte) (KeyInfo, bool) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}
	pubPath := filepath.Join(dir, name+".pub")
	hasPub := fileExists(pubPath)

	info := KeyInfo{Name: name, Path: absPath, HasPub: hasPub}

	raw, err := ssh.ParseRawPrivateKey(data)
	if err == nil {
		signer, serr := ssh.NewSignerFromKey(raw)
		if serr != nil {
			return KeyInfo{}, false
		}
		pub := signer.PublicKey()
		info.Type = displayType(pub.Type())
		info.Fingerprint = ssh.FingerprintSHA256(pub)
		return info, true
	}

	// An encrypted key can still be catalogued: its identity lives in the
	// sibling .pub, which is not passphrase-protected.
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		info.Encrypted = true
		if hasPub {
			if pubData, rerr := os.ReadFile(pubPath); rerr == nil {
				if pk, _, _, _, perr := ssh.ParseAuthorizedKey(pubData); perr == nil {
					info.Type = displayType(pk.Type())
					info.Fingerprint = ssh.FingerprintSHA256(pk)
					return info, true
				}
			}
		}
		info.Type = "?"
		return info, true
	}

	return KeyInfo{}, false
}

// Generate creates an ed25519 keypair dir/name (0600, O_EXCL — never
// overwrites) and dir/name.pub (0644), optionally passphrase-protected,
// and returns its info.
func Generate(dir, name, comment string, passphrase []byte) (KeyInfo, error) {
	if err := validateName(name); err != nil {
		return KeyInfo{}, err
	}

	privPath := filepath.Join(dir, name)
	pubPath := privPath + ".pub"

	// Refuse up front if the public half already exists: O_EXCL guards the
	// private file, but we must not clobber an existing .pub either.
	if fileExists(pubPath) {
		return KeyInfo{}, fmt.Errorf("keys: %s already exists", pubPath)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyInfo{}, err
	}

	var block *pem.Block
	if len(passphrase) > 0 {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, comment, passphrase)
	} else {
		block, err = ssh.MarshalPrivateKey(priv, comment)
	}
	if err != nil {
		return KeyInfo{}, err
	}
	privPEM := pem.EncodeToMemory(block)

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return KeyInfo{}, err
	}

	// O_EXCL: an existing private key is an error, we never overwrite one.
	f, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return KeyInfo{}, err
	}
	if _, werr := f.Write(privPEM); werr != nil {
		f.Close()
		os.Remove(privPath)
		return KeyInfo{}, werr
	}
	if cerr := f.Close(); cerr != nil {
		os.Remove(privPath)
		return KeyInfo{}, cerr
	}

	if err := os.WriteFile(pubPath, authorizedLine(sshPub, comment), 0644); err != nil {
		// Roll back the private key so a failed generate leaves nothing behind.
		os.Remove(privPath)
		return KeyInfo{}, err
	}

	absPath, aerr := filepath.Abs(privPath)
	if aerr != nil {
		absPath = privPath
	}
	return KeyInfo{
		Name:        name,
		Path:        absPath,
		Type:        displayType(sshPub.Type()),
		Fingerprint: ssh.FingerprintSHA256(sshPub),
		Encrypted:   len(passphrase) > 0,
		HasPub:      true,
	}, nil
}

// authorizedLine renders the standard "<type> <base64> <comment>\n" public-key
// line. ssh.MarshalAuthorizedKey drops the comment, so we splice it back in.
func authorizedLine(pub ssh.PublicKey, comment string) []byte {
	line := strings.TrimRight(string(ssh.MarshalAuthorizedKey(pub)), "\n")
	if comment != "" {
		line += " " + comment
	}
	return []byte(line + "\n")
}

// validateName keeps generated keys inside dir: an empty name or one carrying a
// path separator could escape the intended directory.
func validateName(name string) error {
	if name == "" {
		return errors.New("keys: name is required")
	}
	if name == "." || name == ".." {
		return fmt.Errorf("keys: invalid name %q", name)
	}
	if strings.ContainsAny(name, `/\`) || strings.ContainsRune(name, filepath.Separator) {
		return fmt.Errorf("keys: name %q must not contain a path separator", name)
	}
	return nil
}

// displayType maps an SSH wire key type ("ssh-ed25519") to the short label
// shown in the UI ("ED25519").
func displayType(sshType string) string {
	switch {
	case sshType == ssh.KeyAlgoED25519:
		return "ED25519"
	case sshType == ssh.KeyAlgoSKED25519:
		return "ED25519-SK"
	case sshType == ssh.KeyAlgoRSA:
		return "RSA"
	case sshType == ssh.InsecureKeyAlgoDSA:
		return "DSA"
	case sshType == ssh.KeyAlgoSKECDSA256:
		return "ECDSA-SK"
	case strings.HasPrefix(sshType, "ecdsa-sha2-"):
		return "ECDSA"
	default:
		return strings.ToUpper(sshType)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
