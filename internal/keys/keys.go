// Package keys scans and generates SSH identities on disk. Wharf references
// private keys by path (they never enter the vault); the Keys tab is a live
// view over ~/.ssh.
package keys

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
func Scan(dir string) ([]KeyInfo, error) { panic("keys: unimplemented") }

// Generate creates an ed25519 keypair dir/name (0600, O_EXCL — never
// overwrites) and dir/name.pub (0644), optionally passphrase-protected,
// and returns its info.
func Generate(dir, name, comment string, passphrase []byte) (KeyInfo, error) {
	panic("keys: unimplemented")
}
