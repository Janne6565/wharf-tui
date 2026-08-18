package termius

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"github.com/Janne6565/wharf-tui/internal/keys"
	"github.com/Janne6565/wharf-tui/internal/store"
	"golang.org/x/crypto/ssh"
)

// importKeys converts the profile's stored private keys into vault keys.
//
// Termius keeps whatever format the key was added in, so this handles OpenSSH
// and PEM (imported verbatim, since the engine parses them) as well as PuTTY
// .ppk (converted, since it does not). Keys that cannot be made usable are
// returned as skip reasons rather than imported broken.
func importKeys(rows []map[string]any, dec *decryptor) ([]store.VaultKey, map[string]string, []string) {
	var out []store.VaultKey
	var skipped []string
	// Termius key row id → the name the key ends up with in the vault, so a
	// host that references a key can be bound to it after the renames below.
	names := map[string]string{}

	// Termius allows duplicate key labels; the vault requires unique names
	// (case-insensitively), so collisions are suffixed rather than dropped.
	used := map[string]bool{}

	for _, r := range dedupeLatest(rows) {
		label, err := dec.str(r, "label")
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("key %v: %v", r["id"], err))
			continue
		}
		material, err := dec.str(r, "private_key")
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("key %q: %v", label, err))
			continue
		}
		if strings.TrimSpace(material) == "" {
			// A key row can exist with no private half — an agent-only or
			// hardware-backed entry. Nothing to import.
			skipped = append(skipped, fmt.Sprintf("key %q has no private key", label))
			continue
		}

		vk, err := buildKey(label, material, r, dec)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("key %q: %v", displayLabel(label, r), err))
			continue
		}
		vk.Name = uniqueName(vk.Name, used)
		names[fmt.Sprint(r["id"])] = vk.Name
		out = append(out, vk)
	}

	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, names, skipped
}

// buildKey turns one decrypted Termius key row into a vault key.
func buildKey(label, material string, row map[string]any, dec *decryptor) (store.VaultKey, error) {
	raw := []byte(material)
	publicLine, _ := dec.str(row, "public_key")

	if isPPK(raw) {
		converted, line, err := ppkToOpenSSH(raw)
		if err != nil {
			return store.VaultKey{}, err
		}
		raw = converted
		// The .ppk carries its own public key, and the conversion already
		// verified it against the rebuilt private key, so prefer that line.
		publicLine = line
	} else if publicLine == "" {
		// Only unencrypted keys yield a public line; encrypted ones keep "",
		// matching how vault keys added from disk behave.
		if line, err := keys.PublicLineFromPEM(raw, ""); err == nil {
			publicLine = line
		}
	}

	// Refuse anything the engine will not be able to use at connect time.
	typ, err := keyType(raw, publicLine)
	if err != nil {
		return store.VaultKey{}, err
	}

	name := strings.TrimSpace(label)
	if name == "" {
		name = "termius-key"
	}
	return store.VaultKey{
		Name:      name,
		Type:      typ,
		Material:  base64.StdEncoding.EncodeToString(raw),
		PublicKey: strings.TrimSpace(publicLine),
		// SourcePath is display-only and there is no file behind these.
		SourcePath: "termius",
	}, nil
}

// keyType determines the display type, and in doing so proves the material is
// parseable — the point of the check is that an unusable key never reaches the
// vault looking healthy.
func keyType(material []byte, publicLine string) (string, error) {
	if signer, err := ssh.ParsePrivateKey(material); err == nil {
		if _, typ, ok := keys.FingerprintOfAuthorized(
			string(ssh.MarshalAuthorizedKey(signer.PublicKey()))); ok {
			return typ, nil
		}
	} else if _, ok := err.(*ssh.PassphraseMissingError); ok {
		// Encrypted but well-formed: the engine prompts for the passphrase at
		// connect time, so this is importable. Its type comes from the stored
		// public line when there is one.
		if _, typ, ok := keys.FingerprintOfAuthorized(publicLine); ok {
			return typ, nil
		}
		return "ENCRYPTED", nil
	} else {
		return "", fmt.Errorf("unusable private key: %w", err)
	}

	if _, typ, ok := keys.FingerprintOfAuthorized(publicLine); ok {
		return typ, nil
	}
	return "UNKNOWN", nil
}

// uniqueName suffixes a name until it is unused, so duplicate Termius labels do
// not collide in the vault's case-insensitive namespace.
func uniqueName(name string, used map[string]bool) string {
	base := name
	for i := 2; used[strings.ToLower(name)]; i++ {
		name = fmt.Sprintf("%s (%d)", base, i)
	}
	used[strings.ToLower(name)] = true
	return name
}

// displayLabel names a key for a skip message, falling back to its id when the
// label is empty.
func displayLabel(label string, row map[string]any) string {
	if strings.TrimSpace(label) != "" {
		return label
	}
	return fmt.Sprint(row["id"])
}
