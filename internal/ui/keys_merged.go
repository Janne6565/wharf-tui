package ui

import (
	"encoding/base64"
	"os"
	"sort"
	"strings"

	"github.com/Janne6565/wharf-tui/internal/keys"
	"github.com/Janne6565/wharf-tui/internal/store"
)

// mergedKey is a keys-tab row: an optional local scanned key paired with an
// optional synced vault key, matched by SHA256 fingerprint. Exactly one of the
// three states holds:
//   - local-only  (local != nil, vault == nil): on disk, not synced.
//   - synced      (local != nil, vault != nil): on disk and in the vault.
//   - vault-only  (local == nil, vault != nil): synced from another machine.
type mergedKey struct {
	local     *keys.KeyInfo
	vault     *store.VaultKey
	name      string // display name (local name preferred, else vault name)
	typ       string // display type, e.g. "ED25519"
	fp        string // SHA256 fingerprint; "" when an encrypted vault key has no public half
	encrypted bool   // local key needs a passphrase
}

func (mk mergedKey) isSynced() bool    { return mk.local != nil && mk.vault != nil }
func (mk mergedKey) isVaultOnly() bool { return mk.local == nil && mk.vault != nil }

// storeKeys returns the synced vault keys (empty when no store is loaded).
func (m Model) storeKeys() []store.VaultKey {
	if m.st == nil {
		return nil
	}
	return m.st.Keys()
}

// mergedKeys pairs the live ~/.ssh scan with the synced vault keys into one
// name-sorted list. A vault key matches a local key by SHA256 fingerprint;
// unmatchable vault keys (e.g. an encrypted key with no stored public line)
// stand on their own as vault-only rows.
func (m Model) mergedKeys() []mergedKey {
	locals := m.keyInfos
	vaults := m.storeKeys()

	// Index locals by fingerprint; the first local wins a shared fingerprint.
	byFP := make(map[string]int, len(locals))
	for i, l := range locals {
		if l.Fingerprint != "" {
			if _, seen := byFP[l.Fingerprint]; !seen {
				byFP[l.Fingerprint] = i
			}
		}
	}

	matched := make([]bool, len(locals))
	out := make([]mergedKey, 0, len(locals)+len(vaults))

	for i := range vaults {
		vk := vaults[i]
		fp, typ := vaultKeyFingerprint(vk)
		if fp != "" {
			if li, ok := byFP[fp]; ok && !matched[li] {
				matched[li] = true
				l := locals[li]
				out = append(out, mergedKey{
					local: &locals[li], vault: &vaults[i],
					name: l.Name, typ: l.Type, fp: l.Fingerprint, encrypted: l.Encrypted,
				})
				continue
			}
		}
		if typ == "" {
			typ = vk.Type
		}
		out = append(out, mergedKey{vault: &vaults[i], name: vk.Name, typ: typ, fp: fp})
	}

	for i := range locals {
		if matched[i] {
			continue
		}
		l := locals[i]
		out = append(out, mergedKey{
			local: &locals[i], name: l.Name, typ: l.Type, fp: l.Fingerprint, encrypted: l.Encrypted,
		})
	}

	sort.SliceStable(out, func(i, j int) bool {
		return strings.ToLower(out[i].name) < strings.ToLower(out[j].name)
	})
	return out
}

// selectedMergedKey returns the key under the keys-tab cursor.
func (m Model) selectedMergedKey() (mergedKey, bool) {
	mks := m.mergedKeys()
	if len(mks) == 0 {
		return mergedKey{}, false
	}
	return mks[clampIdx(m.keyIdx, len(mks))], true
}

// vaultKeyFingerprint derives a vault key's SHA256 fingerprint (and display
// type) from its stored public line, falling back to the unencrypted material.
// An encrypted key with no public line yields "".
func vaultKeyFingerprint(vk store.VaultKey) (fp, typ string) {
	if vk.PublicKey != "" {
		if f, ty, ok := keys.FingerprintOfAuthorized(vk.PublicKey); ok {
			return f, ty
		}
	}
	if raw, err := base64.StdEncoding.DecodeString(vk.Material); err == nil {
		if line, err := keys.PublicLineFromPEM(raw, ""); err == nil {
			if f, ty, ok := keys.FingerprintOfAuthorized(line); ok {
				return f, ty
			}
		}
	}
	return "", ""
}

// buildVaultKey reads a scanned key's private file (and its sibling .pub when
// present, else derives the public line from unencrypted material) into a
// store.VaultKey ready for the vault. The material is stored base64 verbatim.
func buildVaultKey(info keys.KeyInfo) (store.VaultKey, error) {
	data, err := os.ReadFile(info.Path)
	if err != nil {
		return store.VaultKey{}, err
	}
	pub := ""
	if info.HasPub {
		if pd, rerr := os.ReadFile(info.Path + ".pub"); rerr == nil {
			pub = strings.TrimRight(string(pd), "\r\n")
		}
	}
	if pub == "" {
		// Only unencrypted keys yield a public line here; encrypted ones keep "".
		if line, lerr := keys.PublicLineFromPEM(data, ""); lerr == nil {
			pub = line
		}
	}
	return store.VaultKey{
		Name:       info.Name,
		Type:       info.Type,
		Material:   base64.StdEncoding.EncodeToString(data),
		PublicKey:  pub,
		SourcePath: info.Path,
	}, nil
}
