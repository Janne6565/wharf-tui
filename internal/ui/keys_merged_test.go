package ui

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/Janne6565/wharf-tui/internal/keys"
	"github.com/Janne6565/wharf-tui/internal/store"
)

// genKey generates a real ed25519 key in a temp dir and returns its scanned
// info plus the raw private bytes and authorized_keys public line.
func genKey(t *testing.T, name string) (keys.KeyInfo, []byte, string) {
	t.Helper()
	dir := t.TempDir()
	info, err := keys.Generate(dir, name, "c@host", nil)
	if err != nil {
		t.Fatalf("Generate %s: %v", name, err)
	}
	priv, err := os.ReadFile(info.Path)
	if err != nil {
		t.Fatalf("read priv: %v", err)
	}
	pub, err := os.ReadFile(filepath.Join(dir, name+".pub"))
	if err != nil {
		t.Fatalf("read pub: %v", err)
	}
	return info, priv, string(pub)
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestMergedKeysStates(t *testing.T) {
	synced, syncedPriv, syncedPub := genKey(t, "synced")
	localOnly, _, _ := genKey(t, "localonly")
	_, vaultOnlyPriv, vaultOnlyPub := genKey(t, "vaultonly")
	// A vault key with no stored public line still matches nothing local, and
	// its fingerprint is derived from the (unencrypted) material.
	_, noPubPriv, _ := genKey(t, "nopub")

	st := store.NewMemory(nil, store.DefaultSettings())
	if _, err := st.AddKey(store.VaultKey{Name: "synced", Type: "ED25519", Material: b64(syncedPriv), PublicKey: syncedPub}); err != nil {
		t.Fatalf("add synced: %v", err)
	}
	if _, err := st.AddKey(store.VaultKey{Name: "vaultonly", Type: "ED25519", Material: b64(vaultOnlyPriv), PublicKey: vaultOnlyPub}); err != nil {
		t.Fatalf("add vaultonly: %v", err)
	}
	if _, err := st.AddKey(store.VaultKey{Name: "nopub", Type: "ED25519", Material: b64(noPubPriv)}); err != nil {
		t.Fatalf("add nopub: %v", err)
	}

	m := Model{keyInfos: []keys.KeyInfo{synced, localOnly}, st: st}
	mks := m.mergedKeys()

	// Sorted by name: localonly, nopub, synced, vaultonly.
	names := make([]string, len(mks))
	for i, mk := range mks {
		names[i] = mk.name
	}
	want := []string{"localonly", "nopub", "synced", "vaultonly"}
	if len(names) != len(want) {
		t.Fatalf("merged names = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("merged names = %v, want %v (sorted)", names, want)
		}
	}

	by := map[string]mergedKey{}
	for _, mk := range mks {
		by[mk.name] = mk
	}
	if mk := by["synced"]; !mk.isSynced() {
		t.Errorf("synced entry state wrong: local=%v vault=%v", mk.local != nil, mk.vault != nil)
	}
	if mk := by["localonly"]; mk.local == nil || mk.vault != nil {
		t.Errorf("localonly entry should be local-only")
	}
	if mk := by["vaultonly"]; !mk.isVaultOnly() {
		t.Errorf("vaultonly entry state wrong: local=%v vault=%v", mk.local != nil, mk.vault != nil)
	}
	if mk := by["nopub"]; !mk.isVaultOnly() || mk.fp == "" {
		t.Errorf("nopub entry should be vault-only with a material-derived fingerprint, got fp=%q", mk.fp)
	}
	// Guard the intended fingerprint match, not just the state.
	if by["synced"].fp != synced.Fingerprint {
		t.Errorf("synced fingerprint = %q, want %q", by["synced"].fp, synced.Fingerprint)
	}
}

func TestBuildVaultKeyFromScannedKey(t *testing.T) {
	info, priv, pub := genKey(t, "id_ed25519")

	vk, err := buildVaultKey(info)
	if err != nil {
		t.Fatalf("buildVaultKey: %v", err)
	}
	if vk.Name != "id_ed25519" || vk.Type != "ED25519" {
		t.Errorf("vault key name/type wrong: %+v", vk)
	}
	if vk.Material != b64(priv) {
		t.Error("material should be the base64 of the verbatim private file")
	}
	if vk.PublicKey != pub[:len(pub)-1] { // .pub carries a trailing newline
		t.Errorf("public line = %q, want %q", vk.PublicKey, pub[:len(pub)-1])
	}
	if vk.SourcePath != info.Path {
		t.Errorf("source path = %q, want %q", vk.SourcePath, info.Path)
	}
}
