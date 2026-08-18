package ui

import (
	"encoding/base64"
	"testing"

	"github.com/Janne6565/wharf-tui/internal/sshx"
	"github.com/Janne6565/wharf-tui/internal/store"
)

// addBoundHost puts two keys and one host in the vault and returns the model
// plus the id of the key named "bound".
func addBoundHost(t *testing.T, m Model, bind bool) (Model, store.Host, string) {
	t.Helper()
	var boundID string
	for _, name := range []string{"bound", "other"} {
		k, err := m.st.AddKey(store.VaultKey{
			Name: name, Type: "ED25519",
			Material: base64.StdEncoding.EncodeToString([]byte("pem-" + name)),
		})
		if err != nil {
			t.Fatalf("add key %s: %v", name, err)
		}
		if name == "bound" {
			boundID = k.ID
		}
	}
	h := store.Host{Name: "prod", User: "u", Addr: "a", Port: 22, AuthMethod: sshx.AuthKey}
	if bind {
		h.KeyID = boundID
	}
	stored, err := m.st.AddHost(h)
	if err != nil {
		t.Fatalf("add host: %v", err)
	}
	return m, stored, boundID
}

// A bound host offers exactly its key. Offering the whole vault is what spends
// the server's MaxAuthTries before the right key is reached.
func TestBoundHostOffersOnlyItsKey(t *testing.T) {
	tm, _ := openedModel(t)
	m, h, _ := addBoundHost(t, tm.(Model), true)

	spec := m.hostSpec(h)
	if !spec.KeyBound {
		t.Fatal("a bound host must tell the engine so, or it still offers the agent")
	}
	if len(spec.VaultKeys) != 1 || spec.VaultKeys[0].Name != "bound" {
		t.Fatalf("offered %v, want only the bound key", spec.VaultKeys)
	}
}

// Without a binding nothing changes: the whole vault is offered, in batches.
func TestUnboundHostOffersEveryKey(t *testing.T) {
	tm, _ := openedModel(t)
	m, h, _ := addBoundHost(t, tm.(Model), false)

	spec := m.hostSpec(h)
	if spec.KeyBound {
		t.Fatal("an unbound host must not claim a binding")
	}
	if len(spec.VaultKeys) != 2 {
		t.Fatalf("offered %d keys, want both", len(spec.VaultKeys))
	}
}

// A binding can outlive its key — a vault synced from a device that removed it.
// Trying every key beats trying none, so the host degrades to unbound.
func TestStaleBindingFallsBackToTheWholeVault(t *testing.T) {
	tm, _ := openedModel(t)
	m, h, _ := addBoundHost(t, tm.(Model), true)
	h.KeyID = "0000000000000000"

	spec := m.hostSpec(h)
	if spec.KeyBound || len(spec.VaultKeys) != 2 {
		t.Fatalf("stale binding: KeyBound=%v, %d keys offered; want false and every key",
			spec.KeyBound, len(spec.VaultKeys))
	}
}

// Password mode never offers keys, bound or not.
func TestPasswordModeIgnoresTheBinding(t *testing.T) {
	tm, _ := openedModel(t)
	m, h, _ := addBoundHost(t, tm.(Model), true)
	h.AuthMethod = sshx.AuthPassword

	if spec := m.hostSpec(h); len(spec.VaultKeys) != 0 || spec.KeyBound {
		t.Fatalf("password mode offered %d keys (bound=%v)", len(spec.VaultKeys), spec.KeyBound)
	}
}

// Removing a key must not leave hosts pointing at it.
func TestRemovingAKeyUnbindsItsHosts(t *testing.T) {
	tm, _ := openedModel(t)
	m, h, boundID := addBoundHost(t, tm.(Model), true)

	if err := m.st.RemoveKey(boundID); err != nil {
		t.Fatalf("remove key: %v", err)
	}
	got, ok := m.st.HostByID(h.ID)
	if !ok {
		t.Fatal("host disappeared with the key")
	}
	if got.KeyID != "" {
		t.Fatalf("host still bound to the removed key (%q)", got.KeyID)
	}
}

// The bound-key selector must not be gated on being signed in the way the
// project selector is: vault keys are local-first and exist without an account.
// It appears once there is something to pick, and never in password mode.
func TestVaultKeySelectorVisibility(t *testing.T) {
	tm, _ := openedModel(t)
	m := tm.(Model)
	m = m.openHostForm("")
	m.formVals[fAuth] = sshx.AuthKey

	if m.fieldVisible(fVaultKey) {
		t.Error("an empty vault has nothing to bind to, so the selector should be hidden")
	}

	if _, err := m.st.AddKey(store.VaultKey{
		Name: "work", Type: "ED25519", Material: base64.StdEncoding.EncodeToString([]byte("pem")),
	}); err != nil {
		t.Fatalf("add key: %v", err)
	}
	if !m.fieldVisible(fVaultKey) {
		t.Error("with a synced key present the selector should be shown")
	}

	m.formVals[fAuth] = sshx.AuthPassword
	if m.fieldVisible(fVaultKey) {
		t.Error("password mode offers no keys, so the selector should be hidden")
	}
}
