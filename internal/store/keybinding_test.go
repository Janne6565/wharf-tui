package store

import (
	"encoding/json"
	"testing"
)

// A host's key binding has to survive the round trip through the vault payload,
// or every restart re-opens the "which key does this host use?" question.
func TestKeyIDRoundTrips(t *testing.T) {
	be := &fakeBackend{}
	s, err := Open(be)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	k, err := s.AddKey(VaultKey{Name: "work", Material: "cGVt"})
	if err != nil {
		t.Fatalf("add key: %v", err)
	}
	if _, err := s.AddHost(Host{Name: "prod", Addr: "a", Port: 22, KeyID: k.ID}); err != nil {
		t.Fatalf("add host: %v", err)
	}
	if err := s.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	reopened, err := Open(&fakeBackend{payload: be.saves[len(be.saves)-1]})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := reopened.Hosts()[0].KeyID; got != k.ID {
		t.Fatalf("KeyID = %q after reload, want %q", got, k.ID)
	}
}

// An import that names no key must not wipe a binding the user made by hand:
// ssh_config never carries one, so every re-import would otherwise unbind.
func TestReimportPreservesAManualBinding(t *testing.T) {
	s, err := Open(&fakeBackend{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	s.UpsertImported([]Host{{Name: "prod", Addr: "a", Port: 22, Source: "ssh_config"}})
	h := s.Hosts()[0]
	h.KeyID = "abc123"
	if err := s.UpdateHost(h); err != nil {
		t.Fatalf("update: %v", err)
	}

	s.UpsertImported([]Host{{Name: "prod", Addr: "a", Port: 22, Source: "ssh_config"}})
	if got := s.Hosts()[0].KeyID; got != "abc123" {
		t.Fatalf("re-import dropped the binding: KeyID = %q", got)
	}
}

// Merge re-IDs a carried-over key on an ID collision. A host carried in the same
// merge must follow its key, or sign-in silently unbinds the fleet.
func TestMergeRepointsHostsAtTheirCarriedKey(t *testing.T) {
	base := mustPayload(t, document{
		Schema: schemaVersion,
		Keys:   []VaultKey{{ID: "1111111111111111", Name: "account", Material: "cGVt"}},
	})
	local := mustPayload(t, document{
		Schema: schemaVersion,
		Hosts:  []Host{{ID: "aaaaaaaaaaaaaaaa", Name: "prod", Addr: "a", Port: 22, KeyID: "1111111111111111"}},
		// Same ID as the account's key, different name: the merge must re-ID it.
		Keys: []VaultKey{{ID: "1111111111111111", Name: "local", Material: "cGVt"}},
	})

	merged, res, err := Merge(base, local)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if res.HostsAdded != 1 || res.KeysAdded != 1 {
		t.Fatalf("merge carried %d hosts / %d keys, want 1 / 1", res.HostsAdded, res.KeysAdded)
	}

	doc := mustParse(t, merged)
	local2 := findKey(t, doc, "local")
	if local2.ID == "1111111111111111" {
		t.Fatal("the colliding key kept its ID")
	}
	if got := doc.Hosts[0].KeyID; got != local2.ID {
		t.Fatalf("host binds %q, want the re-IDed local key %q", got, local2.ID)
	}
}

// When the account already has a key by that name, the local copy is skipped —
// and the host that used it should use the account's key of the same name
// rather than keep a reference to something the merged vault does not hold.
func TestMergeRebindsToTheAccountKeyOfTheSameName(t *testing.T) {
	base := mustPayload(t, document{
		Schema: schemaVersion,
		Keys:   []VaultKey{{ID: "2222222222222222", Name: "work", Material: "cGVt"}},
	})
	local := mustPayload(t, document{
		Schema: schemaVersion,
		Hosts:  []Host{{ID: "aaaaaaaaaaaaaaaa", Name: "prod", Addr: "a", Port: 22, KeyID: "9999999999999999"}},
		Keys:   []VaultKey{{ID: "9999999999999999", Name: "work", Material: "cGVt"}},
	})

	merged, res, err := Merge(base, local)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if res.KeysSkipped != 1 {
		t.Fatalf("KeysSkipped = %d, want 1", res.KeysSkipped)
	}
	if got := mustParse(t, merged).Hosts[0].KeyID; got != "2222222222222222" {
		t.Fatalf("host binds %q, want the account's key of the same name", got)
	}
}

// A binding that resolves to nothing on either side is dropped: a dangling
// reference would mean the host offers one key that cannot exist.
func TestMergeDropsADanglingBinding(t *testing.T) {
	base := mustPayload(t, document{Schema: schemaVersion})
	local := mustPayload(t, document{
		Schema: schemaVersion,
		Hosts:  []Host{{ID: "aaaaaaaaaaaaaaaa", Name: "prod", Addr: "a", Port: 22, KeyID: "deadbeefdeadbeef"}},
	})

	merged, _, err := Merge(base, local)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if got := mustParse(t, merged).Hosts[0].KeyID; got != "" {
		t.Fatalf("dangling binding survived as %q", got)
	}
}

func mustPayload(t *testing.T, doc document) []byte {
	t.Helper()
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

func mustParse(t *testing.T, payload []byte) document {
	t.Helper()
	var doc document
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return doc
}

func findKey(t *testing.T, doc document, name string) VaultKey {
	t.Helper()
	for _, k := range doc.Keys {
		if k.Name == name {
			return k
		}
	}
	t.Fatalf("no key named %q in %+v", name, doc.Keys)
	return VaultKey{}
}
