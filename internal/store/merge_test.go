package store

import (
	"encoding/json"
	"strings"
	"testing"
)

// payloadOf marshals a document the way a vault holds one.
func payloadOf(t *testing.T, doc document) []byte {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestMergeKeepsBothSides(t *testing.T) {
	base := payloadOf(t, document{
		Schema:   3,
		Hosts:    []Host{{ID: "a1", Name: "prod-api", Addr: "api.example.com", Port: 22, Source: "manual"}},
		Settings: Settings{Theme: "phosphor", Agent: true},
	})
	local := payloadOf(t, document{
		Schema:   3,
		Hosts:    []Host{{ID: "b2", Name: "homelab", Addr: "10.0.0.5", Port: 22, Source: "manual"}},
		Settings: Settings{Theme: "amber"},
		Keys:     []VaultKey{{ID: "k1", Name: "laptop", Material: "bWF0"}},
	})

	merged, res, err := Merge(base, local)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if res.HostsAdded != 1 || res.KeysAdded != 1 || res.HostsSkipped != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}

	var doc document
	if err := json.Unmarshal(merged, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Hosts) != 2 {
		t.Fatalf("both hosts should survive, got %d", len(doc.Hosts))
	}
	if doc.Hosts[0].Name != "prod-api" {
		t.Fatalf("the account host must stay first, got %q", doc.Hosts[0].Name)
	}
	if doc.Settings.Theme != "phosphor" {
		t.Fatalf("settings must come from the account vault, got %q", doc.Settings.Theme)
	}
	if len(doc.Keys) != 1 || doc.Keys[0].Name != "laptop" {
		t.Fatalf("the local key should be carried over, got %+v", doc.Keys)
	}
}

// A local host whose name is already taken on the account is skipped, never
// overwritten: the account side is the one every other device agrees on.
func TestMergeSkipsNameCollisions(t *testing.T) {
	base := payloadOf(t, document{
		Schema: 3,
		Hosts:  []Host{{ID: "a1", Name: "prod-api", Addr: "api.example.com", Port: 22}},
		Keys:   []VaultKey{{ID: "k1", Name: "Laptop", Material: "YWNjb3VudA=="}},
	})
	local := payloadOf(t, document{
		Schema: 3,
		Hosts:  []Host{{ID: "b2", Name: "PROD-API", Addr: "stale.example.com", Port: 2222}},
		Keys:   []VaultKey{{ID: "k2", Name: "laptop", Material: "bG9jYWw="}},
	})

	merged, res, err := Merge(base, local)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if res.HostsAdded != 0 || res.HostsSkipped != 1 || res.KeysAdded != 0 || res.KeysSkipped != 1 {
		t.Fatalf("collisions should be skipped, got %+v", res)
	}
	var doc document
	if err := json.Unmarshal(merged, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Hosts[0].Addr != "api.example.com" || doc.Keys[0].Material != "YWNjb3VudA==" {
		t.Fatal("the account entries must be untouched")
	}
}

// Two vaults created independently can, in principle, mint the same ID; a
// carried-over entry is re-IDed rather than aliasing an account entry.
func TestMergeReIDsCollidingIDs(t *testing.T) {
	base := payloadOf(t, document{
		Schema: 3,
		Hosts:  []Host{{ID: "dupe", Name: "prod-api", Addr: "api.example.com", Port: 22}},
	})
	local := payloadOf(t, document{
		Schema: 3,
		Hosts:  []Host{{ID: "dupe", Name: "homelab", Addr: "10.0.0.5", Port: 22}},
	})

	merged, _, err := Merge(base, local)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	var doc document
	if err := json.Unmarshal(merged, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Hosts[0].ID == doc.Hosts[1].ID {
		t.Fatalf("colliding IDs must be reassigned, both are %q", doc.Hosts[0].ID)
	}
	if doc.Hosts[0].ID != "dupe" {
		t.Fatalf("the account host must keep its ID, got %q", doc.Hosts[0].ID)
	}
}

// The identity is the keypair the server publishes for the account; a local
// one must never replace it, or every project DEK becomes unwrappable.
func TestMergeKeepsAccountIdentity(t *testing.T) {
	base := payloadOf(t, document{Schema: 3, Identity: &Identity{X25519Pub: "account", X25519Priv: "account-priv"}})
	local := payloadOf(t, document{Schema: 3, Identity: &Identity{X25519Pub: "local", X25519Priv: "local-priv"}})

	merged, _, err := Merge(base, local)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	var doc document
	if err := json.Unmarshal(merged, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Identity == nil || doc.Identity.X25519Pub != "account" {
		t.Fatalf("the account identity must win, got %+v", doc.Identity)
	}
}

func TestMergeEmptySides(t *testing.T) {
	local := payloadOf(t, document{Schema: 3, Hosts: []Host{{ID: "b2", Name: "homelab", Addr: "10.0.0.5", Port: 22}}})
	merged, res, err := Merge(nil, local)
	if err != nil {
		t.Fatalf("Merge with an empty base: %v", err)
	}
	if res.HostsAdded != 1 {
		t.Fatalf("an empty account vault should take the local host, got %+v", res)
	}
	if _, res, err := Merge(merged, nil); err != nil || res.Any() {
		t.Fatalf("an empty local side should add nothing: res=%+v err=%v", res, err)
	}
}

func TestMergeRejectsUnknownSchema(t *testing.T) {
	_, _, err := Merge([]byte(`{"schema":99}`), nil)
	if err == nil || !strings.Contains(err.Error(), "unsupported schema") {
		t.Fatalf("a newer schema must be a hard error, got %v", err)
	}
}
