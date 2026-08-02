package store

import (
	"encoding/json"
	"fmt"
	"strings"
)

// MergeResult reports what a Merge did, so the UI can tell the user exactly
// what happened to the vault they had before signing in.
type MergeResult struct {
	HostsAdded   int
	HostsSkipped int // name already taken on the account side
	KeysAdded    int
	KeysSkipped  int // name already taken on the account side
}

// Any reports whether the merge carried anything over.
func (r MergeResult) Any() bool { return r.HostsAdded > 0 || r.KeysAdded > 0 }

// Merge folds the hosts and synced keys of local into base and returns the
// merged payload. It is the "I used wharf on this machine before I signed in"
// reconciliation: base is the account's payload (the authority — it is what
// every other device already agrees on) and local is this machine's.
//
// The rules are deliberately conservative, because a merge runs unattended
// during sign-in and must never destroy data on either side:
//
//   - base always wins. Nothing in it is modified, replaced or reordered.
//   - A local host or key is carried over only if its name is free on the base
//     side (names are the user-facing identity and must stay unique); a
//     colliding one is skipped and counted, never silently overwritten and
//     never renamed behind the user's back.
//   - A carried-over entry keeps its content but is re-IDed on an ID collision,
//     so two independently generated IDs can never alias.
//   - Settings, schema and the vault identity are taken from base untouched:
//     the identity is the keypair the server publishes for this account, and
//     replacing it with a local one would make every project DEK unwrappable.
//
// Both payloads must be readable documents; an empty payload is treated as an
// empty document.
func Merge(base, local []byte) ([]byte, MergeResult, error) {
	baseDoc, err := parseDocument(base)
	if err != nil {
		return nil, MergeResult{}, fmt.Errorf("store: account vault: %w", err)
	}
	localDoc, err := parseDocument(local)
	if err != nil {
		return nil, MergeResult{}, fmt.Errorf("store: local vault: %w", err)
	}

	var res MergeResult
	merged := baseDoc
	merged.Schema = schemaVersion

	for _, h := range localDoc.Hosts {
		if indexByNameIn(merged.Hosts, h.Name) >= 0 {
			res.HostsSkipped++
			continue
		}
		if h.ID == "" || indexByIDIn(merged.Hosts, h.ID) >= 0 {
			h.ID = newID()
		}
		merged.Hosts = append(merged.Hosts, cloneHost(h))
		res.HostsAdded++
	}

	for _, k := range localDoc.Keys {
		if indexKeyByNameIn(merged.Keys, k.Name) >= 0 {
			res.KeysSkipped++
			continue
		}
		if k.ID == "" || indexKeyByIDIn(merged.Keys, k.ID) >= 0 {
			k.ID = newID()
		}
		merged.Keys = append(merged.Keys, k)
		res.KeysAdded++
	}

	payload, err := json.Marshal(merged)
	if err != nil {
		return nil, MergeResult{}, fmt.Errorf("store: marshal merged document: %w", err)
	}
	return payload, res, nil
}

// parseDocument decodes a payload into a document, enforcing the same schema
// bounds as Open. An empty payload is an empty document.
func parseDocument(payload []byte) (document, error) {
	if len(payload) == 0 {
		return document{Schema: schemaVersion, Settings: DefaultSettings()}, nil
	}
	var doc document
	if err := json.Unmarshal(payload, &doc); err != nil {
		return document{}, fmt.Errorf("invalid vault payload: %w", err)
	}
	if doc.Schema != 1 && doc.Schema != 2 && doc.Schema != 3 {
		return document{}, fmt.Errorf("unsupported schema version %d (this build understands 1-3)", doc.Schema)
	}
	return doc, nil
}

// indexKeyByNameIn returns the slice index of the key named name
// (case-insensitive, trimmed — the uniqueness rule AddKey enforces), or -1.
func indexKeyByNameIn(keys []VaultKey, name string) int {
	want := strings.ToLower(strings.TrimSpace(name))
	for i := range keys {
		if strings.ToLower(strings.TrimSpace(keys[i].Name)) == want {
			return i
		}
	}
	return -1
}
