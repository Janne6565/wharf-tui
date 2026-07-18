// Package store is Wharf's typed data layer: hosts and settings serialized
// as a versioned JSON document into an opaque Backend (the encrypted vault
// in real mode, memory in demo/tests). Probe status and session liveness are
// deliberately NOT part of this schema — they are ephemeral UI state.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

// schemaVersion is the document version this build writes. The document has
// grown by version: 1 was hosts + settings, 2 added the vault identity, 3
// added synced SSH keys. Open still accepts the older versions 1 and 2
// (upgraded in-memory and rewritten as 3 on the next Save); any newer version
// is a hard error, since an old build cannot round-trip fields it does not
// know without silently dropping them.
const schemaVersion = 3

// Backend persists the raw payload. *vault.Vault satisfies this.
type Backend interface {
	Payload() []byte
	Save([]byte) error
}

// Host is a saved SSH destination. ID is 16 random hex chars, assigned by
// AddHost. Source distinguishes manually created hosts from ssh_config
// imports (import merges never touch "manual" hosts).
type Host struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	User    string   `json:"user"`
	Addr    string   `json:"addr"`
	Port    int      `json:"port"`
	Tags    []string `json:"tags,omitempty"`
	KeyPath string   `json:"keyPath,omitempty"`
	// AuthMethod restricts the SSH auth chain: "key" (default) | "password".
	// Add/Update normalize the empty string and the legacy "auto" value to
	// "key"; a document read straight from disk may still hold "" or "auto".
	AuthMethod string `json:"authMethod,omitempty"`
	// Password is the saved login password for password-auth hosts. It lives
	// only inside the encrypted vault — never plaintext on disk.
	Password string    `json:"password,omitempty"`
	Source   string    `json:"source"` // "manual" | "ssh_config"
	LastSeen time.Time `json:"lastSeen,omitempty"`
}

// Conn renders the user@addr:port connection string shown in the UI.
func (h Host) Conn() string {
	return h.User + "@" + h.Addr + ":" + strconv.Itoa(h.Port)
}

// Settings are the persisted app preferences (replaces the ad-hoc bool map).
type Settings struct {
	Theme     string `json:"theme"`
	Agent     bool   `json:"agent"`     // ssh-agent forwarding to auth chain
	Keepalive bool   `json:"keepalive"` // 30s keepalive@openssh.com pings
	Telemetry bool   `json:"telemetry"`
}

// DefaultSettings for a fresh vault.
func DefaultSettings() Settings {
	return Settings{Theme: "abyss", Agent: true, Keepalive: true}
}

// Identity is the vault's X25519 keypair used to wrap project DEKs. The keys
// are base64-encoded; CreatedAt records when the identity was generated.
type Identity struct {
	X25519Priv string    `json:"x25519Priv"` // base64
	X25519Pub  string    `json:"x25519Pub"`  // base64
	CreatedAt  time.Time `json:"createdAt"`
}

// VaultKey is an SSH private key synced through the encrypted vault
// (schema 3, opt-in per key). Material is the keyfile bytes VERBATIM
// (base64) — a passphrase-protected file stays protected inside the
// vault; clients prompt at connect. Never written to a project blob.
type VaultKey struct {
	ID         string    `json:"id"`                   // 16 hex, newID()
	Name       string    `json:"name"`                 // display name, unique (case-insensitive)
	Type       string    `json:"type"`                 // display type, e.g. "ED25519" (keys.displayType)
	Material   string    `json:"material"`             // base64 keyfile bytes, verbatim
	PublicKey  string    `json:"publicKey,omitempty"`  // authorized_keys line; "" when unknown
	SourcePath string    `json:"sourcePath,omitempty"` // origin path on the syncing machine, display only
	AddedAt    time.Time `json:"addedAt"`
}

// document is the on-disk shape. Kept unexported so the JSON envelope can
// evolve independently of the in-memory Store representation.
type document struct {
	Schema   int        `json:"schema"`
	Hosts    []Host     `json:"hosts"`
	Settings Settings   `json:"settings"`
	Identity *Identity  `json:"identity,omitempty"`
	Keys     []VaultKey `json:"keys,omitempty"`
}

// Store is the in-memory working copy; every mutation is only durable after
// Save.
type Store struct {
	backend  Backend
	hosts    []Host
	settings Settings
	identity *Identity
	keys     []VaultKey
}

// Open loads the document from b. An empty payload yields an empty store
// with DefaultSettings. An unknown schema version is an explicit error.
func Open(b Backend) (*Store, error) {
	payload := b.Payload()
	if len(payload) == 0 {
		return &Store{backend: b, settings: DefaultSettings()}, nil
	}

	var doc document
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("store: invalid vault payload: %w", err)
	}
	// Older schemas (1, 2) are read as-is and rewritten as schema 3 on the
	// next Save.
	if doc.Schema != 1 && doc.Schema != 2 && doc.Schema != 3 {
		return nil, fmt.Errorf("store: unsupported schema version %d (this build understands 1-3)", doc.Schema)
	}

	return &Store{
		backend:  b,
		hosts:    doc.Hosts,
		settings: doc.Settings,
		identity: cloneIdentity(doc.Identity),
		keys:     doc.Keys,
	}, nil
}

// noopBackend is the Backend used by NewMemory: it reports no stored payload
// and silently accepts saves, so demo mode and UI tests never touch disk.
type noopBackend struct{}

func (noopBackend) Payload() []byte   { return nil }
func (noopBackend) Save([]byte) error { return nil }

// NewMemory builds a store over a no-op backend, seeded for demo mode and
// tests.
func NewMemory(hosts []Host, s Settings) *Store {
	seeded := make([]Host, len(hosts))
	for i, h := range hosts {
		if h.ID == "" {
			h.ID = newID()
		}
		seeded[i] = cloneHost(h)
	}
	return &Store{backend: noopBackend{}, hosts: seeded, settings: s}
}

// Hosts returns all hosts, stable-sorted by name.
func (s *Store) Hosts() []Host { return sortedHostCopy(s.hosts) }

// HostByID looks a host up by ID.
func (s *Store) HostByID(id string) (Host, bool) {
	if i := indexByIDIn(s.hosts, id); i >= 0 {
		return cloneHost(s.hosts[i]), true
	}
	return Host{}, false
}

// AddHost validates h (name+addr required, 1 <= port <= 65535, unique name),
// assigns an ID and Source "manual" if unset, and returns the stored host.
func (s *Store) AddHost(h Host) (Host, error) {
	hosts, stored, err := addHostTo(s.hosts, h)
	if err != nil {
		return Host{}, err
	}
	s.hosts = hosts
	return cloneHost(stored), nil
}

// UpdateHost replaces the host with h.ID; same validation as AddHost.
func (s *Store) UpdateHost(h Host) error {
	return updateHostIn(s.hosts, h)
}

// DeleteHost removes the host with the given ID.
func (s *Store) DeleteHost(id string) error {
	hosts, err := deleteHostIn(s.hosts, id)
	if err != nil {
		return err
	}
	s.hosts = hosts
	return nil
}

// UpsertImported merges ssh_config-sourced hosts: new names are added,
// existing hosts with Source "ssh_config" are updated, hosts with Source
// "manual" are skipped untouched. A matching ssh_config host that is byte-for
// -byte identical to the incoming one counts as skipped (nothing to write);
// only a real change counts as updated.
func (s *Store) UpsertImported(hs []Host) (added, updated, skipped int) {
	for _, in := range hs {
		i := indexByNameIn(s.hosts, in.Name)
		if i < 0 {
			if in.ID == "" {
				in.ID = newID()
			}
			s.hosts = append(s.hosts, cloneHost(in))
			added++
			continue
		}

		existing := s.hosts[i]
		if existing.Source == "manual" {
			// Manual hosts are user-owned; imports never clobber them.
			skipped++
			continue
		}

		// Re-imported ssh_config host: keep our stable ID and LastSeen so the
		// merge is idempotent, then diff to decide update vs. no-op. Imports
		// never carry auth secrets, so preserve any AuthMethod/Password the
		// user added locally — a re-import must not wipe a saved password.
		// Inheriting them here also makes the DeepEqual below ignore those two
		// fields, so an otherwise-unchanged host still counts as skipped.
		merged := in
		merged.ID = existing.ID
		merged.LastSeen = existing.LastSeen
		merged.AuthMethod = existing.AuthMethod
		merged.Password = existing.Password
		if reflect.DeepEqual(existing, merged) {
			skipped++
			continue
		}
		s.hosts[i] = cloneHost(merged)
		updated++
	}
	return added, updated, skipped
}

// Settings returns the current settings.
func (s *Store) Settings() Settings { return s.settings }

// SetSettings replaces the settings.
func (s *Store) SetSettings(v Settings) { s.settings = v }

// Identity returns a deep copy of the stored vault identity, or nil if unset,
// so callers cannot mutate the persisted pointer.
func (s *Store) Identity() *Identity { return cloneIdentity(s.identity) }

// SetIdentity stores a copy of id (nil clears the identity).
func (s *Store) SetIdentity(id *Identity) { s.identity = cloneIdentity(id) }

// Keys returns all synced vault keys, stable-sorted by name.
func (s *Store) Keys() []VaultKey { return sortedKeyCopy(s.keys) }

// KeyByID looks a synced key up by ID.
func (s *Store) KeyByID(id string) (VaultKey, bool) {
	if i := indexKeyByIDIn(s.keys, id); i >= 0 {
		return s.keys[i], true
	}
	return VaultKey{}, false
}

// AddKey validates k (name+material required, name unique among vault keys
// case-insensitively), assigns an ID and AddedAt if unset, and returns the
// stored key. Vault keys are a separate namespace from hosts, so a key may
// share a name with a host.
func (s *Store) AddKey(k VaultKey) (VaultKey, error) {
	keys, stored, err := addKeyTo(s.keys, k)
	if err != nil {
		return VaultKey{}, err
	}
	s.keys = keys
	return stored, nil
}

// RemoveKey deletes the synced key with the given ID.
func (s *Store) RemoveKey(id string) error {
	keys, err := removeKeyIn(s.keys, id)
	if err != nil {
		return err
	}
	s.keys = keys
	return nil
}

// Save marshals the document and writes it through the backend.
func (s *Store) Save() error {
	doc := document{Schema: schemaVersion, Hosts: s.hosts, Settings: s.settings, Identity: s.identity, Keys: s.keys}
	payload, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("store: marshal document: %w", err)
	}
	return s.backend.Save(payload)
}

// sortedHostCopy returns a stable, name-sorted deep copy of hosts.
func sortedHostCopy(hosts []Host) []Host {
	out := make([]Host, len(hosts))
	for i, h := range hosts {
		out[i] = cloneHost(h)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

// sortedKeyCopy returns a stable, name-sorted copy of keys. VaultKey holds
// only value fields, so copying the slice fully detaches the caller from the
// store — a returned key cannot leak a mutation back in.
func sortedKeyCopy(keys []VaultKey) []VaultKey {
	out := make([]VaultKey, len(keys))
	copy(out, keys)
	sort.SliceStable(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

// addKeyTo validates k, assigns an ID and AddedAt if unset, and returns keys
// with the stored key appended alongside that key.
func addKeyTo(keys []VaultKey, k VaultKey) ([]VaultKey, VaultKey, error) {
	if strings.TrimSpace(k.Name) == "" {
		return keys, VaultKey{}, fmt.Errorf("store: key name is required")
	}
	if strings.TrimSpace(k.Material) == "" {
		return keys, VaultKey{}, fmt.Errorf("store: key material is required")
	}
	name := strings.ToLower(strings.TrimSpace(k.Name))
	for _, other := range keys {
		if strings.ToLower(strings.TrimSpace(other.Name)) == name {
			return keys, VaultKey{}, fmt.Errorf("store: a key named %q already exists", strings.TrimSpace(k.Name))
		}
	}
	if k.ID == "" {
		k.ID = newID()
	}
	if k.AddedAt.IsZero() {
		k.AddedAt = time.Now()
	}
	return append(keys, k), k, nil
}

// removeKeyIn removes the key with id and returns the shortened slice.
func removeKeyIn(keys []VaultKey, id string) ([]VaultKey, error) {
	i := indexKeyByIDIn(keys, id)
	if i < 0 {
		return keys, fmt.Errorf("store: no key with id %q", id)
	}
	return append(keys[:i], keys[i+1:]...), nil
}

// indexKeyByIDIn returns the slice index of the key with id, or -1.
func indexKeyByIDIn(keys []VaultKey, id string) int {
	for i := range keys {
		if keys[i].ID == id {
			return i
		}
	}
	return -1
}

// addHostTo defaults, normalizes and validates h, assigns an ID if unset, and
// returns hosts with the stored clone appended alongside that clone. The input
// slice is not mutated beyond the append semantics callers already rely on.
func addHostTo(hosts []Host, h Host) ([]Host, Host, error) {
	if h.Port == 0 {
		h.Port = 22
	}
	if h.Source == "" {
		h.Source = "manual"
	}
	am, err := normalizeAuthMethod(h.AuthMethod)
	if err != nil {
		return hosts, Host{}, err
	}
	h.AuthMethod = am
	if err := validateHostIn(hosts, h, ""); err != nil {
		return hosts, Host{}, err
	}
	if h.ID == "" {
		h.ID = newID()
	}
	stored := cloneHost(h)
	return append(hosts, stored), stored, nil
}

// updateHostIn replaces the host with h.ID inside hosts, applying the same
// normalization and validation as addHostTo.
func updateHostIn(hosts []Host, h Host) error {
	i := indexByIDIn(hosts, h.ID)
	if i < 0 {
		return fmt.Errorf("store: no host with id %q", h.ID)
	}
	am, err := normalizeAuthMethod(h.AuthMethod)
	if err != nil {
		return err
	}
	h.AuthMethod = am
	if err := validateHostIn(hosts, h, h.ID); err != nil {
		return err
	}
	hosts[i] = cloneHost(h)
	return nil
}

// deleteHostIn removes the host with id and returns the shortened slice.
func deleteHostIn(hosts []Host, id string) ([]Host, error) {
	i := indexByIDIn(hosts, id)
	if i < 0 {
		return hosts, fmt.Errorf("store: no host with id %q", id)
	}
	return append(hosts[:i], hosts[i+1:]...), nil
}

// validateHostIn enforces the shared AddHost/UpdateHost rules against hosts.
// excludeID is the ID of the host being updated (empty for adds) so a host does
// not collide with its own name.
func validateHostIn(hosts []Host, h Host, excludeID string) error {
	if strings.TrimSpace(h.Name) == "" {
		return fmt.Errorf("store: host name is required")
	}
	if strings.TrimSpace(h.Addr) == "" {
		return fmt.Errorf("store: host address is required")
	}
	if h.Port < 1 || h.Port > 65535 {
		return fmt.Errorf("store: port %d out of range (1-65535)", h.Port)
	}
	name := strings.ToLower(strings.TrimSpace(h.Name))
	for _, other := range hosts {
		if other.ID == excludeID {
			continue
		}
		if strings.ToLower(strings.TrimSpace(other.Name)) == name {
			return fmt.Errorf("store: a host named %q already exists", strings.TrimSpace(h.Name))
		}
	}
	return nil
}

// normalizeAuthMethod canonicalizes an AuthMethod value to one of the two
// supported modes and rejects unknown ones. The empty string and the legacy
// "auto" value (from the retired three-way selector) both map to "key", the
// default; anything outside the known set is a validation error rather than
// being silently coerced.
func normalizeAuthMethod(v string) (string, error) {
	switch v {
	case "", "auto", "key":
		return "key", nil
	case "password":
		return "password", nil
	default:
		return "", fmt.Errorf("store: invalid auth method %q (want \"key\" or \"password\")", v)
	}
}

// indexByIDIn returns the slice index of the host with id, or -1.
func indexByIDIn(hosts []Host, id string) int {
	for i := range hosts {
		if hosts[i].ID == id {
			return i
		}
	}
	return -1
}

// indexByNameIn returns the slice index of the host whose name matches name
// case-insensitively, or -1.
func indexByNameIn(hosts []Host, name string) int {
	target := strings.ToLower(strings.TrimSpace(name))
	for i := range hosts {
		if strings.ToLower(strings.TrimSpace(hosts[i].Name)) == target {
			return i
		}
	}
	return -1
}

// cloneHost deep-copies a Host so mutations of the Tags slice can never leak
// across the store boundary.
func cloneHost(h Host) Host {
	if h.Tags != nil {
		tags := make([]string, len(h.Tags))
		copy(tags, h.Tags)
		h.Tags = tags
	}
	return h
}

// cloneIdentity returns a deep copy of id, or nil if id is nil. Identity holds
// only value fields, so a shallow struct copy behind a fresh pointer suffices.
func cloneIdentity(id *Identity) *Identity {
	if id == nil {
		return nil
	}
	cp := *id
	return &cp
}

// newID returns 16 lowercase hex characters from crypto/rand. rand.Read never
// fails on the platforms Wharf targets, so a failure is treated as fatal.
func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("store: crypto/rand unavailable: %v", err))
	}
	return hex.EncodeToString(b[:])
}
