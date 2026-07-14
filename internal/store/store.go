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

// schemaVersion is the only document version this build understands. Bumping
// it is a breaking change and requires an explicit migration path.
const schemaVersion = 1

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

// document is the on-disk shape. Kept unexported so the JSON envelope can
// evolve independently of the in-memory Store representation.
type document struct {
	Schema   int      `json:"schema"`
	Hosts    []Host   `json:"hosts"`
	Settings Settings `json:"settings"`
}

// Store is the in-memory working copy; every mutation is only durable after
// Save.
type Store struct {
	backend  Backend
	hosts    []Host
	settings Settings
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
	if doc.Schema != schemaVersion {
		return nil, fmt.Errorf("store: unsupported schema version %d (this build understands %d)", doc.Schema, schemaVersion)
	}

	return &Store{
		backend:  b,
		hosts:    doc.Hosts,
		settings: doc.Settings,
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
func (s *Store) Hosts() []Host {
	out := make([]Host, len(s.hosts))
	for i, h := range s.hosts {
		out[i] = cloneHost(h)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

// HostByID looks a host up by ID.
func (s *Store) HostByID(id string) (Host, bool) {
	if i := s.indexByID(id); i >= 0 {
		return cloneHost(s.hosts[i]), true
	}
	return Host{}, false
}

// AddHost validates h (name+addr required, 1 <= port <= 65535, unique name),
// assigns an ID and Source "manual" if unset, and returns the stored host.
func (s *Store) AddHost(h Host) (Host, error) {
	if h.Port == 0 {
		h.Port = 22
	}
	if h.Source == "" {
		h.Source = "manual"
	}
	am, err := normalizeAuthMethod(h.AuthMethod)
	if err != nil {
		return Host{}, err
	}
	h.AuthMethod = am
	if err := s.validate(h, ""); err != nil {
		return Host{}, err
	}
	if h.ID == "" {
		h.ID = newID()
	}
	stored := cloneHost(h)
	s.hosts = append(s.hosts, stored)
	return cloneHost(stored), nil
}

// UpdateHost replaces the host with h.ID; same validation as AddHost.
func (s *Store) UpdateHost(h Host) error {
	i := s.indexByID(h.ID)
	if i < 0 {
		return fmt.Errorf("store: no host with id %q", h.ID)
	}
	am, err := normalizeAuthMethod(h.AuthMethod)
	if err != nil {
		return err
	}
	h.AuthMethod = am
	if err := s.validate(h, h.ID); err != nil {
		return err
	}
	s.hosts[i] = cloneHost(h)
	return nil
}

// DeleteHost removes the host with the given ID.
func (s *Store) DeleteHost(id string) error {
	i := s.indexByID(id)
	if i < 0 {
		return fmt.Errorf("store: no host with id %q", id)
	}
	s.hosts = append(s.hosts[:i], s.hosts[i+1:]...)
	return nil
}

// UpsertImported merges ssh_config-sourced hosts: new names are added,
// existing hosts with Source "ssh_config" are updated, hosts with Source
// "manual" are skipped untouched. A matching ssh_config host that is byte-for
// -byte identical to the incoming one counts as skipped (nothing to write);
// only a real change counts as updated.
func (s *Store) UpsertImported(hs []Host) (added, updated, skipped int) {
	for _, in := range hs {
		i := s.indexByName(in.Name)
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

// Save marshals the document and writes it through the backend.
func (s *Store) Save() error {
	doc := document{Schema: schemaVersion, Hosts: s.hosts, Settings: s.settings}
	payload, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("store: marshal document: %w", err)
	}
	return s.backend.Save(payload)
}

// validate enforces the shared AddHost/UpdateHost rules. excludeID is the ID
// of the host being updated (empty for adds) so a host does not collide with
// its own name.
func (s *Store) validate(h Host, excludeID string) error {
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
	for _, other := range s.hosts {
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

// indexByID returns the slice index of the host with id, or -1.
func (s *Store) indexByID(id string) int {
	for i := range s.hosts {
		if s.hosts[i].ID == id {
			return i
		}
	}
	return -1
}

// indexByName returns the slice index of the host whose name matches name
// case-insensitively, or -1.
func (s *Store) indexByName(name string) int {
	target := strings.ToLower(strings.TrimSpace(name))
	for i := range s.hosts {
		if strings.ToLower(strings.TrimSpace(s.hosts[i].Name)) == target {
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

// newID returns 16 lowercase hex characters from crypto/rand. rand.Read never
// fails on the platforms Wharf targets, so a failure is treated as fatal.
func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("store: crypto/rand unavailable: %v", err))
	}
	return hex.EncodeToString(b[:])
}
