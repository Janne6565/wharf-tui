// Package store is Wharf's typed data layer: hosts and settings serialized
// as a versioned JSON document into an opaque Backend (the encrypted vault
// in real mode, memory in demo/tests). Probe status and session liveness are
// deliberately NOT part of this schema — they are ephemeral UI state.
package store

import "time"

// Backend persists the raw payload. *vault.Vault satisfies this.
type Backend interface {
	Payload() []byte
	Save([]byte) error
}

// Host is a saved SSH destination. ID is 16 random hex chars, assigned by
// AddHost. Source distinguishes manually created hosts from ssh_config
// imports (import merges never touch "manual" hosts).
type Host struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	User     string    `json:"user"`
	Addr     string    `json:"addr"`
	Port     int       `json:"port"`
	Tags     []string  `json:"tags,omitempty"`
	KeyPath  string    `json:"keyPath,omitempty"`
	Source   string    `json:"source"` // "manual" | "ssh_config"
	LastSeen time.Time `json:"lastSeen,omitempty"`
}

// Conn renders the user@addr:port connection string shown in the UI.
func (h Host) Conn() string { panic("store: unimplemented") }

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

// Store is the in-memory working copy; every mutation is only durable after
// Save.
type Store struct {
	// implemented in WP2
}

// Open loads the document from b. An empty payload yields an empty store
// with DefaultSettings. An unknown schema version is an explicit error.
func Open(b Backend) (*Store, error) { panic("store: unimplemented") }

// NewMemory builds a store over a no-op backend, seeded for demo mode and
// tests.
func NewMemory(hosts []Host, s Settings) *Store { panic("store: unimplemented") }

// Hosts returns all hosts, stable-sorted by name.
func (s *Store) Hosts() []Host { panic("store: unimplemented") }

// HostByID looks a host up by ID.
func (s *Store) HostByID(id string) (Host, bool) { panic("store: unimplemented") }

// AddHost validates h (name+addr required, 1 <= port <= 65535, unique name),
// assigns an ID and Source "manual" if unset, and returns the stored host.
func (s *Store) AddHost(h Host) (Host, error) { panic("store: unimplemented") }

// UpdateHost replaces the host with h.ID; same validation as AddHost.
func (s *Store) UpdateHost(h Host) error { panic("store: unimplemented") }

// DeleteHost removes the host with the given ID.
func (s *Store) DeleteHost(id string) error { panic("store: unimplemented") }

// UpsertImported merges ssh_config-sourced hosts: new names are added,
// existing hosts with Source "ssh_config" are updated, hosts with Source
// "manual" are skipped untouched.
func (s *Store) UpsertImported(hs []Host) (added, updated, skipped int) {
	panic("store: unimplemented")
}

// Settings returns the current settings.
func (s *Store) Settings() Settings { panic("store: unimplemented") }

// SetSettings replaces the settings.
func (s *Store) SetSettings(v Settings) { panic("store: unimplemented") }

// Save marshals the document and writes it through the backend.
func (s *Store) Save() error { panic("store: unimplemented") }
