package store

import (
	"encoding/json"
	"fmt"
)

// projectSchemaVersion is the document version this build writes for a
// project's decrypted payload. Unlike the personal store there is no legacy
// version to accept yet, so any other value is a hard error.
const projectSchemaVersion = 1

// ProjectDoc is a project's decrypted payload: a versioned envelope carrying
// only the shared hosts. Settings are intentionally personal-store-only and
// never live in a project doc.
type ProjectDoc struct {
	Schema int    `json:"schema"`
	Hosts  []Host `json:"hosts"`
}

// OpenProjectDoc parses a project payload. An empty payload yields a fresh,
// host-less document at the current schema. Any schema other than
// projectSchemaVersion is an explicit error.
func OpenProjectDoc(payload []byte) (*ProjectDoc, error) {
	if len(payload) == 0 {
		return &ProjectDoc{Schema: projectSchemaVersion}, nil
	}

	var doc ProjectDoc
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("store: invalid project payload: %w", err)
	}
	if doc.Schema != projectSchemaVersion {
		return nil, fmt.Errorf("store: unsupported project schema version %d (this build understands %d)", doc.Schema, projectSchemaVersion)
	}
	return &doc, nil
}

// Marshal serializes the document, always stamping the current schema version
// regardless of the in-memory value.
func (d *ProjectDoc) Marshal() ([]byte, error) {
	out := ProjectDoc{Schema: projectSchemaVersion, Hosts: d.Hosts}
	payload, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("store: marshal project document: %w", err)
	}
	return payload, nil
}

// HostList returns all hosts, stable-sorted by name, as a deep copy.
func (d *ProjectDoc) HostList() []Host { return sortedHostCopy(d.Hosts) }

// HostByID looks a host up by ID.
func (d *ProjectDoc) HostByID(id string) (Host, bool) {
	if i := indexByIDIn(d.Hosts, id); i >= 0 {
		return cloneHost(d.Hosts[i]), true
	}
	return Host{}, false
}

// AddHost validates h with the same rules as the personal store, assigns an ID
// and Source "manual" if unset, and returns the stored host.
func (d *ProjectDoc) AddHost(h Host) (Host, error) {
	hosts, stored, err := addHostTo(d.Hosts, h)
	if err != nil {
		return Host{}, err
	}
	d.Hosts = hosts
	return cloneHost(stored), nil
}

// UpdateHost replaces the host with h.ID; same validation as AddHost.
func (d *ProjectDoc) UpdateHost(h Host) error {
	return updateHostIn(d.Hosts, h)
}

// DeleteHost removes the host with the given ID.
func (d *ProjectDoc) DeleteHost(id string) error {
	hosts, err := deleteHostIn(d.Hosts, id)
	if err != nil {
		return err
	}
	d.Hosts = hosts
	return nil
}
