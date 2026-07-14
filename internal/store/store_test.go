package store

import (
	"testing"
	"time"
)

// fakeBackend is an in-memory Backend that records every Save payload so tests
// can assert on what was persisted and reopen from it.
type fakeBackend struct {
	payload []byte
	saves   [][]byte
}

func (f *fakeBackend) Payload() []byte { return f.payload }

func (f *fakeBackend) Save(p []byte) error {
	cp := make([]byte, len(p))
	copy(cp, p)
	f.saves = append(f.saves, cp)
	f.payload = cp // subsequent Open() sees the last write
	return nil
}

func TestOpenEmptyThenAddAndReopen(t *testing.T) {
	be := &fakeBackend{}
	s, err := Open(be)
	if err != nil {
		t.Fatalf("Open empty: %v", err)
	}
	if got := s.Hosts(); len(got) != 0 {
		t.Fatalf("empty store should have no hosts, got %d", len(got))
	}
	if s.Settings() != DefaultSettings() {
		t.Fatalf("empty store settings = %+v, want DefaultSettings %+v", s.Settings(), DefaultSettings())
	}

	added, err := s.AddHost(Host{Name: "web", Addr: "example.com"})
	if err != nil {
		t.Fatalf("AddHost: %v", err)
	}
	if added.ID == "" || len(added.ID) != 16 {
		t.Fatalf("AddHost should assign a 16-char id, got %q", added.ID)
	}
	if added.Port != 22 {
		t.Fatalf("port default = %d, want 22", added.Port)
	}
	if added.Source != "manual" {
		t.Fatalf("source = %q, want manual", added.Source)
	}
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if len(be.saves) != 1 {
		t.Fatalf("expected exactly one recorded Save, got %d", len(be.saves))
	}

	// Reopen from the recorded payload: the host must survive the roundtrip.
	s2, err := Open(be)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	hosts := s2.Hosts()
	if len(hosts) != 1 {
		t.Fatalf("reopened store has %d hosts, want 1", len(hosts))
	}
	if hosts[0].ID != added.ID || hosts[0].Name != "web" || hosts[0].Port != 22 || hosts[0].Source != "manual" {
		t.Fatalf("reopened host = %+v, want id=%s name=web port=22 source=manual", hosts[0], added.ID)
	}
}

func TestValidation(t *testing.T) {
	cases := []struct {
		name string
		host Host
	}{
		{"missing name", Host{Addr: "example.com", Port: 22}},
		{"blank name", Host{Name: "   ", Addr: "example.com", Port: 22}},
		{"missing addr", Host{Name: "web", Port: 22}},
		{"blank addr", Host{Name: "web", Addr: "  ", Port: 22}},
		{"port explicitly zero", Host{Name: "web", Addr: "example.com", Port: 0}},
		{"port too high", Host{Name: "web", Addr: "example.com", Port: 70000}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := NewMemory(nil, DefaultSettings())
			// Force a real zero so AddHost's 0->22 default does not mask the
			// "port explicitly zero" case: use a sentinel negative for that one.
			h := c.host
			if c.name == "port explicitly zero" {
				h.Port = -1 // AddHost only defaults exactly 0; -1 must fail validation
			}
			if _, err := s.AddHost(h); err == nil {
				t.Fatalf("AddHost(%+v) expected error, got nil", h)
			}
		})
	}

	// Duplicate name, case-insensitive.
	s := NewMemory(nil, DefaultSettings())
	if _, err := s.AddHost(Host{Name: "Web", Addr: "a.com"}); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if _, err := s.AddHost(Host{Name: "web", Addr: "b.com"}); err == nil {
		t.Fatalf("duplicate name (case-insensitive) should error")
	}

	// UpdateHost with unknown ID.
	if err := s.UpdateHost(Host{ID: "deadbeefdeadbeef", Name: "x", Addr: "c.com", Port: 22}); err == nil {
		t.Fatalf("UpdateHost with unknown id should error")
	}
}

func TestHostsSortedAndMutationSafe(t *testing.T) {
	s := NewMemory([]Host{
		{Name: "charlie", Addr: "c", Port: 22, Tags: []string{"x"}},
		{Name: "Alpha", Addr: "a", Port: 22},
		{Name: "bravo", Addr: "b", Port: 22},
	}, DefaultSettings())

	hosts := s.Hosts()
	wantOrder := []string{"Alpha", "bravo", "charlie"} // case-insensitive sort
	for i, w := range wantOrder {
		if hosts[i].Name != w {
			t.Fatalf("Hosts()[%d].Name = %q, want %q", i, hosts[i].Name, w)
		}
	}

	// Mutating the returned slice and a Tags slice must not affect the store.
	hosts[0].Name = "ZZZ"
	hosts[2].Tags[0] = "mutated"
	again := s.Hosts()
	if again[0].Name != "Alpha" {
		t.Fatalf("mutating returned host leaked into store: %q", again[0].Name)
	}
	if again[2].Tags[0] != "x" {
		t.Fatalf("mutating returned Tags leaked into store: %q", again[2].Tags[0])
	}
}

func TestUpsertImported(t *testing.T) {
	seen := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	s := NewMemory([]Host{
		{ID: "1111111111111111", Name: "keep-manual", Addr: "m.com", Port: 22, Source: "manual"},
		{ID: "2222222222222222", Name: "from-config", Addr: "old.com", Port: 22, Source: "ssh_config", LastSeen: seen},
		{ID: "3333333333333333", Name: "identical", Addr: "id.com", Port: 22, Source: "ssh_config", LastSeen: seen},
	}, DefaultSettings())

	added, updated, skipped := s.UpsertImported([]Host{
		{Name: "brand-new", Addr: "new.com", Port: 22, Source: "ssh_config"},         // add
		{Name: "from-config", Addr: "changed.com", Port: 2222, Source: "ssh_config"}, // update-changed
		{Name: "identical", Addr: "id.com", Port: 22, Source: "ssh_config"},          // skip-identical
		{Name: "keep-manual", Addr: "hijack.com", Port: 22, Source: "ssh_config"},    // skip-manual
	})

	if added != 1 || updated != 1 || skipped != 2 {
		t.Fatalf("counters = added %d, updated %d, skipped %d; want 1,1,2", added, updated, skipped)
	}

	// Updated ssh_config host keeps its ID and LastSeen but takes new fields.
	upd, ok := s.HostByID("2222222222222222")
	if !ok {
		t.Fatalf("updated host vanished")
	}
	if upd.Addr != "changed.com" || upd.Port != 2222 {
		t.Fatalf("updated host not merged: %+v", upd)
	}
	if !upd.LastSeen.Equal(seen) {
		t.Fatalf("updated host LastSeen changed: %v", upd.LastSeen)
	}

	// Manual host untouched.
	man, _ := s.HostByID("1111111111111111")
	if man.Addr != "m.com" {
		t.Fatalf("manual host was clobbered: %+v", man)
	}
}

func TestAuthMethodValidation(t *testing.T) {
	// "auto" normalizes to the empty (auto) setting on add.
	s := NewMemory(nil, DefaultSettings())
	added, err := s.AddHost(Host{Name: "auto-host", Addr: "a.com", AuthMethod: "auto"})
	if err != nil {
		t.Fatalf("AddHost auto: %v", err)
	}
	if added.AuthMethod != "" {
		t.Fatalf("AuthMethod %q, want normalized to \"\"", added.AuthMethod)
	}

	// The explicit modes are accepted verbatim.
	for _, am := range []string{"", "key", "password"} {
		s := NewMemory(nil, DefaultSettings())
		if _, err := s.AddHost(Host{Name: "h", Addr: "a.com", AuthMethod: am}); err != nil {
			t.Fatalf("AddHost AuthMethod %q: %v", am, err)
		}
	}

	// Garbage is rejected on both add and update.
	s2 := NewMemory(nil, DefaultSettings())
	if _, err := s2.AddHost(Host{Name: "bad", Addr: "a.com", AuthMethod: "totp"}); err == nil {
		t.Fatalf("AddHost with garbage AuthMethod should error")
	}
	h, err := s2.AddHost(Host{Name: "ok", Addr: "a.com", AuthMethod: "password"})
	if err != nil {
		t.Fatalf("AddHost: %v", err)
	}
	h.AuthMethod = "nonsense"
	if err := s2.UpdateHost(h); err == nil {
		t.Fatalf("UpdateHost with garbage AuthMethod should error")
	}
	// "auto" also normalizes on update.
	h.AuthMethod = "auto"
	if err := s2.UpdateHost(h); err != nil {
		t.Fatalf("UpdateHost auto: %v", err)
	}
	if got, _ := s2.HostByID(h.ID); got.AuthMethod != "" {
		t.Fatalf("UpdateHost AuthMethod %q, want normalized to \"\"", got.AuthMethod)
	}
}

func TestPasswordRoundtrip(t *testing.T) {
	be := &fakeBackend{}
	s, err := Open(be)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := s.AddHost(Host{Name: "pw", Addr: "a.com", AuthMethod: "password", Password: "s3cr3t"}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := s.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	s2, err := Open(be)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	hosts := s2.Hosts()
	if len(hosts) != 1 {
		t.Fatalf("reopened %d hosts, want 1", len(hosts))
	}
	if hosts[0].AuthMethod != "password" || hosts[0].Password != "s3cr3t" {
		t.Fatalf("password roundtrip = %+v, want authMethod=password password=s3cr3t", hosts[0])
	}
}

func TestUpsertImportedPreservesAuth(t *testing.T) {
	seen := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	s := NewMemory([]Host{
		// An ssh_config host the user later annotated with password auth.
		{ID: "4444444444444444", Name: "annotated", Addr: "keep.com", Port: 22,
			Source: "ssh_config", LastSeen: seen, AuthMethod: "password", Password: "kept"},
	}, DefaultSettings())

	// A re-import carries no auth fields and changes nothing else.
	added, updated, skipped := s.UpsertImported([]Host{
		{Name: "annotated", Addr: "keep.com", Port: 22, Source: "ssh_config"},
	})
	if added != 0 || updated != 0 || skipped != 1 {
		t.Fatalf("counters = added %d, updated %d, skipped %d; want 0,0,1", added, updated, skipped)
	}
	got, _ := s.HostByID("4444444444444444")
	if got.AuthMethod != "password" || got.Password != "kept" {
		t.Fatalf("re-import wiped auth: %+v", got)
	}

	// A real change (new addr) updates the host but still preserves the auth.
	_, updated, _ = s.UpsertImported([]Host{
		{Name: "annotated", Addr: "moved.com", Port: 22, Source: "ssh_config"},
	})
	if updated != 1 {
		t.Fatalf("changed re-import updated %d, want 1", updated)
	}
	got, _ = s.HostByID("4444444444444444")
	if got.Addr != "moved.com" || got.AuthMethod != "password" || got.Password != "kept" {
		t.Fatalf("changed re-import lost auth or addr: %+v", got)
	}
}

func TestDeleteHost(t *testing.T) {
	s := NewMemory(nil, DefaultSettings())
	h, err := s.AddHost(Host{Name: "gone", Addr: "g.com"})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := s.DeleteHost(h.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := s.HostByID(h.ID); ok {
		t.Fatalf("host still present after delete")
	}
	if err := s.DeleteHost("nope"); err == nil {
		t.Fatalf("deleting unknown id should error")
	}
}

func TestSchemaGuard(t *testing.T) {
	if _, err := Open(&fakeBackend{payload: []byte(`{"schema":2,"hosts":[],"settings":{}}`)}); err == nil {
		t.Fatalf("schema 2 should error")
	}
	if _, err := Open(&fakeBackend{payload: []byte(`{not valid json`)}); err == nil {
		t.Fatalf("garbage JSON should error")
	}
}

func TestSettingsRoundtrip(t *testing.T) {
	be := &fakeBackend{}
	s, err := Open(be)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	want := Settings{Theme: "solaris", Agent: false, Keepalive: true, Telemetry: true}
	s.SetSettings(want)
	if err := s.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	s2, err := Open(be)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if s2.Settings() != want {
		t.Fatalf("settings roundtrip = %+v, want %+v", s2.Settings(), want)
	}
}
