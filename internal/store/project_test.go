package store

import "testing"

func TestOpenProjectDocEmpty(t *testing.T) {
	d, err := OpenProjectDoc(nil)
	if err != nil {
		t.Fatalf("OpenProjectDoc(nil): %v", err)
	}
	if d.Schema != projectSchemaVersion {
		t.Fatalf("empty doc schema = %d, want %d", d.Schema, projectSchemaVersion)
	}
	if len(d.HostList()) != 0 {
		t.Fatalf("empty doc should have no hosts, got %d", len(d.HostList()))
	}
}

func TestProjectDocAddHostValidation(t *testing.T) {
	d, err := OpenProjectDoc(nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	// Missing name is rejected with the shared validation rules.
	if _, err := d.AddHost(Host{Addr: "example.com"}); err == nil {
		t.Fatalf("AddHost missing name should error")
	}

	added, err := d.AddHost(Host{Name: "web", Addr: "example.com"})
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

	// Duplicate name, case-insensitive, is rejected.
	if _, err := d.AddHost(Host{Name: "WEB", Addr: "b.com"}); err == nil {
		t.Fatalf("duplicate name (case-insensitive) should error")
	}
}

func TestProjectDocMarshalRoundtrip(t *testing.T) {
	d, err := OpenProjectDoc(nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	a, err := d.AddHost(Host{Name: "alpha", Addr: "a.com"})
	if err != nil {
		t.Fatalf("add alpha: %v", err)
	}
	if _, err := d.AddHost(Host{Name: "bravo", Addr: "b.com", Port: 2222}); err != nil {
		t.Fatalf("add bravo: %v", err)
	}

	payload, err := d.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	d2, err := OpenProjectDoc(payload)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	hosts := d2.HostList()
	if len(hosts) != 2 {
		t.Fatalf("roundtrip hosts = %d, want 2", len(hosts))
	}
	if hosts[0].Name != "alpha" || hosts[1].Name != "bravo" {
		t.Fatalf("roundtrip order = %q,%q, want alpha,bravo", hosts[0].Name, hosts[1].Name)
	}

	// UpdateHost and DeleteHost operate on the reopened doc.
	a2, ok := d2.HostByID(a.ID)
	if !ok {
		t.Fatalf("alpha vanished after roundtrip")
	}
	a2.Addr = "moved.com"
	if err := d2.UpdateHost(a2); err != nil {
		t.Fatalf("UpdateHost: %v", err)
	}
	if got, _ := d2.HostByID(a.ID); got.Addr != "moved.com" {
		t.Fatalf("UpdateHost did not persist: %+v", got)
	}
	if err := d2.DeleteHost(a.ID); err != nil {
		t.Fatalf("DeleteHost: %v", err)
	}
	if _, ok := d2.HostByID(a.ID); ok {
		t.Fatalf("alpha still present after delete")
	}
	if err := d2.DeleteHost("nope"); err == nil {
		t.Fatalf("deleting unknown id should error")
	}
}

func TestProjectDocMarshalForcesSchema(t *testing.T) {
	d := &ProjectDoc{Schema: 99}
	payload, err := d.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	d2, err := OpenProjectDoc(payload)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if d2.Schema != projectSchemaVersion {
		t.Fatalf("Marshal should force schema %d, got %d", projectSchemaVersion, d2.Schema)
	}
}

func TestProjectDocSchemaGuard(t *testing.T) {
	if _, err := OpenProjectDoc([]byte(`{"schema":2,"hosts":[]}`)); err == nil {
		t.Fatalf("schema 2 project payload should error")
	}
	if _, err := OpenProjectDoc([]byte(`{not valid json`)); err == nil {
		t.Fatalf("garbage JSON should error")
	}
}
