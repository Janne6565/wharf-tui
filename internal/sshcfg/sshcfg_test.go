package sshcfg

import (
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/Janne6565/wharf-tui/internal/store"
)

func TestImport(t *testing.T) {
	home := t.TempDir()
	// Point tilde-expansion (and the library's own include resolution) at a
	// temp home so the test is hermetic.
	t.Setenv("HOME", home)
	old := userHome
	userHome = func() (string, error) { return home, nil }
	defer func() { userHome = old }()

	hosts, skipped, err := Import(filepath.Join("testdata", "config"))
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	want := map[string]store.Host{
		"web": {
			Name: "web", Addr: "web.example.com", User: "deploy", Port: 2222,
			KeyPath: filepath.Join(home, ".ssh", "id_web"), Source: "ssh_config",
		},
		"db1": {
			Name: "db1", Addr: "db.example.com", User: "admin", Port: 22, Source: "ssh_config",
		},
		"db2": {
			Name: "db2", Addr: "db.example.com", User: "admin", Port: 22, Source: "ssh_config",
		},
		"localonly": {
			Name: "localonly", Addr: "localonly", Port: 22, Source: "ssh_config",
		},
		"backup": {
			Name: "backup", Addr: "backup.example.com", User: "root", Port: 22, Source: "ssh_config",
		},
	}

	if len(hosts) != len(want) {
		t.Fatalf("got %d hosts, want %d: %+v", len(hosts), len(want), hosts)
	}
	for _, h := range hosts {
		exp, ok := want[h.Name]
		if !ok {
			t.Errorf("unexpected host %q", h.Name)
			continue
		}
		if !reflect.DeepEqual(h, exp) {
			t.Errorf("host %q =\n  %+v\nwant\n  %+v", h.Name, h, exp)
		}
	}

	wantSkipped := []string{"*", "*.internal"}
	sort.Strings(skipped)
	if !reflect.DeepEqual(skipped, wantSkipped) {
		t.Errorf("skipped = %v, want %v", skipped, wantSkipped)
	}
}

func TestImportMissingFile(t *testing.T) {
	if _, _, err := Import(filepath.Join("testdata", "does-not-exist")); err == nil {
		t.Fatal("expected error for missing file")
	}
}
