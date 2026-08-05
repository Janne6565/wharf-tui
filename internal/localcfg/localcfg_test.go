package localcfg

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadMissingFileIsEmpty(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("Load of a missing file: %v", err)
	}
	if c.Proxy != "" {
		t.Fatalf("Proxy = %q, want empty", c.Proxy)
	}
}

func TestLoadMalformedFileErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load of a malformed file succeeded, want an error")
	}
}

func TestSaveRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "config.json")
	if err := Save(path, Config{Proxy: "socks5://proxy.corp:1080"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Proxy != "socks5://proxy.corp:1080" {
		t.Fatalf("Proxy = %q, want the saved value", c.Proxy)
	}
}

// The detach key shares the file with the proxy and must survive a write that
// only touches the other field — both are edited from their own settings row.
func TestSaveRoundTripsEveryField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Save(path, Config{Proxy: "off", DetachKey: "ctrl+]"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Proxy != "off" || c.DetachKey != "ctrl+]" {
		t.Fatalf("round trip gave %+v, want both fields preserved", c)
	}

	c.Proxy = ""
	if err := Save(path, c); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if c, err = Load(path); err != nil || c.DetachKey != "ctrl+]" {
		t.Fatalf("DetachKey = %q after a proxy-only edit (err %v), want it kept", c.DetachKey, err)
	}
}

func TestSaveFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file modes")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Save(path, Config{Proxy: "socks5://proxy.corp:1080"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %v, want 0600", perm)
	}
}

// The file is plaintext and permanent; a proxy password must never reach it.
func TestSaveStripsPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Save(path, Config{Proxy: "socks5://deniz:hunter2@proxy.corp:1080"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "hunter2") {
		t.Fatalf("config file contains the proxy password:\n%s", raw)
	}
	c, _ := Load(path)
	if !strings.Contains(c.Proxy, "deniz") {
		t.Fatalf("Proxy = %q, want the username kept", c.Proxy)
	}
}

func TestDefaultPathHonoursEnv(t *testing.T) {
	t.Setenv("WHARF_CONFIG", "/tmp/wharf-test.json")
	p, err := DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if p != "/tmp/wharf-test.json" {
		t.Fatalf("DefaultPath = %q, want the WHARF_CONFIG override", p)
	}

	t.Setenv("WHARF_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg")
	p, err = DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if p != filepath.Join("/tmp/xdg", "wharf", "config.json") {
		t.Fatalf("DefaultPath = %q, want it under XDG_CONFIG_HOME", p)
	}
}
