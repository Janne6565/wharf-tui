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

// The hotkeys share the file with the proxy and must survive a write that only
// touches another field — each is edited from its own settings row.
func TestSaveRoundTripsEveryField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Save(path, Config{Proxy: "off", DetachKey: `ctrl+\`, RemoteKey: "ctrl+]"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Proxy != "off" || c.DetachKey != `ctrl+\` || c.RemoteKey != "ctrl+]" {
		t.Fatalf("round trip gave %+v, want every field preserved", c)
	}

	c.Proxy = ""
	if err := Save(path, c); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if c, err = Load(path); err != nil || c.DetachKey != `ctrl+\` || c.RemoteKey != "ctrl+]" {
		t.Fatalf("hotkeys = %q/%q after a proxy-only edit (err %v), want them kept", c.DetachKey, c.RemoteKey, err)
	}
}

// A config written before the remote-access key existed — or by anyone who
// never touched the setting — must load as "unset" rather than as an error, so
// the binding falls back to its default the way the detach key does.
func TestLoadTolerationOfAnAbsentRemoteKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"proxy":"off","detachKey":"ctrl+u"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load of a config without remoteKey: %v", err)
	}
	if c.RemoteKey != "" {
		t.Fatalf("RemoteKey = %q, want empty — empty is what the callers read as the default", c.RemoteKey)
	}
	if c.DetachKey != "ctrl+u" {
		t.Fatalf("DetachKey = %q, want the stored value", c.DetachKey)
	}

	// And an unset key is omitted rather than written as "", so the file stays
	// the short hand-editable thing it is meant to be.
	if err := Save(path, Config{DetachKey: "ctrl+u"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "remoteKey") {
		t.Fatalf("an unset remote key was written out:\n%s", raw)
	}
}

func TestSaveFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file modes")
	}
	dir := filepath.Join(t.TempDir(), "wharf")
	path := filepath.Join(dir, "config.json")
	if err := Save(path, Config{Proxy: "socks5://proxy.corp:1080", RemoteKey: "ctrl+]"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %v, want 0600", perm)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Fatalf("directory mode = %v, want 0700", perm)
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
