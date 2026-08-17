package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Janne6565/wharf-tui/internal/localcfg"
)

// The two in-session hotkeys are validated against each other in the hooks that
// write the config, not only in the UI that calls them. The UI checks against
// the binding it has in memory; this checks against the one on disk, which is
// what a second wharf — or a hand edit between the two writes — could have
// changed underneath. A config with both keys on one byte would leave the
// attach loop firing exactly one of them, silently.
func TestThePersistenceHooksRefuseAKeyTheOtherBindingAlreadyHolds(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.json")

	// ctrl+] is the remote-access default, so the detach hook must refuse it
	// even though nothing has been written yet: a default is a real binding.
	if err := applyDetachKeyFn(cfgPath)("ctrl+]"); err == nil {
		t.Fatal("the detach hook accepted the remote-access key")
	} else if !strings.Contains(err.Error(), "remote-access key") {
		t.Fatalf("the error should name the conflict, got %v", err)
	}

	// And the other way round, against the detach default.
	if err := applyRemoteKeyFn(cfgPath)(`ctrl+\`); err == nil {
		t.Fatal("the remote hook accepted the detach key")
	} else if !strings.Contains(err.Error(), "detach key") {
		t.Fatalf("the error should name the conflict, got %v", err)
	}

	// A free key lands, and then the *other* hook must refuse it, because it is
	// now the stored binding rather than a default.
	if err := applyRemoteKeyFn(cfgPath)("ctrl+o"); err != nil {
		t.Fatalf("a free key should persist: %v", err)
	}
	cfg, err := localcfg.Load(cfgPath)
	if err != nil {
		t.Fatalf("loading the config back: %v", err)
	}
	if cfg.RemoteKey != "ctrl+o" {
		t.Fatalf("remoteKey = %q, want ctrl+o", cfg.RemoteKey)
	}
	if err := applyDetachKeyFn(cfgPath)("ctrl+o"); err == nil {
		t.Fatal("the detach hook accepted the stored remote-access key")
	}

	// Rebinding the detach key to something free leaves the other alone.
	if err := applyDetachKeyFn(cfgPath)("ctrl+g"); err != nil {
		t.Fatalf("a free key should persist: %v", err)
	}
	cfg, err = localcfg.Load(cfgPath)
	if err != nil {
		t.Fatalf("loading the config back: %v", err)
	}
	if cfg.DetachKey != "ctrl+g" || cfg.RemoteKey != "ctrl+o" {
		t.Fatalf("config = %+v, want ctrl+g / ctrl+o", cfg)
	}
}
