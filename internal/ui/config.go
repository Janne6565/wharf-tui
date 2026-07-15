package ui

import (
	"os"
	"path/filepath"

	"github.com/Janne6565/wharf-tui/internal/api"
	"github.com/Janne6565/wharf-tui/internal/data"
	"github.com/Janne6565/wharf-tui/internal/keys"
	"github.com/Janne6565/wharf-tui/internal/probe"
	"github.com/Janne6565/wharf-tui/internal/sshx"
	"github.com/Janne6565/wharf-tui/internal/store"
	syncx "github.com/Janne6565/wharf-tui/internal/sync"
	"github.com/Janne6565/wharf-tui/internal/vault"
)

// Config parameterizes the root model. Demo mode preserves the prototype
// behavior (sample data, simulated session, no disk I/O); real mode boots into
// the encrypted-vault gate and talks to a real SSH engine.
type Config struct {
	Demo      bool
	VaultPath string
	Manager   *sshx.Manager

	// Vault access hooks. Nil fields default to the real vault package; tests
	// inject fakes so unit tests avoid argon2's cost.
	VaultExists  func(string) bool
	OpenVault    func(string, []byte) (vaultHandle, error)
	CreateVault  func(string, []byte) (vaultHandle, string, error)
	OpenRecovery func(string, string) (vaultHandle, error)

	// Sync hooks (real mode). Nil fields default to the real backend client
	// (base URL from WHARF_API_BASE or the production default), the vault
	// file on disk, and vault.OpenPayload; tests inject fakes.
	SyncAPI      syncx.API
	SyncReadBlob func() ([]byte, error)
	SyncOpenBlob func(blob, password []byte) ([]byte, error)
}

// New builds the initial model. Demo mode opens on the simulated account
// screen with seeded sample data; real mode opens on the vault gate.
func New(cfg Config) Model {
	m := Model{
		themeName:    "abyss",
		vaultPath:    cfg.VaultPath,
		mgr:          cfg.Manager,
		projects:     data.Projects(),
		sessions:     map[string]*session{},
		probes:       map[string]probe.Result{},
		vaultExists:  cfg.VaultExists,
		openVault:    cfg.OpenVault,
		createVault:  cfg.CreateVault,
		openRecovery: cfg.OpenRecovery,
		syncAPI:      cfg.SyncAPI,
		syncReadBlob: cfg.SyncReadBlob,
		syncOpenBlob: cfg.SyncOpenBlob,
		deviceURL:    api.DeviceURL(api.BaseURL()),
	}
	if m.vaultExists == nil {
		m.vaultExists = vault.Exists
	}
	if m.openVault == nil {
		m.openVault = realOpen
	}
	if m.createVault == nil {
		m.createVault = realCreate
	}
	if m.openRecovery == nil {
		m.openRecovery = realOpenRecovery
	}

	if cfg.Demo {
		return newDemo(m)
	}

	m.demo = false
	m.screen = scUnlock
	if m.vaultExists(m.vaultPath) {
		m.unlockStep = ulUnlock
	} else {
		m.unlockStep = ulCreate
	}
	return m
}

// newDemo finishes a demo-mode model: sample hosts/keys in a memory store, the
// simulated account screen as the entry point.
func newDemo(m Model) Model {
	m.demo = true
	m.screen = scAuth
	m.st = store.NewMemory(demoHosts(), store.DefaultSettings())
	m.settings = m.st.Settings()
	m.themeName = m.settings.Theme
	m.keyInfos = demoKeys()
	// Seed advisory status straight from the fixtures so the demo reads alive
	// without any real probing.
	for _, h := range m.st.Hosts() {
		if st, ok := demoStatus[h.Name]; ok {
			m.probes[h.ID] = probe.Result{Status: st}
		}
	}
	return m
}

// demoStatus maps fixture host names to a seeded advisory status for demo mode.
var demoStatus = map[string]probe.Status{
	"prod-api-01":    probe.StatusOnline,
	"prod-api-02":    probe.StatusOnline,
	"db-primary":     probe.StatusOnline,
	"edge-lb-euw1":   probe.StatusOnline,
	"homelab":        probe.StatusOnline,
	"build-runner-1": probe.StatusOffline,
}

// demoHosts converts the design fixtures into store hosts for demo mode.
func demoHosts() []store.Host {
	src := data.Hosts()
	out := make([]store.Host, 0, len(src))
	for _, h := range src {
		out = append(out, store.Host{
			Name:    h.Name,
			User:    h.User,
			Addr:    h.Addr,
			Port:    h.Port,
			Tags:    h.Tags,
			KeyPath: h.Key,
			Source:  "manual",
		})
	}
	return out
}

// demoKeys converts the design key fixtures into scan-shaped identities.
func demoKeys() []keys.KeyInfo {
	src := data.Keys()
	out := make([]keys.KeyInfo, 0, len(src))
	for _, k := range src {
		out = append(out, keys.KeyInfo{
			Name:        k.Name,
			Type:        k.Type,
			Fingerprint: k.Fp,
			HasPub:      true,
		})
	}
	return out
}

// --- real vault hooks -------------------------------------------------------

func realCreate(path string, pw []byte) (vaultHandle, string, error) {
	v, code, err := vault.Create(path, pw)
	if err != nil {
		return nil, "", err
	}
	return v, code, nil
}

func realOpen(path string, pw []byte) (vaultHandle, error) {
	v, err := vault.Open(path, pw)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func realOpenRecovery(path, code string) (vaultHandle, error) {
	v, err := vault.OpenWithRecovery(path, code)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// sshDir resolves ~/.ssh for key scan/generation and config import.
func (m Model) sshDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".ssh"
	}
	return filepath.Join(home, ".ssh")
}
