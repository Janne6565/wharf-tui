package ui

import (
	"crypto/rand"
	"os"
	"path/filepath"

	"github.com/Janne6565/wharf-tui/internal/api"
	"github.com/Janne6565/wharf-tui/internal/browser"
	"github.com/Janne6565/wharf-tui/internal/data"
	"github.com/Janne6565/wharf-tui/internal/detachkey"
	"github.com/Janne6565/wharf-tui/internal/keys"
	"github.com/Janne6565/wharf-tui/internal/probe"
	"github.com/Janne6565/wharf-tui/internal/proxydial"
	"github.com/Janne6565/wharf-tui/internal/sessd"
	"github.com/Janne6565/wharf-tui/internal/sshx"
	"github.com/Janne6565/wharf-tui/internal/store"
	syncx "github.com/Janne6565/wharf-tui/internal/sync"
	"github.com/Janne6565/wharf-tui/internal/vault"
)

// dekBytes is the length of a project DEK.
const dekBytes = 32

// vaultProjectCrypto is the production syncx.ProjectCrypto, backed by the vault
// package's WHARFP / sealed-box primitives. Tests inject a fake instead.
type vaultProjectCrypto struct{}

func (vaultProjectCrypto) NewDEK() ([]byte, error) {
	dek := make([]byte, dekBytes)
	_, err := rand.Read(dek)
	return dek, err
}
func (vaultProjectCrypto) Seal(dek, payload []byte) ([]byte, error) {
	return vault.SealProject(dek, payload)
}
func (vaultProjectCrypto) Open(dek, blob []byte) ([]byte, error) {
	return vault.OpenProject(dek, blob)
}
func (vaultProjectCrypto) Wrap(dek, pub []byte) ([]byte, error) {
	return vault.WrapProjectDEK(dek, pub)
}
func (vaultProjectCrypto) Unwrap(wrapped, pub, priv []byte) ([]byte, error) {
	return vault.UnwrapProjectDEK(wrapped, pub, priv)
}

// Config parameterizes the root model. Demo mode preserves the prototype
// behavior (sample data, simulated session, no disk I/O); real mode boots into
// the encrypted-vault gate and talks to a real SSH engine.
type Config struct {
	Demo      bool
	VaultPath string
	// Manager runs port forwards, which stay in-process by design.
	Manager *sshx.Manager
	// Sessions spawns and adopts the session-host children that keep
	// interactive shells alive across a quit. Nil disables connecting.
	Sessions *sessd.Pool

	// ConnectHost is a saved host's name given on the command line
	// (`wharf prod-api-01`). Real mode only: once the vault unlocks, the model
	// resolves it and dials straight through, reporting a toast on the hosts
	// list if it matches no host or more than one.
	ConnectHost string

	// Vault access hooks. Nil fields default to the real vault package; tests
	// inject fakes so unit tests avoid argon2's cost.
	VaultExists  func(string) bool
	OpenVault    func(string, []byte) (vaultHandle, error)
	CreateVault  func(string, []byte) (vaultHandle, string, error)
	OpenRecovery func(string, string) (vaultHandle, error)
	// InstallVault writes an account's vault blob to path verbatim and opens
	// it, replacing any local vault (vault.InstallBlob).
	InstallVault func(path string, blob, password []byte) (vaultHandle, error)

	// Sync hooks (real mode). Nil fields default to the real backend client
	// (base URL from WHARF_API_BASE or the production default), the vault
	// file on disk, and vault.OpenPayload; tests inject fakes.
	SyncAPI      syncx.API
	SyncReadBlob func() ([]byte, error)
	SyncOpenBlob func(blob, password []byte) ([]byte, error)
	// SyncProjectCrypto seals/opens project blobs and wraps/unwraps project
	// DEKs (M3). Nil defaults to the vault-backed implementation; tests inject a
	// fake so the projects flows avoid real crypto.
	SyncProjectCrypto syncx.ProjectCrypto
	// GenIdentity generates a fresh X25519 identity keypair (base64 pub, priv).
	// Nil defaults to vault.GenerateIdentity; tests inject a deterministic fake.
	GenIdentity func() (pub, priv []byte, err error)

	// OpenBrowser opens the device-pairing page when the user reaches the
	// code-entry screen. Nil defaults to browser.Open, except in demo mode or
	// where there is no display to open into (browser.Available), which leaves
	// it disabled. Tests inject a recorder so no real browser is launched.
	OpenBrowser func(string) error

	// Proxy is the machine-local egress proxy setting as stored on disk — what
	// the settings screen edits. It is not necessarily what is in effect:
	// --proxy and $WHARF_PROXY outrank it.
	Proxy string
	// ProxySetting is the shared holder of the proxy in effect — the same one
	// the engine and the session pool dial through. The UI reads it for display
	// and for probes; nil is direct.
	ProxySetting *proxydial.Setting
	// ApplyProxy validates and persists an edited setting, then updates
	// ProxySetting. The UI deliberately does not resolve precedence or write the
	// file itself; nil disables editing (demo mode, tests).
	ApplyProxy func(setting string) error

	// DetachKey is the machine-local detach hotkey as stored on disk, by the
	// name bubbletea reports for it. Empty means the default (ctrl+\).
	DetachKey string
	// ApplyDetachKey validates and persists an edited detach key. Nil disables
	// editing (demo mode, tests) but not the key itself.
	ApplyDetachKey func(name string) error
}

// New builds the initial model. Demo mode opens on the simulated account
// screen with seeded sample data; real mode opens on the vault gate.
func New(cfg Config) Model {
	m := Model{
		themeName:         "abyss",
		vaultPath:         cfg.VaultPath,
		connectTo:         cfg.ConnectHost,
		pool:              cfg.Sessions,
		mgr:               cfg.Manager,
		projects:          data.Projects(),
		sessions:          map[string]*session{},
		probes:            map[string]probe.Result{},
		vaultExists:       cfg.VaultExists,
		openVault:         cfg.OpenVault,
		createVault:       cfg.CreateVault,
		openRecovery:      cfg.OpenRecovery,
		installVault:      cfg.InstallVault,
		syncAPI:           cfg.SyncAPI,
		syncReadBlob:      cfg.SyncReadBlob,
		syncOpenBlob:      cfg.SyncOpenBlob,
		syncProjectCrypto: cfg.SyncProjectCrypto,
		genIdentity:       cfg.GenIdentity,
		projectDocs:       map[string]*store.ProjectDoc{},
		deviceURL:         api.DeviceURL(api.BaseURL()),
		openBrowser:       cfg.OpenBrowser,
		proxyStored:       cfg.Proxy,
		proxy:             cfg.ProxySetting,
		applyProxy:        cfg.ApplyProxy,
		detachName:        detachkey.Name(detachkey.Byte(cfg.DetachKey)),
		applyDetachKey:    cfg.ApplyDetachKey,
	}
	// cfg.Demo, not m.demo: the demo/real branches below are what set m.demo,
	// so reading it here would always see false and hand a demo run a real
	// browser.
	if m.openBrowser == nil && !cfg.Demo && browser.Available() {
		m.openBrowser = browser.Open
	}
	if m.syncProjectCrypto == nil {
		m.syncProjectCrypto = vaultProjectCrypto{}
	}
	if m.genIdentity == nil {
		m.genIdentity = vault.GenerateIdentity
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
	if m.installVault == nil {
		m.installVault = realInstall
	}

	if cfg.Demo {
		return newDemo(m)
	}

	m.demo = false
	m.screen = scUnlock
	if m.vaultExists(m.vaultPath) {
		m.unlockStep = ulUnlock
	} else {
		// First run: local-only or account. The choice is offered exactly once,
		// here, because it decides which vault this machine ends up with —
		// signing in installs the account's vault rather than creating a
		// second one (see update_signin.go).
		m.unlockStep = ulChoose
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

func realInstall(path string, blob, pw []byte) (vaultHandle, error) {
	v, err := vault.InstallBlob(path, blob, pw)
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
