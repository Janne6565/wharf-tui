// Package localcfg stores the handful of preferences that belong to this
// machine rather than to the account.
//
// Everything the user configures normally lives in the synced vault. The proxy
// does not: it describes the network the machine is plugged into, so syncing it
// would push an office egress proxy onto a laptop at home and break every dial
// there. This file is the exception, and deliberately a small one — it is
// plaintext, so nothing secret may be added to it.
package localcfg

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Config is the machine-local preference set.
type Config struct {
	// Proxy is the egress proxy for outbound SSH: a URL, the literal "off" to
	// force direct connections even when the environment offers a proxy, or
	// empty to defer to the environment. Any password in the URL is stripped
	// before writing — see Save.
	Proxy string `json:"proxy,omitempty"`
}

// DefaultPath resolves the config file, honouring $WHARF_CONFIG. It sits beside
// the vault's directory convention but under the config root rather than the
// data root: this is preference, not state.
func DefaultPath() (string, error) {
	if p := strings.TrimSpace(os.Getenv("WHARF_CONFIG")); p != "" {
		return p, nil
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "wharf", "config.json"), nil
}

// Load reads the config at path. A missing file is the zero Config and no
// error — running without one is the normal case. A malformed file *is* an
// error: silently ignoring it would leave someone staring at a setting they
// edited that never took effect.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Config{}, nil
		}
		return Config{}, fmt.Errorf("reading %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	return c, nil
}

// Save writes c to path, creating the directory if needed.
//
// Any password in the proxy URL is dropped first: this file is plaintext, and a
// credential written here would sit on disk in the clear for the life of the
// machine. Proxy credentials belong in $WHARF_PROXY, which lives only as long
// as the process that sets it.
func Save(path string, c Config) error {
	c.Proxy = StripPassword(c.Proxy)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	// 0600 for consistency with the rest of wharf's on-disk state, even though
	// nothing secret is allowed in here.
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// StripPassword removes the password from a proxy URL, keeping the username so
// the value still says which account it authenticates as. A value that is not a
// URL is returned unchanged — validation is proxydial's job, not this one's.
func StripPassword(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.Contains(raw, "://") {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	if _, hasPass := u.User.Password(); !hasPass {
		return raw
	}
	u.User = url.User(u.User.Username())
	return u.String()
}
