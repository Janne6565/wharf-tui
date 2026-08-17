package termius

import (
	"encoding/base64"
	"os"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestLiveImport runs against a real Termius profile and is skipped unless
// WHARF_TERMIUS_LIVE is set — it needs the machine's credential store, which on
// macOS means an authorization prompt. Values are masked: this prints enough to
// confirm the mapping is right without putting anyone's hosts in a test log.
func TestLiveImport(t *testing.T) {
	if os.Getenv("WHARF_TERMIUS_LIVE") == "" {
		t.Skip("set WHARF_TERMIUS_LIVE=1 to run against the local Termius profile")
	}

	res, err := Import(Options{
		DataDir: os.Getenv("WHARF_TERMIUS_DIR"),
		// Lets a run skip the credential store, whose macOS dialog cannot be
		// answered from a non-interactive test.
		LocalKeyFile: os.Getenv("WHARF_TERMIUS_KEYFILE"),
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	t.Logf("key source: %s", res.KeySource)
	t.Logf("hosts=%d keys=%d groups=%d withPassword=%d skipped=%d",
		len(res.Hosts), len(res.Keys), res.Groups, res.WithPassword, len(res.Skipped))
	for _, s := range res.Skipped {
		t.Logf("  skipped: %s", s)
	}

	for i, h := range res.Hosts {
		if i >= 10 {
			t.Logf("  ... and %d more", len(res.Hosts)-10)
			break
		}
		t.Logf("  name=%-14s user=%-8s addr=%-16s port=%-5d auth=%-8s pw=%v tags=%v",
			maskValue(h.Name), maskValue(h.User), maskValue(h.Addr), h.Port,
			h.AuthMethod, h.Password != "", maskAll(h.Tags))
	}

	checkKeysUsable(t, res)

	for _, h := range res.Hosts {
		if h.Addr == "" || h.User == "" || h.Port == 0 {
			t.Errorf("host %q incomplete: user=%q addr=%q port=%d",
				maskValue(h.Name), maskValue(h.User), maskValue(h.Addr), h.Port)
		}
		if h.Source != Source {
			t.Errorf("host %q has source %q, want %q", maskValue(h.Name), h.Source, Source)
		}
		if h.AuthMethod != "key" && h.AuthMethod != "password" {
			t.Errorf("host %q has auth method %q", maskValue(h.Name), h.AuthMethod)
		}
	}
}

// Every imported key must be loadable by the engine: a .ppk that was converted
// wrongly would otherwise sit in the list and fail at connect time.
func checkKeysUsable(t *testing.T, res Result) {
	t.Helper()
	for _, k := range res.Keys {
		material, err := base64.StdEncoding.DecodeString(k.Material)
		if err != nil {
			t.Errorf("key %q: material is not base64", maskValue(k.Name))
			continue
		}
		if _, err := ssh.ParsePrivateKey(material); err != nil {
			t.Errorf("key %q (%s) is not loadable: %v", maskValue(k.Name), k.Type, err)
		}
	}
}

func maskValue(s string) string {
	r := []rune(s)
	switch {
	case len(r) == 0:
		return "(empty)"
	case len(r) <= 4:
		return string(r[0]) + "***"
	default:
		return string(r[:2]) + "***" + string(r[len(r)-1:])
	}
}

func maskAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = maskValue(s)
	}
	return out
}
