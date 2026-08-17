package termius

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// keyringServices are tried in order. Termius uses its executable name as the
// credential-store service, so a snap install stores the key under
// "termius-app" while the macOS builds use "Termius" — looking up only
// "Termius" on a snap install finds nothing.
var keyringServices = []string{
	"termius-app",
	"Termius",
	"Termius (MAS)",
	"termius",
	"com.termius-dmg.mac",
}

// keyringAccount is the account name under every service.
const keyringAccount = "localKey"

// keyringTimeout bounds each credential-store call. On macOS the lookup blocks
// on a GUI authorization dialog; without a bound, an unattended import would
// hang forever instead of reporting that it needs approval. The bound is
// generous because the person answering that dialog has to find it first.
const keyringTimeout = 90 * time.Second

// ErrNoLocalKey means no usable key was found in the OS credential store.
type ErrNoLocalKey struct{ Detail string }

func (e ErrNoLocalKey) Error() string { return e.Detail }

// LocalKey is a key found in the credential store, with where it came from.
type LocalKey struct {
	Key    []byte
	Source string
}

// lookupKeyring reads one service/account pair from the platform credential
// store, returning "" when the entry does not exist.
func lookupKeyring(service string) string {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("security", "find-generic-password", "-s", service, "-a", keyringAccount, "-w")
	case "linux":
		if _, err := exec.LookPath("secret-tool"); err != nil {
			return ""
		}
		cmd = exec.Command("secret-tool", "lookup", "service", service, "account", keyringAccount)
	case "windows":
		// cmdkey cannot print a credential blob, so PowerShell reads it through
		// CredRead and emits the bytes as base64.
		script := fmt.Sprintf(`$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Runtime.InteropServices
$sig = @"
[DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
public static extern bool CredReadW(string target, uint type, uint flags, out IntPtr credential);
"@
$adv = Add-Type -MemberDefinition $sig -Name CredMan -Namespace Win32 -PassThru
$ptr = [IntPtr]::Zero
if ($adv::CredReadW("%s/%s", 1, 0, [ref]$ptr)) {
  $cred = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [Type]"Win32.CredMan+CREDENTIAL")
  Write-Output $cred
}`, service, keyringAccount)
		cmd = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	default:
		return ""
	}

	done := make(chan struct{})
	var out []byte
	go func() {
		out, _ = cmd.Output()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(keyringTimeout):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return ""
	}
	return strings.TrimSpace(string(out))
}

// findLocalKey returns the first credential-store entry that decrypts sample.
//
// validate decides which candidate wins rather than a fixed service order:
// switching between the macOS DMG and App Store builds leaves both entries
// behind holding different keys, and neither order is right for both profiles.
// When sample is empty (no encrypted field to test against) the first entry
// that parses as a 32-byte key is taken.
func findLocalKey(sample string) (LocalKey, error) {
	var rejected []string
	for _, service := range keyringServices {
		value := lookupKeyring(service)
		if value == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(raw) != keySize {
			continue
		}
		source := fmt.Sprintf("%s keyring (service=%s, account=%s)", runtime.GOOS, service, keyringAccount)
		if sample != "" && !validates(raw, sample) {
			// A real key, just not this profile's. Each further macOS candidate
			// costs another authorization prompt, so the loop stops at the
			// first that works rather than collecting them all.
			rejected = append(rejected, source)
			continue
		}
		return LocalKey{Key: raw, Source: source}, nil
	}

	if len(rejected) > 0 {
		return LocalKey{}, ErrNoLocalKey{Detail: fmt.Sprintf(
			"found a Termius localKey but none of them decrypt this profile (tried: %s). "+
				"Each was rejected by Poly1305, so they are real keys for another profile "+
				"rather than corrupt entries — usually a data directory belonging to an "+
				"install whose key is not in this keyring",
			strings.Join(rejected, ", "))}
	}
	return LocalKey{}, ErrNoLocalKey{Detail: fmt.Sprintf(
		"no Termius localKey in the %s credential store (tried services: %s with account=%s). "+
			"Most likely Termius has never run on this machine, the keyring is locked, or the "+
			"authorization prompt was dismissed",
		runtime.GOOS, strings.Join(keyringServices, ", "), keyringAccount)}
}

// loadLocalKey prefers an explicit key file over the credential store.
//
// An explicit file is deliberately not validated against the profile: the user
// named it, so silently falling back to a keyring entry would be the wrong kind
// of helpful. A mismatch surfaces later as ErrWrongKey, which says so plainly.
func loadLocalKey(path, sample string) (LocalKey, error) {
	if path == "" {
		return findLocalKey(sample)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return LocalKey{}, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return LocalKey{}, fmt.Errorf("key file %s is not base64: %w", path, err)
	}
	if len(raw) != keySize {
		return LocalKey{}, fmt.Errorf("key file %s holds %d bytes, want %d", path, len(raw), keySize)
	}
	return LocalKey{Key: raw, Source: "file (" + path + ")"}, nil
}
