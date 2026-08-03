// Command wharf is a terminal-based SSH client with a keyboard-driven TUI.
//
// Wharf is local-first: hosts, keys and sessions work with no account, backed by
// a local encrypted vault. Signing in adds cross-machine sync and team projects.
//
// Usage:
//
//	wharf [flags] [host]
//
// With no arguments wharf opens the TUI at the vault gate. A bare argument names
// a saved host to connect to right after unlocking, so verbs are spelled as
// flags (--logout, --doctor) and never take a name a host could have.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/Janne6565/wharf-tui/internal/api"
	"github.com/Janne6565/wharf-tui/internal/localcfg"
	"github.com/Janne6565/wharf-tui/internal/proxydial"
	"github.com/Janne6565/wharf-tui/internal/sessd"
	"github.com/Janne6565/wharf-tui/internal/sshx"
	syncx "github.com/Janne6565/wharf-tui/internal/sync"
	"github.com/Janne6565/wharf-tui/internal/ui"
	"github.com/Janne6565/wharf-tui/internal/vault"
	tea "github.com/charmbracelet/bubbletea"
)

// version is the release identity, stamped at build time with
// -ldflags "-X main.version=vX.Y.Z". An unstamped build reports "dev" plus the
// VCS revision Go embeds automatically, so a hand-built binary is still
// identifiable.
var version = "dev"

func main() {
	// Session-host mode is checked before flag parsing: it is not a user-facing
	// flag but an internal re-exec, and it takes over the process completely.
	if len(os.Args) == 3 && os.Args[1] == sessd.SessionHostFlag {
		if err := runSessionHost(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "wharf: session host:", err)
			os.Exit(1)
		}
		return
	}

	demo := flag.Bool("demo", false, "run with sample data and a simulated session (no disk I/O, no real SSH)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	logout := flag.Bool("logout", false, "delete the local sync session (sign this device out) and exit")
	doctor := flag.Bool("doctor", false, "print resolved paths and environment, then exit")
	reset := flag.Bool("reset", false, "DESTRUCTIVE: erase the local vault, session and caches after a typed confirmation")
	vaultFlag := flag.String("vault", "", "path to the vault file (overrides $WHARF_VAULT)")
	proxyFlag := flag.String("proxy", "", "egress proxy for outbound SSH (socks5://…, http://…, or \"off\"); overrides $WHARF_PROXY and the saved setting")
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Println("wharf", versionString())
		return
	}

	if *demo {
		if flag.NArg() > 0 {
			fmt.Fprintln(os.Stderr, "wharf: --demo takes no host argument")
			os.Exit(2)
		}
		run(ui.New(ui.Config{Demo: true}), nil, nil)
		return
	}

	vaultPath, err := resolveVaultPath(*vaultFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wharf: resolving vault path:", err)
		os.Exit(1)
	}

	cfgPath, err := localcfg.DefaultPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "wharf: resolving config path:", err)
		os.Exit(1)
	}
	// A broken config file is reported and then ignored: it holds preferences,
	// and refusing to start over a stray character would be a poor trade.
	cfg, err := localcfg.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wharf:", err)
	}
	resolved, err := proxydial.Resolve(*proxyFlag, cfg.Proxy)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wharf: proxy:", err)
		os.Exit(2)
	}
	// One holder, shared by the engine, the session pool, the probes and the
	// settings screen. Everything that dials reads it, so changing the proxy is
	// one Set rather than a call per component that must not be forgotten.
	proxy := proxydial.NewSetting(resolved)

	if *doctor {
		printDoctor(vaultPath, cfgPath, resolved)
		return
	}

	if *logout {
		if err := signOut(vaultPath); err != nil {
			fmt.Fprintln(os.Stderr, "wharf:", err)
			os.Exit(1)
		}
		return
	}

	if *reset {
		err := guardInteractive(os.Stdin)
		if err == nil {
			err = resetInstance(vaultPath, os.Stdin, os.Stdout)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "wharf:", err)
			os.Exit(1)
		}
		return
	}

	var connectTo string
	switch flag.NArg() {
	case 0:
	case 1:
		connectTo = flag.Arg(0)
	default:
		fmt.Fprintln(os.Stderr, "wharf: at most one host argument")
		os.Exit(2)
	}

	mgr := sshx.NewManager(knownHostsPath(), true)
	mgr.SetProxy(proxy)
	pool, err := newSessionPool()
	if err != nil {
		// Without a pool wharf still runs; it just cannot open new sessions.
		// Better a usable dashboard with a clear error than no wharf at all.
		fmt.Fprintln(os.Stderr, "wharf: sessions unavailable:", err)
	}
	if pool != nil {
		pool.SetProxy(proxy)
	}
	model := ui.New(ui.Config{
		VaultPath:    vaultPath,
		Manager:      mgr,
		Sessions:     pool,
		ConnectHost:  connectTo,
		Proxy:        cfg.Proxy,
		ProxySetting: proxy,
		ApplyProxy:   applyProxyFn(cfgPath, *proxyFlag, proxy),
	})
	run(model, mgr, pool)
}

// applyProxyFn returns the hook the settings screen calls when the proxy is
// edited: persist the machine-local setting, re-resolve it against the flag and
// environment that still outrank it, and publish the result to the shared
// setting every dialler reads.
//
// Resolution stays here rather than in the UI so there is exactly one place
// that knows the precedence order, and the update is a single Set rather than
// one call per component. Live sessions and forwards are untouched — they keep
// the path they were dialled through.
func applyProxyFn(cfgPath, flagOverride string, proxy *proxydial.Setting) func(string) error {
	return func(setting string) error {
		// Validate before writing, so a typo never lands in the file.
		d, err := proxydial.Resolve(flagOverride, setting)
		if err != nil {
			return err
		}
		cfg, err := localcfg.Load(cfgPath)
		if err != nil {
			cfg = localcfg.Config{} // unreadable: replace rather than refuse
		}
		cfg.Proxy = setting
		if err := localcfg.Save(cfgPath, cfg); err != nil {
			return err
		}
		proxy.Set(d)
		return nil
	}
}

// newSessionPool prepares the session-host pool and adopts any sessions left
// running by an earlier wharf. Adoption failures are not fatal: a session whose
// socket cannot be reached is simply not listed.
func newSessionPool() (*sessd.Pool, error) {
	dir, err := sessd.RuntimeDir()
	if err != nil {
		return nil, err
	}
	pool := sessd.NewPool(dir, knownHostsPath(), true)
	if _, err := pool.Adopt(); err != nil {
		fmt.Fprintln(os.Stderr, "wharf: could not scan for running sessions:", err)
	}
	return pool, nil
}

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintln(out, "wharf — a terminal SSH client with a keyboard-driven TUI.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  wharf [flags] [host]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "With no arguments wharf opens the TUI. A host argument names a saved host to")
	fmt.Fprintln(out, "connect to right after the vault is unlocked (exact name, else a unique name")
	fmt.Fprintln(out, "prefix; case-insensitive).")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Flags:")
	// --reset is destructive; PrintDefaults lists it, and it prompts before acting.
	flag.PrintDefaults()
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Environment:")
	fmt.Fprintln(out, "  WHARF_VAULT      vault file path (default: per-user data dir)")
	fmt.Fprintln(out, "  WHARF_CONFIG     machine-local config file (default: per-user config dir)")
	fmt.Fprintln(out, "  WHARF_API_BASE   sync backend base URL (default: production)")
	fmt.Fprintln(out, "  WHARF_PROXY      egress proxy for outbound SSH; overrides the saved setting")
	fmt.Fprintln(out, "  ALL_PROXY        egress proxy, if neither of the above is set")
	fmt.Fprintln(out, "  HTTPS_PROXY      same, checked after ALL_PROXY")
	fmt.Fprintln(out, "  NO_PROXY         comma-separated hosts, domains and CIDRs to reach directly")
}

// versionString renders the stamped version, falling back to the VCS revision
// Go embeds in `go build`/`go install` binaries when nothing was stamped.
func versionString() string {
	if version != "dev" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return version
	}
	var rev, dirty string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
			if len(rev) > 12 {
				rev = rev[:12]
			}
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if rev == "" {
		return version
	}
	return version + " (" + rev + dirty + ")"
}

// resolveVaultPath applies --vault, then $WHARF_VAULT, then the per-user
// default location.
func resolveVaultPath(override string) (string, error) {
	if p := strings.TrimSpace(override); p != "" {
		return p, nil
	}
	if p := strings.TrimSpace(os.Getenv("WHARF_VAULT")); p != "" {
		return p, nil
	}
	return vault.DefaultPath()
}

// knownHostsPath resolves ~/.ssh/known_hosts for TOFU host-key storage.
func knownHostsPath() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".ssh", "known_hosts")
	}
	return "known_hosts"
}

// signOut deletes the device-local sync session file. It deliberately needs no
// master password: the session file is sealed under the vault DEK, so the
// in-TUI sign-out is only reachable while unlocked — this is the escape hatch
// for when the vault cannot be opened at all.
//
// Local only. The refresh token cannot be read (let alone revoked server-side)
// without the vault key; to invalidate sessions on the server, reset with the
// recovery code, which rotates the code and revokes every token.
func signOut(vaultPath string) error {
	path := syncx.SessionPath(vaultPath)
	switch err := os.Remove(path); {
	case err == nil:
		fmt.Println("wharf: signed out — removed", path)
		fmt.Println("wharf: local only; reset with your recovery code to revoke server-side sessions")
		return nil
	case os.IsNotExist(err):
		fmt.Println("wharf: not signed in (no session file at " + path + ")")
		return nil
	default:
		return fmt.Errorf("removing session file: %w", err)
	}
}

// resetPhrase is the confirmation a --reset has to be typed out in full.
const resetPhrase = "I am sure"

// confirmsReset reports whether the typed line matches resetPhrase. Matching is
// lenient about case, surrounding and repeated whitespace, and the apostrophe in
// "I'm sure": the challenge exists to make the action deliberate, not to test
// typing accuracy. Anything else — including a bare "y" or "yes" — aborts.
func confirmsReset(typed string) bool {
	clean := strings.NewReplacer("'", "", "’", "").Replace(typed)
	switch strings.ToLower(strings.Join(strings.Fields(clean), " ")) {
	case "i am sure", "im sure":
		return true
	}
	return false
}

// resetTargets lists every artifact a reset removes, in deletion order: derived
// state first, then the vault, then its lock sidecar.
func resetTargets(vaultPath string) []string {
	return []string{
		syncx.ProjectsDir(vaultPath),
		syncx.SessionPath(vaultPath),
		vaultPath,
		vault.LockPath(vaultPath),
	}
}

// existing filters paths down to the ones actually on disk, so the confirmation
// prompt only ever promises to delete things that are there.
func existing(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if _, err := os.Lstat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// guardInteractive refuses a destructive action when stdin is not a terminal, so
// a stray pipe or a CI job can never satisfy the confirmation prompt.
func guardInteractive(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("checking stdin: %w", err)
	}
	if fi.Mode()&os.ModeCharDevice == 0 {
		return errors.New("--reset needs an interactive terminal for its confirmation prompt")
	}
	return nil
}

// resetInstance erases this device's wharf state after a typed confirmation.
// Unrecoverable by design: the recovery code unlocks a vault *file*, so once the
// file is gone it is gone. A signed-in device is the one exception worth saying
// out loud — the server still holds the ciphertext, so signing in again pulls
// the vault back.
func resetInstance(vaultPath string, in io.Reader, out io.Writer) error {
	targets := existing(resetTargets(vaultPath))
	if len(targets) == 0 {
		fmt.Fprintln(out, "wharf: nothing to reset — no vault at "+vaultPath)
		return nil
	}
	// A running instance holds the vault open and would write it straight back
	// out on its next save, quietly undoing the reset.
	if vault.InUse(vaultPath) {
		return errors.New("another wharf instance is running — quit it first, or its next save would restore the vault")
	}

	fmt.Fprintln(out, "Are you sure you want to reset your wharf instance?")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "This permanently erases, on this device:")
	for _, p := range targets {
		fmt.Fprintln(out, "  •", p)
	}
	fmt.Fprintln(out)
	if n := runningSessions(); n > 0 {
		fmt.Fprintln(out)
		fmt.Fprintf(out, "It also closes %s still running on this machine.\n", plural(n, "background session"))
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Every saved host, key and stored password goes with it. Your recovery code")
	fmt.Fprintln(out, "cannot bring it back — it unlocks a vault file, and there will not be one.")
	fmt.Fprintln(out, "If this device is signed in, the server's copy is untouched: sign in again")
	fmt.Fprintln(out, "with your master password to pull the vault back.")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "Type %q to confirm: ", resetPhrase)

	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return fmt.Errorf("reading confirmation: %w", err)
	}
	if !confirmsReset(line) {
		fmt.Fprintln(out, "wharf: aborted — nothing was deleted")
		return nil
	}

	// Session hosts are separate processes holding live SSH connections and the
	// host spec — stored password included — in their memory. Erasing the vault
	// while they keep running would leave exactly what the reset promises to
	// erase, on the machine, reachable through a socket.
	if n := closeRunningSessions(); n > 0 {
		fmt.Fprintln(out, "closed", plural(n, "background session"))
	}

	var failed []string
	for _, p := range targets {
		if err := os.RemoveAll(p); err != nil {
			failed = append(failed, p+": "+err.Error())
			continue
		}
		fmt.Fprintln(out, "removed", p)
	}
	if len(failed) > 0 {
		return fmt.Errorf("reset incomplete: %s", strings.Join(failed, "; "))
	}
	fmt.Fprintln(out, "wharf: reset complete — the next run starts at vault creation")
	return nil
}

// runningSessions counts the session hosts alive on this machine, for the reset
// confirmation. It never fails the reset: a runtime directory that cannot be
// read simply reports nothing to close.
func runningSessions() int {
	dir, err := sessd.RuntimeDir()
	if err != nil {
		return 0
	}
	pool := sessd.NewPool(dir, knownHostsPath(), true)
	n, _ := pool.Adopt()
	pool.Detach()
	return n
}

// closeRunningSessions terminates every session host and returns how many it
// closed.
func closeRunningSessions() int {
	dir, err := sessd.RuntimeDir()
	if err != nil {
		return 0
	}
	pool := sessd.NewPool(dir, knownHostsPath(), true)
	n, _ := pool.Adopt()
	pool.CloseAll()
	return n
}

// plural renders "1 thing" / "3 things".
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// printDoctor dumps the resolved environment: what to paste into a bug report.
// It reads no secrets and never unlocks the vault.
func printDoctor(vaultPath, cfgPath string, proxy *proxydial.Dialer) {
	base := api.BaseURL()
	knownHosts := knownHostsPath()
	sessionPath := syncx.SessionPath(vaultPath)
	fmt.Println("wharf", versionString())
	fmt.Println("go          ", runtime.Version(), runtime.GOOS+"/"+runtime.GOARCH)
	fmt.Println("vault       ", vaultPath, presence(vault.Exists(vaultPath)))
	fmt.Println("config      ", cfgPath, presence(fileExists(cfgPath)))
	fmt.Println("session     ", sessionPath, presence(fileExists(sessionPath)))
	fmt.Println("known_hosts ", knownHosts, presence(fileExists(knownHosts)))
	fmt.Println("api base    ", base, envNote("WHARF_API_BASE"))
	fmt.Println("device url  ", api.DeviceURL(base))
	// String redacts any password; this output is meant to be pasted into bug
	// reports.
	fmt.Println("proxy       ", proxy.String(), "(from "+proxy.Source().String()+")")
	if v := strings.TrimSpace(os.Getenv("NO_PROXY")); v != "" {
		fmt.Println("no_proxy    ", v)
	}
}

func presence(ok bool) string {
	if ok {
		return "(present)"
	}
	return "(missing)"
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// envNote marks values that came from an override rather than the default.
func envNote(key string) string {
	if strings.TrimSpace(os.Getenv(key)) != "" {
		return "(from $" + key + ")"
	}
	return "(default)"
}

// run wires the notify callbacks to the program and runs it. Both must be set
// before any Dial, so they are wired before p.Run.
func run(model tea.Model, mgr *sshx.Manager, pool *sessd.Pool) {
	p := tea.NewProgram(model, tea.WithAltScreen())
	if mgr != nil {
		mgr.SetNotify(p.Send)
	}
	if pool != nil {
		pool.SetNotify(p.Send)
	}
	_, err := p.Run()
	// Belt and braces for an abnormal exit. Forwards are process-bound and are
	// torn down; sessions are only detached from — they live in their own
	// processes and are meant to outlast this one.
	if mgr != nil {
		mgr.CloseAll()
	}
	if pool != nil {
		pool.Detach()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "wharf:", err)
		os.Exit(1)
	}
}
