// Package proxydial routes wharf's outbound TCP connections through a
// corporate egress proxy.
//
// The proxy is deliberately *not* part of the synced vault: it describes the
// network this machine sits on, not the identity using it. Syncing it would
// push an office proxy onto a laptop at home, where every dial would then fail
// against a host that is not reachable. It is therefore resolved from a
// per-invocation flag, the environment, and a machine-local config file — in
// that order — and never leaves this device.
//
// Supported schemes are socks5:// (and socks5h://, which is the same thing
// here — wharf never resolves the target itself, the proxy always does) and
// http:// / https:// via CONNECT, which is what most corporate proxies speak.
package proxydial

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/http/httpproxy"
	"golang.org/x/net/proxy"
)

// Source records where a resolved proxy setting came from, so the settings row
// and --doctor can say why a proxy is in effect. A value the user typed into
// the TUI and an ambient ALL_PROXY inherited from a login shell look identical
// once resolved, and only one of them is worth arguing with.
type Source int

const (
	SourceNone    Source = iota // no proxy configured anywhere
	SourceFlag                  // --proxy
	SourceEnv                   // WHARF_PROXY
	SourceConfig                // machine-local config file (the TUI setting)
	SourceAmbient               // ALL_PROXY / HTTPS_PROXY
)

// String names the source for display.
func (s Source) String() string {
	switch s {
	case SourceFlag:
		return "--proxy"
	case SourceEnv:
		return "$WHARF_PROXY"
	case SourceConfig:
		return "settings"
	case SourceAmbient:
		return "environment"
	}
	return "none"
}

// Off is the value that forces a direct connection even when the environment
// offers a proxy. Without it a machine with ALL_PROXY exported system-wide has
// no way to say "not for wharf" from inside the TUI.
const Off = "off"

// Dialer dials TCP through a proxy, honouring NO_PROXY. The zero value is not
// usable; build one with Resolve or Direct. A nil *Dialer dials directly, so
// callers that never configured one can hold nil.
type Dialer struct {
	url    *url.URL // nil = direct
	source Source
	// proxyFor reports the proxy to use for one target, or nil for direct.
	// It carries the NO_PROXY rules, which are per-target rather than global.
	proxyFor func(addr string) (*url.URL, error)
}

// Direct returns a dialer that never proxies.
func Direct() *Dialer { return &Dialer{source: SourceNone} }

// Resolve picks the proxy for this run. Precedence, highest first:
//
//	--proxy            explicit, this invocation only
//	$WHARF_PROXY       explicit, wharf-specific
//	configured         the machine-local setting, edited in the TUI
//	$ALL_PROXY, $HTTPS_PROXY
//
// The TUI setting outranks the generic environment variables on purpose: those
// are ambient defaults exported for whatever tooling happens to read them,
// whereas someone typing a proxy into wharf's settings screen means wharf. Both
// explicit forms still win, so a one-off `WHARF_PROXY=… wharf` overrides the
// stored setting without editing it.
//
// Any layer may be the literal "off" to force a direct connection and stop the
// search. An empty value at a layer simply falls through to the next.
//
// NO_PROXY is read from the environment in every case; it is a bypass list, not
// a proxy, and there is no reason to spell it twice.
func Resolve(flag, configured string) (*Dialer, error) {
	for _, layer := range []struct {
		val string
		src Source
	}{
		{flag, SourceFlag},
		{os.Getenv("WHARF_PROXY"), SourceEnv},
		{configured, SourceConfig},
		{firstNonEmpty(os.Getenv("ALL_PROXY"), os.Getenv("all_proxy"),
			os.Getenv("HTTPS_PROXY"), os.Getenv("https_proxy")), SourceAmbient},
	} {
		v := strings.TrimSpace(layer.val)
		if v == "" {
			continue
		}
		if strings.EqualFold(v, Off) || strings.EqualFold(v, "direct") || strings.EqualFold(v, "none") {
			return &Dialer{source: SourceNone}, nil
		}
		return newDialer(v, layer.src)
	}
	return Direct(), nil
}

// New builds a dialer for an explicit proxy URL, ignoring the environment
// entirely except for NO_PROXY. It exists for the session-host child process:
// the parent has already resolved which proxy to use, and the child must obey
// that decision rather than re-deriving it from an environment that may be
// stale (an adopted child predates the current run) or different (a re-exec
// carries the parent's env, but only until someone changes it).
//
// An empty raw — or "off" — is a direct dialer, never a fall back to $ALL_PROXY.
func New(raw string) (*Dialer, error) {
	v := strings.TrimSpace(raw)
	if v == "" || strings.EqualFold(v, Off) {
		return Direct(), nil
	}
	return newDialer(v, SourceConfig)
}

// RawURL renders the proxy URL *including any password*, for handing to the
// session host over its 0600 socket. Never log or display this — use String,
// which redacts. Empty when no proxy is configured.
func (d *Dialer) RawURL() string {
	if !d.Enabled() {
		return ""
	}
	return d.url.String()
}

// newDialer validates raw and builds the per-target proxy lookup.
func newDialer(raw string, src Source) (*Dialer, error) {
	u, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	// httpproxy owns the NO_PROXY grammar — suffix matches, CIDRs, bare IPs,
	// host:port and "*" — which is fiddly enough to be worth not reimplementing.
	// It is keyed by request URL, so each target is asked about as an https URL
	// whose host is the SSH endpoint. Its built-in localhost/loopback bypass is
	// welcome here: a proxy has no business in the middle of a dial to 127.0.0.1.
	cfg := &httpproxy.Config{HTTPSProxy: u.String(), NoProxy: firstNonEmpty(os.Getenv("NO_PROXY"), os.Getenv("no_proxy"))}
	fn := cfg.ProxyFunc()
	return &Dialer{
		url:      u,
		source:   src,
		proxyFor: func(addr string) (*url.URL, error) { return fn(&url.URL{Scheme: "https", Host: addr}) },
	}, nil
}

// Parse validates a proxy URL and normalises a bare host:port to socks5://.
// It is exported so the settings screen can reject a bad value at the point it
// is typed rather than at the next dial.
func Parse(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty proxy")
	}
	// A bare "host:port" has no scheme to go on. SOCKS5 is the assumption that
	// fails loudly rather than silently: an HTTP proxy answers a SOCKS greeting
	// with an error, whereas a SOCKS proxy handed a CONNECT may just hang.
	if !strings.Contains(raw, "://") {
		raw = "socks5://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h", "http", "https":
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (use socks5, http or https)", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, errors.New("proxy URL has no host")
	}
	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), defaultPort(u.Scheme))
	}
	return u, nil
}

// defaultPort is the port assumed when a proxy URL omits one.
func defaultPort(scheme string) string {
	switch strings.ToLower(scheme) {
	case "http":
		return "3128"
	case "https":
		return "3129"
	default:
		return "1080" // socks5
	}
}

// Enabled reports whether any proxy is configured.
func (d *Dialer) Enabled() bool { return d != nil && d.url != nil }

// Source reports where the setting came from.
func (d *Dialer) Source() Source {
	if d == nil {
		return SourceNone
	}
	return d.source
}

// String renders the proxy for display with any password redacted — this ends
// up in --doctor output and on the settings screen, both of which get pasted
// into bug reports.
func (d *Dialer) String() string {
	if !d.Enabled() {
		return "direct"
	}
	u := *d.url
	if u.User != nil {
		if _, ok := u.User.Password(); ok {
			u.User = url.UserPassword(u.User.Username(), "xxxxx")
		}
	}
	return u.String()
}

// DialContext connects to addr, through the proxy unless NO_PROXY exempts it.
// network is always "tcp" in wharf; anything else is refused rather than
// quietly dialled direct.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("proxydial: unsupported network %q", network)
	}
	if !d.Enabled() {
		var dd net.Dialer
		return dd.DialContext(ctx, network, addr)
	}
	pu, err := d.proxyFor(addr)
	if err != nil {
		return nil, err
	}
	if pu == nil {
		var dd net.Dialer // NO_PROXY match: this target is dialled directly
		return dd.DialContext(ctx, network, addr)
	}
	switch strings.ToLower(pu.Scheme) {
	case "socks5", "socks5h":
		return dialSOCKS5(ctx, pu, network, addr)
	default:
		return dialConnect(ctx, pu, addr)
	}
}

// dialSOCKS5 hands the target to a SOCKS5 proxy, which resolves it.
func dialSOCKS5(ctx context.Context, pu *url.URL, network, addr string) (net.Conn, error) {
	var auth *proxy.Auth
	if pu.User != nil {
		pw, _ := pu.User.Password()
		auth = &proxy.Auth{User: pu.User.Username(), Password: pw}
	}
	d, err := proxy.SOCKS5(network, pu.Host, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("proxy %s: %w", pu.Host, err)
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		// x/net's SOCKS5 dialer has implemented ContextDialer for years; the
		// fallback exists so a dependency bump can never silently drop the
		// context and leave a dial hanging past its timeout.
		return d.Dial(network, addr)
	}
	conn, err := cd.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("proxy %s: %w", pu.Host, err)
	}
	return conn, nil
}

// firstNonEmpty returns the first value that is not blank.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
