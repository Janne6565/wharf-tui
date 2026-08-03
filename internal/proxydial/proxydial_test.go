package proxydial

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Janne6565/wharf-tui/internal/proxydial/proxytest"
)

// echoServer is a stand-in for the far side of the tunnel: it greets like an
// SSH server (server speaks first) and then echoes.
func echoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.WriteString(c, "SSH-2.0-test\r\n")
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln
}

// dialThrough resolves a dialer for raw and connects it to addr.
func dialThrough(t *testing.T, raw, addr string) net.Conn {
	t.Helper()
	d, err := Resolve(raw, "")
	if err != nil {
		t.Fatalf("Resolve(%q): %v", raw, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// expectGreeting asserts the server's first line survived the tunnel. It is the
// regression guard for CONNECT: bytes buffered alongside the proxy's response
// headers must be replayed, not dropped.
func expectGreeting(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len("SSH-2.0-test\r\n"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("reading greeting: %v", err)
	}
	if got := string(buf); got != "SSH-2.0-test\r\n" {
		t.Fatalf("greeting = %q, want the server banner intact", got)
	}
}

func TestSOCKS5Tunnel(t *testing.T) {
	srv := echoServer(t)
	px := proxytest.StartSOCKS5(t, srv.Addr().String(), "", "")

	conn := dialThrough(t, "socks5://"+px.Addr, proxytest.Target)
	expectGreeting(t, conn)

	if px.Dials() != 1 {
		t.Fatalf("proxy saw %d dials, want 1 — the connection bypassed the proxy", px.Dials())
	}
	// The target reaches the proxy as a name, not an address: wharf never
	// resolves it, which is the point of routing through the proxy at all.
	if got := px.Targets(); len(got) != 1 || got[0] != proxytest.Target {
		t.Fatalf("proxy targets = %v, want [%s]", got, proxytest.Target)
	}
}

func TestSOCKS5Auth(t *testing.T) {
	srv := echoServer(t)
	px := proxytest.StartSOCKS5(t, srv.Addr().String(), "deniz", "hunter2")

	conn := dialThrough(t, "socks5://deniz:hunter2@"+px.Addr, proxytest.Target)
	expectGreeting(t, conn)

	// Wrong credentials must fail rather than fall back to a direct dial.
	d, err := Resolve("socks5://deniz:wrong@"+px.Addr, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := d.DialContext(context.Background(), "tcp", proxytest.Target); err == nil {
		t.Fatal("dial with bad proxy credentials succeeded, want an error")
	}
}

func TestConnectTunnel(t *testing.T) {
	srv := echoServer(t)
	px := proxytest.StartCONNECT(t, srv.Addr().String(), "", "")

	conn := dialThrough(t, "http://"+px.Addr, proxytest.Target)
	expectGreeting(t, conn)

	if _, err := io.WriteString(conn, "ping\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "ping\n" {
		t.Fatalf("echo = %q, want %q", buf, "ping\n")
	}
	if px.Dials() != 1 {
		t.Fatalf("proxy saw %d dials, want 1", px.Dials())
	}
}

func TestConnectAuthRequired(t *testing.T) {
	srv := echoServer(t)
	px := proxytest.StartCONNECT(t, srv.Addr().String(), "deniz", "hunter2")

	d, err := Resolve("http://"+px.Addr, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	_, err = d.DialContext(context.Background(), "tcp", proxytest.Target)
	if err == nil {
		t.Fatal("unauthenticated dial succeeded, want 407")
	}
	// The message has to name the fix; "502" alone sends people to the wrong place.
	if !strings.Contains(err.Error(), "407") || !strings.Contains(err.Error(), "credentials") {
		t.Fatalf("error = %v, want a 407 mentioning credentials", err)
	}

	conn := dialThrough(t, "http://deniz:hunter2@"+px.Addr, proxytest.Target)
	expectGreeting(t, conn)
}

func TestNoProxyBypass(t *testing.T) {
	srv := echoServer(t)
	px := proxytest.StartSOCKS5(t, srv.Addr().String(), "", "")

	host, _, _ := net.SplitHostPort(proxytest.Target)
	t.Setenv("NO_PROXY", host)

	d, err := Resolve("socks5://"+px.Addr, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Bypassed means dialled directly, and the sentinel name never resolves —
	// so the failure *is* the evidence, backed by the proxy seeing nothing.
	if _, err := d.DialContext(context.Background(), "tcp", proxytest.Target); err == nil {
		t.Fatal("dial succeeded, want a direct dial to an unresolvable name")
	}
	if px.Dials() != 0 {
		t.Fatalf("proxy saw %d dials, want 0 — NO_PROXY should have bypassed it", px.Dials())
	}

	// A host outside NO_PROXY still goes through the proxy: the bypass must be
	// per-target, not a global off switch.
	t.Setenv("NO_PROXY", "other.invalid")
	conn := dialThrough(t, "socks5://"+px.Addr, proxytest.Target)
	expectGreeting(t, conn)
	if px.Dials() != 1 {
		t.Fatalf("proxy saw %d dials, want 1", px.Dials())
	}
}

func TestPrecedence(t *testing.T) {
	t.Setenv("WHARF_PROXY", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")

	cases := []struct {
		name       string
		flag, conf string
		env        map[string]string
		want       string
		wantSrc    Source
	}{
		{
			name: "flag beats everything",
			flag: "socks5://flag:1080", conf: "socks5://conf:1080",
			env:  map[string]string{"WHARF_PROXY": "socks5://wharf:1080", "ALL_PROXY": "socks5://all:1080"},
			want: "socks5://flag:1080", wantSrc: SourceFlag,
		},
		{
			name: "WHARF_PROXY beats the stored setting",
			conf: "socks5://conf:1080",
			env:  map[string]string{"WHARF_PROXY": "socks5://wharf:1080"},
			want: "socks5://wharf:1080", wantSrc: SourceEnv,
		},
		{
			// The whole point of the TUI setting: an ambient ALL_PROXY exported
			// for other tooling must not override what was typed into wharf.
			name: "stored setting beats ambient ALL_PROXY",
			conf: "socks5://conf:1080",
			env:  map[string]string{"ALL_PROXY": "socks5://all:1080"},
			want: "socks5://conf:1080", wantSrc: SourceConfig,
		},
		{
			name: "ambient env is the last resort",
			env:  map[string]string{"HTTPS_PROXY": "http://amb:3128"},
			want: "http://amb:3128", wantSrc: SourceAmbient,
		},
		{
			name: "off in the setting suppresses ambient env",
			conf: "off",
			env:  map[string]string{"ALL_PROXY": "socks5://all:1080"},
			want: "direct", wantSrc: SourceNone,
		},
		{
			name: "nothing configured is direct",
			want: "direct", wantSrc: SourceNone,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear every spelling first, then set what the case wants. Windows
			// environment names are case-insensitive, so "all_proxy" and
			// "ALL_PROXY" are one variable there: a single pass that assigns
			// both would blank the value it had just set.
			for _, k := range []string{"WHARF_PROXY", "ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy"} {
				t.Setenv(k, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			d, err := Resolve(tc.flag, tc.conf)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got := d.String(); got != tc.want {
				t.Fatalf("proxy = %s, want %s", got, tc.want)
			}
			if d.Source() != tc.wantSrc {
				t.Fatalf("source = %v, want %v", d.Source(), tc.wantSrc)
			}
		})
	}
}

func TestParse(t *testing.T) {
	ok := []struct{ in, want string }{
		{"socks5://p:1080", "socks5://p:1080"},
		{"p:1080", "socks5://p:1080"},     // bare host:port assumes SOCKS5
		{"socks5://p", "socks5://p:1080"}, // default SOCKS port
		{"http://p", "http://p:3128"},     // default HTTP proxy port
		{"socks5h://p:9050", "socks5h://p:9050"},
	}
	for _, tc := range ok {
		u, err := Parse(tc.in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.in, err)
		}
		if u.String() != tc.want {
			t.Fatalf("Parse(%q) = %s, want %s", tc.in, u, tc.want)
		}
	}

	bad := []string{"", "   ", "ftp://p:21", "socks5://", "://nope"}
	for _, in := range bad {
		if _, err := Parse(in); err == nil {
			t.Fatalf("Parse(%q) succeeded, want an error", in)
		}
	}
}

func TestStringRedactsPassword(t *testing.T) {
	d, err := Resolve("socks5://deniz:hunter2@p:1080", "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got := d.String()
	if strings.Contains(got, "hunter2") {
		t.Fatalf("String() = %s, want the password redacted", got)
	}
	if !strings.Contains(got, "deniz") {
		t.Fatalf("String() = %s, want the username kept for identification", got)
	}
}

func TestDirectDialerStillDials(t *testing.T) {
	t.Setenv("WHARF_PROXY", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	srv := echoServer(t)
	conn := dialThrough(t, "", srv.Addr().String())
	expectGreeting(t, conn)
}

// A nil *Dialer is what every caller holds before the setting is loaded.
func TestNilDialerDialsDirect(t *testing.T) {
	srv := echoServer(t)
	var d *Dialer
	conn, err := d.DialContext(context.Background(), "tcp", srv.Addr().String())
	if err != nil {
		t.Fatalf("nil dialer: %v", err)
	}
	defer conn.Close()
	expectGreeting(t, conn)
}

func TestSettingIsSharedByReference(t *testing.T) {
	s := NewSetting(Direct())
	// Two components wired to the same setting, as the engine and the session
	// pool are.
	a, b := s, s

	if a.Dialer().Enabled() || b.Dialer().Enabled() {
		t.Fatal("a setting built from Direct should not be enabled")
	}

	d, err := New("socks5://proxy.corp:1080")
	if err != nil {
		t.Fatal(err)
	}
	s.Set(d)

	if got := a.Dialer().String(); got != "socks5://proxy.corp:1080" {
		t.Fatalf("first reader sees %s, want the updated proxy", got)
	}
	if got := b.Dialer().String(); got != "socks5://proxy.corp:1080" {
		t.Fatalf("second reader sees %s, want the updated proxy", got)
	}
}

// Components that were never wired to a setting must still dial.
func TestNilSettingDialsDirect(t *testing.T) {
	var s *Setting
	if s.Dialer() != nil {
		t.Fatal("a nil setting should report no dialer")
	}
	s.Set(Direct()) // must not panic

	srv := echoServer(t)
	conn, err := s.DialContext(context.Background(), "tcp", srv.Addr().String())
	if err != nil {
		t.Fatalf("nil setting: %v", err)
	}
	defer conn.Close()
	expectGreeting(t, conn)
}
