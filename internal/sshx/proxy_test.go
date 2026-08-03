package sshx

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Janne6565/wharf-tui/internal/proxydial"
	"github.com/Janne6565/wharf-tui/internal/proxydial/proxytest"
)

// proxiedSpec points a host spec at the sentinel name the stub proxies serve.
// The engine must not resolve it — that is the proxy's job — so a dial that
// escapes the proxy fails on DNS instead of quietly connecting direct.
func proxiedSpec() HostSpec {
	host, portStr, _ := net.SplitHostPort(proxytest.Target)
	port, _ := strconv.Atoi(portStr)
	hs := HostSpec{ID: "h1", Name: "test", User: "tester", Addr: host, Port: port}
	hs.AuthMethod = AuthPassword
	return hs
}

// dialThroughProxy runs a full SSH handshake against ts via the given proxy URL
// and returns the live session.
func dialThroughProxy(t *testing.T, ts *testServer, rawProxy string) *Session {
	t.Helper()
	rec := newRecorder()
	khPath := filepath.Join(t.TempDir(), "known_hosts")
	t.Setenv("SSH_AUTH_SOCK", "")

	d, err := proxydial.Resolve(rawProxy, "")
	if err != nil {
		t.Fatalf("resolve proxy: %v", err)
	}
	m := NewManager(khPath, false)
	m.SetNotify(rec.notify)
	m.SetProxy(proxydial.NewSetting(d))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sess, err := m.Dial(ctx, proxiedSpec(), 80, 24)
	if err != nil {
		t.Fatalf("dial through %s: %v", rawProxy, err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

// clearProxyEnv stops an ambient proxy on the developer's machine from leaking
// into these tests — Resolve reads the environment by design.
func clearProxyEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"WHARF_PROXY", "ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(k, "")
	}
}

func TestDialThroughSOCKS5Proxy(t *testing.T) {
	clearProxyEnv(t)
	ts := startServer(t, testPassword, echoHandler(nil, nil))
	px := proxytest.StartSOCKS5(t, ts.addr(), "", "")

	sess := dialThroughProxy(t, ts, "socks5://"+px.Addr)
	if !sess.Alive() {
		t.Fatal("session not alive after a proxied dial")
	}
	if px.Dials() != 1 {
		t.Fatalf("proxy saw %d dials, want 1 — the engine bypassed the proxy", px.Dials())
	}
}

func TestDialThroughConnectProxy(t *testing.T) {
	clearProxyEnv(t)
	ts := startServer(t, testPassword, echoHandler(nil, nil))
	px := proxytest.StartCONNECT(t, ts.addr(), "deniz", "hunter2")

	sess := dialThroughProxy(t, ts, "http://deniz:hunter2@"+px.Addr)
	if !sess.Alive() {
		t.Fatal("session not alive after a proxied dial")
	}
	if px.Dials() != 1 {
		t.Fatalf("proxy saw %d dials, want 1", px.Dials())
	}
}

// A forward opens its own connection, so it has to be proxied too — otherwise
// sessions work behind a corporate proxy and port forwarding silently does not.
func TestForwardDialsThroughProxy(t *testing.T) {
	clearProxyEnv(t)
	ts := startServer(t, testPassword, echoHandler(nil, nil))
	px := proxytest.StartSOCKS5(t, ts.addr(), "", "")

	rec := newRecorder()
	khPath := filepath.Join(t.TempDir(), "known_hosts")
	t.Setenv("SSH_AUTH_SOCK", "")

	d, err := proxydial.Resolve("socks5://"+px.Addr, "")
	if err != nil {
		t.Fatalf("resolve proxy: %v", err)
	}
	m := NewManager(khPath, false)
	m.SetNotify(rec.notify)
	m.SetProxy(proxydial.NewSetting(d))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fwd, err := m.StartForward(ctx, proxiedSpec(), ForwardSpec{
		Kind:       ForwardLocal,
		BindAddr:   "127.0.0.1",
		BindPort:   0,
		TargetAddr: "127.0.0.1",
		TargetPort: 9,
	})
	if err != nil {
		t.Fatalf("start forward through proxy: %v", err)
	}
	t.Cleanup(func() { _ = fwd.Close() })

	if px.Dials() != 1 {
		t.Fatalf("proxy saw %d dials, want 1 — the forward opened a direct connection", px.Dials())
	}
}

// A proxy that is configured but unreachable must surface as a dial error, not
// as a silent fall back to a direct connection: on a locked-down network the
// direct dial would hang until the context expires, and on a permissive one it
// would quietly defeat the setting.
func TestUnreachableProxyFailsRatherThanBypassing(t *testing.T) {
	clearProxyEnv(t)

	// Port 1 on loopback: nothing listens there, and it refuses immediately.
	d, err := proxydial.Resolve("socks5://127.0.0.1:1", "")
	if err != nil {
		t.Fatalf("resolve proxy: %v", err)
	}
	m := NewManager(filepath.Join(t.TempDir(), "known_hosts"), false)
	m.SetNotify(newRecorder().notify)
	m.SetProxy(proxydial.NewSetting(d))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := m.Dial(ctx, proxiedSpec(), 80, 24); err == nil {
		t.Fatal("dial succeeded with an unreachable proxy, want an error")
	}
}

// The manager reads the shared setting at each dial rather than snapshotting it
// at wiring time. This is what lets one Set reach the engine, the session pool
// and the probes at once, instead of a setter per component that has to be kept
// in lockstep.
func TestProxySettingChangeAppliesToNextDial(t *testing.T) {
	clearProxyEnv(t)
	ts := startServer(t, testPassword, echoHandler(nil, nil))
	px := proxytest.StartSOCKS5(t, ts.addr(), "", "")

	rec := newRecorder()
	t.Setenv("SSH_AUTH_SOCK", "")
	setting := proxydial.NewSetting(proxydial.Direct())

	m := NewManager(filepath.Join(t.TempDir(), "known_hosts"), false)
	m.SetNotify(rec.notify)
	m.SetProxy(setting)

	// Wired direct; the proxy is chosen only afterwards, as it is when someone
	// edits the setting mid-session.
	d, err := proxydial.Resolve("socks5://"+px.Addr, "")
	if err != nil {
		t.Fatalf("resolve proxy: %v", err)
	}
	setting.Set(d)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sess, err := m.Dial(ctx, proxiedSpec(), 80, 24)
	if err != nil {
		t.Fatalf("dial after the setting changed: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	if px.Dials() != 1 {
		t.Fatalf("proxy saw %d dials, want 1 — the manager snapshotted the old value", px.Dials())
	}
}
