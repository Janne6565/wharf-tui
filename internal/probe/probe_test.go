package probe

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/Janne6565/wharf-tui/internal/proxydial"
	"github.com/Janne6565/wharf-tui/internal/proxydial/proxytest"
)

// hostPort splits a listener address into host and numeric port.
func hostPort(t *testing.T, addr net.Addr) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("atoi %q: %v", portStr, err)
	}
	return host, port
}

func TestDialOnline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	// Accept-and-close in the background so the connect completes cleanly.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	host, port := hostPort(t, ln.Addr())
	res := Dial(nil, host, port, DefaultTimeout)
	if res.Status != StatusOnline {
		t.Errorf("status = %v, want Online", res.Status)
	}
	if res.RTT <= 0 {
		t.Errorf("RTT = %v, want > 0", res.RTT)
	}
}

func TestDialOfflineClosedPort(t *testing.T) {
	// Reserve a port, then close the listener so nothing answers on it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port := hostPort(t, ln.Addr())
	ln.Close()

	res := Dial(nil, host, port, DefaultTimeout)
	if res.Status != StatusOffline {
		t.Errorf("status = %v, want Offline", res.Status)
	}
	if res.RTT != 0 {
		t.Errorf("RTT = %v, want 0 for offline", res.RTT)
	}
}

func TestDialOfflineTimeout(t *testing.T) {
	// 203.0.113.0/24 (TEST-NET-3) is reserved and unroutable, so the dial can
	// only end in a timeout.
	timeout := 50 * time.Millisecond
	start := time.Now()
	res := Dial(nil, "203.0.113.1", 22, timeout)
	elapsed := time.Since(start)

	if res.Status != StatusOffline {
		t.Errorf("status = %v, want Offline", res.Status)
	}
	if res.RTT != 0 {
		t.Errorf("RTT = %v, want 0", res.RTT)
	}
	// Must not block much past the timeout budget.
	if elapsed > time.Second {
		t.Errorf("elapsed = %v, want < 1s (timeout %v)", elapsed, timeout)
	}
}

// Behind a proxy a failed probe says nothing about the host — the proxy may
// simply decline CONNECT to port 22 on policy — so it must read as unknown
// rather than painting a reachable host red.
func TestDialThroughProxyFailureIsUnknown(t *testing.T) {
	for _, k := range []string{"WHARF_PROXY", "ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(k, "")
	}
	// Nothing listens on port 1, so the proxy itself is unreachable.
	d, err := proxydial.Resolve("socks5://127.0.0.1:1", "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	host, portStr, _ := net.SplitHostPort(proxytest.Target)
	port, _ := strconv.Atoi(portStr)

	res := Dial(d, host, port, DefaultTimeout)
	if res.Status != StatusUnknown {
		t.Errorf("status = %v, want Unknown", res.Status)
	}
}

// A working proxy still yields a real reading: the dot stays meaningful for
// people who are behind one all day.
func TestDialThroughProxyOnline(t *testing.T) {
	for _, k := range []string{"WHARF_PROXY", "ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(k, "")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	px := proxytest.StartSOCKS5(t, ln.Addr().String(), "", "")
	d, err := proxydial.Resolve("socks5://"+px.Addr, "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	host, portStr, _ := net.SplitHostPort(proxytest.Target)
	port, _ := strconv.Atoi(portStr)

	res := Dial(d, host, port, DefaultTimeout)
	if res.Status != StatusOnline {
		t.Errorf("status = %v, want Online", res.Status)
	}
	if px.Dials() != 1 {
		t.Errorf("proxy saw %d dials, want 1", px.Dials())
	}
}
