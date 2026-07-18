package sshx

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	gliderssh "github.com/gliderlabs/ssh"
)

// startForwardServer runs an sshd wired for both local (-L / -D via
// direct-tcpip) and remote (-R via tcpip-forward) port forwarding, on top of
// the default session handler. It returns the *gliderssh.Server too so a test
// can force the connection to drop mid-flight. The existing startServer stays
// untouched — plain-session tests don't need the forwarding plumbing.
func startForwardServer(t *testing.T, password string) (*testServer, *gliderssh.Server) {
	t.Helper()
	signer := newHostSigner(t)

	fwd := &gliderssh.ForwardedTCPHandler{}
	srv := &gliderssh.Server{
		Handler: echoHandler(nil, nil),
		PasswordHandler: func(ctx gliderssh.Context, pass string) bool {
			return password != "" && pass == password
		},
		LocalPortForwardingCallback:   func(ctx gliderssh.Context, host string, port uint32) bool { return true },
		ReversePortForwardingCallback: func(ctx gliderssh.Context, host string, port uint32) bool { return true },
		ChannelHandlers: map[string]gliderssh.ChannelHandler{
			"session":      gliderssh.DefaultSessionHandler,
			"direct-tcpip": gliderssh.DirectTCPIPHandler,
		},
		RequestHandlers: map[string]gliderssh.RequestHandler{
			"tcpip-forward":        fwd.HandleSSHRequest,
			"cancel-tcpip-forward": fwd.HandleSSHRequest,
		},
	}
	srv.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})

	tcp := ln.Addr().(*net.TCPAddr)
	ts := &testServer{host: "127.0.0.1", port: tcp.Port, hostPub: signer.PublicKey()}
	return ts, srv
}

// echoListener is an in-process TCP echo server used as a forward target.
func echoListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// forwardManager builds a keepalive-free manager wired to rec, verifying host
// keys into a throwaway known_hosts (TOFU auto-accepted by rec).
func forwardManager(t *testing.T, rec *recorder) *Manager {
	t.Helper()
	khPath := filepath.Join(t.TempDir(), "known_hosts")
	t.Setenv("SSH_AUTH_SOCK", "")
	m := NewManager(khPath, false)
	m.SetNotify(rec.notify)
	return m
}

// forwardSpec is the host recipe for a forward: password mode with the password
// stored so the connect phase never has to prompt.
func forwardSpec(ts *testServer) HostSpec {
	hs := ts.passwordSpec()
	hs.Password = testPassword
	return hs
}

func portOf(t *testing.T, addr string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("atoi %q: %v", p, err)
	}
	return n
}

func TestForwardLabel(t *testing.T) {
	cases := []struct {
		spec ForwardSpec
		want string
	}{
		{ForwardSpec{Kind: ForwardLocal, BindAddr: "127.0.0.1", BindPort: 8080, TargetAddr: "db.internal", TargetPort: 5432}, "L 127.0.0.1:8080 → db.internal:5432"},
		{ForwardSpec{Kind: ForwardRemote, BindAddr: "server", BindPort: 9000, TargetAddr: "127.0.0.1", TargetPort: 3000}, "R server:9000 → 127.0.0.1:3000"},
		{ForwardSpec{Kind: ForwardDynamic, BindAddr: "127.0.0.1", BindPort: 1080}, "D socks5 127.0.0.1:1080"},
	}
	for _, c := range cases {
		if got := c.spec.Label(); got != c.want {
			t.Errorf("Label() = %q, want %q", got, c.want)
		}
	}
}

func TestForwardValidation(t *testing.T) {
	rec := newRecorder()
	ts, _ := startForwardServer(t, testPassword)
	m := forwardManager(t, rec)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	bad := []ForwardSpec{
		{Kind: "bogus", TargetPort: 1},
		{Kind: ForwardLocal, TargetPort: 0},     // target port required
		{Kind: ForwardLocal, TargetPort: 70000}, // out of range
		{Kind: ForwardLocal, BindPort: -1, TargetPort: 1},
		{Kind: ForwardRemote, TargetPort: 99999},
	}
	for _, spec := range bad {
		if f, err := m.StartForward(ctx, forwardSpec(ts), spec); err == nil {
			_ = f.Close()
			t.Fatalf("StartForward(%+v) accepted an invalid spec", spec)
		}
	}
}

func TestForwardLocalRoundTrip(t *testing.T) {
	rec := newRecorder()
	echo := echoListener(t)
	ts, _ := startForwardServer(t, testPassword)
	m := forwardManager(t, rec)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	spec := ForwardSpec{Kind: ForwardLocal, TargetAddr: "127.0.0.1", TargetPort: portOf(t, echo.Addr().String())}
	f, err := m.StartForward(ctx, forwardSpec(ts), spec)
	if err != nil {
		t.Fatalf("StartForward: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	if !f.Alive() {
		t.Fatal("forward not alive after start")
	}
	if m.GetForward(f.ID()) != f {
		t.Fatal("forward not registered")
	}

	conn, err := net.Dial("tcp", f.BoundAddr())
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("round trip = %q, want %q", buf, "hello")
	}

	waitFor(t, 5*time.Second, "Conns to reach 1", func() bool { return f.Conns() == 1 })
	_ = conn.Close()
	waitFor(t, 5*time.Second, "Conns to return to 0", func() bool { return f.Conns() == 0 })
}

func TestForwardBindPortZeroResolves(t *testing.T) {
	rec := newRecorder()
	echo := echoListener(t)
	ts, _ := startForwardServer(t, testPassword)
	m := forwardManager(t, rec)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	spec := ForwardSpec{Kind: ForwardLocal, BindPort: 0, TargetAddr: "127.0.0.1", TargetPort: portOf(t, echo.Addr().String())}
	f, err := m.StartForward(ctx, forwardSpec(ts), spec)
	if err != nil {
		t.Fatalf("StartForward: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	if p := portOf(t, f.BoundAddr()); p == 0 {
		t.Fatalf("BoundAddr %q did not resolve a concrete port", f.BoundAddr())
	}
}

// socks5RoundTrip performs a full SOCKS5 CONNECT via conn for the given address
// type and target, then verifies bytes echo back through the tunnel.
func socks5RoundTrip(t *testing.T, conn net.Conn, atyp byte, host string, port int) {
	t.Helper()
	reply := socks5Request(t, conn, atyp, host, port)
	if reply[1] != socksReplySuccess {
		t.Fatalf("CONNECT reply code = 0x%02x, want success", reply[1])
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write through socks: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read through socks: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("socks round trip = %q, want %q", buf, "ping")
	}
}

// socks5Request runs the greeting + request exchange and returns the 10-byte
// reply. It uses only the no-auth method and CONNECT unless cmd is overridden by
// the caller supplying a raw address type/host/port.
func socks5Request(t *testing.T, conn net.Conn, atyp byte, host string, port int) []byte {
	t.Helper()
	if _, err := conn.Write([]byte{socks5Version, 0x01, socksNoAuth}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if sel[0] != socks5Version || sel[1] != socksNoAuth {
		t.Fatalf("method selection = % x, want 05 00", sel)
	}

	req := []byte{socks5Version, socksCmdConnect, 0x00, atyp}
	switch atyp {
	case socksATYPIPv4:
		req = append(req, net.ParseIP(host).To4()...)
	case socksATYPDomain:
		req = append(req, byte(len(host)))
		req = append(req, host...)
	default:
		t.Fatalf("unsupported test atyp 0x%02x", atyp)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return reply
}

func TestForwardDynamicSOCKS5(t *testing.T) {
	rec := newRecorder()
	echo := echoListener(t)
	ts, _ := startForwardServer(t, testPassword)
	m := forwardManager(t, rec)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	f, err := m.StartForward(ctx, forwardSpec(ts), ForwardSpec{Kind: ForwardDynamic})
	if err != nil {
		t.Fatalf("StartForward: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	targetPort := portOf(t, echo.Addr().String())

	// IPv4 CONNECT.
	c1, err := net.Dial("tcp", f.BoundAddr())
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	defer c1.Close()
	socks5RoundTrip(t, c1, socksATYPIPv4, "127.0.0.1", targetPort)

	// Domain-name CONNECT.
	c2, err := net.Dial("tcp", f.BoundAddr())
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	defer c2.Close()
	socks5RoundTrip(t, c2, socksATYPDomain, "localhost", targetPort)

	// A non-CONNECT command must be refused with 0x07.
	c3, err := net.Dial("tcp", f.BoundAddr())
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	defer c3.Close()
	if _, err := c3.Write([]byte{socks5Version, 0x01, socksNoAuth}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(c3, sel); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	// CMD 0x02 = BIND, unsupported.
	if _, err := c3.Write([]byte{socks5Version, 0x02, 0x00, socksATYPIPv4, 127, 0, 0, 1, 0, 80}); err != nil {
		t.Fatalf("write bind request: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c3, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != socksReplyCmdNotSupported {
		t.Fatalf("BIND reply code = 0x%02x, want 0x07", reply[1])
	}
}

func TestForwardRemoteRoundTrip(t *testing.T) {
	rec := newRecorder()
	echo := echoListener(t)
	ts, _ := startForwardServer(t, testPassword)
	m := forwardManager(t, rec)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	spec := ForwardSpec{Kind: ForwardRemote, BindPort: 0, TargetAddr: "127.0.0.1", TargetPort: portOf(t, echo.Addr().String())}
	f, err := m.StartForward(ctx, forwardSpec(ts), spec)
	if err != nil {
		t.Fatalf("StartForward: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	// The server-side listener lives on localhost in-process; dial it directly.
	conn, err := net.Dial("tcp", f.BoundAddr())
	if err != nil {
		t.Fatalf("dial server listener %q: %v", f.BoundAddr(), err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("world")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "world" {
		t.Fatalf("remote round trip = %q, want %q", buf, "world")
	}
}

func TestForwardCloseEndsCleanly(t *testing.T) {
	rec := newRecorder()
	echo := echoListener(t)
	ts, _ := startForwardServer(t, testPassword)
	m := forwardManager(t, rec)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	spec := ForwardSpec{Kind: ForwardLocal, TargetAddr: "127.0.0.1", TargetPort: portOf(t, echo.Addr().String())}
	f, err := m.StartForward(ctx, forwardSpec(ts), spec)
	if err != nil {
		t.Fatalf("StartForward: %v", err)
	}
	bound := f.BoundAddr()
	id := f.ID()

	_ = f.Close()

	select {
	case msg := <-rec.forwardEndedCh:
		if msg.ForwardID != id {
			t.Fatalf("ForwardEndedMsg ID = %q, want %q", msg.ForwardID, id)
		}
		if msg.HostID != f.Host().ID {
			t.Fatalf("ForwardEndedMsg HostID = %q, want %q", msg.HostID, f.Host().ID)
		}
		if msg.Err != nil {
			t.Fatalf("deliberate Close reported Err = %v, want nil", msg.Err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no ForwardEndedMsg after Close")
	}

	waitFor(t, 5*time.Second, "forward to be marked dead", func() bool { return !f.Alive() })

	if m.GetForward(id) != nil {
		t.Fatal("closed forward still registered")
	}
	if len(m.Forwards()) != 0 {
		t.Fatalf("closed forward still listed: %d", len(m.Forwards()))
	}

	// The listener must have stopped accepting.
	if c, err := net.DialTimeout("tcp", bound, 500*time.Millisecond); err == nil {
		_ = c.Close()
		t.Fatal("forward listener still accepting after Close")
	}
}

func TestForwardConnectionDeathEnds(t *testing.T) {
	rec := newRecorder()
	echo := echoListener(t)
	ts, srv := startForwardServer(t, testPassword)
	m := forwardManager(t, rec)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	spec := ForwardSpec{Kind: ForwardLocal, TargetAddr: "127.0.0.1", TargetPort: portOf(t, echo.Addr().String())}
	f, err := m.StartForward(ctx, forwardSpec(ts), spec)
	if err != nil {
		t.Fatalf("StartForward: %v", err)
	}

	// Killing the server drops the SSH connection under the forward.
	_ = srv.Close()

	select {
	case msg := <-rec.forwardEndedCh:
		if msg.Err == nil {
			t.Fatal("connection death reported nil Err, want non-nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no ForwardEndedMsg after connection death")
	}

	waitFor(t, 5*time.Second, "forward to be marked dead", func() bool { return !f.Alive() })
}

func TestForwardCloseAll(t *testing.T) {
	rec := newRecorder()
	echo := echoListener(t)
	ts, _ := startForwardServer(t, testPassword)
	m := forwardManager(t, rec)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	spec := ForwardSpec{Kind: ForwardLocal, TargetAddr: "127.0.0.1", TargetPort: portOf(t, echo.Addr().String())}
	f, err := m.StartForward(ctx, forwardSpec(ts), spec)
	if err != nil {
		t.Fatalf("StartForward: %v", err)
	}

	m.CloseAll()

	select {
	case <-rec.forwardEndedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("CloseAll did not end the forward")
	}
	waitFor(t, 5*time.Second, "forward dead after CloseAll", func() bool { return !f.Alive() })
	if len(m.Forwards()) != 0 {
		t.Fatalf("forwards remain after CloseAll: %d", len(m.Forwards()))
	}
}
