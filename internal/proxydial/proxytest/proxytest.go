// Package proxytest provides in-process SOCKS5 and HTTP CONNECT proxies for
// tests. It lives outside _test.go files so both proxydial's own tests and the
// sshx engine tests can dial through the same stubs.
package proxytest

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// Proxy is a running stub proxy.
type Proxy struct {
	Addr string // host:port to point a proxy URL at

	ln       net.Listener
	upstream string // where every tunnel actually lands; "" = the requested target
	dials    atomic.Int64
	mu       sync.Mutex
	targets  []string
}

// Target is the sentinel hostname tests ask a proxy to reach. It is a name
// rather than 127.0.0.1 because proxydial (via x/net/httpproxy) always dials
// loopback directly — proxying a connection to your own machine makes no sense
// in production, and a loopback target would silently make these tests vacuous.
// The .invalid TLD is guaranteed never to resolve (RFC 6761), so a dial that
// escapes the proxy fails loudly instead of connecting by luck.
const Target = "wharf-test.invalid:2222"

// Dials reports how many tunnels the proxy was asked to open. A test that only
// asserts "the connection worked" cannot tell a proxied dial from a direct one;
// this is what makes the difference observable.
func (p *Proxy) Dials() int { return int(p.dials.Load()) }

// Targets lists the addresses the proxy was asked to reach, in order.
func (p *Proxy) Targets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...)
}

func (p *Proxy) record(target string) {
	p.dials.Add(1)
	p.mu.Lock()
	p.targets = append(p.targets, target)
	p.mu.Unlock()
}

// StartSOCKS5 runs a SOCKS5 proxy until the test ends. Every tunnel lands on
// upstream regardless of the address requested, so tests can ask for Target and
// still reach a local server. If user is non-empty the proxy demands
// username/password authentication and rejects anything else.
func StartSOCKS5(t *testing.T, upstream, user, pass string) *Proxy {
	t.Helper()
	p := listen(t)
	p.upstream = upstream
	go p.serve(func(c net.Conn) error { return p.socks5(c, user, pass) })
	return p
}

// StartCONNECT runs an HTTP proxy speaking CONNECT until the test ends, with
// the same upstream redirection as StartSOCKS5. If user is non-empty the proxy
// answers unauthenticated requests with 407.
func StartCONNECT(t *testing.T, upstream, user, pass string) *Proxy {
	t.Helper()
	p := listen(t)
	p.upstream = upstream
	go p.serve(func(c net.Conn) error { return p.connect(c, user, pass) })
	return p
}

// dial opens the upstream connection for a recorded target.
func (p *Proxy) dial(target string) (net.Conn, error) {
	if p.upstream != "" {
		return net.Dial("tcp", p.upstream)
	}
	return net.Dial("tcp", target)
}

func listen(t *testing.T) *Proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxytest: listen: %v", err)
	}
	p := &Proxy{Addr: ln.Addr().String(), ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	return p
}

// serve accepts until the listener closes. Handler errors are dropped rather
// than failing the test: several cases deliberately provoke them, and a client
// that hangs up mid-handshake is not a proxy bug.
func (p *Proxy) serve(handle func(net.Conn) error) {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			_ = handle(c)
		}()
	}
}

// socks5 implements just enough of RFC 1928 to tunnel a TCP connection.
func (p *Proxy) socks5(c net.Conn, user, pass string) error {
	br := bufio.NewReader(c)

	ver, err := br.ReadByte()
	if err != nil || ver != 5 {
		return fmt.Errorf("bad version %d", ver)
	}
	n, err := br.ReadByte()
	if err != nil {
		return err
	}
	methods := make([]byte, n)
	if _, err := io.ReadFull(br, methods); err != nil {
		return err
	}

	want := byte(0x00) // no auth
	if user != "" {
		want = 0x02 // username/password
	}
	if !contains(methods, want) {
		_, _ = c.Write([]byte{5, 0xff})
		return fmt.Errorf("no acceptable method")
	}
	if _, err := c.Write([]byte{5, want}); err != nil {
		return err
	}

	if want == 0x02 {
		// RFC 1929: ver, ulen, uname, plen, passwd.
		if v, err := br.ReadByte(); err != nil || v != 1 {
			return fmt.Errorf("bad auth version")
		}
		gotUser, err := readByteString(br)
		if err != nil {
			return err
		}
		gotPass, err := readByteString(br)
		if err != nil {
			return err
		}
		if gotUser != user || gotPass != pass {
			_, _ = c.Write([]byte{1, 1})
			return fmt.Errorf("bad credentials")
		}
		if _, err := c.Write([]byte{1, 0}); err != nil {
			return err
		}
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(br, head); err != nil {
		return err
	}
	if head[0] != 5 || head[1] != 1 { // CONNECT only
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("unsupported command %d", head[1])
	}

	var host string
	switch head[3] {
	case 1: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return err
		}
		host = net.IP(b).String()
	case 3: // domain
		l, err := br.ReadByte()
		if err != nil {
			return err
		}
		b := make([]byte, l)
		if _, err := io.ReadFull(br, b); err != nil {
			return err
		}
		host = string(b)
	case 4: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return err
		}
		host = net.IP(b).String()
	default:
		return fmt.Errorf("unsupported address type %d", head[3])
	}
	var port uint16
	if err := binary.Read(br, binary.BigEndian, &port); err != nil {
		return err
	}

	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	p.record(target)

	up, err := p.dial(target)
	if err != nil {
		_, _ = c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return err
	}
	defer up.Close()

	// Success, with a zero BND.ADDR — clients here never look at it.
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	splice(c, br, up)
	return nil
}

// connect implements the HTTP CONNECT method.
func (p *Proxy) connect(c net.Conn, user, pass string) error {
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}
	if req.Method != http.MethodConnect {
		_, _ = io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
		return fmt.Errorf("method %s", req.Method)
	}
	if user != "" {
		want := "Basic " + basic(user, pass)
		if req.Header.Get("Proxy-Authorization") != want {
			_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
			return fmt.Errorf("bad credentials")
		}
	}

	target := req.Host
	if !strings.Contains(target, ":") {
		target = net.JoinHostPort(target, "443")
	}
	p.record(target)

	up, err := p.dial(target)
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return err
	}
	defer up.Close()

	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return err
	}
	splice(c, br, up)
	return nil
}

// splice copies in both directions until either side is done. Reads from the
// client go through br so anything it buffered during the handshake is not lost.
func splice(c net.Conn, br *bufio.Reader, up net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(up, br)
		if t, ok := up.(*net.TCPConn); ok {
			_ = t.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(c, up)
		if t, ok := c.(*net.TCPConn); ok {
			_ = t.CloseWrite()
		}
	}()
	wg.Wait()
}

func readByteString(br *bufio.Reader) (string, error) {
	n, err := br.ReadByte()
	if err != nil {
		return "", err
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(br, b); err != nil {
		return "", err
	}
	return string(b), nil
}

func contains(b []byte, want byte) bool {
	for _, v := range b {
		if v == want {
			return true
		}
	}
	return false
}

func basic(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}
