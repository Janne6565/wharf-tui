package proxydial

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// connectTimeout bounds the CONNECT handshake when the caller's context has no
// deadline of its own. A proxy that accepts the TCP connection and then says
// nothing is a real failure mode, and it must not hang a dial forever.
const connectTimeout = 30 * time.Second

// dialConnect tunnels to addr through an HTTP proxy with CONNECT. This is
// hand-rolled because x/net/proxy speaks SOCKS only, and CONNECT is what most
// corporate proxies actually offer.
func dialConnect(ctx context.Context, pu *url.URL, addr string) (net.Conn, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, connectTimeout)
		defer cancel()
	}

	var dd net.Dialer
	conn, err := dd.DialContext(ctx, "tcp", pu.Host)
	if err != nil {
		return nil, fmt.Errorf("proxy %s: %w", pu.Host, err)
	}

	// An https:// proxy wants the CONNECT request itself encrypted; the tunnel
	// inside it is SSH either way.
	if strings.EqualFold(pu.Scheme, "https") {
		tc := tls.Client(conn, &tls.Config{ServerName: pu.Hostname()})
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("proxy %s: TLS handshake: %w", pu.Host, err)
		}
		conn = tc
	}

	// Deadlines are what actually interrupt the blocking read below; the
	// watcher covers a context cancelled without a deadline having been set.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if pu.User != nil {
		pw, _ := pu.User.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(pu.User.Username() + ":" + pw))
		req.Header.Set("Proxy-Authorization", "Basic "+cred)
	}
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy %s: sending CONNECT: %w", pu.Host, err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy %s: reading CONNECT response: %w", pu.Host, err)
	}
	// The body of a non-2xx CONNECT reply is an error page nobody wants in a
	// terminal; the status line carries the useful part.
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		if resp.StatusCode == http.StatusProxyAuthRequired {
			return nil, fmt.Errorf("proxy %s: %s (set credentials in the proxy URL)", pu.Host, resp.Status)
		}
		return nil, fmt.Errorf("proxy %s refused CONNECT to %s: %s", pu.Host, addr, resp.Status)
	}

	// The tunnel is open. SSH servers speak first, so the reader may already
	// hold banner bytes read along with the response headers — dropping br here
	// would eat the start of the SSH version string.
	_ = conn.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		peek, _ := br.Peek(br.Buffered())
		return &prefixConn{Conn: conn, pre: peek}, nil
	}
	return conn, nil
}

// prefixConn replays bytes that were buffered past the CONNECT response before
// reading anything further from the connection.
type prefixConn struct {
	net.Conn
	pre []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.pre) > 0 {
		n := copy(p, c.pre)
		c.pre = c.pre[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// interface guard: prefixConn must stay a drop-in net.Conn.
var _ io.ReadWriteCloser = (*prefixConn)(nil)
