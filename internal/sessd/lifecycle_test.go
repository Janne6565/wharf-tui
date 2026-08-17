//go:build !windows

package sessd

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Janne6565/wharf-tui/internal/sshx"
	tea "github.com/charmbracelet/bubbletea"
)

// hostGone reports whether the session host behind sock has exited: the socket
// is unlinked, or nothing is listening on it any more.
func hostGone(sock string) bool {
	if _, err := os.Stat(sock); os.IsNotExist(err) {
		return true
	}
	c, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		return true
	}
	_ = c.Close()
	return false
}

// waitGone fails unless every socket in dir belongs to a host that has exited.
func waitGone(t *testing.T, dir string) {
	t.Helper()
	waitFor(t, "the session host to exit", func() bool {
		socks, err := listSockets(dir)
		if err != nil {
			return false
		}
		for _, s := range socks {
			if !hostGone(s) {
				return false
			}
		}
		return true
	})
}

// A client that gives up while an auth prompt is outstanding used to strand the
// child forever: the prompt relay waited on a reply that could never arrive and
// the dial ran on a context nobody could cancel.
func TestClientVanishingMidPromptRetiresTheHost(t *testing.T) {
	ts := startServer(t)
	sockDir, knownHosts := tempDirs(t)
	pool, _ := newPool(t, sockDir, knownHosts)

	ctx, cancel := context.WithCancel(context.Background())
	prompted := make(chan struct{})
	pool.SetNotify(func(msg tea.Msg) {
		if _, ok := msg.(sshx.HostKeyPromptMsg); ok {
			close(prompted)
			cancel() // the TUI quit: Pool.Dial drops the control connection
		}
	})

	done := make(chan struct{})
	go func() { defer close(done); _, _ = pool.Dial(ctx, ts.spec(), 80, 24) }()
	<-prompted
	<-done

	waitGone(t, sockDir)
}

// A session that completes after its client left cannot be reattached to by
// anyone, so it must not be left running.
func TestSessionCompletedAfterClientLeftIsNotOrphaned(t *testing.T) {
	ts := startServer(t)
	sockDir, knownHosts := tempDirs(t)
	pool, _ := newPool(t, sockDir, knownHosts)

	// Answer the host key, then drop the client while the shell is starting.
	ctx, cancel := context.WithCancel(context.Background())
	pool.SetNotify(func(msg tea.Msg) {
		if m, ok := msg.(sshx.HostKeyPromptMsg); ok {
			m.Reply <- true
			cancel()
		}
	})
	done := make(chan struct{})
	go func() { defer close(done); _, _ = pool.Dial(ctx, ts.spec(), 80, 24) }()
	<-done

	waitGone(t, sockDir)
}

// A host whose client never arrives retires itself instead of sitting on a
// socket for the rest of the login session.
func TestHostWithoutAClientRetiresItself(t *testing.T) {
	restore := idleGrace
	idleGrace = 2 * time.Second // the watchdog ticks once a second
	t.Cleanup(func() { idleGrace = restore })

	sockDir, _ := tempDirs(t)
	sock, err := socketPath(sockDir, "h1")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan struct{})
	go func() { defer close(served); _ = Serve(ln, sock) }()

	select {
	case <-served:
	case <-time.After(idleGrace + 15*time.Second):
		t.Fatal("a host with no session and no clients should exit after idleGrace")
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatal("the retiring host should unlink its socket")
	}
}

// Adoption must retire a reachable host that has nothing running, or its socket
// is re-probed on every start.
func TestAdoptRetiresSessionlessHost(t *testing.T) {
	sockDir, knownHosts := tempDirs(t)
	sock, err := socketPath(sockDir, "h1")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = Serve(ln, sock) }()

	// Wait for the host to come up — but with a connection that stays open, and
	// with a real round trip.
	//
	// Not hostGone: it dials and hangs up, and Host.drop reads "no session and
	// no clients left" as "nothing can ever give this process a purpose" and
	// shuts the host down. So a throwaway probe retires the very host this test
	// is about to adopt. Adopt then races that shutdown — its connection is
	// broken, or is handed kindEnded, before the info reply arrives — takes the
	// deliberate "reachable but not answering, leave the socket" branch, and
	// the socket survives until Serve's goroutine gets around to unlinking it,
	// which is asynchronous with respect to the assertion below. That is the
	// flake, and it is the probe's doing, not Adopt's.
	//
	// A dial alone would not prove readiness either: a bound unix socket
	// completes a connect from the backlog even if nothing is accepting yet.
	// One kindInfo round trip proves the accept loop is actually serving, and
	// holding the connection keeps the host alive until Adopt has had its turn,
	// which is what this test set out to measure.
	probe, err := net.DialTimeout("unix", sock, 10*time.Second)
	if err != nil {
		t.Fatalf("the host should be accepting connections: %v", err)
	}
	defer func() { _ = probe.Close() }()
	if err := writeFrame(probe, kindInfo, nil); err != nil {
		t.Fatalf("probing the host: %v", err)
	}
	if err := probe.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if kind, _, err := readFrame(probe); err != nil || kind != kindInfoOK {
		t.Fatalf("the host should answer an info probe, got kind %d, err %v", kind, err)
	}

	pool, _ := newPool(t, sockDir, knownHosts)
	n, err := pool.Adopt()
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if n != 0 {
		t.Fatalf("a sessionless host should not be adopted, got %d", n)
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatal("adoption should unlink the socket of a host with no session")
	}
}

// fakeConn is a net.Conn that swallows writes, for exercising the frame writer
// without a peer.
type fakeConn struct{ net.Conn }

func (fakeConn) Write(p []byte) (int, error) { return len(p), nil }
func (fakeConn) Close() error                { return nil }

// The output writer is handed to sshx's tee, which is an io.Copy-shaped
// consumer: a short write that reports no error is a contract violation waiting
// to truncate a stream.
func TestConnOutWriteReportsBytesWritten(t *testing.T) {
	c := &conn{net: fakeConn{}}
	for _, size := range []int{0, 1, outChunk, outChunk + 1, 3*outChunk + 7} {
		n, err := c.outWriter().Write(make([]byte, size))
		if err != nil {
			t.Fatalf("write of %d bytes: %v", size, err)
		}
		if n != size {
			t.Fatalf("write of %d bytes reported n=%d", size, n)
		}
	}
}

// The socket directory's parent must be ours and private: owning it is enough
// to swap the directory the sockets live in.
func TestRuntimeDirRejectsAWritableParent(t *testing.T) {
	base, err := os.MkdirTemp("/tmp", "wh-p")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WHARF_RUNTIME_DIR", base)

	if _, err := RuntimeDir(); err == nil {
		t.Fatal("a group/world-writable parent should be refused")
	} else if !strings.Contains(err.Error(), "writable by group or others") {
		t.Fatalf("the refusal should say why, got: %v", err)
	}

	// Tightened, it is accepted again — and the socket directory is private.
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	dir, err := RuntimeDir()
	if err != nil {
		t.Fatalf("a private parent should be accepted: %v", err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("socket directory should be 0700, got %#o", fi.Mode().Perm())
	}
}

// A child is spawned with no terminal, so its stderr has to land somewhere; a
// clean exit must not leave the log behind.
func TestSessionHostLogIsRemovedOnCleanExit(t *testing.T) {
	ts := startServer(t)
	sockDir, knownHosts := tempDirs(t)
	pool, _ := newPool(t, sockDir, knownHosts)

	r, err := pool.Dial(context.Background(), ts.spec(), 80, 24)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	logPath := logPathFor(r.sock)
	if _, err := os.Stat(logPath); err != nil {
		t.Fatalf("a spawned host should have a stderr log at %s: %v", logPath, err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	waitFor(t, "the log to be cleaned up", func() bool {
		_, err := os.Stat(logPath)
		return os.IsNotExist(err)
	})
}

// New sessions must be dialed with the current keep-alive preference, which is
// only known once the vault is unlocked — after the pool is built.
func TestPoolKeepaliveIsSettable(t *testing.T) {
	sockDir, _ := tempDirs(t)
	p := NewPool(sockDir, "", true)
	if !p.Keepalive() {
		t.Fatal("the pool should start on the value it was built with")
	}
	p.SetKeepalive(false)
	if p.Keepalive() {
		t.Fatal("SetKeepalive should take effect")
	}
}
