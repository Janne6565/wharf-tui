//go:build !windows

package ui

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/Janne6565/wharf-tui/internal/sessd"
	gliderssh "github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

const stubPassword = "hunter2"

// TestMain doubles as the session-host binary for the picker tests: the pool
// re-executes this test binary, exactly as the TUI re-executes wharf, so the
// picker is exercised against real sessions in real child processes.
func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == sessd.SessionHostFlag {
		f := os.NewFile(3, "listener")
		if f == nil {
			os.Exit(1)
		}
		ln, err := net.FileListener(f)
		if err != nil {
			os.Exit(1)
		}
		_ = sessd.Serve(ln, os.Args[2])
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type stubSSHD struct {
	host       string
	port       int
	knownHosts string
}

// startStubSSHD runs an echoing, password-authenticating sshd on 127.0.0.1:0
// with a scratch known_hosts, so seeded sessions are genuinely connected.
func startStubSSHD(t *testing.T) *stubSSHD {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	srv := &gliderssh.Server{
		Handler: func(s gliderssh.Session) {
			_, winCh, isPty := s.Pty()
			if isPty {
				go func() {
					for range winCh {
					}
				}()
			}
			_, _ = io.Copy(s, s)
		},
		PasswordHandler: func(_ gliderssh.Context, pass string) bool { return pass == stubPassword },
	}
	srv.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close(); _ = ln.Close() })

	return &stubSSHD{
		host:       "127.0.0.1",
		port:       ln.Addr().(*net.TCPAddr).Port,
		knownHosts: filepath.Join(t.TempDir(), "known_hosts"),
	}
}
