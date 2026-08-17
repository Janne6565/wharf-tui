//go:build !windows

package remoteaccess

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// sockSuffix marks the socket files this package owns, matching sessd's.
const sockSuffix = ".sock"

// Dial finds the grant whose token matches and runs one command through it,
// returning the remote exit code.
//
// It scans the grants directory and runs the challenge–response handshake
// against each socket in turn. That is why the socket path never has to be
// handed to the caller — and why a wrong token cannot be used to enumerate
// anything: every failure, from an empty directory to a rejected token to a
// socket that died mid-scan, comes back as ErrNoGrant.
//
// Note what is *not* happening: the token is never sent. Walking a shared
// directory and handing the secret to whatever answers is how a same-uid
// attacker collects tokens for grants it was never given — it only has to bind a
// socket that sorts first. The handshake proves knowledge of the token in both
// directions instead, so a planted socket learns nothing it can replay and never
// gets to see the command.
//
// The remote's exit code is returned verbatim with a nil error; a non-zero
// remote exit is not a Go error. A non-nil error means the command did not run,
// or did not finish, which is the caller's cue to use its own failure exit code
// rather than the remote's.
func Dial(ctx context.Context, token string, req Request, stdout, stderr io.Writer) (int, error) {
	if token == "" {
		return 0, ErrNoGrant
	}
	dir, err := grantsDir()
	if err != nil {
		return 0, err
	}
	socks, err := listGrantSockets(dir)
	if err != nil {
		return 0, err
	}
	for _, sock := range socks {
		c, err := net.DialTimeout("unix", sock, dialTimeout)
		if err != nil {
			// A socket with nobody behind it is left alone rather than
			// unlinked: this process is a short-lived client that may not even
			// own the grant, and a running wharf unlinks its own socket on
			// revocation.
			continue
		}
		ok, err := authenticate(c, token, filepath.Base(sock))
		if err != nil || !ok {
			_ = c.Close()
			continue
		}
		defer c.Close()
		return runCommand(ctx, c, req, stdout, stderr)
	}
	return 0, ErrNoGrant
}

// listGrantSockets returns the candidate sockets in dir. A missing directory is
// not an error: it only means no grant has ever been opened on this machine.
func listGrantSockets(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), sockSuffix) {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	return out, nil
}

// authenticate performs the mandatory handshake against one candidate socket.
// It reports whether this socket both accepted our proof and produced its own;
// any other outcome — a rejection, a mute peer, a garbled reply, a peer that
// cannot prove it holds the token — is "not this one", never a reason to report
// something specific about the grant on the other end.
//
// The server's proof is checked *before* the caller is allowed to send the
// command. That ordering is the whole defence against a rogue listener in the
// grants directory: it can accept a connection and say anything it likes, but it
// cannot compute a MAC over a token it does not have, so it never sees the argv
// and never gets to answer with fabricated output.
func authenticate(c net.Conn, token, sockName string) (bool, error) {
	_ = c.SetDeadline(time.Now().Add(dialTimeout))
	// The server speaks first. Reads are capped at the handshake's true size so
	// a hostile peer cannot make the client allocate either.
	kind, serverNonce, err := readFrameLimit(c, maxHandshakeFrame)
	if err != nil {
		return false, err
	}
	if kind != kindChallenge || len(serverNonce) != nonceLen {
		return false, nil
	}
	var clientNonce [nonceLen]byte
	if _, err := rand.Read(clientNonce[:]); err != nil {
		return false, err
	}
	// The client's nonce goes in the same frame as the proof: it costs nothing
	// and it means neither side can pick the whole transcript, so neither can
	// steer the other into MACing something it precomputed.
	proof := make([]byte, 0, nonceLen+macLen)
	proof = append(proof, clientNonce[:]...)
	proof = append(proof, handshakeMAC(token, macLabelClient, serverNonce, clientNonce[:], sockName)...)
	if err := writeFrame(c, kindAuth, proof); err != nil {
		return false, err
	}
	kind, reply, err := readFrameLimit(c, maxHandshakeFrame)
	if err != nil {
		return false, err
	}
	if kind != kindAuthOK {
		return false, nil
	}
	want := handshakeMAC(token, macLabelServer, serverNonce, clientNonce[:], sockName)
	if subtle.ConstantTimeCompare(reply, want) != 1 {
		return false, nil
	}
	_ = c.SetDeadline(time.Time{})
	return true, nil
}

// runCommand sends the request and pumps output frames until the command ends.
func runCommand(ctx context.Context, c net.Conn, req Request, stdout, stderr io.Writer) (int, error) {
	if err := writeJSON(c, kindRun, runRequest{
		Command:   req.Command,
		Stdin:     req.Stdin,
		TimeoutMs: int(req.Timeout / time.Millisecond),
	}); err != nil {
		return 0, err
	}
	// Cancellation is delivered by closing the connection, which is the only
	// thing that unblocks a read on a socket; the server sees the hangup and
	// cancels the command with it.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-done:
		}
	}()

	for {
		kind, payload, err := readFrame(c)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return 0, ctxErr
			}
			return 0, err
		}
		switch kind {
		case kindOut:
			var out outFrame
			if err := json.Unmarshal(payload, &out); err != nil {
				return 0, err
			}
			w := stdout
			if out.Stream == "err" {
				w = stderr
			}
			if w != nil {
				if _, err := w.Write(out.Data); err != nil {
					return 0, err
				}
			}
		case kindEnd:
			var end endFrame
			if err := json.Unmarshal(payload, &end); err != nil {
				return 0, err
			}
			if end.Err != "" {
				return end.Code, errors.New(end.Err)
			}
			return end.Code, nil
		case kindError:
			var e errFrame
			if err := json.Unmarshal(payload, &e); err != nil {
				return 0, err
			}
			return 0, errors.New(e.Err)
		default:
			// An unknown frame kind means the peer is a different build of
			// wharf. Refusing beats guessing at a stream we cannot frame.
			return 0, errors.New("remoteaccess: unexpected frame from the grant")
		}
	}
}
