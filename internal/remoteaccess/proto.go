package remoteaccess

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// frameKind tags a protocol frame. The numbering mirrors sessd's convention —
// low numbers client → server, twenties server → client — so the two protocols
// read the same way even though they never share a socket.
type frameKind byte

const (
	// client → server
	kindAuth frameKind = 1 // clientNonce ‖ client MAC; mandatory first client frame
	kindRun  frameKind = 2 // JSON runRequest

	// server → client
	kindAuthOK    frameKind = 20 // server MAC, proving the server holds the token too
	kindOut       frameKind = 21 // JSON outFrame
	kindEnd       frameKind = 22 // JSON endFrame
	kindError     frameKind = 23 // JSON errFrame
	kindChallenge frameKind = 24 // serverNonce; the very first frame on a connection
)

// maxFrame caps a single frame's payload, so a corrupt or hostile length
// cannot drive an unbounded allocation — the length is checked before any
// buffer is made, which is the whole point of having the constant. It doubles
// as the cap on forwarded stdin, which v1 sends in the request rather than
// streaming.
const maxFrame = 1 << 20

// nonceLen and macLen size the handshake. 32 random bytes per side is far more
// than the birthday bound needs; it is the same width as the token's entropy so
// there is one number to reason about.
const (
	nonceLen = 32
	macLen   = sha256.Size
)

// maxHandshakeFrame is the exact size of the largest handshake frame — a
// challenge is nonceLen bytes and an auth frame is nonceLen+macLen — and every
// pre-authentication read is capped at it rather than at maxFrame.
//
// The generic cap is a megabyte because a *command* may legitimately carry a
// megabyte of stdin. A peer that has not authenticated may carry 64 bytes, and
// letting it declare a megabyte anyway is how a few hundred connections turn
// into a few hundred megabytes of resident memory — measured, not theorised.
// Sizing the cap to the frame's true maximum removes the amplification entirely:
// the header is refused before a buffer exists.
const maxHandshakeFrame = nonceLen + macLen

// The handshake is a challenge–response, and the token never goes on the wire.
//
// The obvious design — the client sends the token, the server compares it — was
// implemented first and is broken: Dial has to offer its secret to every socket
// in the grants directory to find out which one owns it, and any process running
// as the same uid can bind a socket that sorts first (or unlink a live grant's
// socket and bind over it) and simply read the token off the first frame. That
// is the exact process the feature exists to constrain, and it would collect a
// token for a host it was never granted.
//
// So: the server opens with a random nonce, the client answers with
// HMAC-SHA256(token, transcript), and only the MAC is ever transmitted. The
// server answers with a MAC of its own over the same transcript under a
// different label, which the client verifies before it sends the command — a
// rogue listener cannot produce it, so it never learns what the agent was
// trying to run, and cannot feed it fabricated output.
//
// The transcript binds both nonces and the socket's *base name*. The name is
// what distinguishes a rogue socket from the real grant inside the shared
// grants directory, and binding it stops the relay attack the nonces alone
// leave open: a rogue that forwards the real grant's challenge gets back a MAC
// computed over its own name, which the real grant will not accept. The base
// name rather than the full path, because both sides must derive byte-identical
// strings and only the leaf is guaranteed to match without depending on how each
// side happened to clean the directory prefix.
//
// Residual, stated plainly: a same-uid attacker that unlinks a live grant's
// socket and binds its own at the identical name inside the authTimeout window
// can still relay. Nothing short of a channel binding the kernel provides for
// unix sockets would close that, and the directory mode is what is really
// holding the line there — the token was never the defence against a peer that
// can already rewrite our runtime directory.
const (
	macLabelClient = "wharf-remoteaccess-client-v1"
	macLabelServer = "wharf-remoteaccess-server-v1"
)

// handshakeMAC computes one side's proof over the whole transcript. The label
// keeps the two directions from being interchangeable: without it a rogue could
// echo the client's own MAC back as the server's proof.
func handshakeMAC(token, label string, serverNonce, clientNonce []byte, sockName string) []byte {
	h := hmac.New(sha256.New, []byte(token))
	// Every field but the last has a fixed width, so a plain concatenation is
	// unambiguous and needs no length prefixes.
	h.Write([]byte(label))
	h.Write([]byte{0})
	h.Write(serverNonce)
	h.Write(clientNonce)
	h.Write([]byte(sockName))
	return h.Sum(nil)
}

// outChunk caps one output frame's raw payload. Output is streamed
// continuously, so this only bounds latency and frame overhead; it leaves ample
// room for base64's 4/3 expansion inside maxFrame.
const outChunk = 32 * 1024

// runRequest is one command to run. There is no correlation ID: a connection
// carries exactly one command and then closes, which removes a whole class of
// cross-delivery bug the sessd exec path has to solve with a registry.
type runRequest struct {
	Command   string `json:"command"`
	Stdin     []byte `json:"stdin,omitempty"`
	TimeoutMs int    `json:"timeoutMs,omitempty"`
}

// outFrame is a chunk of the command's output. Stream is "out" or "err".
type outFrame struct {
	Stream string `json:"stream"`
	Data   []byte `json:"data"`
}

// endFrame terminates a command. Code is the remote exit status and is
// meaningful only when Err is empty.
type endFrame struct {
	Code int    `json:"code"`
	Err  string `json:"err,omitempty"`
}

// errFrame reports a request that never ran: a rejected token, a revoked or
// expired grant, too many commands at once.
type errFrame struct {
	Err string `json:"err"`
}

// errClosed is reported for a clean hangup at a frame boundary, so callers can
// tell it from a truncated frame.
var errClosed = errors.New("remoteaccess: connection closed")

// writeFrame emits one length-prefixed frame: kind, 4-byte big-endian length,
// payload. Callers serialize their own writes; see frameWriter for the side
// that has several goroutines writing at once.
func writeFrame(w io.Writer, kind frameKind, payload []byte) error {
	if len(payload) > maxFrame {
		return fmt.Errorf("remoteaccess: frame of %d bytes exceeds the %d limit "+
			"(stdin is sent in the request in v1, so it is capped there too)", len(payload), maxFrame)
	}
	var head [5]byte
	head[0] = byte(kind)
	binary.BigEndian.PutUint32(head[1:], uint32(len(payload)))
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// writeJSON marshals v and writes it as a frame of the given kind.
func writeJSON(w io.Writer, kind frameKind, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeFrame(w, kind, b)
}

// readFrame reads exactly one frame under the generic maxFrame cap. Callers on
// a not-yet-authenticated connection must use readFrameLimit with
// maxHandshakeFrame instead: a megabyte is what a command may cost, not what a
// stranger may.
func readFrame(r io.Reader) (frameKind, []byte, error) {
	return readFrameLimit(r, maxFrame)
}

// readFrameLimit reads exactly one frame, refusing any declared length over
// limit. The length is validated before the payload buffer is allocated: a peer
// that claims 4 GiB gets an error, not four gigabytes of resident memory, and a
// peer that claims a megabyte before authenticating gets one too.
func readFrameLimit(r io.Reader, limit uint32) (frameKind, []byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return 0, nil, errClosed
		}
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(head[1:])
	if n > limit {
		return 0, nil, fmt.Errorf("remoteaccess: frame length %d exceeds the %d limit", n, limit)
	}
	if n == 0 {
		return frameKind(head[0]), nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return frameKind(head[0]), buf, nil
}

// frameWriter serializes frames onto one connection. Exec streams stdout and
// stderr from separate goroutines, so without a lock the two would interleave
// mid-frame and desynchronise the client permanently.
type frameWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (fw *frameWriter) writeJSON(kind frameKind, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	fw.mu.Lock()
	defer fw.mu.Unlock()
	return writeFrame(fw.w, kind, b)
}

func (fw *frameWriter) writeFrame(kind frameKind, payload []byte) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	return writeFrame(fw.w, kind, payload)
}

// streamWriter turns the io.Writer that Exec streams into a sequence of outFrames.
type streamWriter struct {
	fw     *frameWriter
	stream string // "out" or "err"
}

func (sw *streamWriter) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		chunk := p
		if len(chunk) > outChunk {
			chunk = chunk[:outChunk]
		}
		if err := sw.fw.writeJSON(kindOut, outFrame{Stream: sw.stream, Data: chunk}); err != nil {
			return total - len(p), err
		}
		p = p[len(chunk):]
	}
	return total, nil
}
