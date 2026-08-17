//go:build !windows

// Package sessd makes SSH sessions outlive the wharf process.
//
// Each connection runs in its own child process ("session host"): the TUI forks
// `wharf --session-host`, hands it a listening unix socket, and the child owns
// the ssh.Client, the PTY and the scrollback ring for that one session. The TUI
// attaches over the socket and proxies bytes to the terminal; quitting wharf
// simply disconnects, and the child keeps the shell alive. A later run scans the
// socket directory and reattaches.
//
// One session per child is deliberate. There is no singleton daemon to
// supervise, no version handshake across upgrades, and a crash takes down one
// session rather than all of them.
//
// Trust model: the socket directory is 0700 under $XDG_RUNTIME_DIR (falling back
// to a user-owned dir under TMPDIR) and every socket is 0600. Anyone who can
// open the socket can type into the shell — the same exposure tmux and OpenSSH's
// ControlMaster accept. The child never sees the master password and never holds
// the vault: it receives one host spec, uses it to authenticate, and keeps only
// what the live connection needs.
package sessd

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// frameKind tags a protocol frame. Values are explicit because both sides of a
// socket may be different wharf builds — a child from before an upgrade is still
// serving when the new binary reattaches.
type frameKind byte

const (
	// client → host
	kindDial        frameKind = 1 // JSON dialRequest: authenticate and start the shell
	kindAttach      frameKind = 2 // JSON attachRequest: begin streaming to this client
	kindData        frameKind = 3 // raw bytes for the remote stdin
	kindResize      frameKind = 4 // JSON resizeRequest
	kindDetach      frameKind = 5 // stop streaming; the session stays alive
	kindInfo        frameKind = 6 // request an infoResponse
	kindKill        frameKind = 7 // terminate the session and exit
	kindPromptReply frameKind = 8 // JSON promptReply, answering a kindPrompt
	kindExec        frameKind = 9 // JSON execRequest: run a command in its own channel

	// host → client
	kindOutput  frameKind = 20 // raw bytes from the remote
	kindPrompt  frameKind = 21 // JSON promptRequest: TOFU or a secret
	kindInfoOK  frameKind = 22 // JSON infoResponse
	kindDialOK  frameKind = 23 // the shell is running
	kindEnded   frameKind = 24 // JSON endedNotice: the session is over
	kindError   frameKind = 25 // JSON errorNotice: the request failed
	kindExecOut frameKind = 26 // JSON execOutput: a chunk of an exec's output
	kindExecEnd frameKind = 27 // JSON execEnd: that exec is over
)

// maxFrame caps a single frame's payload. Output frames are chunked well below
// this; the limit exists so a corrupt or hostile length can't drive an
// unbounded allocation.
const maxFrame = 1 << 20

// protocolVersion is reported in infoResponse. A client that does not
// understand a host's version refuses to attach rather than mis-framing its
// stream; the socket is still listed, so the session can be killed.
//
// Version 2 added exec (kindExec/kindExecOut/kindExecEnd). The bump matters
// because sessions deliberately outlive the TUI: the moment after an upgrade,
// the hosts still running are all version 1, and a version-1 host drops an
// unknown frame kind on the floor without so much as an error frame. A client
// that assumed exec worked would wait for a reply that is never coming.
const protocolVersion = 2

// minAdoptProtocol is the oldest host a client will adopt. Version 2 is purely
// additive — it introduced new frame kinds and changed the meaning of none — so
// refusing a version-1 host would orphan every session running under the
// binary the user just upgraded from, to buy nothing. Adoption records the
// version instead and features negotiate against it (see execProtocol).
//
// The asymmetry is deliberate: an older host is adopted, a *newer* one is still
// refused. A newer host may send kinds this build has no case for, and those
// fall through readLoop's default into ctl, where they would be mistaken for
// somebody's dial or info reply.
const minAdoptProtocol = 1

// execProtocol is the first protocol version that can run an exec. A host below
// it is not broken, it is simply older than the feature.
const execProtocol = 2

// promptKind distinguishes the two interactive prompts the auth chain raises.
const (
	promptHostKey = "hostkey"
	promptSecret  = "secret"
)

// dialRequest carries the connection recipe. It holds secrets (a stored
// password, private key material) and therefore only ever travels over the
// 0600 socket — never argv, never the environment.
type dialRequest struct {
	Spec       hostSpecWire `json:"spec"`
	Cols       int          `json:"cols"`
	Rows       int          `json:"rows"`
	KnownHosts string       `json:"knownHosts"`
	Keepalive  bool         `json:"keepalive"`
	Term       string       `json:"term"`
	// Proxy is the egress proxy URL resolved by the parent, credentials and
	// all — which is exactly why it travels here and not in the child's
	// environment, where any process on the machine could read it. Empty means
	// a direct connection: the child must not consult $ALL_PROXY itself, or an
	// adopted session would silently use a different network path than the run
	// that spawned it.
	Proxy string `json:"proxy,omitempty"`
}

// hostSpecWire mirrors sshx.HostSpec on the wire. It is spelled out here rather
// than reusing the struct so a field added to the engine's spec cannot silently
// change the protocol.
type hostSpecWire struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	User       string        `json:"user"`
	Addr       string        `json:"addr"`
	Port       int           `json:"port"`
	KeyPath    string        `json:"keyPath,omitempty"`
	AuthMethod string        `json:"authMethod,omitempty"`
	Password   string        `json:"password,omitempty"`
	VaultKeys  []vaultKeyWir `json:"vaultKeys,omitempty"`
}

type vaultKeyWir struct {
	Name string `json:"name"`
	PEM  []byte `json:"pem"`
}

type attachRequest struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
}

type resizeRequest struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
}

// promptRequest is an auth prompt relayed from the engine to whichever client
// asked for the dial. Only the fields relevant to Kind are set.
type promptRequest struct {
	Kind        string `json:"kind"`
	Title       string `json:"title,omitempty"`
	Detail      string `json:"detail,omitempty"`
	Echo        bool   `json:"echo,omitempty"`
	Host        string `json:"host,omitempty"`
	KeyType     string `json:"keyType,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// promptReply answers a promptRequest. Canceled cancels authentication;
// for a host-key prompt Accept decides TOFU, for a secret Secret carries the
// bytes.
type promptReply struct {
	Accept   bool   `json:"accept,omitempty"`
	Secret   []byte `json:"secret,omitempty"`
	Canceled bool   `json:"canceled,omitempty"`
}

// infoResponse describes a session host to a client that just found its socket.
type infoResponse struct {
	Protocol  int    `json:"protocol"`
	PID       int    `json:"pid"`
	HostID    string `json:"hostId"`
	HostName  string `json:"hostName"`
	User      string `json:"user"`
	Addr      string `json:"addr"`
	Port      int    `json:"port"`
	StartedAt int64  `json:"startedAt"` // unix seconds
	Alive     bool   `json:"alive"`
	Attached  bool   `json:"attached"` // another client is streaming
	Cols      int    `json:"cols"`
	Rows      int    `json:"rows"`
}

// execRequest asks the host to run one non-interactive command. Every frame of
// the exchange carries ID, because several execs may be in flight on the same
// socket at once and the socket is a single ordered byte stream: without an
// explicit correlation id there is nothing to tell one command's stdout from
// another's. The id is minted by the client, which is the side that has to
// match replies to callers.
type execRequest struct {
	ID      string `json:"id"` // correlation id, client-generated
	Command string `json:"command"`
	Stdin   []byte `json:"stdin,omitempty"`
	Timeout int    `json:"timeoutMs,omitempty"`
	// Cancel turns the frame into a cancellation of the exec already running
	// under ID rather than a new one. It is a flag on this struct instead of a
	// fourth frame kind because the alternative — letting a canceled client just
	// stop listening — leaves the command running on the real host for as long
	// as it likes, which is exactly the authority a revocable grant is supposed
	// to be able to withdraw. A host from an older build ignores the field and
	// merely finishes the command, which is the pre-existing behaviour.
	Cancel bool `json:"cancel,omitempty"`
}

// execOutput is one chunk of an exec's output. Data is chunked well below
// maxFrame by the host (see execWriter): it is base64-encoded by encoding/json,
// so the frame is roughly a third larger than the bytes it carries.
type execOutput struct {
	ID     string `json:"id"`
	Stream string `json:"stream"` // "out" | "err"
	Data   []byte `json:"data"`   // base64 in JSON
}

// execEnd terminates an exec exactly once, whether it ran or not. Code is the
// remote exit status and is meaningful only when Err is empty: a command that
// ran and failed is a code, while Err means wharf never learned an outcome.
type execEnd struct {
	ID   string `json:"id"`
	Code int    `json:"code"`
	Err  string `json:"err,omitempty"`
}

// execStreamOut and execStreamErr name the two streams an exec multiplexes over
// one socket. They are strings rather than a bool so a third stream could be
// added without changing the meaning of frames already on the wire.
const (
	execStreamOut = "out"
	execStreamErr = "err"
)

type endedNotice struct {
	Err string `json:"err,omitempty"`
}

type errorNotice struct {
	Err string `json:"err"`
}

// ErrClosed is returned when the peer hung up mid-conversation.
var ErrClosed = errors.New("sessd: connection closed")

// writeFrame emits one length-prefixed frame: kind, 4-byte big-endian length,
// payload. Callers serialize their own writes.
func writeFrame(w io.Writer, kind frameKind, payload []byte) error {
	if len(payload) > maxFrame {
		return fmt.Errorf("sessd: frame of %d bytes exceeds the %d limit", len(payload), maxFrame)
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

// readFrame reads exactly one frame. A clean EOF at a frame boundary is
// reported as ErrClosed so callers can distinguish a hangup from a truncation.
func readFrame(r io.Reader) (frameKind, []byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return 0, nil, ErrClosed
		}
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(head[1:])
	if n > maxFrame {
		return 0, nil, fmt.Errorf("sessd: frame length %d exceeds the %d limit", n, maxFrame)
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
