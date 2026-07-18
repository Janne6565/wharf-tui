package sshx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
)

// Minimal SOCKS5 (RFC 1928) server backing dynamic (-D) forwards. Only the
// no-auth method and the CONNECT command are supported — enough for a browser
// or CLI to tunnel TCP through the SSH connection, with no external dependency.
const (
	socks5Version = 0x05

	socksNoAuth       = 0x00 // the only auth method we accept
	socksNoAcceptable = 0xFF // "no acceptable methods" reply to method selection

	socksCmdConnect = 0x01 // the only command we serve

	socksATYPIPv4   = 0x01
	socksATYPDomain = 0x03
	socksATYPIPv6   = 0x04

	socksReplySuccess          = 0x00
	socksReplyGeneralFailure   = 0x01
	socksReplyHostUnreachable  = 0x04
	socksReplyConnRefused      = 0x05
	socksReplyCmdNotSupported  = 0x07
	socksReplyAddrNotSupported = 0x08
)

// socks5Negotiate runs the greeting and CONNECT request exchange on conn and
// returns the requested "host:port" target. It reads exactly the protocol bytes
// (no buffering) so the caller can pipe conn directly afterwards. On a protocol
// violation it writes the appropriate failure reply before returning an error;
// the caller only needs to close conn.
func socks5Negotiate(conn net.Conn) (string, error) {
	// Greeting: VER, NMETHODS, METHODS.
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}
	if header[0] != socks5Version {
		return "", fmt.Errorf("socks5: unsupported version 0x%02x", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}
	if !bytes.Contains(methods, []byte{socksNoAuth}) {
		_, _ = conn.Write([]byte{socks5Version, socksNoAcceptable})
		return "", errors.New("socks5: client offered no acceptable auth method")
	}
	if _, err := conn.Write([]byte{socks5Version, socksNoAuth}); err != nil {
		return "", err
	}

	// Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT.
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return "", err
	}
	if req[0] != socks5Version {
		return "", fmt.Errorf("socks5: unsupported request version 0x%02x", req[0])
	}
	if req[1] != socksCmdConnect {
		_ = socks5Reply(conn, socksReplyCmdNotSupported)
		return "", fmt.Errorf("socks5: unsupported command 0x%02x", req[1])
	}

	host, err := socks5ReadAddr(conn, req[3])
	if err != nil {
		return "", err
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBytes)
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// socks5ReadAddr reads the DST.ADDR field for the given ATYP. An unsupported
// address type is answered with the standard reply before returning an error.
func socks5ReadAddr(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case socksATYPIPv4:
		addr := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		return net.IP(addr).String(), nil
	case socksATYPIPv6:
		addr := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		return net.IP(addr).String(), nil
	case socksATYPDomain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return "", err
		}
		domain := make([]byte, int(lenByte[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		return string(domain), nil
	default:
		_ = socks5Reply(conn, socksReplyAddrNotSupported)
		return "", fmt.Errorf("socks5: unsupported address type 0x%02x", atyp)
	}
}

// socks5Reply writes a reply carrying code and a zero bound address
// (0.0.0.0:0). Reporting no meaningful bound address is standard practice for a
// forwarding proxy and every SOCKS5 client accepts it.
func socks5Reply(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{socks5Version, code, 0x00, socksATYPIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// socks5ReplyCode maps a dial error onto a SOCKS5 reply code. Dials run through
// the SSH connection, so the underlying refusal usually arrives as a message
// string rather than a syscall errno; both are matched.
func socks5ReplyCode(err error) byte {
	if err == nil {
		return socksReplySuccess
	}
	msg := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, syscall.ECONNREFUSED), strings.Contains(msg, "refused"):
		return socksReplyConnRefused
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH), strings.Contains(msg, "unreachable"):
		return socksReplyHostUnreachable
	default:
		return socksReplyGeneralFailure
	}
}
