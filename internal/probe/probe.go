// Package probe implements advisory reachability checks for the host list.
// Results are ephemeral UI state and never persisted; an "offline" host can
// still be connected to.
package probe

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/Janne6565/wharf-tui/internal/proxydial"
)

// Status is the traffic-light shown next to a host.
type Status int

const (
	StatusOnline   Status = iota // TCP connect within budget
	StatusDegraded               // connected, but RTT > DegradedRTT
	StatusOffline                // refused / unreachable / timeout
	StatusUnknown                // behind a proxy: the failure is not attributable
)

// DegradedRTT is the dial latency above which a reachable host is flagged
// degraded.
const DegradedRTT = 750 * time.Millisecond

// DefaultTimeout bounds one probe dial.
const DefaultTimeout = 3 * time.Second

// Result is the outcome of one probe.
type Result struct {
	Status Status
	RTT    time.Duration
}

// Dial TCP-connects to addr:port within timeout and classifies the result. It
// goes through d — a nil dialer connects directly — so that behind a corporate
// proxy the dots reflect what wharf can actually reach rather than turning the
// whole list red.
//
// Through a proxy the measured RTT includes the proxy handshake and describes
// the path to the proxy at least as much as the path to the host. The number is
// advisory either way, and a connection that took longer than DegradedRTT to
// establish is worth flagging whoever is slow.
func Dial(d *proxydial.Dialer, addr string, port int, timeout time.Duration) Result {
	target := net.JoinHostPort(addr, strconv.Itoa(port))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", target)
	rtt := time.Since(start)
	if err != nil {
		// Behind a proxy a failure is not attributable: a proxy that declines
		// CONNECT to port 22 on policy and a host that is genuinely down look
		// identical from here, and calling a reachable host "offline" is the
		// worse mistake — it is the one that stops someone trying.
		if d.Enabled() {
			return Result{Status: StatusUnknown, RTT: 0}
		}
		// Refused, unreachable, or timed out — all "offline" for the UI. RTT is
		// meaningless without a connection, so we report zero.
		return Result{Status: StatusOffline, RTT: 0}
	}
	// We only care that the port is reachable; drop the connection immediately.
	conn.Close()

	status := StatusOnline
	if rtt > DegradedRTT {
		status = StatusDegraded
	}
	return Result{Status: status, RTT: rtt}
}
