// Package probe implements advisory reachability checks for the host list.
// Results are ephemeral UI state and never persisted; an "offline" host can
// still be connected to.
package probe

import (
	"net"
	"strconv"
	"time"
)

// Status is the traffic-light shown next to a host.
type Status int

const (
	StatusOnline   Status = iota // TCP connect within budget
	StatusDegraded               // connected, but RTT > DegradedRTT
	StatusOffline                // refused / unreachable / timeout
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

// Dial TCP-connects to addr:port within timeout and classifies the result.
func Dial(addr string, port int, timeout time.Duration) Result {
	target := net.JoinHostPort(addr, strconv.Itoa(port))

	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, timeout)
	rtt := time.Since(start)
	if err != nil {
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
