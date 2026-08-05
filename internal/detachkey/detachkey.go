// Package detachkey maps the detach hotkey between the name the user sees
// ("ctrl+\") and the single byte the attach loop watches for.
//
// While attached the terminal is in raw mode and every keystroke is a byte on
// its way to the remote, so the detach key can only ever be a control byte —
// there is no key event to inspect, and a multi-byte sequence would have to be
// buffered out of the stream the remote is reading. That is what bounds the
// choice to the set below.
package detachkey

import (
	"fmt"
	"sort"
	"strings"
)

// DefaultName is the detach key wharf ships with, and the value used whenever
// the stored preference is empty or unreadable.
const DefaultName = `ctrl+\`

// DefaultByte is DefaultName as the byte the attach loop sees (0x1C).
const DefaultByte = 0x1C

// allowed lists the bindable keys by the name bubbletea reports for them
// (tea.KeyMsg.String()), so a captured keypress can be looked up directly.
//
// Everything omitted is either not a control byte at all or is needed as
// itself: ctrl+c/ctrl+d/ctrl+z are what the remote shell expects for
// interrupt, EOF and suspend; ctrl+[ is escape (and with it every arrow key
// and every vim keystroke); ctrl+i/ctrl+m/ctrl+j are tab, enter and newline;
// ctrl+h is backspace; ctrl+s/ctrl+q are flow control, and ctrl+q also quits
// wharf; ctrl+@ is NUL. Binding any of them would cost the remote a key it
// cannot do without.
var allowed = map[string]byte{
	"ctrl+a": 0x01,
	"ctrl+b": 0x02,
	"ctrl+e": 0x05,
	"ctrl+f": 0x06,
	"ctrl+g": 0x07,
	"ctrl+k": 0x0B,
	"ctrl+l": 0x0C,
	"ctrl+n": 0x0E,
	"ctrl+o": 0x0F,
	"ctrl+p": 0x10,
	"ctrl+r": 0x12,
	"ctrl+t": 0x14,
	"ctrl+u": 0x15,
	"ctrl+v": 0x16,
	"ctrl+w": 0x17,
	"ctrl+x": 0x18,
	"ctrl+y": 0x19,
	`ctrl+\`: 0x1C,
	"ctrl+]": 0x1D,
	"ctrl+^": 0x1E,
	"ctrl+_": 0x1F,
}

// reserved explains, per key, why it cannot be bound. The message is shown in
// the capture modal, so it says what the key is needed for rather than just
// refusing.
var reserved = map[string]string{
	"ctrl+c":    "interrupt — the remote shell needs it",
	"ctrl+d":    "end of input — the remote shell needs it",
	"ctrl+z":    "suspend — the remote shell needs it",
	"ctrl+[":    "escape — arrow keys and vim are built on it",
	"esc":       "escape — arrow keys and vim are built on it",
	"ctrl+h":    "backspace",
	"backspace": "backspace",
	"tab":       "tab",
	"ctrl+i":    "tab",
	"enter":     "enter",
	"ctrl+m":    "enter",
	"ctrl+j":    "newline",
	"ctrl+s":    "flow control (XOFF)",
	"ctrl+q":    "flow control (XON), and quits wharf",
	"ctrl+@":    "NUL",
}

// Parse resolves a key name to its byte. The name is what bubbletea calls the
// key, which is also what Save writes to the config file, so a hand-edited
// config and a captured keypress go through the same door.
func Parse(name string) (byte, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return DefaultByte, nil
	}
	if b, ok := allowed[n]; ok {
		return b, nil
	}
	if why, ok := reserved[n]; ok {
		return 0, fmt.Errorf("%s is %s", n, why)
	}
	if !strings.HasPrefix(n, "ctrl+") {
		return 0, fmt.Errorf("%s is not a control key — the detach key has to be a ctrl combination", n)
	}
	return 0, fmt.Errorf("%s cannot be used as the detach key", n)
}

// Name returns the display name for a detach byte, falling back to the default
// for anything not bindable — including the zero byte, which is how callers
// spell "unset".
func Name(b byte) string {
	for name, v := range allowed {
		if v == b {
			return name
		}
	}
	return DefaultName
}

// Names lists the bindable keys in byte order, for help text and tests.
func Names() []string {
	out := make([]string, 0, len(allowed))
	for name := range allowed {
		out = append(out, name)
	}
	sort.Slice(out, func(i, j int) bool { return allowed[out[i]] < allowed[out[j]] })
	return out
}

// Byte resolves a stored name to its byte, falling back to the default rather
// than failing: a config that no longer parses must not leave someone attached
// with no way out.
func Byte(name string) byte {
	b, err := Parse(name)
	if err != nil {
		return DefaultByte
	}
	return b
}
