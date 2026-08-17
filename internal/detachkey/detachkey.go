// Package detachkey maps wharf's in-session hotkeys between the name the user
// sees ("ctrl+\") and the single byte the attach loop watches for.
//
// While attached the terminal is in raw mode and every keystroke is a byte on
// its way to the remote, so an in-session hotkey can only ever be a control
// byte — there is no key event to inspect, and a multi-byte sequence would have
// to be buffered out of the stream the remote is reading. That is what bounds
// the choice to the set below.
//
// There are two such hotkeys: the detach key, which leaves the session running,
// and the remote-access key, which toggles an exec grant for an AI agent. They
// are the same problem — same raw mode, same control-byte constraint, same keys
// the remote shell cannot spare — so they share one set and one set of
// explanations. A parallel package per binding was the obvious alternative and
// was rejected: two copies of `allowed` would drift, and only one of them would
// be the one someone remembered to update.
//
// What the two bindings do not share is a key: whichever byte the attach loop
// swallows for one is a byte the other can never see, so binding both to the
// same key would silently disable one. See Binding.ParseAgainst.
package detachkey

import (
	"fmt"
	"sort"
	"strings"
)

// Binding is one of the two in-session hotkeys. Only the Detach and
// RemoteAccess values below are meaningful — the type exists to give the two
// bindings one implementation rather than to be constructed by callers.
type Binding struct {
	// which selects the counterpart in other(). It is an index rather than a
	// pointer so Binding stays a comparable value type that callers can pass
	// around and store on a struct.
	which       int
	label       string
	defaultName string
	defaultByte byte
}

var (
	// Detach is the key that leaves an attached session running.
	Detach = Binding{which: 0, label: "detach key", defaultName: `ctrl+\`, defaultByte: 0x1C}

	// RemoteAccess is the key that toggles the remote-access grant while
	// attached. ctrl+] is the default because the remote shell has no use for
	// it — readline, vim and the job-control keys all leave it alone — and
	// because telnet spent decades training it as "talk to the client, not the
	// server", which is exactly what this key does. ctrl+g and ctrl+t were the
	// alternatives considered: both are free in the same sense, but neither
	// carries that meaning, and ctrl+t is taken by SIGINFO on the BSDs.
	RemoteAccess = Binding{which: 1, label: "remote-access key", defaultName: "ctrl+]", defaultByte: 0x1D}
)

// other returns the binding this one must not collide with. With exactly two
// bindings this is a flip; if a third is ever added, this is the function that
// has to become a real set difference.
func (b Binding) other() Binding {
	if b.which == RemoteAccess.which {
		return Detach
	}
	return RemoteAccess
}

// Label names the binding as the user knows it, for error and toast text.
func (b Binding) Label() string { return b.label }

// DefaultName is the key this binding ships with, and the value used whenever
// the stored preference is empty or unreadable.
func (b Binding) DefaultName() string { return b.defaultName }

// DefaultByte is DefaultName as the byte the attach loop sees.
func (b Binding) DefaultByte() byte { return b.defaultByte }

// DefaultName is the detach key wharf ships with, and the value used whenever
// the stored preference is empty or unreadable. It is Detach.DefaultName(),
// kept as a constant because the attach paths reach for it by name.
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
// refusing. It is shared by both bindings: a key the remote shell needs is
// needed whichever hotkey wanted it.
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

// Parse resolves a key name to its byte for this binding. The name is what
// bubbletea calls the key, which is also what the config file stores, so a
// hand-edited config and a captured keypress go through the same door.
//
// It does not know about the other binding — see ParseAgainst for that. The
// split is deliberate: the attach paths resolve a stored name with no second
// name to hand, and a collision is a reason to refuse a *new* binding, not a
// reason to leave a live session with no way out.
func (b Binding) Parse(name string) (byte, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return b.defaultByte, nil
	}
	if v, ok := allowed[n]; ok {
		return v, nil
	}
	if why, ok := reserved[n]; ok {
		return 0, fmt.Errorf("%s is %s", n, why)
	}
	if !strings.HasPrefix(n, "ctrl+") {
		return 0, fmt.Errorf("%s is not a control key — the %s has to be a ctrl combination", n, b.label)
	}
	return 0, fmt.Errorf("%s cannot be used as the %s", n, b.label)
}

// ParseAgainst resolves name for this binding and additionally refuses it when
// it is the key the *other* binding already holds. otherName is that binding's
// stored preference; empty means it is on its default, which still counts —
// the default is a real binding, not an absence.
//
// The error names the conflict ("ctrl+] is already the detach key") rather than
// just refusing, matching the register of the reserved messages: a capture
// modal shows it verbatim, and "not allowed" would leave the user guessing
// which of their own settings was in the way.
//
// The comparison is on bytes, not names, so a shouted or padded config value
// ("CTRL+] ") is caught just the same.
func (b Binding) ParseAgainst(name, otherName string) (byte, error) {
	v, err := b.Parse(name)
	if err != nil {
		return 0, err
	}
	o := b.other()
	if v == o.Byte(otherName) {
		return 0, fmt.Errorf("%s is already the %s", o.Name(v), o.label)
	}
	return v, nil
}

// Name returns the display name for a byte, falling back to this binding's
// default for anything not bindable — including the zero byte, which is how
// callers spell "unset".
func (b Binding) Name(v byte) string {
	for name, have := range allowed {
		if have == v {
			return name
		}
	}
	return b.defaultName
}

// Byte resolves a stored name to its byte, falling back to this binding's
// default rather than failing: a config that no longer parses must not leave
// someone attached with no way out.
func (b Binding) Byte(name string) byte {
	v, err := b.Parse(name)
	if err != nil {
		return b.defaultByte
	}
	return v
}

// Parse resolves a key name to its detach byte. It is Detach.Parse, kept at
// package level because the detach key is the older and more common caller.
func Parse(name string) (byte, error) { return Detach.Parse(name) }

// Name returns the display name for a detach byte, falling back to the detach
// default. It is Detach.Name.
func Name(b byte) string { return Detach.Name(b) }

// Byte resolves a stored name to its detach byte, falling back to the detach
// default. It is Detach.Byte.
func Byte(name string) byte { return Detach.Byte(name) }

// Names lists the bindable keys in byte order, for help text and tests. Both
// bindings draw from this one set; which of them a given key is free for is
// ParseAgainst's question, not this one's.
func Names() []string {
	out := make([]string, 0, len(allowed))
	for name := range allowed {
		out = append(out, name)
	}
	sort.Slice(out, func(i, j int) bool { return allowed[out[i]] < allowed[out[j]] })
	return out
}
