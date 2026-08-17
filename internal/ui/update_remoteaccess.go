package ui

import (
	"sync"

	"github.com/Janne6565/wharf-tui/internal/remoteaccess"
	"github.com/Janne6565/wharf-tui/internal/sessd"
	"github.com/Janne6565/wharf-tui/internal/sshx"
	tea "github.com/charmbracelet/bubbletea"
)

// raChangedMsg asks for a re-render because the Holder changed: a grant was
// minted or revoked, or a command was audited.
//
// It carries nothing, and that is the whole point. Phase 1 pushed each
// remoteaccess.Event through a depth-64 channel and folded it into a log on the
// Model; a full queue dropped events, which an agent could exploit by flooding
// trivial commands to push the one that mattered out of the log. The Holder
// owns the log now, so this message is only a nudge to look again — a dropped
// one costs nothing, because the next render reads the whole log regardless.
// With it went the generation stamps that told a live grant's events from a
// revoked grant's stragglers, and the drain-on-revoke path that existed to
// catch the terminal events of commands revocation had cancelled: the Holder
// records those itself, on the goroutine that produces them.
type raChangedMsg struct{}

// waitRemoteAccessChangedCmd is the single consumer of the nudge. It blocks
// until the Holder reports a change and then re-arms itself from its own
// handler, so exactly one waiter exists at a time — see Model.Init.
func waitRemoteAccessChangedCmd(h *remoteaccess.Holder) tea.Cmd {
	if h == nil {
		return nil
	}
	// Resolved once, outside the closure: Changed returns the same channel every
	// time, and reading it here keeps the command from touching the Holder at
	// all once it is running.
	ch := h.Changed()
	return func() tea.Msg {
		<-ch
		return raChangedMsg{}
	}
}

// raCopyStatus records whether the clipboard actually took a grant's command
// line, for the grant it took it for.
//
// It exists because that one fact is neither the Holder's business — the Holder
// knows about grants, not about terminals — nor safe to keep on the Model: the
// in-session hotkey copies from the attach goroutine, which may not write to a
// Model. Keying on the grant pointer rather than a bare bool is what makes a
// stale answer impossible: after a replacement or a revocation the pointer no
// longer matches and the overlay falls back to "not copied", which is the
// honest reading when nobody has proof of a copy.
//
// The grant pointer is only ever compared, never dereferenced, so holding one
// past its revocation costs nothing but the memory of a closed grant.
type raCopyStatus struct {
	mu    sync.Mutex
	grant *remoteaccess.Grant
	ok    bool
	err   string
}

// copy runs the clipboard hook for g's command line and records the result. It
// returns the same pair for a caller that has to say so immediately — the
// attach callback prints it, the overlay renders it on the next frame.
//
// A nil hook is "no clipboard here", which is a supported state rather than a
// failure: the overlay and the printed line both always show the command as
// text, so nothing is lost, and saying so out loud beats a silent no-op.
func (c *raCopyStatus) copy(g *remoteaccess.Grant, fn func(string) error) (ok bool, why string) {
	// The hook is somebody else's code — clipboard.Copy in production, an
	// injected function in tests and in demo builds — and it is called on the
	// path that has just minted a live grant. A panic here used to unwind past
	// the caller and reach the attach loop's own recover, which prints "remote
	// access failed": the user would be told the keystroke did nothing while a
	// capability was live on a real host, with the command line never printed
	// and no way to reach it from inside the session. Containing it here rather
	// than at the call sites is what makes that impossible from all three of
	// them at once — the dashboard, the overlay's re-copy, and the in-session
	// hotkey — instead of relying on each to remember.
	defer func() {
		if p := recover(); p != nil {
			ok, why = false, "the clipboard hook failed"
			c.set(g, ok, why)
		}
	}()
	// A nil receiver is a Model that was assembled by hand rather than by New —
	// a renderer fixture, in practice. It is answered rather than crashed on:
	// nothing about a clipboard record is worth taking a frame down for.
	if c == nil || g == nil {
		return false, ""
	}
	ok, why = false, "no clipboard configured"
	if fn != nil {
		// Copied is proven, not assumed: OSC 52 is silently swallowed by some
		// terminals (Terminal.app), so a nil error only means the bytes were
		// written — which is still the strongest claim anyone can make.
		if err := fn(g.CommandLine()); err != nil {
			why = cleanErr(err)
		} else {
			ok, why = true, ""
		}
	}
	c.set(g, ok, why)
	return ok, why
}

// set records a result without performing a copy.
func (c *raCopyStatus) set(g *remoteaccess.Grant, ok bool, why string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.grant, c.ok, c.err = g, ok, why
}

// forGrant reports what is known about g. An unknown grant — one minted before
// this record, or one that replaced the recorded one — reads as not copied.
func (c *raCopyStatus) forGrant(g *remoteaccess.Grant) (bool, string) {
	if c == nil {
		return false, ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if g == nil || c.grant != g {
		return false, ""
	}
	return c.ok, c.err
}

// --- grant lifecycle --------------------------------------------------------

// raGrant is the live grant, or nil. It reads through the Holder rather than a
// Model field, which is what makes a grant minted while attached visible on the
// dashboard the instant Bubble Tea resumes: there is nothing to deliver and
// nothing to synchronise, because the Model never held it in the first place.
func (m Model) raGrant() *remoteaccess.Grant {
	if m.ra == nil {
		return nil
	}
	return m.ra.Current()
}

// raLog is the audit trail, newest first. Same reasoning as raGrant: it is read
// from the Holder per render rather than accumulated on the Model, so no event
// can be lost between the goroutine that produced it and the frame that shows
// it.
func (m Model) raLog() []remoteaccess.Entry {
	if m.ra == nil {
		return nil
	}
	return m.ra.Log()
}

// toggleRemoteAccess is the `r` key on the hosts tab: mint a grant on the
// selected host's live session, or revoke the one that exists.
//
// One grant at a time, for the whole app rather than per host: the badge, the
// overlay and the revoke key all have to mean exactly one thing at a glance,
// and "which of my three grants is that command running under" is a question a
// security feature should never make a user ask.
//
// Unlike the in-session hotkey, this revokes whatever grant is live regardless
// of which host the cursor is on, and never replaces one host's grant with
// another's. That is deliberate: the hosts-tab hint reads "r revoke remote"
// whenever a grant exists, and taking a capability back must not depend on
// having first parked the cursor on the right row — least of all when the right
// row is a host whose session has since died. Attached, the host is not in
// question at all, so the hotkey can afford Holder.Toggle's replace semantics.
func (m Model) toggleRemoteAccess() (tea.Model, tea.Cmd) {
	if g := m.raGrant(); g != nil {
		name := g.HostName()
		m = m.revokeRemoteAccess()
		return m.setToast("remote access to "+name+" revoked", "ok"), nil
	}

	mh, ok := m.selectedMergedHost()
	if !ok {
		return m, nil
	}
	h := mh.Host

	// A grant must ride a connection that already exists. Dialing here would
	// mean a keystroke that grants a capability could also raise a passphrase or
	// a TOFU prompt, and the user would be authorising two different things with
	// one decision.
	sess := m.liveSessionFor(h.ID)
	if sess == nil {
		m.raErr = "no live session on " + h.Name + " — connect first (enter); a grant rides a connection wharf already holds"
		return m.setToast(m.raErr, "err"), nil
	}
	return m.grantRemoteAccess(h.ID, h.Name, sess)
}

// grantRemoteAccess mints a grant over an executor that is already connected.
//
// It is split from toggleRemoteAccess so the degrade path can be tested where
// it actually applies: on Windows remoteaccess.Open always returns
// ErrUnsupported, and there is no way to stand up the live session that the
// toggle demands first — so the one platform whose behaviour the contract
// singles out would otherwise be the one platform with no test.
func (m Model) grantRemoteAccess(hostID, hostName string, exec remoteaccess.Executor) (tea.Model, tea.Cmd) {
	if m.ra == nil {
		return m, nil
	}
	out, err := m.ra.Toggle(remoteaccess.Options{Exec: exec, HostID: hostID, HostName: hostName})
	if err != nil {
		// Windows lands here with remoteaccess.ErrUnsupported. It is an inline
		// error and a toast, never a crash: the key exists on every platform, so
		// the UI has to be able to say why it did nothing.
		m.raErr = err.Error()
		return m.setToast("remote access unavailable: "+m.raErr, "err"), nil
	}
	if out.Grant == nil {
		// Overtaken while Open was in flight — a lock, a quit, or a second press
		// settled the question and the grant tore itself down again. Nothing
		// failed, so this is not an error toast, and there is nothing to copy or
		// to show: opening the overlay on a grant that does not exist would put
		// an empty panel over a dashboard that is already correct.
		return m.setToast(out.String(), "ok"), nil
	}
	// The cursor starts on the newest row, and the note about how the last grant
	// ended is stale the moment a new one exists.
	m.raSel = 0
	m.raErr = ""
	m.raEnded = ""
	m.raCopy.copy(out.Grant, m.copyToClipboard)
	// Open the overlay straight away: the command line is the whole point of the
	// keystroke, and if the clipboard copy failed this is where the user finds
	// that out and selects the text by hand instead.
	m.modal = modalRemoteAccess
	return m.setToast("remote access granted on "+hostName, "ok"), nil
}

// liveSessionFor returns a live session on the given host, or nil. The first
// live one is as good as any: a grant runs its commands in their own exec
// channel on that session's client, so which shell it rides is invisible.
func (m Model) liveSessionFor(hostID string) *sessd.Remote {
	if m.pool == nil {
		return nil
	}
	for _, s := range m.pool.ForHost(hostID) {
		if s.Alive() {
			return s
		}
	}
	return nil
}

// revokeRemoteAccess withdraws the grant and clears the UI state that only
// makes sense while one exists. It is safe to call with nothing outstanding,
// which is what lets the five revocation sites (the `r` toggle, TTL expiry,
// session end, lock and quit) all call it unconditionally.
//
// Holder.Revoke is synchronous down to Grant.Close — when it returns the socket
// is unlinked and no further command can start — so by the time this returns
// the capability is really gone, not merely scheduled to be.
//
// The audit log deliberately survives: it records what was run on a real host,
// and revoking is exactly the moment a user wants to read it.
func (m Model) revokeRemoteAccess() Model {
	if m.ra == nil {
		return m
	}
	m.ra.Revoke()
	m.raCopy.set(nil, false, "")
	// The inline error described a grant that no longer exists ("no live
	// session on web1"), and it is rendered by the overlay, which outlives the
	// grant. Left standing it reappears next to an unrelated grant minutes
	// later.
	m.raErr = ""
	// The overlay deliberately stays open. It is the only place the audit log
	// can be read, and the moments this is reached — a TTL lapsing, a session
	// dying — are exactly when someone is reading it to see what ran. Yanking
	// the panel shut mid-read was the old behaviour and it took the log away at
	// the worst possible time. An explicit revoke (x/d) still closes it, from
	// the key handler: there the user asked to be done with it.
	return m
}

// revokeGrantForHost revokes a grant that rides hostID, and reports whether it
// did. Called when a session ends.
//
// It matches on the host, not on the individual session, even though a host can
// have several shells open: the grant knows which host it is scoped to and the
// end message names only that. Erring towards revoking a still-usable grant
// costs one keystroke to mint again; erring the other way leaves a capability
// alive on a connection the user believes is gone.
func (m Model) revokeGrantForHost(hostID string) (Model, bool) {
	g := m.raGrant()
	if g == nil || g.HostID() != hostID {
		return m, false
	}
	name := g.HostName()
	m = m.revokeRemoteAccess()
	m.raEnded = "the grant on " + name + " ended with its session"
	return m, true
}

// --- messages ---------------------------------------------------------------

// handleRemoteAccessChanged re-renders on a Holder nudge and re-arms the
// waiter. There is nothing to fold in: the log is read from the Holder when it
// is rendered, so all this handler owes is a cursor that still points at a row
// that exists.
// There is nothing to fold in and nothing to clamp: the log is read from the
// Holder when it is rendered, and the cursor is an Entry.ID that resolves
// itself against whatever log exists at that moment.
func (m Model) handleRemoteAccessChanged() (tea.Model, tea.Cmd) {
	return m, waitRemoteAccessChangedCmd(m.ra)
}

// expireRemoteAccess revokes a grant whose TTL has run out. It is called from
// the tick loop rather than from a timer armed at mint time, because a grant
// can now be minted while Bubble Tea is suspended, and a timer nobody was there
// to arm would never fire. Polling a deadline that is already enforced by the
// grant itself costs one comparison every 120ms and cannot be forgotten by a
// path that mints without going through the reducer.
//
// The lag this introduces is bounded by the tick and is not a security window:
// Grant refuses commands past its expiry on its own, so what the tick removes
// is the *claim* that a capability is live, not the capability.
func (m Model) expireRemoteAccess() (Model, bool) {
	g := m.raGrant()
	if g == nil || !g.Expired() {
		return m, false
	}
	name := g.HostName()
	m = m.revokeRemoteAccess()
	// The toast is in the status bar, which the overlay covers. Somebody
	// reading the log when the TTL lapses would otherwise watch the grant
	// header vanish with nothing to say why.
	m.raEnded = "the grant on " + name + " expired"
	return m.setToast("remote access to "+name+" expired", "ok"), true
}

// handleRemoteAccessSessionEnded revokes a grant whose host lost its session,
// and reports whether it did so the session toast can say so.
func (m Model) handleRemoteAccessSessionEnded(msg sshx.SessionEndedMsg) (Model, bool) {
	return m.revokeGrantForHost(msg.HostID)
}

// --- the in-session hotkey --------------------------------------------------

// remoteAccessHotkey builds the OnRemoteAccess callback for one attach: the
// thing the remote-access key actually does while the TUI is suspended.
//
// It takes plain values rather than a Model, and the contract behind that is
// hard: the callback runs on a helper goroutine inside the attach loop while
// Bubble Tea is suspended, so it must not read or write Model state. Everything
// it needs is captured here — the Holder, the clipboard hook, the copy record,
// and the host this session belongs to — and every mutation it makes goes
// through the Holder, which is built for exactly this. The Holder's nudge then
// makes the result visible to the dashboard with no message and no
// synchronisation step of any kind.
//
// The returned text is printed verbatim into a terminal that is still in raw
// mode, hence \r\n and a leading blank line: the remote's own output may have
// left the cursor mid-line, and starting a fresh one is the difference between
// a readable notice and a notice spliced into a shell prompt. Returning "" is
// how a callback prints nothing; this one always has something to say, because
// a hotkey that appears to do nothing is indistinguishable from a broken one.
func remoteAccessHotkey(h *remoteaccess.Holder, copyState *raCopyStatus, copyFn func(string) error, hostID, hostName string, exec remoteaccess.Executor) func() string {
	if h == nil || exec == nil {
		return nil
	}
	return func() string {
		out, err := h.Toggle(remoteaccess.Options{Exec: exec, HostID: hostID, HostName: hostName})
		if err != nil {
			// This is the Windows path, where Open returns ErrUnsupported and its
			// text is the whole explanation. Printing it beats a key that silently
			// does nothing: the binding exists on every platform, so the only way a
			// user learns their platform cannot serve it is if it says so.
			return raLine("wharf: remote access unavailable: " + err.Error())
		}
		return remoteAccessOutcomeText(out, copyState, copyFn)
	}
}

// remoteAccessOutcomeText renders one Toggle outcome as the lines to print on a
// raw-mode terminal, performing the clipboard copy that belongs with a grant.
//
// It is split from the callback so the rendering can be tested against outcomes
// that cannot be produced on demand from here — OutcomeSuperseded needs two
// goroutines meeting inside Open, which internal/remoteaccess exercises with a
// seam this package has no access to. Racing it for real from a test would buy
// a flake, not a guarantee.
func remoteAccessOutcomeText(out remoteaccess.Outcome, copyState *raCopyStatus, copyFn func(string) error) string {
	// Branch on the grant, not on the error and not on the kind: a nil error
	// does not mean a grant exists. A revocation has none by definition, and
	// a Toggle that was overtaken while it was inside Open — by a lock, a
	// quit, or another press — comes back with OutcomeSuperseded, no error
	// and no grant, having already torn its own socket down. Neither may
	// print a command line: a token for a grant that is not there is a line
	// the user would paste and never get an answer from, and it would be
	// indistinguishable from the one that works. Outcome.String says which
	// of the two happened in either case.
	if out.Grant == nil {
		return raLine("wharf: " + out.String())
	}

	g := out.Grant
	// Outcome.String suits this exactly as it stands, including the
	// replacement case: it renders "remote access ON for web1 — db1 lost it",
	// which is the requirement that a moved capability names the host it was
	// taken from. Nothing here has to reconstruct that, and nothing here may
	// drop it.
	status := "wharf: " + out.String() + " · expires " + g.ExpiresAt().Format("15:04")
	if ok, why := copyState.copy(g, copyFn); ok {
		status += " · copied to clipboard"
	} else if why != "" {
		status += " · not copied (" + why + ")"
	} else {
		status += " · not copied"
	}
	// The command line is printed in full even when the copy succeeded,
	// because OSC 52 is silently swallowed by some terminals and there is no
	// reply to prove otherwise. That does put the token in this terminal's
	// scrollback — the same exposure the overlay already accepts, and
	// consistency is worth more than a marginal reduction.
	return raLine(status) + g.CommandLine() + "\r\n"
}

// raLine renders one line of hotkey feedback for a raw-mode terminal. The
// leading \r\n is not cosmetic: without it the notice lands wherever the remote
// left the cursor, which is usually the middle of a prompt.
func raLine(s string) string { return "\r\n" + s + "\r\n" }

// --- overlay ----------------------------------------------------------------

// openRemoteAccess shows the remote-access overlay (A). It opens with no grant
// outstanding too — the empty state is where a user learns the key that mints
// one, exactly as the active-forwards overlay names `f`.
// The inline error is cleared on the way in: it describes a keystroke, not a
// state, and "no live session on web1 — connect first" standing in the overlay
// long after web1 was connected is worse than no message at all. raEnded is
// deliberately *not* cleared here — someone opening the overlay after a grant
// lapsed is exactly who that note is for.
func (m Model) openRemoteAccess() Model {
	m.modal = modalRemoteAccess
	m.raErr = ""
	return m
}

func (m Model) remoteAccessKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "A":
		m.modal = modalNone
		// Read and dismissed: the note has done its job.
		m.raEnded = ""
	case "j", "down":
		m = m.moveRemoteAccessCursor(1)
	case "k", "up":
		m = m.moveRemoteAccessCursor(-1)
	case "c":
		// Re-copy, for the common case where the first attempt was swallowed by
		// the terminal and the user has since switched to one that honours it.
		g := m.raGrant()
		if g == nil || m.copyToClipboard == nil {
			return m, nil
		}
		if ok, why := m.raCopy.copy(g, m.copyToClipboard); !ok {
			return m.setToast("clipboard copy failed: "+why, "err"), nil
		}
		return m.setToast("command copied", "ok"), nil
	case "x", "d":
		g := m.raGrant()
		if g == nil {
			return m, nil
		}
		name := g.HostName()
		m = m.revokeRemoteAccess()
		// An explicit revoke closes the overlay, unlike a TTL or a dead session:
		// the user asked to be done with this, and the panel's headline act is
		// the one they just performed.
		m.modal = modalNone
		m.raEnded = ""
		return m.setToast("remote access to "+name+" revoked", "ok"), nil
	}
	return m, nil
}

// moveRemoteAccessCursor steps the selection d rows through the log and stores
// the id of the row it lands on. It resolves the current selection first, so a
// cursor whose row has been pushed down by newer commands moves from where it
// is now rather than from where its index used to point.
func (m Model) moveRemoteAccessCursor(d int) Model {
	log := m.raLog()
	if len(log) == 0 {
		return m
	}
	m.raSel = log[clampIdx(raCursor(log, m.raSel)+d, len(log))].ID
	return m
}
