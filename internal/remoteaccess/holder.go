package remoteaccess

import (
	"sync"
	"sync/atomic"
	"time"
)

// Holder owns the process's single remote-access grant, and the audit log that
// goes with it.
//
// It exists because the grant must be toggled from two places that never run at
// the same time but also never share a goroutine: the dashboard reducer, and
// the attach byte scanner that runs while the Bubble Tea program is suspended
// under tea.Exec. A value living on the ui.Model cannot serve the second —
// Model is copied on every update and may only be touched by Update, so a
// callback firing from the attach goroutine has nothing it is allowed to write
// to. Ownership therefore moves out of the Model entirely: the Model keeps a
// stable *Holder pointer and reads through it, and the attach callback calls
// the same methods directly.
//
// Every method is safe to call from any goroutine. The Model reads Current and
// Log during a render; the attach scanner calls Toggle from its own goroutine;
// a grant's server goroutines feed the log from theirs.
//
// # Why the audit log lives here
//
// It used to live on the Model, fed by a depth-64 channel whose sender dropped
// events when the queue was full. A security review flagged that as a real
// hole rather than a nicety: an agent that has been prompt-injected can flood
// the grant with trivial commands to push the one command that matters out of
// the queue, and the log is the entire reason a compromised agent is
// survivable. Phase 2 makes it worse still — while attached, the Bubble Tea
// program is suspended for minutes at a time and nothing is draining the
// queue, so "drops when full" stops being an edge case and becomes the normal
// case.
//
// With the log here, nothing is ever lost. Changed is demoted from a transport
// to a *nudge*: a depth-1 channel whose only job is to prompt a re-render, on
// which a non-blocking send may safely be dropped, because the UI re-reads the
// whole log every time it renders. A dropped nudge costs nothing; a dropped
// event cost the record of what ran on a real host.
//
// This deletes rather than moves machinery: no queue, no generation stamps to
// tell a live grant's events from a revoked grant's stragglers, no drain-on-
// revoke path.
type Holder struct {
	// mu guards everything below and is held only for the handful of
	// instructions it takes to read or write them. It is never held across
	// Open, Close, or a call into anybody else's code.
	//
	// There is deliberately no second, coarser lock serialising the slow half.
	// An earlier version had one, held by Toggle across Open and by Revoke for
	// its whole call, so that two goroutines could not both mint. It was removed
	// because it made Revoke — the thing lock() and quit call — wait out
	// whatever Open was stuck on. A wedged runtime directory would then freeze
	// the vault lock rather than merely delay a grant, which is a far worse
	// failure than the one the lock prevented. Mutual exclusion between minters
	// is provided by epoch instead: they may run concurrently, and all but the
	// last to publish tear their own grant down.
	mu     sync.Mutex
	grant  *Grant
	log    []record
	gen    uint64 // grants minted so far; namespaces Event.ID (see record.key)
	nextID uint64 // Entry.ID sequence, process-wide and monotonic

	// epoch counts settled intents: every publish and every Revoke bumps it. A
	// Toggle captures it on entry and re-checks it after Open returns; if it
	// moved, something has said what it wants about the grant since this Toggle
	// was asked for, and this Toggle's answer is stale.
	//
	// It exists because a caller can walk away from a Toggle that has not
	// returned. The in-session hotkey callback runs on a helper goroutine that
	// the attach loop abandons after a ten-second timeout without cancelling it;
	// that goroutine is still inside Toggle and will keep going. If Open stalls
	// past the timeout — a wedged NFS or FUSE $WHARF_RUNTIME_DIR, a filesystem
	// under extreme pressure — the user sees "remote access is not responding",
	// detaches, locks the vault and walks away. lock() calls Revoke, which finds
	// nothing to revoke. Then Open finally returns, and without this check the
	// abandoned goroutine would install a live grant socket on a locked vault,
	// invisible (the unlock screen renders no badge) and unrevoked for the full
	// TTL. The epoch turns that into a grant that closes itself.
	epoch uint64

	// changed is the coalescing re-render nudge. Depth 1 and written with a
	// non-blocking send: when a nudge is already pending, a second one would say
	// nothing the first does not.
	changed chan struct{}
}

// LogMax caps the audit log. The log is the feature that makes a
// prompt-injected agent survivable, so the cap is generous — an agent can
// easily run a few hundred commands in an hour — but it is a cap all the same:
// the log is unbounded input from a process wharf does not control, and an
// uncapped slice would let that process grow this one's memory without limit.
//
// The *oldest* entries are dropped, never the newest. That is the opposite of
// what the old queue did under pressure, and it is the direction that cannot be
// weaponised: an attacker who floods the log pushes out its own earlier
// commands, and the flood itself is then the visible thing.
const LogMax = 200

// NewHolder returns an empty holder with no grant.
func NewHolder() *Holder {
	return &Holder{changed: make(chan struct{}, 1)}
}

// Entry is one line of the audit log: a command a grant ran, or tried to.
//
// A command's start and its finish are two events about one command and are
// folded into a single entry that flips from running to its exit status. The
// alternative — a row per event — was rejected because it doubles the length of
// the log with rows that permanently claim to be running, which is exactly the
// reading a user must be able to trust.
type Entry struct {
	// ID is a stable, process-wide identifier assigned when the entry is
	// created. It never changes when the entry is updated in place, so a UI may
	// use it as a list key or to keep a cursor pinned to the same row across
	// re-renders. It is not a wire value and means nothing outside this process.
	ID uint64

	// HostName and HostID name the host the command ran on. They are on the
	// entry rather than implied by the current grant because the log outlives
	// the grant that produced it — a Toggle on a different host replaces the
	// grant but keeps the log, and a row that did not say which host it belonged
	// to would be actively misleading at exactly that moment.
	HostName string
	HostID   string

	// At is when the command started. It is preserved when the finish event
	// folds in: when a command began is the interesting half.
	At time.Time

	Command string

	// Finished is false while the command is still running. Code and Err are
	// meaningful only once it is true.
	Finished bool
	Code     int

	// Err is the failure text, stored as a string rather than an error because
	// it is display state that outlives the call that produced it and nothing
	// here ever inspects it with errors.Is.
	Err string

	// Refused marks a command that was turned away — revoked grant, lapsed TTL,
	// too many already running — and so never reached the host. A refusal is a
	// finished entry with no running phase before it. A burst of refusals is the
	// shape a prompt-injected agent makes when it keeps trying after being cut
	// off, and a log that showed only what succeeded would hide precisely that.
	Refused bool
}

// record is an Entry plus the correlation key that folds a finish event into
// the entry its start event created. The key is not exported because it is a
// detail of this package's own event plumbing and means nothing to a renderer.
type record struct {
	entry Entry
	key   evKey
}

// evKey identifies one command across the two events that describe it.
//
// Event.ID is unique only within a single Grant, so it is paired with the
// holder's generation counter — otherwise the first command of a newly minted
// grant would fold into the first command of the previous one, which is the
// worst possible kind of wrong for an audit log: two different hosts' commands
// silently merged into one row.
type evKey struct {
	gen uint64
	id  uint64
}

// OutcomeKind says what a Toggle did.
type OutcomeKind uint8

const (
	// OutcomeNone is the zero value, reported only alongside an error.
	OutcomeNone OutcomeKind = iota
	// OutcomeGranted: there was no grant, and now there is one.
	OutcomeGranted
	// OutcomeRevoked: the grant on this host was withdrawn.
	OutcomeRevoked
	// OutcomeReplaced: a grant on a *different* host was withdrawn and one on
	// this host minted in its place.
	OutcomeReplaced
	// OutcomeSuperseded: the grant was minted and then immediately torn down
	// again, because something settled the question while this Toggle was still
	// inside Open — a Revoke, or another Toggle. Nothing is live and nothing
	// failed; the request was simply overtaken.
	//
	// It is an Outcome rather than an error because an error would be a lie: no
	// operation failed, and a caller that treated it as one would tell the user
	// remote access was broken when in fact it was cancelled. It is a distinct
	// kind rather than folded into OutcomeRevoked because a caller printing a
	// line has to be able to say "your request was overtaken" instead of
	// claiming to have revoked something the user never saw.
	OutcomeSuperseded
)

// Outcome reports what Toggle did, in enough detail that a caller with no view
// layer can say so.
//
// That caller is real and is the reason this type exists at all: while attached,
// the hotkey is handled by the byte scanner in sessd's attach path, which has no
// Model, no theme and no renderer — it writes raw text to a terminal that is
// still in raw mode. Returning only an error would have left it guessing which
// of three things just happened.
type Outcome struct {
	Kind OutcomeKind

	// HostName and HostID name the host the outcome is about: the one that
	// gained the grant for Granted and Replaced, the one that lost it for
	// Revoked.
	HostName string
	HostID   string

	// ReplacedHostName and ReplacedHostID name the host whose grant was taken
	// away, and are set only for OutcomeReplaced.
	//
	// Reporting this is not optional. Silently moving a capability from one host
	// to another is not acceptable: a user who pressed a key expecting to grant
	// access to web1 must be told, in the same breath, that db1 just lost it.
	ReplacedHostName string
	ReplacedHostID   string

	// Grant is the live grant after the toggle, or nil for OutcomeRevoked. It is
	// how a caller reaches the command line and the expiry without a second
	// call that could race a concurrent revocation.
	Grant *Grant
}

// String is a one-line summary suitable for printing straight to a terminal.
//
// It never contains the token. The token belongs on the line the user is meant
// to copy — Grant.CommandLine — and keeping it out of every other string means
// a caller that logs an Outcome somewhere careless cannot leak it by accident.
func (o Outcome) String() string {
	switch o.Kind {
	case OutcomeGranted:
		return "remote access ON for " + o.HostName
	case OutcomeRevoked:
		return "remote access revoked for " + o.HostName
	case OutcomeReplaced:
		return "remote access ON for " + o.HostName + " — " + o.ReplacedHostName + " lost it"
	case OutcomeSuperseded:
		return "remote access for " + o.HostName + " was overtaken and is not active"
	default:
		return "remote access unchanged"
	}
}

// Toggle revokes the current grant, or mints one for this host if there is
// none — or if the live grant belongs to a different host, in which case the
// other host's grant is replaced and the Outcome says whose it was.
//
// Hosts are told apart by Options.HostID, not by name: names are for humans and
// two hosts may share one.
//
// The Holder installs Options.Notify itself, pointing it at its own log; a
// Notify the caller supplied is still called, after the entry is recorded and
// outside every lock, so a caller that wants its own sink is not silently
// ignored. Everything else in Options — the executor, the host, the TTL, the
// in-flight ceiling — comes from the caller, because the Holder knows nothing
// about sessions.
//
// On a replacement the new grant is opened *before* the old one is closed. The
// alternative, closing first, was rejected: if Open then failed the user would
// be left with no grant at all, having asked for one. The cost is a window of
// microseconds in which both sockets exist, which no attacker can be scheduled
// into and which is over before Toggle returns.
//
// If Open fails, the existing grant (if any) is left alone and the error is
// returned with a zero Outcome.
//
// If a Revoke or another Toggle settles while Open is in flight, this one is
// overtaken: the freshly opened grant is closed again, nothing is published,
// and OutcomeSuperseded is returned with no error. See the epoch field for why
// that case is not hypothetical — the caller may be a goroutine nobody is
// waiting for any more.
func (h *Holder) Toggle(opts Options) (Outcome, error) {
	h.mu.Lock()
	cur := h.grant
	epoch := h.epoch
	// The generation is allocated here, before Open, because the sink closure has
	// to capture it: events may be emitted before Open returns and a stamp
	// assigned afterwards could not reach them. It is allocated rather than
	// merely read, so that two Toggles running at once cannot pick the same
	// number and fold each other's audit entries together.
	h.gen++
	gen := h.gen
	h.mu.Unlock()

	if cur != nil && cur.HostID() == opts.HostID {
		h.Revoke()
		return Outcome{Kind: OutcomeRevoked, HostName: cur.HostName(), HostID: cur.HostID()}, nil
	}

	opts.Notify = h.sinkFor(gen, opts.HostID, opts.HostName, opts.Notify)
	g, err := Open(opts)
	if err != nil {
		return Outcome{}, err
	}

	publishGate()

	h.mu.Lock()
	if h.epoch != epoch {
		// Overtaken: a Revoke or another Toggle settled while Open was in flight,
		// and that is a more recent statement of what the user wants than this
		// one. Publishing now would resurrect a capability somebody has already
		// asked to be rid of — see the epoch field for the abandoned-callback
		// scenario this is really about.
		h.mu.Unlock()
		// Close, not leak. The grant is fully live at this point — it has a bound
		// socket and a running accept loop — and nothing else holds a reference to
		// it, so if this goroutine does not tear it down nobody ever will. Close is
		// synchronous and unlinks the socket whether or not the grant was ever
		// published; it knows its own path and asks nothing of the holder.
		_ = g.Close()
		return Outcome{
			Kind:     OutcomeSuperseded,
			HostName: opts.HostName,
			HostID:   opts.HostID,
		}, nil
	}
	h.epoch++
	h.grant = g
	h.mu.Unlock()

	out := Outcome{Kind: OutcomeGranted, HostName: g.HostName(), HostID: g.HostID(), Grant: g}
	if cur != nil {
		out.Kind = OutcomeReplaced
		out.ReplacedHostName = cur.HostName()
		out.ReplacedHostID = cur.HostID()
		// Closed after the swap, so a straggling terminal event from a command
		// this Close cancels still finds a live sink and lands in the log. That is
		// the row the user is most likely to come back and read: the one they hit
		// revoke over.
		_ = cur.Close()
	}
	h.nudge()
	return out, nil
}

// Current is the live grant, or nil when there is none. The pointer is stable —
// a Grant is never mutated in place by the Holder — so a caller may hold it
// across a render, but it may be revoked underneath, which is why every
// interesting method on Grant is itself safe to call on a closed one.
func (h *Holder) Current() *Grant {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.grant
}

// Revoke withdraws the grant if there is one, and does nothing if there is not.
// It is idempotent so that the five revocation sites — the toggle key, TTL
// expiry, the session ending, lock and quit — can all call it unconditionally
// without first asking whether there is anything to revoke.
//
// Grant.Close is synchronous, so when this returns the socket is unlinked and
// no further command can start.
//
// The log deliberately survives: it records what was run on a real host, and
// revoking is exactly the moment a user wants to read it.
func (h *Holder) Revoke() {
	// The epoch is bumped even when there is nothing to revoke, and that is the
	// whole point of bumping it here rather than only on a real close: the case
	// that matters is lock() calling Revoke on an empty holder while a Toggle is
	// still stuck inside Open. "There is no grant" is a statement about the
	// future as much as the present — it has to cancel the one being minted, not
	// just the one that exists.
	h.mu.Lock()
	g := h.grant
	// Cleared before the close rather than after, so that the instant Close
	// begins — and it can take as long as a listener shutdown takes — Current
	// already answers nil and no other goroutine believes the capability is live.
	h.grant = nil
	h.epoch++
	h.mu.Unlock()

	if g != nil {
		_ = g.Close()
	}
	h.nudge()
}

// publishProbe is a test seam, nil in every build that is not a test. Toggle
// calls it after Open has returned and before it takes the lock to publish,
// which is exactly the window an abandoned Toggle sits in when Open stalls.
//
// A seam rather than a timing hack, following dispatchProbe in grant.go: the
// defect is a stall measured in seconds against a publish measured in
// nanoseconds, so a test that tried to hit the window by racing would pass
// whether the epoch check existed or not — it would assert nothing. It is an
// atomic.Pointer so that setting it cannot race the goroutine that reads it.
var publishProbe atomic.Pointer[func()]

func publishGate() {
	if p := publishProbe.Load(); p != nil {
		(*p)()
	}
}

// Log returns the audit log, newest first, capped at LogMax.
//
// It returns a copy. The caller is a renderer that may hold the slice across a
// frame while the grant's goroutines keep writing, and handing out the live
// backing array would be a data race dressed up as an optimisation.
func (h *Holder) Log() []Entry {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Entry, len(h.log))
	for i, r := range h.log {
		out[i] = r.entry
	}
	return out
}

// Changed is the re-render nudge: it fires when the grant or the log changed.
//
// It carries no data on purpose. It is not a transport and must never become
// one again — the depth-64 event channel it replaces is the thing that could
// drop an audit record. A receive here means only "read the Holder again", so
// a send that finds the buffer full may be dropped with nothing lost: the
// pending nudge already says everything the dropped one would have.
//
// One consumer. The channel is a single buffered channel rather than a
// fan-out, because there is exactly one event loop that needs waking.
func (h *Holder) Changed() <-chan struct{} { return h.changed }

// nudge asks for a re-render, without ever blocking the caller. It is called
// from the goroutine that runs a command, so blocking here would stall a
// command mid-flight for as long as the UI took to notice.
func (h *Holder) nudge() {
	select {
	case h.changed <- struct{}{}:
	default:
	}
}

// sinkFor builds the Notify function for one grant. It closes over the
// generation so that Event.ID — which is unique only within a Grant — can be
// namespaced, and over the host, so that an entry still names its host after
// the grant that produced it is gone.
//
// next is the caller's own Notify, or nil. It is called last, outside the lock:
// a sink that blocks must not be able to take the holder's mutex with it.
func (h *Holder) sinkFor(gen uint64, hostID, hostName string, next func(Event)) func(Event) {
	return func(ev Event) {
		h.record(gen, hostID, hostName, ev)
		h.nudge()
		if next != nil {
			next(ev)
		}
	}
}

// record folds one event into the log.
//
// Correlation is by (generation, Event.ID) — a real identifier assigned by the
// Grant that ran the command. The previous implementation matched on command
// *text* against the most recent unfinished row, because Event carried no id at
// all; that mismatched two identical commands running concurrently and swapped
// their outcomes. An id was added to Event rather than making the heuristic
// cleverer, because no amount of cleverness makes text a key.
//
// An event whose start has already aged off the end of the log finds no entry
// to fold into and is prepended as a fresh, already-finished one. That is
// honest — the command did run — and it can only happen after LogMax later
// commands have started, by which point the running row was long gone from
// anything a user was reading.
func (h *Holder) record(gen uint64, hostID, hostName string, ev Event) {
	key := evKey{gen: gen, id: ev.ID}

	h.mu.Lock()
	defer h.mu.Unlock()

	// An id of zero means the event carries no correlation id at all. Nothing in
	// this package emits one, but folding on a zero key would merge every such
	// event into a single row, so they are kept apart instead: a missing id
	// costs a duplicate row, never a lost one.
	if ev.ID != 0 {
		for i := range h.log {
			if h.log[i].key == key {
				e := &h.log[i].entry
				// The start time is kept: when the command began is the interesting
				// half, and the finish event's own timestamp would overwrite it with
				// something the reader already knows (roughly, now).
				e.Finished = ev.Finished
				e.Code = ev.Code
				e.Refused = ev.Refused
				e.Err = errText(ev.Err)
				return
			}
		}
	}

	h.nextID++
	r := record{
		key: key,
		entry: Entry{
			ID:       h.nextID,
			HostName: hostName,
			HostID:   hostID,
			At:       ev.At,
			Command:  ev.Command,
			Finished: ev.Finished,
			Code:     ev.Code,
			Err:      errText(ev.Err),
			Refused:  ev.Refused,
		},
	}
	// Newest first: a user reaching for the overlay is looking at what is
	// happening now, not at what happened when the grant was minted.
	h.log = append(h.log, record{})
	copy(h.log[1:], h.log)
	h.log[0] = r
	if len(h.log) > LogMax {
		h.log = h.log[:LogMax]
	}
}

// errText renders an event's error for display. It is a function rather than an
// inline nil check because it is done in two places and getting it wrong once
// would print Go's rendering of a nil error into the audit log.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
