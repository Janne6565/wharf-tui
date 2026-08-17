//go:build !windows

package remoteaccess

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- helpers ----------------------------------------------------------------

// newHolderIn returns a holder whose grants land in a private runtime
// directory, with any surviving grant revoked at the end of the test. It uses
// the same /tmp trick as openGrant: socket paths are capped at 100 bytes and
// macOS hands tests a TMPDIR far longer than that.
func newHolderIn(t *testing.T) *Holder {
	t.Helper()
	runtimeDir(t)
	h := NewHolder()
	t.Cleanup(h.Revoke)
	return h
}

// hostOpts is the caller's half of Options: an executor and a host. Notify is
// deliberately absent — installing it is the Holder's job, and a test that
// supplied one would be testing something the UI never does.
func hostOpts(exec Executor, id, name string) Options {
	return Options{Exec: exec, HostID: id, HostName: name}
}

// sinkOf returns the audit sink for the holder's current grant generation,
// built by the same constructor Toggle uses. Tests that flood the log call it
// directly rather than driving thousands of real sockets: what is under test is
// the log's behaviour when Notify is called from arbitrary goroutines, which is
// exactly what this is.
func sinkOf(h *Holder, hostID, hostName string) func(Event) {
	h.mu.Lock()
	gen := h.gen
	h.mu.Unlock()
	return h.sinkFor(gen, hostID, hostName, nil)
}

// commandsIn indexes a log by command text, which every flood test uses as the
// per-event identity it then asserts nothing lost.
func commandsIn(log []Entry) map[string]Entry {
	byCmd := make(map[string]Entry, len(log))
	for _, e := range log {
		byCmd[e.Command] = e
	}
	return byCmd
}

// --- tests ------------------------------------------------------------------

func TestTogglingTwiceOnTheSameHostGrantsThenRevokes(t *testing.T) {
	h := newHolderIn(t)
	exec := &fakeExec{}

	out, err := h.Toggle(hostOpts(exec, "h1", "web1"))
	if err != nil {
		t.Fatalf("Toggle: %v", err)
	}
	if out.Kind != OutcomeGranted {
		t.Fatalf("first toggle kind = %v, want OutcomeGranted", out.Kind)
	}
	if out.HostName != "web1" || out.HostID != "h1" {
		t.Fatalf("first toggle named %q/%q, want web1/h1", out.HostName, out.HostID)
	}
	if out.Grant == nil || h.Current() != out.Grant {
		t.Fatal("the outcome must carry the grant the holder now holds")
	}
	if out.ReplacedHostName != "" {
		t.Fatalf("nothing was displaced, but the outcome says %q", out.ReplacedHostName)
	}
	sock := out.Grant.SocketPath()

	out, err = h.Toggle(hostOpts(exec, "h1", "web1"))
	if err != nil {
		t.Fatalf("second Toggle: %v", err)
	}
	if out.Kind != OutcomeRevoked {
		t.Fatalf("second toggle kind = %v, want OutcomeRevoked", out.Kind)
	}
	if out.HostName != "web1" {
		t.Fatalf("revocation named %q, want web1", out.HostName)
	}
	if out.Grant != nil {
		t.Fatal("a revocation has no live grant to report")
	}
	if h.Current() != nil {
		t.Fatal("Current still reports a grant after it was toggled off")
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("the socket outlived the revocation: stat = %v", err)
	}
}

func TestTogglingOnADifferentHostReplacesTheGrantAndNamesTheDisplacedHost(t *testing.T) {
	h := newHolderIn(t)
	exec := &fakeExec{}

	first, err := h.Toggle(hostOpts(exec, "h1", "web1"))
	if err != nil {
		t.Fatalf("Toggle web1: %v", err)
	}
	oldSock := first.Grant.SocketPath()

	out, err := h.Toggle(hostOpts(exec, "h2", "db1"))
	if err != nil {
		t.Fatalf("Toggle db1: %v", err)
	}
	if out.Kind != OutcomeReplaced {
		t.Fatalf("kind = %v, want OutcomeReplaced", out.Kind)
	}
	if out.HostName != "db1" || out.HostID != "h2" {
		t.Fatalf("the new host is %q/%q, want db1/h2", out.HostName, out.HostID)
	}
	if out.ReplacedHostName != "web1" || out.ReplacedHostID != "h1" {
		t.Fatalf("the displaced host is %q/%q, want web1/h1",
			out.ReplacedHostName, out.ReplacedHostID)
	}
	// The whole point of reporting the displacement is that a caller with no
	// view layer can say it out loud, so the summary has to contain both names.
	if line := out.String(); !strings.Contains(line, "db1") || !strings.Contains(line, "web1") {
		t.Fatalf("Outcome.String() = %q, want both host names in it", line)
	}
	if out.String() == "" || strings.Contains(out.String(), out.Grant.Token()) {
		t.Fatal("the one-line summary must never carry the token")
	}
	if h.Current() != out.Grant {
		t.Fatal("the holder must hold the new grant, not the displaced one")
	}
	if _, err := os.Stat(oldSock); !os.IsNotExist(err) {
		t.Fatalf("the displaced grant's socket survived: stat = %v", err)
	}
}

func TestRevokeIsIdempotentAndTheSocketIsGoneAfterwards(t *testing.T) {
	h := newHolderIn(t)

	// Revoking with nothing outstanding must be a no-op, because all five
	// revocation sites call it unconditionally.
	h.Revoke()

	out, err := h.Toggle(hostOpts(&fakeExec{}, "h1", "web1"))
	if err != nil {
		t.Fatalf("Toggle: %v", err)
	}
	sock := out.Grant.SocketPath()

	for i := 0; i < 3; i++ {
		h.Revoke()
		if h.Current() != nil {
			t.Fatalf("Current is non-nil after revoke number %d", i+1)
		}
		if _, err := os.Stat(sock); !os.IsNotExist(err) {
			t.Fatalf("the socket is still there after revoke number %d: %v", i+1, err)
		}
	}
}

func TestTheAuditLogNeverLosesAnEventUnderAFlood(t *testing.T) {
	// This is the property the depth-64 channel could not give. The old bridge
	// dropped an event whenever the queue was full, which an agent could
	// weaponise: flood the grant with trivial commands and the one command that
	// mattered is pushed out of the record. Here every event is driven through
	// the real sink, concurrently, from far more goroutines than the old queue
	// had slots, and every single one must be in the log at the end.
	h := newHolderIn(t)
	if _, err := h.Toggle(hostOpts(&fakeExec{}, "h1", "web1")); err != nil {
		t.Fatalf("Toggle: %v", err)
	}
	notify := sinkOf(h, "h1", "web1")

	const workers = 16
	const perWorker = LogMax / workers // 12 commands each, 384 events in total

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				id := uint64(w*perWorker + i + 1)
				cmd := fmt.Sprintf("cmd-%d", id)
				notify(Event{ID: id, Command: cmd, At: time.Now()})
				notify(Event{ID: id, Command: cmd, At: time.Now(), Code: 7, Finished: true})
			}
		}(w)
	}
	wg.Wait()

	log := h.Log()
	want := workers * perWorker
	if len(log) != want {
		t.Fatalf("the log holds %d entries, want %d — %d events went missing",
			len(log), want, want-len(log))
	}
	byCmd := commandsIn(log)
	if len(byCmd) != want {
		t.Fatalf("the log holds %d distinct commands, want %d", len(byCmd), want)
	}
	for i := 1; i <= want; i++ {
		cmd := fmt.Sprintf("cmd-%d", i)
		e, ok := byCmd[cmd]
		if !ok {
			t.Fatalf("%s is not in the log at all", cmd)
		}
		// Folding must have happened: one entry per command, showing its outcome
		// rather than still claiming to be running.
		if !e.Finished || e.Code != 7 {
			t.Fatalf("%s reads finished=%v code=%d, want true/7", cmd, e.Finished, e.Code)
		}
	}
}

func TestTheLogIsCappedAtLogMaxAndDropsTheOldestFirst(t *testing.T) {
	h := newHolderIn(t)
	if _, err := h.Toggle(hostOpts(&fakeExec{}, "h1", "web1")); err != nil {
		t.Fatalf("Toggle: %v", err)
	}
	notify := sinkOf(h, "h1", "web1")

	const total = LogMax * 3
	for i := 1; i <= total; i++ {
		cmd := fmt.Sprintf("cmd-%d", i)
		notify(Event{ID: uint64(i), Command: cmd, At: time.Now()})
		notify(Event{ID: uint64(i), Command: cmd, At: time.Now(), Finished: true})
	}

	log := h.Log()
	if len(log) != LogMax {
		t.Fatalf("the log holds %d entries, want the cap of %d", len(log), LogMax)
	}
	// Newest first, and the survivors are the newest LogMax commands: an
	// attacker who floods the log pushes out its own earlier noise, never the
	// newest record.
	if log[0].Command != fmt.Sprintf("cmd-%d", total) {
		t.Fatalf("the newest entry is %q, want cmd-%d", log[0].Command, total)
	}
	for i, e := range log {
		want := fmt.Sprintf("cmd-%d", total-i)
		if e.Command != want {
			t.Fatalf("entry %d is %q, want %q", i, e.Command, want)
		}
	}
}

func TestAStartAndItsFinishFoldIntoOneEntryEvenWhenTheCommandsAreIdentical(t *testing.T) {
	// The heuristic this replaces matched on command text against the most
	// recent unfinished row, so two identical commands overlapping swapped their
	// outcomes. With a real id they cannot.
	h := newHolderIn(t)
	if _, err := h.Toggle(hostOpts(&fakeExec{}, "h1", "web1")); err != nil {
		t.Fatalf("Toggle: %v", err)
	}
	notify := sinkOf(h, "h1", "web1")

	start := time.Now().Add(-time.Minute)
	notify(Event{ID: 1, Command: "uptime", At: start})
	notify(Event{ID: 2, Command: "uptime", At: time.Now()})
	if log := h.Log(); len(log) != 2 {
		t.Fatalf("two overlapping commands made %d entries, want 2", len(log))
	}
	notify(Event{ID: 1, Command: "uptime", At: time.Now(), Code: 3, Finished: true})

	log := h.Log()
	if len(log) != 2 {
		t.Fatalf("the finish event made a third entry: %d entries", len(log))
	}
	// Newest first, so the still-running command 2 is at the top and the one
	// that just finished is below it.
	if log[0].Finished || log[0].ID == log[1].ID {
		t.Fatalf("expected a distinct, still-running newest entry, got %+v", log[0])
	}
	folded := log[1]
	if !folded.Finished || folded.Code != 3 {
		t.Fatalf("the folded entry reads finished=%v code=%d, want true/3", folded.Finished, folded.Code)
	}
	if !folded.At.Equal(start) {
		t.Fatalf("folding overwrote the start time: %v, want %v", folded.At, start)
	}
	if folded.HostName != "web1" || folded.HostID != "h1" {
		t.Fatalf("the entry names host %q/%q, want web1/h1", folded.HostName, folded.HostID)
	}

	// A refusal is a single terminal entry with no running phase before it, and
	// it must be distinguishable from a command that ran and failed.
	notify(Event{ID: 3, Command: "rm -rf /", At: time.Now(),
		Err: errors.New("refused: this grant has been revoked"), Finished: true, Refused: true})
	log = h.Log()
	if len(log) != 3 {
		t.Fatalf("the refusal made %d entries in total, want 3", len(log))
	}
	if !log[0].Refused || !log[0].Finished || log[0].Err == "" {
		t.Fatalf("the refusal entry is %+v, want refused, finished and carrying a reason", log[0])
	}
}

func TestTheLogSurvivesRevocationAndAReplacementNamesBothHosts(t *testing.T) {
	// Revoking is exactly when a user wants to read what ran, so the log outlives
	// the grant. Because it does, each entry has to say which host it belonged to
	// — otherwise a replacement would leave two hosts' commands in one
	// undifferentiated list.
	h := newHolderIn(t)
	if _, err := h.Toggle(hostOpts(&fakeExec{}, "h1", "web1")); err != nil {
		t.Fatalf("Toggle web1: %v", err)
	}
	sinkOf(h, "h1", "web1")(Event{ID: 1, Command: "on-web1", At: time.Now(), Finished: true})

	if _, err := h.Toggle(hostOpts(&fakeExec{}, "h2", "db1")); err != nil {
		t.Fatalf("Toggle db1: %v", err)
	}
	// Id 1 again, on the new grant: ids are unique per grant, not across them,
	// and the holder must not fold the two into one row.
	sinkOf(h, "h2", "db1")(Event{ID: 1, Command: "on-db1", At: time.Now(), Finished: true})

	log := h.Log()
	if len(log) != 2 {
		t.Fatalf("the log holds %d entries, want both hosts' commands", len(log))
	}
	byCmd := commandsIn(log)
	if got := byCmd["on-web1"].HostName; got != "web1" {
		t.Fatalf("the first command is attributed to %q, want web1", got)
	}
	if got := byCmd["on-db1"].HostName; got != "db1" {
		t.Fatalf("the second command is attributed to %q, want db1", got)
	}
	if byCmd["on-web1"].ID == byCmd["on-db1"].ID {
		t.Fatal("two entries share an Entry.ID; ids must be unique per process")
	}
}

func TestChangedNudgesWithoutBlockingTheProducerAndADroppedNudgeLosesNoLogData(t *testing.T) {
	h := newHolderIn(t)
	if _, err := h.Toggle(hostOpts(&fakeExec{}, "h1", "web1")); err != nil {
		t.Fatalf("Toggle: %v", err)
	}
	// The grant itself nudged; drain that one so the flood below starts from a
	// known state.
	<-h.Changed()

	notify := sinkOf(h, "h1", "web1")

	// Nobody is receiving. Every one of these nudges after the first is dropped,
	// which is the whole design: the nudge is not a transport. The producer must
	// not block on any of them — while attached, the receiving loop is suspended
	// for minutes, and a blocking nudge would stall a command mid-flight.
	const n = LogMax
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 1; i <= n; i++ {
			notify(Event{ID: uint64(i), Command: fmt.Sprintf("cmd-%d", i), At: time.Now(), Finished: true})
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the producer blocked on the nudge channel")
	}

	// Exactly one nudge is pending: it coalesced, as intended.
	select {
	case <-h.Changed():
	default:
		t.Fatal("no nudge is pending after a flood of log writes")
	}
	select {
	case <-h.Changed():
		t.Fatal("a second nudge is pending; the channel must coalesce, not queue")
	default:
	}

	// And not one of the dropped nudges cost a log entry: the UI re-reads the
	// whole log, so the nudge only ever had to say "look again".
	log := h.Log()
	if len(log) != n {
		t.Fatalf("the log holds %d entries, want %d", len(log), n)
	}
}

func TestConcurrentTogglesRevokesAndReadsAreSafe(t *testing.T) {
	// Toggle is called from the dashboard reducer and from the attach byte
	// scanner, Current and Log from a render, and the audit sink from one
	// goroutine per in-flight command. Under -race, all of them at once.
	h := newHolderIn(t)
	exec := &fakeExec{}

	hosts := []struct{ id, name string }{{"h1", "web1"}, {"h2", "db1"}, {"h3", "edge1"}}

	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				host := hosts[(w+i)%len(hosts)]
				if _, err := h.Toggle(hostOpts(exec, host.id, host.name)); err != nil {
					t.Errorf("Toggle: %v", err)
					return
				}
			}
		}(w)
	}
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				h.Revoke()
			}
		}()
	}
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 80; i++ {
				if g := h.Current(); g != nil {
					// Reading through a grant that another goroutine may be closing
					// under us has to be safe: the render does exactly this.
					_, _, _ = g.HostName(), g.ExpiresAt(), g.Count()
				}
				_ = h.Log()
				sinkOf(h, "hx", "hostx")(Event{
					ID: uint64(i + 1), Command: fmt.Sprintf("w%d-%d", w, i), At: time.Now()})
			}
		}(w)
	}
	// Nothing reads Changed, so it stays full and every send is dropped. That
	// must not wedge any of the above.
	wg.Wait()

	h.Revoke()
	if h.Current() != nil {
		t.Fatal("a grant survived the final revoke")
	}
	if len(h.Log()) == 0 {
		t.Fatal("the log is empty after hundreds of audited events")
	}
	// Whatever the interleaving was, the log must never exceed its cap.
	if len(h.Log()) > LogMax {
		t.Fatalf("the log grew to %d entries, past the cap of %d", len(h.Log()), LogMax)
	}
}

// holdPublish installs the publish seam and returns two channels: reached,
// closed once a Toggle has opened its grant and is about to publish it, and
// release, which the test closes to let it carry on.
//
// This is how the abandoned-callback window is reproduced deterministically.
// The real thing is a multi-second stall inside Open against a publish that
// takes nanoseconds; a test that tried to win that race by repetition would
// pass whether the epoch check existed or not.
func holdPublish(t *testing.T) (reached <-chan struct{}, release chan struct{}) {
	t.Helper()
	got := make(chan struct{})
	rel := make(chan struct{})
	// An atomic flag rather than a sync.Once: Once.Do blocks every other caller
	// until the first returns, and the overtaking-Toggle test needs the second
	// Toggle to run straight through while the first is still parked here.
	var fired atomic.Bool
	fn := func() {
		if fired.CompareAndSwap(false, true) {
			close(got)
			<-rel
		}
	}
	publishProbe.Store(&fn)
	t.Cleanup(func() { publishProbe.Store(nil) })
	return got, rel
}

// grantSockets lists the socket files sitting in the grants directory. The
// leaked socket is the actual harm in the superseded case — a live capability
// on a locked vault — so the assertions are on the filesystem, not only on the
// holder's field.
func grantSockets(t *testing.T) []string {
	t.Helper()
	dir, err := grantsDir()
	if err != nil {
		t.Fatalf("grantsDir: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("reading %s: %v", dir, err)
	}
	var socks []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sock") {
			socks = append(socks, e.Name())
		}
	}
	return socks
}

func TestAToggleOvertakenByRevokeWhileOpenIsStalledPublishesNothing(t *testing.T) {
	// The defect this pins down: the in-session hotkey callback runs on a helper
	// goroutine the attach loop abandons after ten seconds without cancelling it.
	// If Open stalls past that, the user detaches, locks the vault and walks
	// away — lock() calls Revoke on an empty holder — and the abandoned goroutine
	// then installs a live grant socket on a locked vault, invisible and
	// unrevoked for the full TTL.
	h := newHolderIn(t)
	reached, release := holdPublish(t)

	type result struct {
		out Outcome
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := h.Toggle(hostOpts(&fakeExec{}, "h1", "web1"))
		done <- result{out, err}
	}()

	<-reached
	// This is lock(): a Revoke that finds nothing to revoke. It must still cancel
	// the mint that is in flight, or the guarantee lock() carries is worth
	// nothing.
	if h.Current() != nil {
		t.Fatal("the grant was published before the holder was asked to publish it")
	}
	h.Revoke()
	close(release)

	got := <-done
	if got.err != nil {
		t.Fatalf("an overtaken Toggle must not report an error: %v", got.err)
	}
	if got.out.Kind != OutcomeSuperseded {
		t.Fatalf("kind = %v, want OutcomeSuperseded", got.out.Kind)
	}
	if got.out.Grant != nil {
		t.Fatal("a superseded outcome must not hand out the grant it just tore down")
	}
	if got.out.HostName != "web1" {
		t.Fatalf("the outcome names %q, want the host that was asked for", got.out.HostName)
	}
	if h.Current() != nil {
		t.Fatal("a grant was installed after the vault was locked")
	}
	// The field being nil is not enough: the harm is a socket somebody can
	// connect to. Nothing published it, so nothing but the Toggle itself could
	// ever have unlinked it.
	if socks := grantSockets(t); len(socks) != 0 {
		t.Fatalf("the superseded grant left its socket behind: %v", socks)
	}
}

func TestAToggleOvertakenByAnotherToggleTearsItsOwnGrantDown(t *testing.T) {
	// Same window, different overtaker. A Revoke is not the only thing that can
	// settle the question while Open is stalled — a second keystroke on another
	// host is just as authoritative, and the loser must not leave a socket
	// behind either.
	h := newHolderIn(t)
	reached, release := holdPublish(t)

	type result struct {
		out Outcome
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := h.Toggle(hostOpts(&fakeExec{}, "h1", "web1"))
		done <- result{out, err}
	}()
	<-reached

	// The seam fires once, so this second Toggle runs straight through.
	winner, err := h.Toggle(hostOpts(&fakeExec{}, "h2", "db1"))
	if err != nil {
		t.Fatalf("the overtaking Toggle failed: %v", err)
	}
	if winner.Kind != OutcomeGranted {
		t.Fatalf("the overtaking toggle reported %v, want OutcomeGranted", winner.Kind)
	}
	close(release)

	got := <-done
	if got.err != nil {
		t.Fatalf("an overtaken Toggle must not report an error: %v", got.err)
	}
	if got.out.Kind != OutcomeSuperseded {
		t.Fatalf("kind = %v, want OutcomeSuperseded", got.out.Kind)
	}
	if h.Current() != winner.Grant {
		t.Fatal("the loser overwrote the grant that won")
	}
	// Exactly one socket: the winner's. The loser unlinked its own.
	socks := grantSockets(t)
	if len(socks) != 1 {
		t.Fatalf("the grants directory holds %v, want only the winner's socket", socks)
	}
	if socks[0] != filepath.Base(winner.Grant.SocketPath()) {
		t.Fatalf("the surviving socket is %q, want the winner's %q",
			socks[0], filepath.Base(winner.Grant.SocketPath()))
	}
}

func TestRevokeDoesNotWaitOutAStalledOpen(t *testing.T) {
	// lock() and quit call Revoke on the event loop. An earlier version held one
	// coarse lock across Open, which meant a wedged runtime directory froze the
	// vault lock instead of merely delaying a grant. Revoke must return while
	// Open is still stuck.
	h := newHolderIn(t)
	reached, release := holdPublish(t)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = h.Toggle(hostOpts(&fakeExec{}, "h1", "web1"))
	}()
	<-reached

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		h.Revoke()
	}()
	select {
	case <-returned:
	case <-time.After(10 * time.Second):
		t.Fatal("Revoke blocked behind a stalled mint")
	}

	// Current and Log must stay answerable too — they are called from a render.
	if h.Current() != nil {
		t.Fatal("Current reports a grant that was never published")
	}
	_ = h.Log()

	close(release)
	<-done
}

func TestToggleReportsAnOpenFailureAndKeepsTheGrantItAlreadyHad(t *testing.T) {
	h := newHolderIn(t)
	first, err := h.Toggle(hostOpts(&fakeExec{}, "h1", "web1"))
	if err != nil {
		t.Fatalf("Toggle: %v", err)
	}

	// A grant with no executor cannot be opened. The existing grant must survive
	// that: a user who asked for a capability and got an error must not silently
	// lose the one they already had.
	out, err := h.Toggle(Options{HostID: "h2", HostName: "db1"})
	if err == nil {
		t.Fatal("Toggle with no executor returned no error")
	}
	if out.Kind != OutcomeNone {
		t.Fatalf("a failed toggle reported kind %v, want OutcomeNone", out.Kind)
	}
	if h.Current() != first.Grant {
		t.Fatal("the failed toggle dropped the grant that was already live")
	}
}
