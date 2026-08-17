//go:build windows

package ui

import (
	"strings"
	"testing"
)

// The grant server is unix-only: its security model is a bearer token on a 0600
// socket, and the file-mode half of that has no Windows equivalent. The UI must
// therefore degrade to an inline error rather than crash — and since that is a
// behaviour the contract names explicitly, it is tested where it happens rather
// than reasoned about.
func TestOnWindowsAGrantDegradesToAnInlineErrorRatherThanCrashing(t *testing.T) {
	tm, _ := openedModel(t)
	mm := tm.(Model)
	copies := 0
	mm.copyToClipboard = func(string) error { copies++; return nil }

	next, _ := mm.grantRemoteAccess("h1", "web1", stubExec{})
	got := next.(Model)

	if got.raGrant() != nil {
		t.Fatal("remoteaccess.Open cannot succeed on Windows, so no grant may be recorded")
	}
	if !strings.Contains(got.raErr, "unix-only") {
		t.Fatalf("the inline error should explain why the key did nothing, raErr = %q", got.raErr)
	}
	if got.modal == modalRemoteAccess {
		t.Fatal("a failed grant must not open the overlay: there is no command to show")
	}
	if copies != 0 {
		t.Fatalf("nothing was granted, so nothing may be copied (copies = %d)", copies)
	}
	if view := got.View(); !strings.Contains(view, "remote access unavailable") {
		t.Fatalf("the failure should reach the screen as a toast:\n%s", view)
	}
}

// The in-session hotkey exists on Windows too — the binding is cross-platform,
// and the byte is watched by sshx's in-process attach loop. It cannot mint
// anything, so what it owes the user is the reason. A key that silently does
// nothing is worse than one that says why: from inside an attached session
// there is no other channel through which the user could ever find out.
func TestOnWindowsTheInSessionHotkeyPrintsTheUnsupportedExplanation(t *testing.T) {
	tm, _ := openedModel(t)
	mm := tm.(Model)
	copies := 0
	mm.copyToClipboard = func(string) error { copies++; return nil }

	text := remoteAccessHotkey(mm.ra, mm.raCopy, mm.copyToClipboard, "h1", "web1", stubExec{})()

	if !strings.Contains(text, "unix-only") {
		t.Fatalf("the printed line must explain why the key did nothing, got %q", text)
	}
	if !strings.HasPrefix(text, "\r\n") || !strings.HasSuffix(text, "\r\n") {
		t.Fatalf("the terminal is in raw mode, so the text needs \\r\\n line endings, got %q", text)
	}
	if mm.raGrant() != nil {
		t.Fatal("no grant can exist on Windows")
	}
	if copies != 0 {
		t.Fatalf("nothing was granted, so nothing may be copied (copies = %d)", copies)
	}
}
