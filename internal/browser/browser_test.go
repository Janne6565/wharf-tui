package browser

import (
	"runtime"
	"strings"
	"testing"
)

func TestOpenRejectsNonHTTPSchemes(t *testing.T) {
	// WHARF_API_BASE feeds this URL, so a hostile or fat-fingered value must
	// not reach the desktop's URL handler.
	for _, raw := range []string{
		"file:///etc/passwd",
		"javascript:alert(1)",
		"ms-msdt:/id",
		"vnd.ms-search:query",
	} {
		if err := Open(raw); err == nil {
			t.Errorf("Open(%q) = nil, want an error", raw)
		}
	}
}

func TestOpenRejectsHostlessURLs(t *testing.T) {
	for _, raw := range []string{"https://", "http:///device", "not a url at all"} {
		if err := Open(raw); err == nil {
			t.Errorf("Open(%q) = nil, want an error", raw)
		}
	}
}

func TestOpenerUsesThePlatformHandler(t *testing.T) {
	name, args := opener("https://wharf.jannekeipert.de/device")
	if name == "" {
		t.Fatalf("no opener for %s", runtime.GOOS)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "https://wharf.jannekeipert.de/device") {
		t.Errorf("opener args %q do not carry the URL", joined)
	}
	switch runtime.GOOS {
	case "darwin":
		if name != "open" {
			t.Errorf("opener = %q, want open", name)
		}
	case "windows":
		// `cmd /c start` would swallow the ampersands in a query string.
		if name != "rundll32" {
			t.Errorf("opener = %q, want rundll32", name)
		}
	default:
		if name != "xdg-open" {
			t.Errorf("opener = %q, want xdg-open", name)
		}
	}
}

func TestAvailableIsOffOverSSH(t *testing.T) {
	// A browser on the far end of an SSH session opens on someone else's desk.
	t.Setenv("SSH_CONNECTION", "10.0.0.2 51000 10.0.0.9 22")
	if Available() {
		t.Error("Available() = true over SSH, want false")
	}
}

func TestAvailableHonoursTheOptOut(t *testing.T) {
	t.Setenv("WHARF_NO_BROWSER", "1")
	if Available() {
		t.Error("Available() = true with WHARF_NO_BROWSER set, want false")
	}
}

func TestAvailableNeedsADisplayOnUnix(t *testing.T) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		t.Skip("always has a windowing system")
	}
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_TTY", "")
	t.Setenv("WHARF_NO_BROWSER", "")
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	if Available() {
		t.Error("Available() = true with no display, want false")
	}
	t.Setenv("DISPLAY", ":0")
	if !Available() {
		t.Error("Available() = false with DISPLAY set, want true")
	}
}
