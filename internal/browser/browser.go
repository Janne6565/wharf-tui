// Package browser opens a URL in the user's desktop browser.
//
// It exists for one job: the device-code sign-in shows a pairing page, and
// typing that URL by hand is friction the user did not ask for. Everything here
// is best-effort — the URL stays on screen either way, so a failure to open is
// a missed convenience rather than a dead end.
package browser

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Open asks the desktop to open rawURL in the default browser. It returns once
// the handler has been launched, not once the page has loaded.
func Open(rawURL string) error {
	if err := checkURL(rawURL); err != nil {
		return err
	}
	name, args := opener(rawURL)
	if name == "" {
		return fmt.Errorf("browser: no opener for %s", runtime.GOOS)
	}
	cmd := exec.Command(name, args...)
	// The handler is a detached GUI process: its stdio must not touch ours, or
	// a chatty xdg-open writes over the TUI's own rendering.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("browser: %w", err)
	}
	// Reap it rather than leaving a zombie. The caller does not wait on this:
	// xdg-open can outlive the launch, and on some desktops it blocks for as
	// long as the browser runs.
	go func() { _ = cmd.Wait() }()
	return nil
}

// checkURL rejects anything that is not plain http(s). The base URL comes from
// WHARF_API_BASE, so it is not necessarily trustworthy input, and handing an
// arbitrary scheme to the desktop's URL handler is how a "URL" turns into a
// command.
func checkURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("browser: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("browser: refusing to open %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("browser: no host in %q", rawURL)
	}
	return nil
}

// opener names the platform's URL handler.
func opener(rawURL string) (string, []string) {
	switch runtime.GOOS {
	case "darwin":
		return "open", []string{rawURL}
	case "windows":
		// Not `cmd /c start`: that parses the URL as a command line and eats
		// the ampersands in a query string.
		return "rundll32", []string{"url.dll,FileProtocolHandler", rawURL}
	default:
		return "xdg-open", []string{rawURL}
	}
}

// Available reports whether opening a browser is likely to reach a screen the
// user is actually looking at.
//
// The case that matters is wharf running over SSH: the machine may well have a
// browser, but it is on someone else's desk. Opening it there is worse than
// doing nothing, because the user waits for a window that never appears while
// the URL they needed scrolls past.
func Available() bool {
	if os.Getenv("WHARF_NO_BROWSER") != "" {
		return false
	}
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" {
		return false
	}
	// macOS and Windows always have a windowing system; on X11/Wayland a
	// missing display means there is nothing to open into.
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		if strings.TrimSpace(os.Getenv("DISPLAY")) == "" &&
			strings.TrimSpace(os.Getenv("WAYLAND_DISPLAY")) == "" {
			return false
		}
	}
	return true
}
