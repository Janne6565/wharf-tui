package main

import "errors"

// runSessionHost never has anything to do on Windows: sessions run in the TUI's
// own process there, so nothing ever re-executes wharf with --session-host.
//
// It still exists, and still fails loudly, because the flag is recognised on
// every platform — a user who finds it in a process list and tries it deserves
// an explanation rather than a confusing crash.
func runSessionHost(string) error {
	return errors.New("session hosts are a unix-only mechanism; on Windows sessions run inside wharf itself")
}
