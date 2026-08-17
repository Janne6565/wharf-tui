//go:build !windows

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Janne6565/wharf-tui/internal/remoteaccess"
	"github.com/Janne6565/wharf-tui/internal/sessd"
)

// argSeparator is the byte the argv-printing helper writes after each argument.
// A record separator rather than a newline or a NUL: newlines are one of the
// inputs under test, and POSIX printf(1) cannot portably emit a NUL.
const argSeparator = "\x1e"

// writeScript drops an executable /bin/sh script in a temp dir and returns its
// path.
func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// loginShellStub stands in for the remote user's login shell during a test. It
// exists because remoteCommand runs "$SHELL" -lc, and -l would source the
// developer's profile and mix its output into what the test is asserting on. The
// stub drops the -l and nothing else, so both quoting layers — the outer shell
// that parses remoteCommand's string, and the inner one that parses the script
// it hands over — are still exercised exactly as they are in production.
func loginShellStub(t *testing.T, dir string) string {
	return writeScript(t, dir, "login-shell", "#!/bin/sh\nexec /bin/sh -c \"$2\"\n")
}

// argPrinter writes each of its arguments to stdout followed by argSeparator,
// which is how a test recovers the argv the far end actually received.
func argPrinter(t *testing.T, dir string) string {
	return writeScript(t, dir, "print-args", "#!/bin/sh\nfor a in \"$@\"; do printf '%s"+argSeparator+"' \"$a\"; done\n")
}

// This is the load-bearing test of the whole client. Wharf quotes the agent's
// argv exactly once and the far end is a real shell, so the only honest way to
// check the quoting is to run the string it produces through a real shell and
// see which argv comes out the other side. Every input here is one that a naive
// implementation — join with spaces, or double quotes, or a hand-rolled
// backslash escape — gets wrong.
func TestRemoteArgvSurvivesTheShellVerbatim(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SHELL", loginShellStub(t, dir))
	printer := argPrinter(t, dir)

	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"a plain command", []string{"curl", "-sS", "localhost:9000/health"}},
		{"a JSON body, the case this feature exists for", []string{"curl", "-X", "POST", "-d", `{"a":1,"b":[2,3]}`, "http://localhost:9000/x"}},
		{"an embedded single quote", []string{"echo", "it's", "Bob's"}},
		{"nothing but quotes", []string{"echo", `'`, `''`, `a'b'c`}},
		{"mixed quote styles", []string{"sh", "-c", `echo "a 'b' c"`}},
		{"spaces and tabs", []string{"echo", "a b", "c\td", "  leading"}},
		{"an empty argument", []string{"echo", "", "after"}},
		{"things a shell would expand", []string{"echo", "$HOME", "${PATH}", "$(id)", "`id`"}},
		{"backslashes", []string{"echo", `a\b`, `\\`, `\`, `\'`, `\n`}},
		{"newlines", []string{"echo", "line1\nline2", "\n"}},
		{"glob and brace characters", []string{"echo", "*", "?", "[a-z]", "{1,2}", "~", "~root"}},
		{"shell operators as data", []string{"echo", "a|b", "a&&b", "a;b", "a>b", "a<b", "(a)", "#c", "!h"}},
		{"non-ASCII", []string{"echo", "héllo — wörld", "✓", "日本語"}},
		{"a whole script as one argument", []string{"ssh-host", "for i in 1 2 3; do echo \"n=$i\"; done"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			argv := append([]string{printer}, tc.argv...)
			cmd := remoteCommand(argv, false)

			out, err := exec.Command("/bin/sh", "-c", cmd).Output()
			if err != nil {
				t.Fatalf("running %s: %v", cmd, err)
			}
			got := strings.Split(string(out), argSeparator)
			got = got[:len(got)-1] // the trailing separator leaves an empty tail

			if len(got) != len(tc.argv) {
				t.Fatalf("got %d arguments %q, want %d %q (from %s)", len(got), got, len(tc.argv), tc.argv, cmd)
			}
			for i := range got {
				if got[i] != tc.argv[i] {
					t.Errorf("argument %d = %q, want %q (from %s)", i, got[i], tc.argv[i], cmd)
				}
			}
		})
	}
}

// --sh is the opposite promise: the string is a shell command, so the shell is
// supposed to interpret it.
func TestRemoteShellFormIsInterpretedByTheShell(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SHELL", loginShellStub(t, dir))

	out, err := exec.Command("/bin/sh", "-c", remoteCommand([]string{`echo one two | tr ' ' '-'`}, true)).Output()
	if err != nil {
		t.Fatalf("running the raw form: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "one-two" {
		t.Errorf("--sh should let the shell do its work, got %q", got)
	}
}

// localExecutor is the far end of a grant in these tests: it runs the command it
// is handed on this machine, which is exactly what the real executor does on the
// remote one. It makes the test cover the whole client path — parse, quote,
// dial, authenticate, stream, exit code — with nothing stubbed on the way.
type localExecutor struct{}

func (localExecutor) Exec(ctx context.Context, req sessd.ExecRequest, stdout, stderr io.Writer) (int, error) {
	c := exec.CommandContext(ctx, "/bin/sh", "-c", req.Command)
	c.Stdin = bytes.NewReader(req.Stdin)
	c.Stdout, c.Stderr = stdout, stderr
	err := c.Run()
	var exitErr *exec.ExitError
	switch {
	case ctx.Err() != nil:
		// What sshx.Exec does: a command cut short by the deadline reports the
		// deadline, not the -1 the killed process leaves behind.
		return 0, ctx.Err()
	case errors.As(err, &exitErr):
		// A non-zero exit is the remote's answer, not a failure to run it.
		return exitErr.ExitCode(), nil
	case err != nil:
		return 0, err
	}
	return 0, nil
}

// runtimeDir points wharf's runtime directory at a fresh, short path. Short
// because a unix socket path has a ~100-byte ceiling and macOS hands out a
// 50-character $TMPDIR, which t.TempDir would inherit.
func runtimeDir(t *testing.T) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "wharf-ra")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv("WHARF_RUNTIME_DIR", dir)
}

// openTestGrant starts a real grant served by localExecutor and returns its
// token.
func openTestGrant(t *testing.T) string {
	t.Helper()
	runtimeDir(t)
	g, err := remoteaccess.Open(remoteaccess.Options{Exec: localExecutor{}, HostName: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g.Token()
}

func TestRemoteExitCodePassesThroughVerbatim(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SHELL", loginShellStub(t, dir))
	token := openTestGrant(t)

	for _, want := range []int{0, 1, 2, 7, 42, remoteFailureExit} {
		code, _, stderr := runRemoteWith(t, "", "--remote", token, "--", "sh", "-c", "exit "+itoa(want))
		if code != want {
			t.Errorf("exit = %d, want %d (stderr: %s)", code, want, stderr)
		}
		// The remote's own 125 is indistinguishable by code alone, so the other
		// half of the contract is that wharf stays silent when it did not fail.
		if stderr != "" {
			t.Errorf("wharf should say nothing when the command ran, got: %s", stderr)
		}
	}
}

func TestRemoteStreamsAreKeptApart(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SHELL", loginShellStub(t, dir))
	token := openTestGrant(t)

	code, stdout, stderr := runRemoteWith(t, "", "--remote", token, "--sh", "--", "echo out; echo err >&2")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if strings.TrimSpace(stdout) != "out" {
		t.Errorf("stdout = %q, want %q", stdout, "out")
	}
	if strings.TrimSpace(stderr) != "err" {
		t.Errorf("stderr = %q, want %q", stderr, "err")
	}
}

func TestRemoteForwardsStdinWhenItIsNotATerminal(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SHELL", loginShellStub(t, dir))
	token := openTestGrant(t)

	code, stdout, stderr := runRemoteWith(t, "hello from stdin", "--remote", token, "--", "cat")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if stdout != "hello from stdin" {
		t.Errorf("stdout = %q, want the stdin back", stdout)
	}
}

// The cap has to be tested where it is actually enforced: on the wire. The
// original 1 MiB cap passed a unit test against readRemoteStdin and failed
// against a real socket, because stdin is base64'd into JSON before it meets a
// frame limit and nothing in-process ever sees that. So this drives a live
// grant, at the cap and one byte past it.
func TestRemoteStdinCapHoldsThroughAGrant(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SHELL", loginShellStub(t, dir))
	token := openTestGrant(t)

	// Not all one byte: a run of identical bytes is the input least likely to
	// expose an off-by-one in a length calculation.
	payload := make([]byte, remoteStdinLimit)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}

	code, stdout, stderr := runRemoteWith(t, string(payload), "--remote", token, "--", "cat")
	if code != 0 {
		t.Fatalf("stdin exactly at the %s cap must go through, got exit %d: %s",
			remoteStdinLimitText, code, stderr)
	}
	if stdout != string(payload) {
		t.Errorf("got %d bytes back, want the %d sent", len(stdout), len(payload))
	}

	// One byte over is wharf's own refusal, in wharf's words — not a framing
	// error leaking up from remoteaccess or sessd.
	code, stdout, stderr = runRemoteWith(t, string(payload)+"!", "--remote", token, "--", "cat")
	if code != remoteFailureExit {
		t.Fatalf("one byte over the cap should exit %d, got %d", remoteFailureExit, code)
	}
	if stdout != "" {
		t.Errorf("nothing should have run, got %d bytes of output", len(stdout))
	}
	if !strings.Contains(stderr, remoteStdinLimitText) {
		t.Errorf("the refusal should name the cap, got: %s", stderr)
	}
	if strings.Contains(stderr, "frame") && !strings.Contains(stderr, "wharf: stdin") {
		t.Errorf("this must not be an internal framing error, got: %s", stderr)
	}
}

// The other half of the frame budget: an enormous command with no stdin at all.
// The reserve is what overflows here, and the user must still hear it from
// wharf rather than from a framing error two packages away.
func TestRemoteOversizedCommandIsRefusedByWharf(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SHELL", loginShellStub(t, dir))
	token := openTestGrant(t)

	code, _, stderr := runRemoteWith(t, "", "--remote", token, "--sh", "--",
		"echo "+strings.Repeat("x", remoteFrameLimit))
	if code != remoteFailureExit {
		t.Fatalf("exit = %d, want %d", code, remoteFailureExit)
	}
	if !strings.Contains(stderr, "shorten the command") {
		t.Errorf("the refusal should be wharf's own and say what to do, got: %s", stderr)
	}
}

// The end-to-end version of the quoting test: the same nasty payload, but
// through a live grant rather than a bare shell, so nothing between the argv and
// the host is allowed to reinterpret it either.
func TestRemoteJSONPayloadArrivesIntactThroughAGrant(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SHELL", loginShellStub(t, dir))
	token := openTestGrant(t)
	payload := `{"a":1,"b":"it's","c":["x y","$HOME","\\"]}`

	code, stdout, stderr := runRemoteWith(t, "", "--remote", token, "--", "printf", "%s", payload)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if stdout != payload {
		t.Errorf("payload arrived as %q, want %q", stdout, payload)
	}
}

func TestRemoteTokenEnvIsUsedWhenArgvHasNone(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SHELL", loginShellStub(t, dir))
	token := openTestGrant(t)
	t.Setenv(remoteTokenEnv, token)

	code, stdout, stderr := runRemoteWith(t, "", "--remote", "--", "echo", "from-env")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if strings.TrimSpace(stdout) != "from-env" {
		t.Errorf("stdout = %q", stdout)
	}
}

// A token in argv is a deliberate act; an exported variable is often a leftover.
// The explicit one has to win, or a stale export silently redirects a command to
// a different host.
func TestRemoteArgvTokenBeatsTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SHELL", loginShellStub(t, dir))
	token := openTestGrant(t)
	t.Setenv(remoteTokenEnv, "not-a-real-token")

	code, _, stderr := runRemoteWith(t, "", "--remote", token, "--", "true")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
}

// The failure an agent will hit most: the grant was revoked, or expired, or the
// wharf holding it has quit. It must be 125 and it must say so, since there is
// no remote exit code to report.
func TestRemoteUnreachableGrantExits125(t *testing.T) {
	runtimeDir(t)

	code, stdout, stderr := runRemoteWith(t, "", "--remote", "no-such-token", "--", "echo", "hi")
	if code != remoteFailureExit {
		t.Fatalf("exit = %d, want %d", code, remoteFailureExit)
	}
	if stdout != "" {
		t.Errorf("nothing ran, so stdout should be empty, got %q", stdout)
	}
	if !strings.Contains(stderr, "no live grant") {
		t.Errorf("stderr should explain, got: %s", stderr)
	}
}

// A wrong token against a live grant is the same opaque failure as no grant at
// all: telling them apart would confirm that some grant exists.
func TestRemoteWrongTokenIsIndistinguishableFromNoGrant(t *testing.T) {
	openTestGrant(t)

	code, _, stderr := runRemoteWith(t, "", "--remote", "wrong", "--", "echo", "hi")
	if code != remoteFailureExit {
		t.Fatalf("exit = %d, want %d", code, remoteFailureExit)
	}
	if !strings.Contains(stderr, "no live grant") {
		t.Errorf("stderr should be the same opaque message, got: %s", stderr)
	}
}

func TestRemoteTimeoutIsReportedAsWharfsOwnFailure(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SHELL", loginShellStub(t, dir))
	token := openTestGrant(t)

	code, _, stderr := runRemoteWith(t, "", "--remote", token, "--timeout", "100ms", "--", "sleep", "5")
	if code != remoteFailureExit {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, remoteFailureExit, stderr)
	}
	if !strings.HasPrefix(stderr, "wharf: ") {
		t.Errorf("stderr should be a wharf-prefixed line, got: %s", stderr)
	}
}

// itoa keeps the exit-code table readable without pulling strconv into a test
// that has no other use for it.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
