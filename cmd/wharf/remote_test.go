package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// runRemoteWith runs the client with captured streams, so a test can assert on
// the exit code and on what the user was told, which for this command are the
// two halves of one answer.
func runRemoteWith(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code = runRemote(args, strings.NewReader(stdin), &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func TestRemoteFlagIsRecognisedInEverySpelling(t *testing.T) {
	for _, arg := range []string{"--remote", "-remote", "--remote=tok", "-remote=tok"} {
		if !isRemoteFlag(arg) {
			t.Errorf("isRemoteFlag(%q) = false, want true", arg)
		}
	}
	// A host called "remote" must still be a host, and no other flag may be
	// mistaken for this one.
	for _, arg := range []string{"remote", "--remotely", "--demo", "--", "-", "", "--session-host"} {
		if isRemoteFlag(arg) {
			t.Errorf("isRemoteFlag(%q) = true, want false", arg)
		}
	}
}

func TestParseRemoteArgsAcceptsTheDocumentedForms(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want remoteInvocation
	}{
		{
			name: "token, separator, argv",
			args: []string{"--remote", "TOK", "--", "curl", "-sS", "localhost"},
			want: remoteInvocation{token: "TOK", timeout: defaultRemoteTimeout, command: []string{"curl", "-sS", "localhost"}},
		},
		{
			name: "token attached to the flag",
			args: []string{"--remote=TOK", "--", "uptime"},
			want: remoteInvocation{token: "TOK", timeout: defaultRemoteTimeout, command: []string{"uptime"}},
		},
		{
			name: "no token at all, for the environment to supply",
			args: []string{"--remote", "--", "uptime"},
			want: remoteInvocation{timeout: defaultRemoteTimeout, command: []string{"uptime"}},
		},
		{
			name: "no token, with our own flags still recognised",
			args: []string{"--remote", "--timeout", "5s", "--sh", "--", "a | b"},
			want: remoteInvocation{raw: true, timeout: 5 * time.Second, command: []string{"a | b"}},
		},
		{
			name: "a separate timeout value",
			args: []string{"--remote", "TOK", "--timeout", "90s", "--", "make"},
			want: remoteInvocation{token: "TOK", timeout: 90 * time.Second, command: []string{"make"}},
		},
		{
			name: "an attached timeout value",
			args: []string{"--remote", "TOK", "--timeout=1h30m", "--", "make"},
			want: remoteInvocation{token: "TOK", timeout: 90 * time.Minute, command: []string{"make"}},
		},
		{
			name: "zero timeout means wait as long as the grant lives",
			args: []string{"--remote", "TOK", "--timeout", "0", "--", "make"},
			want: remoteInvocation{token: "TOK", command: []string{"make"}},
		},
		{
			name: "raw shell mode",
			args: []string{"--remote", "TOK", "--sh", "--", "a | b"},
			want: remoteInvocation{token: "TOK", raw: true, timeout: defaultRemoteTimeout, command: []string{"a | b"}},
		},
		{
			name: "a second separator belongs to the command",
			args: []string{"--remote", "TOK", "--", "git", "log", "--", "path"},
			want: remoteInvocation{token: "TOK", timeout: defaultRemoteTimeout, command: []string{"git", "log", "--", "path"}},
		},
		{
			name: "the command may carry flags that look like ours",
			args: []string{"--remote", "TOK", "--", "sleep", "--timeout", "--sh"},
			want: remoteInvocation{token: "TOK", timeout: defaultRemoteTimeout, command: []string{"sleep", "--timeout", "--sh"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseRemoteArgs(tc.args)
			if err != nil {
				t.Fatalf("parseRemoteArgs(%q): %v", tc.args, err)
			}
			if got.token != tc.want.token || got.raw != tc.want.raw || got.timeout != tc.want.timeout {
				t.Errorf("parseRemoteArgs(%q) = %+v, want %+v", tc.args, got, tc.want)
			}
			if strings.Join(got.command, "\x00") != strings.Join(tc.want.command, "\x00") {
				t.Errorf("command = %q, want %q", got.command, tc.want.command)
			}
		})
	}
}

// Tokens are base64url, so "-" and "_" are in their alphabet and about one
// token in sixty-four starts with a dash. The word after --remote is therefore
// the token by grammar, not by inspection — a parser that flag-tests it breaks a
// command line wharf printed itself, at random, for one grant in sixty-four.
//
// These tokens are written out rather than minted, precisely because a random
// one would exercise the leading-dash case only sometimes: a test that passes
// 63 runs in 64 is worse than none.
func TestParseRemoteArgsTakesTheTokenPositionally(t *testing.T) {
	for _, token := range []string{
		"-Et4ue43nImA-E-VraOQHbx3oEM-k753y8uK8RkFtUI", // the one that actually failed
		"-abc",
		"_abc",
		"--leading-double-dash",
		"a-b_c-d",
		"aXbYcZ",
		"-",
	} {
		got, err := parseRemoteArgs([]string{"--remote", token, "--", "uptime"})
		if err != nil {
			t.Errorf("token %q should parse, got: %v", token, err)
			continue
		}
		if got.token != token {
			t.Errorf("token = %q, want %q", got.token, token)
		}
		// The attached spelling has to agree, since it is the escape hatch for
		// anything the positional form cannot express.
		if got, err := parseRemoteArgs([]string{"--remote=" + token, "--", "uptime"}); err != nil || got.token != token {
			t.Errorf("--remote=%s gave %q, %v", token, got.token, err)
		}
	}
}

func TestParseRemoteArgsRejectsMalformedCommandLines(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no separator at all", []string{"--remote", "TOK", "uptime"}, "missing -- before the command"},
		{"nothing but the flag", []string{"--remote"}, "missing --"},
		{"an unknown flag before the separator", []string{"--remote", "TOK", "--verbose", "--", "x"}, "unknown flag"},
		{"a timeout with no value", []string{"--remote", "TOK", "--timeout"}, "needs a duration"},
		{"a timeout that is not a duration", []string{"--remote", "TOK", "--timeout", "30", "--", "x"}, "not a duration"},
		{"a negative timeout", []string{"--remote", "TOK", "--timeout", "-5s", "--", "x"}, "negative"},
		{"a value attached to --sh", []string{"--remote", "TOK", "--sh=x", "--", "y"}, "takes no value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRemoteArgs(tc.args)
			if err == nil {
				t.Fatalf("parseRemoteArgs(%q) should have failed", tc.args)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should mention %q", err, tc.want)
			}
		})
	}
}

// Every wharf-side failure exits 125 and says so on stderr, prefixed. The exit
// code is the only thing a calling agent can branch on, so it matters more here
// than the wording does.
func TestRemoteUsageErrorsExit125AndExplain(t *testing.T) {
	t.Setenv(remoteTokenEnv, "")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"a missing token", []string{"--remote", "--", "uptime"}, "no grant token"},
		{"a missing command", []string{"--remote", "TOK", "--"}, "no command after --"},
		{"--sh with several words", []string{"--remote", "TOK", "--sh", "--", "a", "b"}, "--sh takes exactly one argument"},
		{"a malformed command line", []string{"--remote", "TOK", "uptime"}, "missing --"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runRemoteWith(t, "", tc.args...)
			if code != remoteFailureExit {
				t.Errorf("exit = %d, want %d", code, remoteFailureExit)
			}
			for _, line := range strings.Split(strings.TrimSuffix(stderr, "\n"), "\n") {
				if !strings.HasPrefix(line, "wharf: ") {
					t.Errorf("every stderr line wharf writes is prefixed; got %q in:\n%s", line, stderr)
				}
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr should mention %q, got:\n%s", tc.want, stderr)
			}
		})
	}
}

// --help is not a failure: an agent that reads the help and then runs the real
// command must not see the help path as an error.
func TestRemoteHelpGoesToStdoutAndSucceeds(t *testing.T) {
	code, stdout, stderr := runRemoteWith(t, "", "--remote", "--help")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if stderr != "" {
		t.Errorf("help should not touch stderr, got:\n%s", stderr)
	}
	for _, want := range []string{"--timeout", "--sh", remoteTokenEnv, "125"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("help should document %q, got:\n%s", want, stdout)
		}
	}
}

// The cap exists because v1 sends stdin inside the request frame; the error has
// to name the limit, or a caller cannot tell a size problem from a hang.
func TestRemoteStdinOverTheCapIsRefusedWithTheLimitNamed(t *testing.T) {
	code, _, stderr := runRemoteWith(t, strings.Repeat("x", remoteStdinLimit+1), "--remote", "TOK", "--", "cat")
	if code != remoteFailureExit {
		t.Fatalf("exit = %d, want %d", code, remoteFailureExit)
	}
	if !strings.Contains(stderr, remoteStdinLimitText) {
		t.Errorf("the error should name the cap, got:\n%s", stderr)
	}
}

// A cap the wire cannot carry is worse than no cap: it promises a size and then
// fails with a framing error from a package the user has never heard of, which
// is exactly what a 1 MiB cap did here. This pins the arithmetic in both
// directions — the cap must fit, and it must not be needlessly small.
//
// The end-to-end proof is TestRemoteStdinCapHoldsThroughAGrant; this one is what
// says *why* the number is what it is.
func TestRemoteStdinCapSurvivesBase64Inflation(t *testing.T) {
	// encoding/json base64s a []byte: 4 bytes out per 3 in, rounded up.
	onTheWire := 4 * ((remoteStdinLimit + 2) / 3)
	if onTheWire+remoteFrameFixed > remoteFrameLimit {
		t.Fatalf("%d bytes of stdin become %d on the wire, over the %d-byte frame limit",
			remoteStdinLimit, onTheWire, remoteFrameLimit)
	}
	if left := remoteFrameLimit - onTheWire; left < 1<<10 {
		t.Errorf("only %d bytes left for the command; the reserve is not doing its job", left)
	}
	// The naive figure this replaced, kept as the regression it is: a 1 MiB cap
	// cannot fit, so anyone tempted to round the number up again fails here.
	if naive := 4 * ((1<<20 + 2) / 3); naive <= remoteFrameLimit {
		t.Fatalf("1 MiB of stdin is %d bytes encoded, which was supposed to be over the limit", naive)
	}
}

func TestRemoteStdinIsAbsentRatherThanEmpty(t *testing.T) {
	data, err := readRemoteStdin(strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if data != nil {
		t.Errorf("an empty stdin should send nothing, got %q", data)
	}
	if data, err = readRemoteStdin(nil); err != nil || data != nil {
		t.Errorf("a nil stdin should send nothing, got %q, %v", data, err)
	}
}

func TestShellQuoteLeavesInertWordsAlone(t *testing.T) {
	for _, s := range []string{"curl", "-sS", "localhost:9000/health", "a_b.c", "1,2", "x=y", "@host", "50%"} {
		if got := shellQuote(s); got != s {
			t.Errorf("shellQuote(%q) = %q, want it unchanged — the audit log is read by humans", s, got)
		}
	}
	// Anything that could be expanded, split or globbed is quoted, including the
	// empty word, which would otherwise disappear entirely.
	for _, s := range []string{"", " ", "*", "~", "$HOME", "a b", "a'b", "a\nb", "{1,2}", "!"} {
		if got := shellQuote(s); !strings.HasPrefix(got, "'") {
			t.Errorf("shellQuote(%q) = %q, want it quoted", s, got)
		}
	}
}

// The single quote is the one character single-quoting cannot contain, so its
// escape is the part of the construction most likely to be got wrong. The unix
// round-trip test proves the behaviour; this pins the exact shape, because a
// regression here is otherwise only visible as a mangled payload.
func TestShellQuoteBreaksOutAroundSingleQuotes(t *testing.T) {
	if got, want := shellQuote("it's"), `'it'\''s'`; got != want {
		t.Errorf("shellQuote(%q) = %s, want %s", "it's", got, want)
	}
	if got, want := shellQuote("'"), `''\'''`; got != want {
		t.Errorf("shellQuote(%q) = %s, want %s", "'", got, want)
	}
}

// Both forms run under the remote's login shell: that is what gives an agent the
// same PATH the user sees interactively, and it is easy to lose in a refactor
// because everything still works for anything already on the default PATH.
func TestRemoteCommandAlwaysGoesThroughTheLoginShell(t *testing.T) {
	argv := remoteCommand([]string{"echo", "hi"}, false)
	raw := remoteCommand([]string{"echo hi | tr a-z A-Z"}, true)
	for _, cmd := range []string{argv, raw} {
		if !strings.HasPrefix(cmd, `exec "${SHELL:-/bin/sh}" -lc `) {
			t.Errorf("command %q should run under the login shell", cmd)
		}
	}
	// --sh hands its string over untouched; the argv form does not.
	if !strings.Contains(raw, "echo hi | tr a-z A-Z") {
		t.Errorf("--sh should pass its string through verbatim, got %q", raw)
	}
}
