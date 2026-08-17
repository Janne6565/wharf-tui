package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Janne6565/wharf-tui/internal/remoteaccess"
)

// remoteFlagName is the flag that switches wharf from "open the TUI" to "be the
// client half of a remote-access grant".
//
// It is a flag and not a verb (`wharf remote …`) because the repo's rule is that
// a bare argument names a saved host: `wharf remote` would be ambiguous with a
// host actually called "remote". See the package comment and README.md.
const remoteFlagName = "remote"

// remoteFailureExit is the exit code for every failure that is wharf's own
// rather than the remote command's: an unusable token, no grant that accepts it,
// a timeout, a malformed invocation.
//
// 125 follows the convention env(1) and timeout(1) established for exactly this
// problem — a wrapper has to report its own failure through the same channel it
// is forwarding somebody else's exit code on. 1 and 2 were rejected because they
// are the two codes ordinary programs return most often, so a caller could not
// tell "your command failed" from "wharf could not run it". Usage errors use 125
// too rather than the 2 the rest of wharf uses, so that a caller has exactly one
// code to test for.
//
// The residual ambiguity is real and worth stating: a remote command that itself
// exits 125 is indistinguishable from a wharf-side failure. Anything wharf
// reports is accompanied by a "wharf: " line on stderr, which is the tiebreak.
const remoteFailureExit = 125

// defaultRemoteTimeout bounds a command that never finishes. It is finite on
// purpose: a hung command holds one of the grant's few in-flight slots until the
// grant's whole TTL runs out, and an agent that gets no answer usually retries
// rather than waits. Two minutes covers the health checks, greps and test runs
// this is built for; anything longer is a deliberate --timeout away.
//
// "No timeout by default" was rejected for the reason above. Matching the
// grant's 60m TTL was rejected as the same thing with extra steps.
const defaultRemoteTimeout = 2 * time.Minute

// remoteFrameLimit is the ceiling a single frame may not exceed. Both framing
// layers between this command and the host enforce it independently:
// internal/remoteaccess/proto.go's maxFrame on the grant socket, and
// internal/sessd/proto.go's on the session socket behind it.
//
// It is duplicated here because both are unexported, and it must stay in step
// with them. Duplicating the number is the lesser evil: the alternative is this
// command promising a stdin size that a layer two hops away silently refuses,
// which is exactly the defect this constant exists to prevent.
const remoteFrameLimit = 1 << 20

// remoteFrameReserve is the part of a frame that is not stdin: the command
// string, the JSON field names, the correlation ID sessd adds on its own hop,
// and the escaping around all of it. 64 KiB is far more than any of that
// plausibly needs — a command line is measured in hundreds of bytes — and the
// slack is deliberate, because being wrong in this direction costs a few
// kilobytes of capacity while being wrong in the other costs the user a
// confusing framing error from a package they have never heard of.
const remoteFrameReserve = 64 << 10

// remoteStdinLimit caps forwarded stdin. v1 sends stdin inside the request
// rather than streaming it, so the whole thing is held in memory in three
// processes at once — and, more to the point here, has to fit in one frame.
//
// The number is derived rather than chosen. Stdin is []byte in a JSON struct,
// so encoding/json base64-encodes it: 4 bytes on the wire for every 3 bytes in.
// The frame that carries it therefore holds ceil(n/3)*4 bytes of stdin plus
// everything else in the request:
//
//	n ≤ (remoteFrameLimit - remoteFrameReserve) × 3/4
//	  = (1048576 - 65536) × 3/4
//	  = 737280 bytes = 720 KiB
//
// A round 1 MiB was the original figure and was simply wrong: 1 MiB of stdin
// becomes 1398104 base64 bytes and is refused by both frame layers, so the cap
// the help text promised could not be reached. The chunking on the output path
// (outChunk, execChunk) got this right; only stdin was missed.
const remoteStdinLimit = (remoteFrameLimit - remoteFrameReserve) * 3 / 4

// remoteStdinLimitText renders the cap the way the error and the help text say
// it, so the two can never disagree.
var remoteStdinLimitText = fmt.Sprintf("%d KiB", remoteStdinLimit>>10)

// remoteTokenEnv supplies the token when it is not in argv. The token is a
// bearer credential and argv is world-readable through ps(1), so a caller who
// cares can keep it out of the process list this way. It is an alternative, not
// the default: the copy-pasteable one-liner wharf prints is the ergonomic case.
const remoteTokenEnv = "WHARF_REMOTE_TOKEN"

// isRemoteFlag reports whether arg starts a remote-access invocation.
//
// Both dash spellings are accepted because Go's own flag package accepts both
// and nothing else in wharf teaches a user which one this is; an attached value
// (--remote=TOKEN) is accepted for the same reason.
func isRemoteFlag(arg string) bool {
	name, _, _ := splitFlagArg(arg)
	return name == remoteFlagName
}

// splitFlagArg decomposes "--name=value" into its parts. It reports hasValue
// only for the attached form, so "--timeout" and "--timeout=" are distinguished
// — the second is a user who meant to type a duration.
func splitFlagArg(arg string) (name, value string, hasValue bool) {
	if !strings.HasPrefix(arg, "-") || arg == "-" || arg == "--" {
		return "", "", false
	}
	s := strings.TrimPrefix(arg, "-")
	s = strings.TrimPrefix(s, "-")
	if i := strings.IndexByte(s, '='); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, "", false
}

// isRemoteOption reports whether arg is one of the options this command defines,
// in any of the spellings splitFlagArg accepts.
//
// It exists so that the token position can be recognised by grammar rather than
// by "does it start with a dash", which a base64url token does about one time in
// sixty-four. Keep it in step with the switch in parseRemoteArgs: a flag listed
// there and missing here would be swallowed as a token whenever it appeared
// before one.
func isRemoteOption(arg string) bool {
	name, _, _ := splitFlagArg(arg)
	switch name {
	case "timeout", "sh", "h", "help":
		return true
	}
	return false
}

// remoteInvocation is a parsed `wharf --remote …` command line.
type remoteInvocation struct {
	token   string
	raw     bool // --sh: command[0] is a shell script, not an argv
	timeout time.Duration
	command []string
}

// errRemoteHelp is the non-failure outcome of `wharf --remote --help`. It is a
// sentinel rather than a bool return so the parser has one result type.
var errRemoteHelp = errors.New("help requested")

// parseRemoteArgs parses the arguments of a remote invocation, args[0] being the
// --remote flag itself.
//
// This is hand-rolled instead of a flag.FlagSet because the whole point is the
// "--" separator: stdlib flag consumes it and hands back the rest as
// positionals, which is fine here but would silently accept
// `wharf --remote TOK curl …` with no separator at all. The separator is what
// makes the command's own flags (`curl -sS`) unambiguous, so it is required
// rather than optional — the same reason the TUI never prints the short form.
func parseRemoteArgs(args []string) (remoteInvocation, error) {
	inv := remoteInvocation{timeout: defaultRemoteTimeout}

	// The token may be attached (--remote=TOK) or, far more often, be the next
	// word; it may also be absent entirely, which means $WHARF_REMOTE_TOKEN is
	// expected to supply it.
	//
	// The next word is taken as the token whatever it looks like, including when
	// it starts with a dash. That is not a nicety: a token is base64url, whose
	// alphabet contains "-" and "_", so roughly one token in sixty-four begins
	// with a dash — and rejecting those as an unknown flag would break a command
	// line wharf itself printed and told the user to paste, at random, for one
	// grant in sixty-four. Tokens are user-supplied input and must be treated as
	// opaque bytes here regardless of what the minting side promises.
	//
	// The two exceptions are the separator and this command's own three options,
	// because the no-token form has to be able to say "no token" somehow. No real
	// token can collide with them — they are at most eight characters and a token
	// is forty-three — and --remote=<token> takes even that away.
	_, attached, hasAttached := splitFlagArg(args[0])
	i := 1
	switch {
	case hasAttached:
		inv.token = attached
	case i < len(args) && args[i] != "--" && !isRemoteOption(args[i]):
		inv.token = args[i]
		i++
	}

	sawSeparator := false
	for ; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			sawSeparator = true
			i++
			break
		}
		if !strings.HasPrefix(arg, "-") {
			// A bare word here is almost always the command with the separator
			// forgotten, and saying "unknown flag" about `uptime` would send the
			// user looking for the wrong mistake.
			return inv, fmt.Errorf("missing -- before the command (found %q): "+
				"wharf --remote <token> -- %s …", arg, arg)
		}
		name, value, hasValue := splitFlagArg(arg)
		switch name {
		case "h", "help":
			return inv, errRemoteHelp
		case "sh":
			if hasValue {
				return inv, fmt.Errorf("--sh takes no value (got %q)", arg)
			}
			inv.raw = true
		case "timeout":
			if !hasValue {
				i++
				if i >= len(args) {
					return inv, errors.New("--timeout needs a duration, e.g. --timeout 30s")
				}
				value = args[i]
			}
			d, err := time.ParseDuration(value)
			if err != nil {
				return inv, fmt.Errorf("--timeout %q is not a duration (try 30s, 2m, 1h): %w", value, err)
			}
			if d < 0 {
				return inv, fmt.Errorf("--timeout %q is negative", value)
			}
			inv.timeout = d
		default:
			return inv, fmt.Errorf("unknown flag %q — only --timeout and --sh may follow --remote, "+
				"and the command goes after --", arg)
		}
	}
	if !sawSeparator {
		return inv, errors.New("missing -- before the command: wharf --remote <token> -- <command>")
	}
	inv.command = args[i:]
	return inv, nil
}

// runRemote is the whole of remote-access client mode: parse, connect to the
// grant that accepts the token, stream the command's output, return its exit
// code.
//
// It takes argv and its streams explicitly, and returns rather than exits, so
// that all of it is testable in-process — the resetInstance precedent. main's
// share is one call and one os.Exit.
func runRemote(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "wharf: "+format+"\n", a...)
		return remoteFailureExit
	}

	// A shape error gets the one-line synopsis after it, not the whole help:
	// stderr is a stream a caller may well be parsing, every line of it is
	// prefixed by convention, and --remote --help is one word away.
	failUsage := func(format string, a ...any) int {
		fail(format, a...)
		fmt.Fprintln(stderr, "wharf: usage: wharf --remote <token> [--timeout <dur>] [--sh] -- <command…>")
		fmt.Fprintln(stderr, "wharf: see `wharf --remote --help`")
		return remoteFailureExit
	}

	inv, err := parseRemoteArgs(args)
	switch {
	case errors.Is(err, errRemoteHelp):
		remoteUsage(stdout)
		return 0
	case err != nil:
		return failUsage("%v", err)
	}

	// The environment is only consulted when argv did not carry a token, so a
	// pasted command line always wins over a stale exported variable.
	token := inv.token
	if token == "" {
		token = strings.TrimSpace(os.Getenv(remoteTokenEnv))
	}
	if token == "" {
		return failUsage("no grant token: pass it after --remote, or set $%s", remoteTokenEnv)
	}
	if len(inv.command) == 0 {
		return failUsage("no command after --")
	}
	if inv.raw && len(inv.command) != 1 {
		return failUsage("--sh takes exactly one argument, the shell command as a single quoted word "+
			"(got %d) — drop --sh to pass an argv instead", len(inv.command))
	}

	stdinBytes, err := readRemoteStdin(stdin)
	if err != nil {
		return fail("%v", err)
	}

	command := remoteCommand(inv.command, inv.raw)
	if err := checkRemoteFrame(command, stdinBytes); err != nil {
		return fail("%v", err)
	}

	// Two deadlines with one number. inv.timeout travels in the request and is
	// what actually kills the command on the host; the context is a local
	// backstop, given slack so that a grant which is merely slow to report the
	// timeout still gets to report it, rather than being cut off and blamed for
	// a different failure.
	ctx := context.Background()
	if inv.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, inv.timeout+remoteTimeoutSlack)
		defer cancel()
	}

	code, err := remoteaccess.Dial(ctx, token, remoteaccess.Request{
		Command: command,
		Stdin:   stdinBytes,
		Timeout: inv.timeout,
	}, stdout, stderr)
	switch {
	case err == nil:
		// The remote's code, verbatim. This is the only path that does not
		// return remoteFailureExit.
		return code
	case errors.Is(err, remoteaccess.ErrNoGrant):
		return fail("no live grant accepted this token — it may have been revoked, " +
			"expired, or belong to a wharf that has since quit")
	case errors.Is(err, remoteaccess.ErrUnsupported):
		return fail("%v", err)
	case isDeadline(err):
		return fail("the command did not finish within %s — raise it with --timeout, "+
			"or --timeout 0 to wait as long as the grant lives", inv.timeout)
	default:
		return fail("%v", err)
	}
}

// isDeadline reports whether err is the command running out of time.
//
// It matches on the message as well as the sentinel because the timeout that
// normally fires is the host's, and that one crosses the grant socket as a
// string: JSON has no way to carry an error's identity, so errors.Is alone
// would only ever catch the local backstop and the common case would be
// reported as an unexplained failure. Sentinel first, text second — the text
// check is the fallback, not the mechanism.
func isDeadline(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) ||
		strings.Contains(err.Error(), context.DeadlineExceeded.Error())
}

// remoteTimeoutSlack is how much longer the local context waits than the
// timeout the host was asked to enforce. Small, but non-zero: without it the two
// deadlines race and the loser's error message is the one the user sees.
const remoteTimeoutSlack = 5 * time.Second

// readRemoteStdin collects stdin when there is any to collect.
//
// A terminal is skipped rather than read: with no redirect there is nothing to
// send, and reading would hang the command waiting for the user to type EOF at a
// prompt that was never printed. Anything else — a pipe, a file, a test's
// strings.Reader — is forwarded.
func readRemoteStdin(stdin io.Reader) ([]byte, error) {
	if stdin == nil {
		return nil, nil
	}
	if f, ok := stdin.(*os.File); ok {
		fi, err := f.Stat()
		if err != nil || fi.Mode()&os.ModeCharDevice != 0 {
			return nil, nil
		}
	}
	// One byte past the limit, so "exactly at the limit" is allowed and
	// "one byte over" is detected without reading a gigabyte to find out.
	data, err := io.ReadAll(io.LimitReader(stdin, remoteStdinLimit+1))
	if err != nil {
		return nil, fmt.Errorf("reading stdin: %w", err)
	}
	if len(data) > remoteStdinLimit {
		return nil, fmt.Errorf("stdin is over the %s limit for --remote "+
			"(v1 sends it inside the request, and it has to fit in one frame after "+
			"base64); write it to a file on the host instead", remoteStdinLimitText)
	}
	if len(data) == 0 {
		return nil, nil
	}
	return data, nil
}

// checkRemoteFrame refuses a request that would not fit in one frame, so that
// the user hears it from wharf and in wharf's terms.
//
// remoteStdinLimit already reserves 64 KiB for the command, which covers every
// realistic command line. This is the backstop for the one that is not
// realistic — an argv near ARG_MAX, or a --sh script pasted from a file — where
// the reserve is what overflows rather than stdin. Without it that request goes
// out and comes back as "frame of N bytes exceeds the 1048576 limit" from a
// package the user has never heard of, about a limit no wharf documentation
// mentions.
//
// The command's contribution is measured with the same encoder that will put it
// on the wire, because JSON escaping is what makes it unpredictable: a quote
// costs two bytes and a control character six, so a length in bytes would
// under-count exactly the payloads most likely to be large.
func checkRemoteFrame(command string, stdin []byte) error {
	encoded, err := json.Marshal(command)
	if err != nil {
		return fmt.Errorf("encoding the command: %w", err)
	}
	// base64 emits 4 bytes per 3 input bytes, rounded up to a whole quantum.
	size := len(encoded) + 4*((len(stdin)+2)/3) + remoteFrameFixed
	if size > remoteFrameLimit {
		return fmt.Errorf("the command and its stdin come to %d bytes on the wire, "+
			"over the %d KiB a single request may occupy — shorten the command "+
			"(stdin alone may be up to %s)", size, remoteFrameLimit>>10, remoteStdinLimitText)
	}
	return nil
}

// remoteFrameFixed is the JSON scaffolding around the two variable fields —
// braces, field names, quotes, the timeout, and the correlation ID sessd adds
// on the hop after this one. It is an over-estimate on purpose; the real figure
// is under a hundred bytes.
const remoteFrameFixed = 256

// remoteCommand assembles the single command string the host will run.
//
// Both forms end up as `<login shell> -lc <script>`. The login shell is the
// remote user's own ($SHELL, which sshd sets from the passwd entry), and -l is
// what gives the agent the same PATH the user sees interactively — without it,
// tooling installed by nvm, pyenv, asdf or Homebrew's shellenv is simply absent
// and the agent is told "command not found" for something that plainly exists.
//
// The default form quotes the argv exactly once, here, and hands the result to
// that shell. The alternative — letting the agent do its own quoting and passing
// the words through — was rejected because the string then crosses two shell
// parsers, and the second one re-expands whatever survived the first: the
// canonical `curl -d '{"a":1}'` loses its braces to brace expansion or its
// quotes to word splitting, depending on which shell is on the far end. Quoting
// once, ourselves, makes the far end's shell irrelevant to the payload.
//
// --sh is the escape hatch for the cases that genuinely want a shell — pipes,
// redirection, `&&`. Its string is passed to the login shell verbatim; it is
// still wrapped in -lc for the same PATH parity, which is the only reason it is
// not simply sent as-is.
func remoteCommand(command []string, raw bool) string {
	script := ""
	if raw {
		script = command[0]
	} else {
		script = joinArgv(command)
	}
	// exec, so the remote process tree is one shell rather than two and signals
	// reach the command itself.
	return `exec "${SHELL:-/bin/sh}" -lc ` + shellQuote(script)
}

// joinArgv renders an argv as a shell command line that parses back to exactly
// that argv.
func joinArgv(argv []string) string {
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = shellQuote(a)
	}
	return strings.Join(quoted, " ")
}

// shellQuote wraps s so that a POSIX shell parses it back as one word, byte for
// byte.
//
// Single quotes are the only quoting a POSIX shell does not interpret anything
// inside: no $, no backtick, no backslash, no history, and newlines are ordinary
// characters. The single quote itself cannot be escaped inside them, so the
// string is broken out and back in around each one — '\” is a closing quote, an
// escaped quote, and a reopening quote. This is the same construction
// shlex.quote uses, for the same reason: everything else has an exception.
//
// Words made only of characters no shell touches are returned bare. That is
// cosmetic — the command is printed in wharf's audit log and read by humans —
// and the safe set is deliberately conservative: no ~ (tilde expansion), no
// glob characters, no braces.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsFunc(s, unsafeInShell) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// unsafeInShell reports whether r must be quoted. It is an allow-list, because
// the set of characters some shell somewhere treats specially is open-ended
// while the set that is inert everywhere is small and stable.
func unsafeInShell(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return false
	}
	return !strings.ContainsRune("@%+=:,./-_", r)
}

// remoteUsage prints the remote-access help. It is separate from usage() because
// the two describe different programs: everything else wharf does opens a TUI,
// and this one is a pipe-friendly command an agent runs.
func remoteUsage(out io.Writer) {
	fmt.Fprintln(out, "wharf --remote — run one command on a host through a remote-access grant.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  wharf --remote <token> [--timeout <dur>] [--sh] -- <command…>")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "The token comes from wharf itself: press r on a connected host to open a")
	fmt.Fprintln(out, "grant, and wharf prints (and copies) the exact command line to run. A grant")
	fmt.Fprintln(out, "is exec-only, bound to that one host, and revocable at any time.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Flags:")
	fmt.Fprintf(out, "  --timeout <dur>  how long the command may run (default %s; 0 waits as long\n", defaultRemoteTimeout)
	fmt.Fprintln(out, "                   as the grant lives)")
	fmt.Fprintln(out, "  --sh             treat the single remaining argument as a shell command")
	fmt.Fprintln(out, "                   string, for pipes and redirection")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Everything after -- is the command. By default it is an argv: wharf quotes it")
	fmt.Fprintln(out, "once, itself, and runs it under the remote's login shell, so arguments arrive")
	fmt.Fprintln(out, "byte for byte and $PATH matches an interactive login.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "  wharf --remote TOKEN -- curl -sS -d '{\"a\":1}' localhost:9000/health")
	fmt.Fprintln(out, "  wharf --remote TOKEN --sh -- 'journalctl -u api | tail -50'")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Streams: stdout and stderr are forwarded as they arrive. stdin is forwarded")
	fmt.Fprintf(out, "when it is not a terminal, up to %s (v1 sends it inside the request, so it\n", remoteStdinLimitText)
	fmt.Fprintln(out, "has to fit in one frame once base64 has grown it by a third).")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Exit status: the remote command's, verbatim. Wharf's own failures — no grant")
	fmt.Fprintf(out, "accepted the token, a timeout, a bad command line — exit %d and print a\n", remoteFailureExit)
	fmt.Fprintf(out, "\"wharf: \" line on stderr. A remote command that itself exits %d is\n", remoteFailureExit)
	fmt.Fprintln(out, "indistinguishable; the stderr line is the tiebreak.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Environment:")
	fmt.Fprintf(out, "  %s  the token, when it is not in argv (keeps it out of ps)\n", remoteTokenEnv)
}
