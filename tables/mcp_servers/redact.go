package mcp_servers

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/macadmins/osquery-extension/pkg/redact"
)

// Secret-detection regexes. Compiled once at package init; cheap to evaluate against
// short MCP args. The intent is conservative redaction: a false positive (over-redacting
// a benign value) is a much smaller failure than leaking a real credential into a
// security tool's table output.
var (
	// Flags whose name contains a specific secret-related keyword
	// (token/secret/password/etc.). Matches both inline `--token=VALUE` and
	// standalone `--token` forms (the two-arg case is handled in redactArgs).
	secretFlagNameRe = regexp.MustCompile(`(?i)^--?[a-z0-9_-]*(?:token|secret|password|passwd|bearer|credential|apikey|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)[a-z0-9_-]*$`)

	// Flags ending in a delimited "key" word, to catch vendor-specific
	// names like `--dd-key` (Datadog), `--gcp-key`, `--anth-key`. The
	// delimiter requirement prevents over-matching on words that happen
	// to contain "key" as a substring (e.g., `--monkey-server`, `--keyword`).
	//
	// Pattern: optional prefix ending in `_-`, then `key`, then optional
	// suffix starting with `_-`. Matches: --key, --dd-key, --cache-key-id.
	// Does not match: --monkey, --keyword, --keystroke.
	secretFlagKeyRe = regexp.MustCompile(`(?i)^--?(?:[a-z0-9_-]+[_-])?key(?:[_-][a-z0-9_-]+)?$`)

	// The inline form as an entire value -- --token=VALUE -- is no longer a regexp. It was
	// `^(--?[A-Za-z0-9_-]+)=(.+)$`, and Go's `.` does not match a newline without dot-all,
	// so a value carrying one did not match here and did not match the embedded pattern
	// either, whose value begins at a non-space character. `{"x": "--token=\nsecret"}` is
	// valid JSON and reached the row intact. Splitting at the first `=` has no such gap:
	// see wholeValueAssignment.

	// The same assignment embedded in a longer string: a server name, a project path, or a
	// command line that reached this table as one field rather than as argv. Anchoring the
	// pattern above to the whole string left `fetch --api-key=opaque` in server_name and
	// source_context untouched, and an opaque value is precisely what the token shapes in
	// pkg/redact cannot recognise.
	//
	// Bounded on the left by start-of-string or any character a flag name cannot contain,
	// so a flag is a flag rather than the tail of a longer word. Whitespace alone was too
	// narrow: the delimiter before an option is a separator far more often than it is a
	// space, and every one of these leaked an opaque value verbatim --
	// `group/--api-key=x` in a server name, `projects[/tmp/--api-key=x]` in a source
	// context, `/Users/a/--token=x/p/.mcp.json` in a path, and `label\u00a0--token=x` using
	// the non-ASCII whitespace the command parser accepts but Go's ASCII `\s` does not.
	// Excluding only the flag-name character class covers all four in one rule and still
	// refuses `weird--token=x`, where the dashes are interior to a word.
	//
	// The value ends at the next space because without an argv boundary there is nothing
	// else to say where it stops. In a path-shaped field that swallows the remainder, which
	// is the intended direction to fail: over-redacting a benign suffix costs a reader some
	// context, and under-redacting costs a credential.
	secretFlagEmbeddedRe = regexp.MustCompile(`(^|[^A-Za-z0-9_-])(--?[A-Za-z0-9_-]+)=(\S+)`)

	// The same thing where whitespace separates the `=` from the value, which the pattern
	// above cannot match because its value starts at a non-space character. Applied as a
	// second pass rather than by relaxing the first, and the order matters: a single
	// tolerant pattern reads `--verbose= --token=secret` as one assignment of the benign
	// option `--verbose`, consumes the real assignment as that option's value, and leaves
	// the credential untouched. Running the strict pattern first redacts the real one, and
	// this pass then finds only an already-sanitized value.
	//
	// `\s` is ASCII-only in Go, so `\p{Zs}` is named alongside it to cover the non-ASCII
	// spaces the command parser already accepts.
	secretFlagSpacedRe = regexp.MustCompile(`(^|[^A-Za-z0-9_-])(--?[A-Za-z0-9_-]+)=[\s\p{Zs}]+(\S+)`)
)

// The issuer-prefixed token shapes this file used to carry its own copy of now live in
// pkg/redact, which is the package whose whole job is redaction. One copy means a newly
// published token format is added in one place rather than two that drift.

// isSecretFlagName reports whether name (e.g. "--token", "--api-key", "--dd-key") looks like
// a flag whose value should be redacted.
//
// A single-letter flag is not one of them, and "-T" was listed here as though it were. Both
// patterns require a credential keyword or a delimited "key" in the name, which no
// single-letter option can carry. Adding one would mean redacting on a letter rather than on
// a word, and "-t" means something different in every tool that has it.
func isSecretFlagName(name string) bool {
	return secretFlagNameRe.MatchString(name) || secretFlagKeyRe.MatchString(name)
}

// maxAssignmentDepth bounds how far redactSecret follows an assignment nested inside
// another assignment's value.
//
// The recursion shrinks its input by at least the flag name and the `=` at every level, so
// it terminates on its own. The bound is about cost. Every level re-runs the token-shape
// scan over what is left, so a value holding n nested assignments is scanned O(n) times over
// O(n) bytes, and these fields come from a config file a user controls: a server name of
// `-a=` repeated is quadratic work inside a process the osquery watchdog will kill, taking
// every other table's rows with it. Eight is far past any real command line.
const maxAssignmentDepth = 8

// redactSecret returns a sanitized copy of s with any known token shapes or
// secret-flag-style values replaced by the [REDACTED] marker, whether the assignment is the
// whole string or sits inside a longer one. Idempotent: [REDACTED] carries no space, so a
// second pass matches the marker and rewrites it to itself.
func redactSecret(s string) string {
	return redactSecretDepth(s, 0)
}

func redactSecretDepth(s string, depth int) string {
	if s == "" {
		return s
	}
	s = redact.String(s)
	if whole, ok := wholeValueAssignment(s); ok {
		return whole
	}
	// ReplaceAllStringFunc rather than a capture-group replacement template: whether a match
	// is redacted depends on the flag *name*, which only a callback can decide. The leading
	// boundary is replayed so the separator survives; whitespace between the `=` and the
	// value is not, because a marker on the far side of a newline reads as unredacted text.
	redactMatches := func(re *regexp.Regexp) {
		s = re.ReplaceAllStringFunc(s, func(match string) string {
			groups := re.FindStringSubmatch(match)
			if isSecretFlagName(groups[2]) {
				return groups[1] + groups[2] + "=" + redact.RedactedMark
			}
			// A benign option keeps its value -- but the scan has just consumed that value
			// as one unit, and the value runs to the next space, so a credential assigned
			// inside it was never examined at all. `--verbose=--token=secret`,
			// `a,--verbose=--token=secret` and `--out=/tmp/--token=secret` each left the
			// credential in the row verbatim, because the outer option is not one this
			// file recognises and the match ended at the end of the string.
			//
			// Descending into the value rather than re-scanning the whole string: a second
			// pass over the parent would find the same outer match and make no progress,
			// while the value on its own is a shorter string with the outer assignment
			// stripped, so the nested one is now at a boundary the patterns can see.
			value := groups[len(groups)-1]
			// Everything the match holds before the value, replayed byte for byte, so the
			// separator a benign option was written with survives -- including the
			// whitespace the spaced pattern matched, which the credential branch above
			// deliberately drops.
			prefix := match[:len(match)-len(value)]
			if depth >= maxAssignmentDepth {
				// Out of budget rather than out of suspicion. Redacting is the direction
				// this file fails in, and a value nested eight assignments deep is not a
				// value any reader was going to use.
				return prefix + redact.RedactedMark
			}
			return prefix + redactSecretDepth(value, depth+1)
		})
	}
	redactMatches(secretFlagEmbeddedRe)
	redactMatches(secretFlagSpacedRe)
	return s
}

// wholeValueAssignment reports whether s is entirely one credential-named assignment, and
// if so returns it with the value replaced.
//
// Split rather than matched. The regexp this replaced could not see a value containing a
// newline, and the field this runs on is a JSON string, where a newline is one escape away.
// Everything right of the first `=` is the value whatever it holds -- spaces, newlines, more
// `=` signs -- because one argv element is one value however it is spelled.
//
// A left side carrying whitespace is not a flag, and isSecretFlagName rejects it, so
// `name --token=x` falls through to the embedded patterns rather than being treated as a
// whole-value assignment to the option `name --token`.
func wholeValueAssignment(s string) (string, bool) {
	equals := strings.Index(s, "=")
	// No `=`, nothing after it, or a leading `=` with no option name: no assignment here.
	if equals <= 0 || equals == len(s)-1 {
		return "", false
	}
	name := s[:equals]
	if !isSecretFlagName(name) {
		return "", false
	}
	return name + "=" + redact.RedactedMark, true
}

// redactArgs returns a sanitized copy of args. The two-arg flag form (`--token VALUE`)
// is detected by looking back at the previous element. Allocates one slice; element
// values are reused unchanged when no redaction is needed.
func redactArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}
	out := make([]string, len(args))
	for i, a := range args {
		// No exemption for a dash prefix. `--token -opaque` is a secret whose value happens
		// to start with a dash, and skipping it left the raw value in place. Distinguishing
		// that from `--token --verbose`, where the flag has no value, needs a real option
		// parser with per-flag arity; absent one, this over-redacts. That is the documented
		// preference for this file, and args are counted rather than emitted, so the cost of
		// redacting one argument too many is nil.
		if i > 0 && isSecretFlagName(args[i-1]) {
			out[i] = redact.RedactedMark
			continue
		}
		out[i] = redactSecret(a)
	}
	return out
}

// sanitizeRemoteURL returns the scheme+host portion of a remote MCP endpoint and
// nothing else. Path, query, fragment, and userinfo are all dropped because tokens
// are commonly embedded in any of them (e.g., "/mcp/<token>/sse" in the path, or
// "?api_key=..." in the query). Regex-based token detection cannot reliably catch
// opaque tokens in path segments; the conservative strategy is "keep only what we
// know is safe to record."
//
// Returns "" if no host can be recovered: better to emit nothing than risk leaking a raw URL.
func sanitizeRemoteURL(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := parsed.Host
	if host == "" {
		return ""
	}
	// Strip userinfo defensively even though u.Host is supposed to exclude it.
	if at := strings.LastIndexByte(host, '@'); at >= 0 {
		host = host[at+1:]
	}
	if parsed.Scheme != "" {
		return parsed.Scheme + "://" + host
	}
	// Scheme-less network-path reference ("//host/path"): preserve "//host" form.
	if strings.HasPrefix(raw, "//") {
		return "//" + host
	}
	return ""
}
