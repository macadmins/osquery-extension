// Package redact provides cross-ecosystem string sanitization used by every
// table plugin before values are emitted to osquery (and from there to the
// SIEM). The single guiding principle:
//
//	NO CREDENTIAL VALUE FROM A USER-WRITABLE FILE SHALL LEAK TO THE SIEM.
//
// We can't perfectly enforce that with regex: opaque tokens (no recognizable
// prefix or structure) will slip through. The strategy is layered:
//
//  1. Drop fields where bounded-format defense is impossible (e.g., MCP's
//     raw `args`, full URLs).
//  2. Restrict bounded fields to known-safe shapes (e.g., URL → scheme+host;
//     command → basename only; package_name → validated via package-spec
//     regex).
//  3. Apply this package's redactSecret as defense-in-depth on any remaining
//     string that originated from user-controlled input. It catches the
//     well-known token shapes (GitHub, AWS, JWT, OpenAI, Anthropic, …).
package redact

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// RedactedMark uses square brackets so the marker survives JSON encoding
// intact. Go's encoding/json HTML-escapes `<` and `>` by default: using
// `<REDACTED>` would land in JSON-encoded fields (env_keys,
// lifecycle_scripts) as `<REDACTED>`, breaking operator queries
// like `WHERE env_keys LIKE '%[REDACTED]%'`.
const RedactedMark = "[REDACTED]"

// knownTokenRe matches issuer-prefixed token shapes. False positives are
// rare; we'd rather over-redact in error messages and paths than leak.
//
// The sk- alternative alone carries a left-boundary group, because "sk" is a common letter
// pair and the prefix is only two characters plus a dash. Unanchored, it matched inside
// ordinary identifiers: task-management-service-client became ta[REDACTED], and a project
// directory named task-tracker-frontend-app mangled every source_path that contained it.
// disk-, risk- and desk- do the same.
//
// The boundary excludes alphanumerics only. It used to exclude "-" and "_" as well, which
// was too wide in the dangerous direction: a real key written after an ordinary separator
// -- server-sk-..., MY_sk-... -- was left in the clear, which is the one outcome this
// package exists to prevent. Every false positive above is blocked by the character before
// "sk" being a letter, so separators can safely delimit a token.
//
// The other prefixes are distinctive enough that matching mid-string is a feature rather
// than a hazard, so they are deliberately left unanchored.
//
// Group 1 is the consumed separator, replayed by String so only the credential is replaced.
// For every other alternative it captures nothing and the group expands to empty.
var knownTokenRe = regexp.MustCompile(strings.Join([]string{
	`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}`,
	`github_pat_[A-Za-z0-9_]{20,}`,
	`gitlab-[a-z]+-[A-Za-z0-9_-]{20,}`,
	`glpat-[A-Za-z0-9_-]{20,}`,
	`xox[abprs]-[A-Za-z0-9-]{10,}`,
	`(^|[^A-Za-z0-9])(sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,})`,
	`AKIA[0-9A-Z]{16}`,
	`ASIA[0-9A-Z]{16}`,
	`AIza[0-9A-Za-z_-]{35}`,
	`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`, // JWT
}, "|"))

// String returns s with any known-token-shape substrings replaced with
// the [REDACTED] marker. Idempotent.
func String(s string) string {
	if s == "" {
		return s
	}
	if !mayContainKnownToken(s) {
		return s
	}
	// ${1} replays the separator the sk- alternative had to consume for want of lookbehind,
	// which RE2 does not have. It is empty for every other alternative.
	return knownTokenRe.ReplaceAllString(s, "${1}"+RedactedMark)
}

func mayContainKnownToken(s string) bool {
	for _, marker := range []string{
		"ghp_", "gho_", "ghu_", "ghs_", "ghr_",
		"github_pat_", "gitlab-", "glpat-", "xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-",
		"sk-", "AKIA", "ASIA", "AIza", "eyJ",
	} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

// Path is a safer wrapper for filesystem paths. Paths can contain
// directory or file names that are themselves secrets (a user might name a
// directory "api-key-XXXX"). The same known-token-shape regex catches the
// common cases. Trailing components are particularly suspect.
func Path(p string) string {
	return String(p)
}

// ErrorText is a safer wrapper for error message strings that may embed
// attacker-controlled bytes from a parsed file.
//
// Redaction runs before truncation, not after. The other order can cut a token in half at the
// byte limit, leaving a prefix too short for knownTokenRe to match, which passes partial
// credential material through in the one place we are least able to inspect it.
func ErrorText(s string) string {
	return Truncate(String(s), 500)
}

// Truncate caps s at limit bytes, appending "..." if cut. Used in error
// strings to bound row size when an attacker plants a 30 MiB lockfile key.
//
// The cut moves back to a rune boundary, so the result is never invalid UTF-8. A blind
// slice at the byte limit can land inside a multi-byte rune, and the trailing fragment
// travels: encoding/json rewrites it as U+FFFD, so a filename or error message that merely
// contained non-ASCII would be reported with a corrupted final character. The bound is on
// bytes because the point is to bound the row, so a string of multi-byte runes yields
// fewer characters than limit, by design.
func Truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}
