package redact

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestString_KnownTokens(t *testing.T) {
	cases := []struct{ in, want string }{
		{"ghp_abcdefghijklmnopqrstuvwx12345", RedactedMark},
		{"AKIAIOSFODNN7EXAMPLE", RedactedMark},
		{"plain text with no token", "plain text with no token"},
		{"prefix sk-proj-abcdefghijklmnopqrstuvwxyz suffix", "prefix " + RedactedMark + " suffix"},
		{"", ""},
	}
	for _, c := range cases {
		if got := String(c.in); got != c.want {
			t.Errorf("String(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := Truncate("hello world", 5); got != "hello..." {
		t.Errorf("got %q", got)
	}
	if got := Truncate("short", 100); got != "short" {
		t.Errorf("got %q", got)
	}
}

// TestTruncateKeepsValidUTF8 pins the cut to a rune boundary at every offset within a
// multi-byte rune.
//
// A blind slice at the byte limit leaves a fragment of that rune at the end of the string.
// It is not caught locally -- the value looks fine in Go -- but it reaches a row, and
// encoding/json rewrites the fragment as U+FFFD, so an error message or filename that
// merely contained an accent is reported with its last character corrupted. Non-ASCII in
// these strings is ordinary: they carry filenames chosen by the user.
func TestTruncateKeepsValidUTF8(t *testing.T) {
	// One 1-byte, one 2-byte, one 3-byte and one 4-byte rune, so a cut anywhere in the
	// string lands inside a rune of some width.
	const in = "aé☃🙂"
	for limit := 0; limit <= len(in); limit++ {
		got := Truncate(in, limit)
		if !utf8.ValidString(got) {
			t.Errorf("Truncate(%q, %d) = %q, which is not valid UTF-8", in, limit, got)
		}
		if !strings.HasPrefix(in, strings.TrimSuffix(got, "...")) {
			t.Errorf("Truncate(%q, %d) = %q, which is not a prefix of the input", in, limit, got)
		}
		if len(got) > limit+len("...") {
			t.Errorf("Truncate(%q, %d) = %q, longer than the limit allows", in, limit, got)
		}
	}
}

func TestErrorText_TruncatesAndRedacts(t *testing.T) {
	// 600-char string starting with a GitHub PAT.
	in := "ghp_abcdefghijklmnopqrstuvwx12345" + string(make([]byte, 600))
	got := ErrorText(in)
	if len(got) > 510 { // 500 + "..."
		t.Errorf("not truncated: %d chars", len(got))
	}
	if got[:len(RedactedMark)] != RedactedMark {
		t.Errorf("token not redacted at start: %q", got[:20])
	}
}

// Truncation must not be able to cut a token in half. ErrorText redacts first for this
// reason: a token straddling the byte limit would otherwise be left as a prefix too short
// for the regex to match, passing partial credential material through.
func TestErrorTextRedactsTokensStraddlingTheTruncationBoundary(t *testing.T) {
	token := "ghp_" + strings.Repeat("A", 36)
	// Position the token so that it starts before the 500-byte limit and ends after it.
	message := strings.Repeat("x", 480) + token + strings.Repeat("y", 200)
	got := ErrorText(message)
	if strings.Contains(got, "ghp_") {
		t.Errorf("a token prefix survived truncation: %q", got)
	}
	if len(got) > 503 {
		t.Errorf("result is not bounded: %d bytes", len(got))
	}
}

// "sk" is a common letter pair, so an unanchored sk- prefix matched inside ordinary
// identifiers: task-management-service-client became ta[REDACTED], and a project directory
// named task-tracker-frontend-app mangled every source_path containing it. Over-redaction is
// this package's stated preference over leaking, but destroying legitimate values in the two
// columns an operator navigates by is a different failure.
func TestStringLeavesOrdinaryNamesContainingSkAlone(t *testing.T) {
	for _, unchanged := range []string{
		"@company/task-management-service-client",
		"/Users/x/Documents/task-tracker-frontend-app/mcp.json",
		"disk-usage-reporter-for-macos",
		"risk-assessment-engine-v2-client",
		"desk-booking-service-integration",
	} {
		if got := String(unchanged); got != unchanged {
			t.Errorf("mangled an ordinary name: %q -> %q", unchanged, got)
		}
	}
}

// The boundary must not cost a real detection, including when the token is preceded by a
// separator that has to survive into the output.
func TestStringStillRedactsRealSkTokens(t *testing.T) {
	for _, testCase := range []struct{ in, want string }{
		{"sk-abcdefghijklmnopqrstuvwxyz", RedactedMark},
		{"sk-ant-abcdefghijklmnopqrstuvwxyz", RedactedMark},
		{"sk-proj-abcdefghijklmnopqrstuvwxyz", RedactedMark},
		{"--api-key=sk-abcdefghijklmnopqrstuvwxyz", "--api-key=" + RedactedMark},
		{"Bearer sk-abcdefghijklmnopqrstuvwxyz", "Bearer " + RedactedMark},
		{"/path/to/sk-abcdefghijklmnopqrstuvwxyz", "/path/to/" + RedactedMark},
	} {
		if got := String(testCase.in); got != testCase.want {
			t.Errorf("String(%q) = %q, want %q", testCase.in, got, testCase.want)
		}
	}
}

// TestSecretAfterASeparatorIsRedacted pins the boundary fix.
//
// The sk- alternative carries a left boundary because "sk" is a common letter pair: without
// one it mangled task-management-service-client and any path containing it. But the boundary
// excluded "-" and "_" as well as alphanumerics, which was too wide in the dangerous
// direction -- a real key written after an ordinary separator was returned in the clear,
// which is the single outcome this package exists to prevent.
func TestSecretAfterASeparatorIsRedacted(t *testing.T) {
	key := "sk-" + strings.Repeat("a", 24)

	for _, in := range []string{
		key,             // bare
		"server-" + key, // after a hyphen: previously escaped
		"MY_" + key,     // after an underscore: previously escaped
		"/opt/" + key,   // after a slash
		"env=" + key,    // after an equals
	} {
		if got := String(in); strings.Contains(got, key) {
			t.Errorf("String(%q) = %q, the key survived", in, got)
		}
	}

	// And the false positives the boundary exists for must stay untouched. In each the
	// character before "sk" is a letter, which is what the boundary now tests.
	for _, in := range []string{
		"task-management-service-client",
		"task-tracker-frontend-app",
		"disk-" + strings.Repeat("b", 24),
		"risk-" + strings.Repeat("c", 24),
		"desk-" + strings.Repeat("d", 24),
	} {
		if got := String(in); got != in {
			t.Errorf("String(%q) = %q, an ordinary identifier was mangled", in, got)
		}
	}
}
