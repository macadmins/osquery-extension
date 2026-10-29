package redact

import (
	"strings"
	"testing"
)

// TestSecretRedactsCredentialAssignments covers each form an assignment reaches a published
// column in: as the whole value, embedded behind a separator, with whitespace after the `=`,
// and nested inside a benign option's value.
func TestSecretRedactsCredentialAssignments(t *testing.T) {
	const opaque = "opaqueSecretValue"
	for _, tc := range []struct{ name, in, want string }{
		{"whole value", "--token=" + opaque, "--token=" + RedactedMark},
		{"whole value with newline", "--api-key=\n" + opaque, "--api-key=" + RedactedMark},
		{"embedded after a space", "fetch --api-key=" + opaque, "fetch --api-key=" + RedactedMark},
		{"embedded after a slash", "/Users/a/--token=" + opaque + "/p", "/Users/a/--token=" + RedactedMark},
		{"spaced value", "x --password= " + opaque, "x --password=" + RedactedMark},
		{"nested in a benign value", "--verbose=--token=" + opaque, "--verbose=--token=" + RedactedMark},
		{"delimited key flag", "--dd-key=" + opaque, "--dd-key=" + RedactedMark},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Secret(tc.in)
			if got != tc.want {
				t.Errorf("Secret(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if strings.Contains(got, opaque) {
				t.Errorf("Secret(%q) kept the credential: %q", tc.in, got)
			}
		})
	}
}

// TestSecretLeavesBenignTextAlone pins the other direction: an option name with no credential
// word keeps its value, and words that merely contain "key" are not flags.
func TestSecretLeavesBenignTextAlone(t *testing.T) {
	for _, in := range []string{
		"",
		"--verbose=true",
		"--monkey-server=x",
		"--keyword=go",
		"weird--token=x",
		"/Users/a/projects/go-service",
	} {
		if got := Secret(in); got != in {
			t.Errorf("Secret(%q) = %q, want it unchanged", in, got)
		}
	}
}

// TestSecretIsIdempotent matters because published values pass through Secret at more than
// one layer, and a second pass must not change what the first produced.
func TestSecretIsIdempotent(t *testing.T) {
	for _, in := range []string{"--token=abc", "a --api-key=b c", "ghp_" + strings.Repeat("A", 36)} {
		once := Secret(in)
		if twice := Secret(once); twice != once {
			t.Errorf("Secret is not idempotent on %q: %q then %q", in, once, twice)
		}
	}
}

// TestSecretBoundsNesting checks that an assignment nested past MaxAssignmentDepth is
// redacted rather than followed, so a hostile value cannot buy quadratic work.
func TestSecretBoundsNesting(t *testing.T) {
	const opaque = "opaqueSecretValue"
	deep := strings.Repeat("-a=", MaxAssignmentDepth+2) + opaque
	if got := Secret(deep); strings.Contains(got, opaque) {
		t.Errorf("a value nested past the depth bound survived: %q", got)
	}
}

// TestIsSecretFlagName pins the two name patterns and the single-letter exclusion.
func TestIsSecretFlagName(t *testing.T) {
	for name, want := range map[string]bool{
		"--token": true, "--api-token": true, "--client-secret": true, "--key": true,
		"--dd-key": true, "--cache-key-id": true,
		"--monkey": false, "--keyword": false, "-t": false, "--verbose": false,
	} {
		if got := IsSecretFlagName(name); got != want {
			t.Errorf("IsSecretFlagName(%q) = %v, want %v", name, got, want)
		}
	}
}
