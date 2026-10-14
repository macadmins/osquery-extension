package mcp_servers

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/redact"
	"github.com/osquery/osquery-go/plugin/table"
)

func TestStripJSONC(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"no comments", `{"a": 1}`, `{"a": 1}`},
		{"line comment", "{\n// hi\n\"a\": 1\n}", "{\n\n\"a\": 1\n}"},
		// Two spaces: the separator the stripper substitutes for the comment, then the
		// space that followed it in the input. The line-comment case above substitutes a
		// newline for the same reason.
		{"block comment", `{/* hi */ "a": 1}`, `{  "a": 1}`},
		{"slash inside string", `{"url": "https://example.com"}`, `{"url": "https://example.com"}`},
		{"escaped quote in string", `{"a": "he said \"hi\" // joke"}`, `{"a": "he said \"hi\" // joke"}`},
		{"line comment at EOF", `{"a": 1} // trailing`, `{"a": 1} `},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stripped, terminated := stripJSONC([]byte(c.in))
			if !terminated {
				t.Fatalf("%s: unexpected unterminated block comment", c.name)
			}
			got := string(stripped)
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestExtractEnvelope(t *testing.T) {
	data := []byte(`{
		"mcpServers": {
			"stdio-srv": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"], "env": {"FOO": "bar"}},
			"remote-srv": {"type": "sse", "url": "https://mcp.example.com/sse"}
		}
	}`)
	rows, err := extractEnvelopeSimple(data)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("want 2 rows, got %d", len(rows))
	}
	byName := map[string]Server{}
	for _, r := range rows {
		byName[r.ServerName] = r
	}
	if got := byName["stdio-srv"].Command; got != "npx" {
		t.Errorf("stdio command: got %q want npx", got)
	}
	// Env values must never appear; only keys.
	if got := byName["stdio-srv"].EnvKeys; !reflect.DeepEqual(got, []string{"FOO"}) {
		t.Errorf("env keys: got %v want [FOO]", got)
	}
	// URL is sanitized to scheme://host (path is dropped because tokens can live there).
	if got := byName["remote-srv"].URL; got != "https://mcp.example.com" {
		t.Errorf("remote url: got %q want https://mcp.example.com", got)
	}
}

func TestExtractEnvelopeMCPServersWinsOverServers(t *testing.T) {
	// `servers` and `mcpServers` both present: mcpServers wins on key collision.
	data := []byte(`{
		"servers": {"a": {"command": "OLD"}},
		"mcpServers": {"a": {"command": "NEW"}, "b": {"command": "B"}}
	}`)
	rows, err := extractEnvelopeSimple(data)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]string{}
	for _, r := range rows {
		byName[r.ServerName] = r.Command
	}
	if byName["a"] != "NEW" {
		t.Errorf("collision resolution wrong: %v", byName)
	}
	if byName["b"] != "B" {
		t.Errorf("missing b: %v", byName)
	}
}

func TestExtractFlat(t *testing.T) {
	// Project-local .mcp.json shape.
	data := []byte(`{"my-srv": {"command": "uvx", "args": ["mcp-server-fetch"]}}`)
	rows, err := extractEnvelopeSimple(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ServerName != "my-srv" {
		t.Fatalf("unexpected: %#v", rows)
	}
}

func TestExtractClaudeCode(t *testing.T) {
	data := []byte(`{
		"mcpServers": {"global-srv": {"type": "http", "url": "https://x.example/mcp"}},
		"projects": {
			"/repo/foo": {"mcpServers": {"local": {"command": "node", "args": ["server.js"]}}}
		},
		"unrelatedKey": "ignored"
	}`)
	rows, err := extractClaudeCode(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("want 2, got %d", len(rows))
	}
	var globalCtx, localCtx string
	for _, r := range rows {
		if r.ServerName == "global-srv" {
			globalCtx = r.SourceContext
		}
		if r.ServerName == "local" {
			localCtx = r.SourceContext
		}
	}
	if globalCtx != "mcpServers" {
		t.Errorf("global ctx: %q", globalCtx)
	}
	if localCtx != "projects[/repo/foo].mcpServers" {
		t.Errorf("local ctx: %q", localCtx)
	}
}

func TestInferIdentity_RejectsCredentialBearingURL(t *testing.T) {
	// Attack: a hostile MCP config uses --registry with creds, then a real
	// package. The scan would naively return the credential URL. The
	// looksLikePackageSpec validator must reject it so RequestedSpec is
	// either empty or the real package.
	s := Server{
		Command: "npx",
		Args:    []string{"--registry", "https://user:tokenABC@npm.example.com/", "@playwright/mcp@latest"},
	}
	inferIdentity(&s)
	if strings.Contains(s.RequestedSpec, "tokenABC") {
		t.Errorf("credential URL leaked into RequestedSpec: %q", s.RequestedSpec)
	}
	if strings.Contains(s.PackageName, "tokenABC") {
		t.Errorf("credential URL leaked into PackageName: %q", s.PackageName)
	}
}

// The option-arity list cannot be complete, so the value of an option it has never heard of
// is a package-shaped token sitting in package position. When the option's *name* says the
// value is a credential, that is a leak and not merely a wrong answer: package_name is
// emitted as-is, and an opaque secret matches none of the token shapes pkg/redact knows.
//
// The real package still has to be found afterwards. Refusing the token without continuing
// the scan would trade a leak for an empty inventory row.
func TestInferIdentity_SkipsTheValueOfACredentialNamedOption(t *testing.T) {
	for _, args := range [][]string{
		{"--auth-token", "opaquevalue123", "real-server"},
		{"--api-key", "opaquevalue123", "real-server"},
		{"--dd-key", "opaquevalue123", "real-server"},
	} {
		server := Server{Command: "uvx", Args: args}
		inferIdentity(&server)
		if strings.Contains(server.PackageName, "opaquevalue") ||
			strings.Contains(server.RequestedSpec, "opaquevalue") {
			t.Errorf("%v: option value reported as the package: %+v", args, server)
		}
		if server.PackageName != "real-server" {
			t.Errorf("%v: package after the option was lost: %q", args, server.PackageName)
		}
	}
}

func TestInferIdentity_NPX(t *testing.T) {
	s := Server{Command: "npx", Args: []string{"-y", "@playwright/mcp@latest"}}
	inferIdentity(&s)
	if s.PackageManager != "npx" {
		t.Errorf("mgr: %q", s.PackageManager)
	}
	if s.PackageName != "@playwright/mcp" {
		t.Errorf("name: %q", s.PackageName)
	}
	// `@latest` selects whatever the maintainer published most recently, so it pins no
	// version and the column is empty. The selector is still reported in requested_spec.
	if s.PinnedVersion != "" {
		t.Errorf("ver: %q, want empty for a moving tag", s.PinnedVersion)
	}
	if s.RequestedSpec != "@playwright/mcp@latest" {
		t.Errorf("requested_spec: %q, want the selector verbatim", s.RequestedSpec)
	}
	if s.Transport != "stdio" {
		t.Errorf("transport: %q", s.Transport)
	}
}

func TestInferIdentity_Docker(t *testing.T) {
	s := Server{
		Command: "docker",
		Args:    []string{"run", "-i", "--rm", "-e", "API_KEY", "hashicorp/terraform-mcp-server:0.4.0"},
	}
	inferIdentity(&s)
	if s.PackageManager != "docker" {
		t.Errorf("mgr: %q", s.PackageManager)
	}
	if s.PackageName != "hashicorp/terraform-mcp-server" {
		t.Errorf("name: %q", s.PackageName)
	}
	if s.PinnedVersion != "0.4.0" {
		t.Errorf("ver: %q", s.PinnedVersion)
	}
}

func TestInferIdentity_DockerWithRegistryPort(t *testing.T) {
	s := Server{Command: "docker", Args: []string{"run", "localhost:5000/myrepo/server:dev"}}
	inferIdentity(&s)
	if s.PackageName != "localhost:5000/myrepo/server" {
		t.Errorf("name: %q", s.PackageName)
	}
	if s.PinnedVersion != "dev" {
		t.Errorf("ver: %q", s.PinnedVersion)
	}
}

func TestInferIdentity_CommandWithSpacesEmptyArgs(t *testing.T) {
	// Real-world Cursor quirk: the whole invocation is in `command`, args is empty.
	s := Server{Command: "uvx awslabs.aws-documentation-mcp-server@latest"}
	inferIdentity(&s)
	if s.PackageManager != "uvx" {
		t.Errorf("mgr: %q", s.PackageManager)
	}
	if s.PackageName != "awslabs.aws-documentation-mcp-server" {
		t.Errorf("name: %q", s.PackageName)
	}
	// Original Command preserved (the operator sees what was actually configured).
	if s.Command != "uvx awslabs.aws-documentation-mcp-server@latest" {
		t.Errorf("command was mutated: %q", s.Command)
	}
}

func TestInferIdentity_UVRunFrom(t *testing.T) {
	s := Server{Command: "uv", Args: []string{"run", "--from", "mcp-server-fetch", "mcp-server-fetch"}}
	inferIdentity(&s)
	if s.PackageManager != "uv" || s.PackageName != "mcp-server-fetch" {
		t.Errorf("uv: %+v", s)
	}
}

func TestInferIdentity_UnresolvedShellVar(t *testing.T) {
	s := Server{Command: "node", Args: []string{"${MCP_HOME}/server.js"}}
	inferIdentity(&s)
	if s.PackageName != "" || s.RequestedSpec != "" {
		t.Errorf("expected cleared identity, got %+v", s)
	}
	if s.Confidence != "low" {
		t.Errorf("confidence: %q", s.Confidence)
	}
}

func TestSanitizeRemoteURL(t *testing.T) {
	cases := []struct{ in, want string }{
		// The userinfo is the point of the case: a valid https URL carrying a credential
		// keeps its scheme and host and loses everything else. Reviewers have twice read
		// this as malformed input and reported the expectation as impossible, because a
		// tool quoting the line masks `https://user:secret@` down to asterisks and what is
		// left looks scheme-less. It is not; the scheme-less case is three lines down and
		// expects the empty string.
		{"https://user:secret@mcp.example.com/path?api_key=abc", "https://mcp.example.com"},
		{"https://mcp.example.com/mcp/abc123tokenhere/sse", "https://mcp.example.com"},
		{"http://localhost:8080/foo", "http://localhost:8080"},
		{"//example.com/path", "//example.com"},
		// Scheme-less with a path parses as all-path and no host. The endpoint is dropped
		// rather than guessed at: inventing a scheme would report one the config never
		// named, and the query string it arrives with is exactly where a key hides.
		{"mcp.example.com/path?api_key=abc", ""},
		{"not a url", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := sanitizeRemoteURL(c.in); got != c.want {
			t.Errorf("sanitizeRemoteURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSecretFlagNameDetection(t *testing.T) {
	cases := []struct {
		flag string
		want bool
	}{
		// existing patterns
		{"--token", true},
		{"--api-token", true},
		{"--api_token", true},
		{"--client-secret", true},
		{"--password", true},
		// new "delimited key" patterns
		{"--key", true},
		{"--dd-key", true},
		{"--gcp-key", true},
		{"--cache-key-id", true},
		// must NOT match (substring "key" without delimiter)
		{"--monkey", false},
		{"--keyword", false},
		{"--monkey-server", false},
		// other non-matches
		{"--verbose", false},
		{"-y", false},
		{"--no-save", false},
	}
	for _, c := range cases {
		got := isSecretFlagName(c.flag)
		if got != c.want {
			t.Errorf("isSecretFlagName(%q) = %v, want %v", c.flag, got, c.want)
		}
	}
}

func TestRedactArgs(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"github PAT in arg", []string{"--header", "Authorization: Bearer ghp_abcdefghijklmnopqrstuvwx12345"},
			[]string{"--header", "Authorization: Bearer [REDACTED]"}},
		{"inline secret flag", []string{"--api-key=sk-abcdefghijklmnopqrstuvwxyz"},
			[]string{"--api-key=[REDACTED]"}},
		{"two-arg secret flag", []string{"--token", "supersecret123"},
			[]string{"--token", "[REDACTED]"}},
		// Deliberately over-redacts. The exemption this replaces skipped any dash-prefixed
		// token, which meant `--token -opaque-secret` left the secret in place. Telling that
		// apart from a flag with no value needs per-flag arity, which this does not have, and
		// this file's stated preference is to over-redact rather than risk a leak. Nothing is
		// lost: no column emits args, only their count.
		{"two-arg secret flag consumes the next token even if it looks like a flag",
			[]string{"--token", "--verbose"}, []string{"--token", "[REDACTED]"}},
		{"a dash-prefixed secret value is still redacted",
			[]string{"--token", "-opaque-secret-value"}, []string{"--token", "[REDACTED]"}},
		{"jwt", []string{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dozjgNryP-D"},
			[]string{"[REDACTED]"}},
		{"benign args untouched", []string{"-y", "@modelcontextprotocol/server-fs", "/tmp"},
			[]string{"-y", "@modelcontextprotocol/server-fs", "/tmp"}},
		{"aws key", []string{"--key", "AKIAIOSFODNN7EXAMPLE"},
			[]string{"--key", "[REDACTED]"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := redactArgs(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("len mismatch: got %v want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("arg %d: got %q want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestRedactSecret_Idempotent(t *testing.T) {
	once := redactSecret("ghp_abcdefghijklmnopqrstuvwx12345")
	twice := redactSecret(once)
	if once != twice {
		t.Errorf("not idempotent: %q vs %q", once, twice)
	}
}

// An assignment embedded in a longer string, which is how these arrive outside argv: a
// server name is a JSON object key, a source context carries a project path, and a command
// can reach the table as one field. The whole-string form was handled; this one was not, and
// an opaque value after --token is exactly what the known-shape redactor cannot catch.
func TestRedactSecretRedactsAnAssignmentInsideALongerValue(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"embedded secret flag", "fetch --api-key=opaquevalue123",
			"fetch --api-key=" + redact.RedactedMark},
		{"value ends at the next space", "server --token=opaquevalue123 --verbose",
			"server --token=" + redact.RedactedMark + " --verbose"},
		{"whole string is still handled", "--token=opaquevalue123",
			"--token=" + redact.RedactedMark},
		{"ordinary option is left alone", "server --port=8080", "server --port=8080"},
		// The delimiter requirement in secretFlagKeyRe, from the other side: a flag that
		// merely contains "key" is not a key flag, and over-redacting it would erase an
		// ordinary value.
		{"key as a substring is not a key flag", "run --monkey=grape", "run --monkey=grape"},
		// The delimiter before an option is a separator far more often than it is a space.
		// Every case below leaked its opaque value verbatim while the left boundary was
		// `\s`, and each is a field this table actually emits.
		{"path separator delimits the option", "group/--api-key=opaquevalue123",
			"group/--api-key=" + redact.RedactedMark},
		{"bracket delimits the option, as in a source context",
			"projects[/tmp/--api-key=opaquevalue123].mcpServers",
			"projects[/tmp/--api-key=" + redact.RedactedMark},
		{"non-ASCII whitespace delimits the option", "label\u00a0--token=opaquevalue123",
			"label\u00a0--token=" + redact.RedactedMark},
		{"comma delimits the option", "a,--token=opaquevalue123",
			"a,--token=" + redact.RedactedMark},
		// The other side of the widened boundary: dashes interior to a word do not start
		// an option, so this is a value rather than an assignment and keeps its text.
		{"dashes inside a word do not start an option", "weird--token=opaquevalue123",
			"weird--token=opaquevalue123"},
		// A newline is one escape away in a JSON string, and Go's `.` does not cross one.
		// The whole-value form matched with a regexp, so every case below returned its
		// value verbatim or redacted only the first line of it.
		{"newline between the equals and the value", "--token=\nopaquevalue123",
			"--token=" + redact.RedactedMark},
		{"value spanning a newline is redacted whole", "--token=opaque\nvalue123",
			"--token=" + redact.RedactedMark},
		{"newline inside a longer value", "name --token=\nopaquevalue123",
			"name --token=" + redact.RedactedMark},
		{"a value separated by a space is still the value", "--token= opaquevalue123",
			"--token=" + redact.RedactedMark},
		// The reason the whitespace-tolerant pattern runs second. Read as one assignment,
		// this is a benign option whose value happens to be the real one, and the
		// credential survives. The strict pattern has to claim it first.
		{"a benign option does not swallow the assignment after it",
			"--verbose= --token=opaquevalue123",
			"--verbose= --token=" + redact.RedactedMark},
		{"the same across a newline", "--verbose=\n--token=opaquevalue123",
			"--verbose=\n--token=" + redact.RedactedMark},
		// Nothing to the right of the equals is nothing to redact, and a bare equals names
		// no option at all.
		{"an assignment with no value is left alone", "--token=", "--token="},
		{"a leading equals is not an assignment", "=nothing", "=nothing"},
		// A benign option's value runs to the next space, so the scan consumed a nested
		// credential assignment as part of that value and never looked inside it. Each of
		// these returned the secret verbatim.
		{"a credential nested directly in a benign value",
			"--verbose=--token=opaquevalue123",
			"--verbose=--token=" + redact.RedactedMark},
		{"the same after a comma", "a,--verbose=--token=opaquevalue123",
			"a,--verbose=--token=" + redact.RedactedMark},
		{"a comma inside the benign value", "--verbose=x,--token=opaquevalue123",
			"--verbose=x,--token=" + redact.RedactedMark},
		{"a path-shaped benign value", "--out=/tmp/--token=opaquevalue123",
			"--out=/tmp/--token=" + redact.RedactedMark},
		{"nested several deep", "--a=--b=--c=--token=opaquevalue123",
			"--a=--b=--c=--token=" + redact.RedactedMark},
		// Descending must not disturb a value with nothing in it. These reach the same
		// branch and have to come back byte for byte, separator included.
		{"a benign path value is untouched", "--out=/tmp/file.txt", "--out=/tmp/file.txt"},
		{"a benign numeric value is untouched", "--port=8080", "--port=8080"},
		{"a benign spaced value keeps its separator", "--out= /tmp/file.txt",
			"--out= /tmp/file.txt"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := redactSecret(testCase.in)
			if got != testCase.want {
				t.Errorf("redactSecret(%q) = %q, want %q", testCase.in, got, testCase.want)
			}
			if again := redactSecret(got); again != got {
				t.Errorf("not idempotent: %q then %q", got, again)
			}
		})
	}
}

// Following a nested assignment is recursive, so it needs a bound that is about cost rather
// than about termination -- the input shrinks by a flag name and an `=` at every level, so
// it always ends. Each level re-scans what is left, so an unbounded descent is quadratic in
// the number of nested assignments, and these fields come from a file a user controls: the
// watchdog kills an extension that spends that long, taking every other table with it.
//
// Past the bound the value is redacted rather than followed: this file over-redacts by
// preference, and a value nested that deep is not one a reader was going to use.
func TestNestedAssignmentsAreBoundedAndStillRedact(t *testing.T) {
	const secret = "opaquevalue123"

	atTheLimit := strings.Repeat("-a=", maxAssignmentDepth-1) + "--token=" + secret
	if got := redactSecret(atTheLimit); strings.Contains(got, secret) {
		t.Errorf("a credential within the depth bound was not redacted: %q", got)
	}

	// Far past it, and long enough that per-level recursion would not survive.
	// Enough nesting that an unbounded descent is measurably quadratic, without making the
	// suite pay for proving it.
	pathological := strings.Repeat("-a=", 20000) + "--token=" + secret
	got := redactSecret(pathological)
	if strings.Contains(got, secret) {
		t.Error("deeply nested input leaked its credential")
	}
	if !strings.Contains(got, redact.RedactedMark) {
		t.Errorf("deeply nested input produced no marker: %q", got)
	}
	if again := redactSecret(got); again != got {
		t.Errorf("not idempotent at the bound: %q then %q", got, again)
	}
}

func TestSplitNPMSpec(t *testing.T) {
	cases := []struct{ in, name, ver string }{
		{"@scope/pkg@1.0.0", "@scope/pkg", "1.0.0"},
		{"@scope/pkg", "@scope/pkg", ""},
		// `pkg@1` is an npm X-range, equivalent to `1.x.x`: a missing component is a
		// wildcard, so it selects whatever is published next within the major. This
		// expected "1" and reported it as an exact pin at high confidence.
		{"pkg@1", "pkg", ""},
		{"pkg@1.2", "pkg", ""},
		{"pkg", "pkg", ""},
		// A complete version, including the prerelease and build forms semver allows.
		{"pkg@1.2.3", "pkg", "1.2.3"},
		{"pkg@1.2.3-beta.1", "pkg", "1.2.3-beta.1"},
		{"pkg@v1.2.3", "pkg", "v1.2.3"},
		{"@scope/pkg@1", "@scope/pkg", ""},
		{"@scope/pkg@2.0.0", "@scope/pkg", "2.0.0"},
		{"https://example.com/pkg.tgz", "", ""},
	}
	for _, c := range cases {
		n, v := splitNPMSpec(c.in)
		if n != c.name || v != c.ver {
			t.Errorf("splitNPMSpec(%q) = (%q,%q) want (%q,%q)", c.in, n, v, c.name, c.ver)
		}
	}
}

func TestEnvKeysNeverContainValues(t *testing.T) {
	// Belt-and-suspenders: confirm secret env values never round-trip into a Server.
	data := []byte(`{"mcpServers":{"x":{"command":"x","env":{"GITHUB_TOKEN":"ghp_supersecretvalue1234567890"}}}}`)
	rows, err := extractEnvelopeSimple(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1: %+v", len(rows), rows)
	}
	sort.Strings(rows[0].EnvKeys)
	if !reflect.DeepEqual(rows[0].EnvKeys, []string{"GITHUB_TOKEN"}) {
		t.Errorf("env keys: %v", rows[0].EnvKeys)
	}
	for _, v := range []string{rows[0].Command, rows[0].URL, rows[0].RequestedSpec, rows[0].PackageName} {
		if strings.Contains(v, "ghp_supersecret") {
			t.Errorf("secret leaked into field: %q", v)
		}
	}
}

func TestServerNameRedacted(t *testing.T) {
	// HIGH finding: JSON map keys are attacker-controlled. A token-shaped
	// server name must be redacted before it reaches the table.
	data := []byte(`{"mcpServers":{"ghp_abcdefghijklmnopqrstuvwx12345":{"command":"npx","args":["x"]}}}`)
	rows, err := extractEnvelopeSimple(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1: %+v", len(rows), rows)
	}
	if strings.Contains(rows[0].ServerName, "ghp_") {
		t.Errorf("token-shaped server name leaked into ServerName: %q", rows[0].ServerName)
	}
}

func TestSourceContextRedacted(t *testing.T) {
	// projects[<path>].mcpServers: the <path> is attacker-controlled. If
	// the path on disk contains a token-shaped substring, it lands in
	// source_context. Verify redaction.
	data := []byte(`{
		"projects": {
			"/Users/x/code/proj-ghp_realtoken1234567890abcdef": {
				"mcpServers": {"a": {"command": "x"}}
			}
		}
	}`)
	rows, err := extractClaudeCode(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1: %+v", len(rows), rows)
	}
	if strings.Contains(rows[0].SourceContext, "ghp_realtoken") {
		t.Errorf("token-shaped project path leaked into SourceContext: %q", rows[0].SourceContext)
	}
}

func TestSecretInArgsRedacted_EndToEnd(t *testing.T) {
	// A real-world misconfig: someone shoves a token into args instead of env.
	data := []byte(`{"mcpServers":{"x":{"command":"node","args":["server.js","--token","ghp_abcdefghijklmnopqrstuv12345"]}}}`)
	rows, err := extractEnvelopeSimple(data)
	if err != nil || len(rows) != 1 {
		t.Fatalf("parse: %v rows=%d", err, len(rows))
	}
	for _, a := range rows[0].Args {
		if strings.Contains(a, "ghp_") {
			t.Errorf("token leaked through args: %q", a)
		}
	}
}

// A flat .mcp.json carrying a non-object sibling, which "$schema" makes common. Decoding the
// whole document into map[string]rawServerEntry fails on that string, and the caller reads a
// failure here as "not MCP configuration", so every real server in the file used to disappear
// with no warning row to show it had happened. Silent row loss, so it gets a named test.
func TestExtractFlatKeepsServersAlongsideNonObjectSiblings(t *testing.T) {
	rows, err := extractEnvelopeSimple([]byte(`{
		"$schema": "https://modelcontextprotocol.io/schema.json",
		"pinned_version": 3,
		"enabled": true,
		"real-server": {"command": "npx", "args": ["-y", "real-mcp@1.0.0"]}
	}`))
	if err != nil {
		t.Fatalf("metadata siblings must not fail the parse: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want the one real server: %+v", len(rows), rows)
	}
	if rows[0].ServerName != "real-server" || rows[0].Command != "npx" {
		t.Errorf("wrong row survived: %+v", rows[0])
	}
}

// One malformed entry must not take its healthy siblings with it, and its absence has to be
// stated. Flat files used to skip silently while envelopes reported a count, so a short
// listing from a flat .mcp.json was indistinguishable from a complete one.
func TestExtractFlatKeepsHealthyEntriesAndReportsSkippedOnes(t *testing.T) {
	rows, err := extractEnvelopeSimple([]byte(
		`{"broken": {"command": 123}, "good": {"command": "uvx", "args": ["good-mcp"]}}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var healthy, diagnostics int
	for _, row := range rows {
		switch {
		case row.Warning.empty() == false:
			diagnostics++
		case row.ServerName == "good":
			healthy++
		default:
			t.Errorf("unexpected row: %+v", row)
		}
	}
	if healthy != 1 || diagnostics != 1 {
		t.Errorf("want one healthy row and one diagnostic, got %d/%d: %+v",
			healthy, diagnostics, rows)
	}
}

// A metadata sibling that is not an object is not a failed entry, so it must not be counted
// as one. Only an object that fails to decode is a server we could not read.
func TestExtractFlatDoesNotCountMetadataSiblingsAsSkipped(t *testing.T) {
	rows, err := extractEnvelopeSimple([]byte(
		`{"$schema": "https://example.test/s.json", "good": {"command": "npx"}}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, row := range rows {
		if row.Warning.empty() == false {
			t.Errorf("a metadata sibling should not produce a diagnostic: %q", row.Warning.render())
		}
	}
}

// Top-level JSON that is not an object at all is still a parse failure, since that is a file
// we genuinely cannot read rather than one we can read selectively.
func TestExtractFlatStillRejectsInvalidTopLevelJSON(t *testing.T) {
	if _, _, err := extractFlat([]byte(`{"a": }`)); err == nil {
		t.Error("malformed JSON should error")
	}
}

// The confidence column's contract is high, medium or low. An empty value is not in that set
// and silently drops out of any query filtering on it, so a remote entry carrying no endpoint
// still has to land somewhere.
func TestInferIdentityAlwaysSetsConfidence(t *testing.T) {
	for _, entry := range []string{
		`{"mcpServers":{"s":{"type":"http"}}}`,
		`{"mcpServers":{"s":{"transport":"sse"}}}`,
		`{"mcpServers":{"s":{"command":"npx","args":["-y","x-mcp@1.0.0"]}}}`,
		`{"mcpServers":{"s":{"type":"http","url":"https://example.com/mcp"}}}`,
	} {
		rows, err := extractEnvelopeSimple([]byte(entry))
		if err != nil || len(rows) != 1 {
			t.Fatalf("%s: setup rows=%d err=%v", entry, len(rows), err)
		}
		server := rows[0]
		inferIdentity(&server)
		switch server.Confidence {
		case "high", "medium", "low":
		default:
			t.Errorf("%s: confidence = %q, want one of high/medium/low", entry, server.Confidence)
		}
	}
}

// The inline form carries its value in the same token, so it is valid as the final argument.
// Bounding the scan at len(args)-1 to protect the two-token lookahead skipped it there.
func TestNpxIdentityFindsInlinePackageInFinalPosition(t *testing.T) {
	spec, version, _ := npxIdentity([]string{"-y", "--package=some-mcp@1.2.3"})
	if spec != "some-mcp@1.2.3" || version != "1.2.3" {
		t.Errorf("inline in final position: spec=%q version=%q", spec, version)
	}
	// The two-token form must still work, and must not read past the end when the flag is
	// itself the last argument.
	if spec, _, _ := npxIdentity([]string{"--package", "other-mcp@2.0.0"}); spec != "other-mcp@2.0.0" {
		t.Errorf("two-token form regressed: %q", spec)
	}
	if spec, _, _ := npxIdentity([]string{"-y", "--package"}); spec != "" {
		t.Errorf("dangling --package should yield nothing, got %q", spec)
	}
}

// Removing a block comment must not let its neighbours fuse into a single token.
//
// The separator itself is asserted byte-exactly by the "block comment" case in
// TestStripJSONC above. What that cannot show is why it matters, which is this: the input
// below is malformed, two numbers with only a comment between them. With a separator it stays
// malformed and the file is reported with a parse warning. Without one it becomes {"a":12},
// which parses cleanly to a value that was never in the file. A table that inventories
// configuration must not invent data out of a corrupt one.
//
// An earlier version of this test used `{"a":1/*c*/,"b":2}`, which parses to the same thing
// with or without a separator, so it passed either way and asserted nothing.
func TestStripJSONCBlockCommentDoesNotFuseAdjacentTokens(t *testing.T) {
	for _, malformed := range []string{`{"a":1/*c*/2}`, `{"a":[1/*c*/2]}`} {
		stripped, _ := stripJSONC([]byte(malformed))
		var parsed any
		if err := json.Unmarshal(stripped, &parsed); err == nil {
			t.Errorf("%s stripped to %q, which parsed to %v: malformed input must stay "+
				"malformed rather than fusing into a different value", malformed, stripped, parsed)
		}
	}
	// The well-formed case still has to survive the separator unharmed.
	stripped, _ := stripJSONC([]byte(`{"a":1/*c*/,"b":2}`))
	var parsed map[string]int
	if err := json.Unmarshal(stripped, &parsed); err != nil {
		t.Fatalf("valid JSONC broke: %v (%q)", err, stripped)
	}
	if parsed["a"] != 1 || parsed["b"] != 2 {
		t.Errorf("values wrong: %v", parsed)
	}
}

// A malformed entry inside an envelope must not take its healthy siblings with it, and its
// absence must be stated rather than left to inference.
//
// An earlier version of this test asserted the opposite -- zero rows plus an error -- which
// was the wrong target. Surfacing the whole file as unreadable because one of six entries has
// a bad field type loses five servers that were perfectly legible, and a supply-chain
// inventory should prefer partial-and-labelled over nothing.
func TestEnvelopeKeepsHealthyEntriesAndReportsSkippedOnes(t *testing.T) {
	rows, err := extractEnvelopeSimple([]byte(
		`{"mcpServers":{"good":{"command":"npx","args":["x"]},"bad":{"command":123}}}`))
	if err != nil {
		t.Fatalf("one bad entry must not fail the document: %v", err)
	}
	var healthy, diagnostics int
	for _, row := range rows {
		switch {
		case row.Warning.empty() == false:
			diagnostics++
		case row.ServerName == "good":
			healthy++
		default:
			t.Errorf("unexpected row: %+v", row)
		}
	}
	if healthy != 1 {
		t.Errorf("the healthy server should survive, got %d: %+v", healthy, rows)
	}
	if diagnostics != 1 {
		t.Errorf("the skipped entry should be reported, got %d diagnostics: %+v", diagnostics, rows)
	}
}

// An unterminated block comment makes a file malformed. The prefix before the opener can be
// valid JSON on its own, so returning it silently would report a truncated file as clean.
func TestStripJSONCReportsUnterminatedBlockComment(t *testing.T) {
	stripped, terminated := stripJSONC([]byte(`{"mcpServers":{"a":{"command":"npx"}}} /* oops`))
	if terminated {
		t.Errorf("unterminated comment reported as terminated; stripped=%q", stripped)
	}
	// A properly closed comment still reports terminated.
	if _, ok := stripJSONC([]byte(`{"a":1/*c*/}`)); !ok {
		t.Error("a closed block comment must report terminated")
	}
}

// args_count and disabled hold numbers. Declared TEXT, SQLite compares them as strings, so
// `args_count > 5` would rank "10" below "5".
func TestNumericColumnsAreDeclaredIntegers(t *testing.T) {
	byName := make(map[string]table.ColumnDefinition)
	for _, column := range MCPServersColumns() {
		byName[column.Name] = column
	}
	for _, name := range []string{"args_count", "disabled"} {
		if got := byName[name].Type; got != table.ColumnTypeInteger {
			t.Errorf("%s declared as %q, want INTEGER: it carries a number", name, got)
		}
	}
}

// The /sse convention lives in the endpoint path, and sanitizeRemoteURL drops the path before
// the row is built. Transport therefore has to be inferred while the raw URL still exists;
// inferring it later reported every untyped SSE endpoint as http.
func TestUntypedSSEEndpointIsNotReportedAsHTTP(t *testing.T) {
	for _, testCase := range []struct{ url, want string }{
		{"https://example.test/sse", "sse"},
		{"https://example.test/mcp/events", "sse"},
		{"https://example.test/mcp", "http"},
	} {
		rows, err := extractEnvelopeSimple([]byte(`{"mcpServers":{"s":{"url":"` + testCase.url + `"}}}`))
		if err != nil || len(rows) != 1 {
			t.Fatalf("%s: setup rows=%d err=%v", testCase.url, len(rows), err)
		}
		server := rows[0]
		inferIdentity(&server)
		if server.Transport != testCase.want {
			t.Errorf("%s: transport = %q, want %q", testCase.url, server.Transport, testCase.want)
		}
		// The emitted endpoint must still be scheme and host only.
		if server.URL != "https://example.test" {
			t.Errorf("%s: endpoint leaked a path: %q", testCase.url, server.URL)
		}
	}
	// An explicit type still wins over the path heuristic.
	//
	// Asserted unconditionally. Guarding this on len(rows) == 1 meant an extraction that
	// returned nothing satisfied the test without ever comparing a transport -- the precedence
	// rule would have stopped being checked and nothing would have said so.
	rows, err := extractEnvelopeSimple([]byte(
		`{"mcpServers":{"s":{"type":"http","url":"https://e.test/sse"}}}`))
	if err != nil {
		t.Fatalf("explicit type: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("explicit type: got %d rows, want 1: %+v", len(rows), rows)
	}
	if rows[0].Transport != "http" {
		t.Errorf("an explicit type should win over the /sse path, got %q", rows[0].Transport)
	}
}

// An option that takes a separate value must not be mistaken for the package. Attributing the
// value is worse than attributing nothing, because confidence is then medium on a wrong answer
// and nothing in the row marks it as suspect.
func TestValueTakingOptionsDoNotBecomeThePackage(t *testing.T) {
	for _, testCase := range []struct {
		command string
		args    []string
		want    string
	}{
		{"uvx", []string{"--python", "3.12", "actual-server"}, "actual-server"},
		{"uvx", []string{"--with", "extra-dep", "actual-server"}, "actual-server"},
		// pipx skipped flags but not the values they consume, so this returned 3.12.
		{"pipx", []string{"run", "--python", "3.12", "actual-server"}, "actual-server"},
		// uv indexed blindly to run+2 regardless of what sat there, returning --python.
		{"uv", []string{"tool", "run", "--python", "3.12", "actual-server"}, "actual-server"},
		{"uv", []string{"run", "--from", "real-pkg", "cmd"}, "real-pkg"},
		{"docker", []string{"run", "--pull", "always", "myorg/real:1.0"}, "myorg/real"},
		{"docker", []string{"run", "--rm", "-v", "/tmp:/tmp", "myorg/img:2"}, "myorg/img"},
		{"npx", []string{"-y", "@scope/pkg@1.0.0"}, "@scope/pkg"},
	} {
		server := Server{Command: testCase.command, Args: testCase.args, Transport: "stdio"}
		inferIdentity(&server)
		if server.PackageName != testCase.want {
			t.Errorf("%s %v: package_name = %q, want %q",
				testCase.command, testCase.args, server.PackageName, testCase.want)
		}
	}
}

// VS Code and several other clients write `servers`; most write `mcpServers`. Merging both
// into one map and labelling every row "mcpServers" made source_context describe a location
// the entry did not come from, which is the one thing that column is for.
func TestSourceContextNamesTheEnvelopeTheEntryCameFrom(t *testing.T) {
	rows, err := extractEnvelopeSimple([]byte(
		`{"mcpServers":{"from-mcp":{"command":"npx"}},"servers":{"from-servers":{"command":"node"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, row := range rows {
		got[row.ServerName] = row.SourceContext
	}
	if got["from-mcp"] != "mcpServers" {
		t.Errorf("from-mcp: source_context = %q, want mcpServers", got["from-mcp"])
	}
	if got["from-servers"] != "servers" {
		t.Errorf("from-servers: source_context = %q, want servers", got["from-servers"])
	}
}

// mcpServers still wins a name collision, and the losing entry must not also appear under the
// other context: one configured server, one row.
func TestCollidingEnvelopeNamesYieldOneRow(t *testing.T) {
	rows, err := extractEnvelopeSimple([]byte(
		`{"mcpServers":{"dup":{"command":"npx"}},"servers":{"dup":{"command":"node"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want one: %+v", len(rows), rows)
	}
	if rows[0].Command != "npx" || rows[0].SourceContext != "mcpServers" {
		t.Errorf("mcpServers should win: %+v", rows[0])
	}
}

// dockerRunIdentity has been through several arity strategies and regressed on each, so the
// cases that broke it are pinned here rather than left to ad-hoc checks.
//
// The strategy is to enumerate the boolean options and assume everything else consumes a
// value. That is the inversion of listing value-bearing options, which grew three times during
// review -- --pull, then --cap-add, then --publish -- each addition prompted by a wrong package
// name rather than by reading the docs.
func TestDockerRunIdentityArity(t *testing.T) {
	for _, testCase := range []struct {
		name string
		args []string
		want string
	}{
		// Values that satisfy the image grammar, which is why a grammar alone cannot decide.
		{"publish long", []string{"run", "--publish", "8080:80", "myorg/s:1"}, "myorg/s:1"},
		{"publish short", []string{"run", "-p", "8080:80", "myorg/s:1"}, "myorg/s:1"},
		{"memory", []string{"run", "--memory", "512m", "myorg/s:1"}, "myorg/s:1"},
		{"dns", []string{"run", "--dns", "1.1.1.1", "myorg/s:1"}, "myorg/s:1"},
		{"env bare word", []string{"run", "-e", "debug", "myorg/s:1"}, "myorg/s:1"},
		{"pull policy", []string{"run", "--pull", "always", "myorg/s:1"}, "myorg/s:1"},
		{"restart policy", []string{"run", "--restart", "no", "myorg/s:1"}, "myorg/s:1"},
		// Values the grammar rejects on case or structure.
		{"cap-add", []string{"run", "--cap-add", "NET_ADMIN", "myorg/s:1"}, "myorg/s:1"},
		// Booleans, listed and unlisted.
		{"known booleans", []string{"run", "--rm", "-i", "-t", "myorg/s"}, "myorg/s"},
		{"boolean then option", []string{"run", "--sig-proxy", "--publish", "8080:80", "myorg/s:1"}, "myorg/s:1"},
		{"unlisted boolean then option", []string{"run", "--made-up-bool", "--publish", "8080:80", "myorg/s:1"}, "myorg/s:1"},
		// An unlisted boolean directly before the image swallows it. No image beats a wrong
		// one, which is the intended direction of error.
		{"unlisted boolean then image", []string{"run", "--made-up-bool", "myorg/s:1"}, ""},
		// Structural forms.
		{"inline value", []string{"run", "--env=FOO=bar", "myorg/s:1"}, "myorg/s:1"},
		{"double dash", []string{"run", "--", "myorg/s:1"}, "myorg/s:1"},
		{"registry with port", []string{"run", "--privileged", "localhost:5000/t/i:tag"}, "localhost:5000/t/i:tag"},
		{"digest reference", []string{"run", "myorg/s@sha256:" + strings.Repeat("a", 64)}, "myorg/s@sha256:" + strings.Repeat("a", 64)},
		// Options whose value can begin with a dash. These fail in both directions and need
		// their own category: classifying --oom-score-adj as boolean made the positive case
		// report 100 as the image, and merely removing it from the boolean set made the
		// negative case return nothing, because -100 was then read as an option that
		// consumed the image. Docker documents --oom-score-adj as -1000..1000, and
		// --pids-limit and --memory-swap use -1 for unlimited.
		{"oom-score-adj positive", []string{"run", "--oom-score-adj", "100", "myorg/s:1"}, "myorg/s:1"},
		{"oom-score-adj negative", []string{"run", "--oom-score-adj", "-100", "myorg/s:1"}, "myorg/s:1"},
		{"pids-limit unlimited", []string{"run", "--pids-limit", "-1", "myorg/s:1"}, "myorg/s:1"},
		{"memory-swap unlimited", []string{"run", "--memory-swap", "-1", "myorg/s:1"}, "myorg/s:1"},
		{"negatable then chained option", []string{"run", "--oom-score-adj", "-100", "--publish", "8080:80", "myorg/s:1"}, "myorg/s:1"},
		// Grouped short options. pflag walks a cluster left to right; -it is the most common
		// docker invocation in existence and appeared in no flag table, so the generic rule
		// consumed the image and reported nothing.
		{"grouped booleans", []string{"run", "-it", "myorg/s:1"}, "myorg/s:1"},
		{"grouped booleans three", []string{"run", "-itd", "myorg/s:1"}, "myorg/s:1"},
		{"grouped after a value option", []string{"run", "-v", "/tmp:/tmp", "-it", "myorg/s:1"}, "myorg/s:1"},
		// A value-taking shorthand ending a cluster consumes the next token; one in the
		// middle takes the cluster remainder as its value and consumes nothing. Getting
		// these backwards loses the image in one direction and misreads a value as it in
		// the other.
		{"cluster ending in a value short", []string{"run", "-itp", "8080:80", "myorg/s:1"}, "myorg/s:1"},
		{"value short carrying its own value", []string{"run", "-p8080:80", "myorg/s:1"}, "myorg/s:1"},
		{"value short mid-cluster", []string{"run", "-ip8080:80", "myorg/s:1"}, "myorg/s:1"},
		// -P is --publish-all and takes nothing; -p is --publish and takes one. Folding case
		// here would make -P consume the image.
		{"capital P is publish-all", []string{"run", "-P", "myorg/s:1"}, "myorg/s:1"},
		{"grouped with capital P", []string{"run", "-itP", "myorg/s:1"}, "myorg/s:1"},
		// An unknown character in a cluster falls back to the conservative default rather
		// than assuming the rest are booleans.
		{"cluster with an unknown short", []string{"run", "-itZ", "myorg/s:1"}, ""},
		// A negative number must not be mistaken for a cluster.
		{"negative number is not a cluster", []string{"run", "--pids-limit", "-1", "myorg/s:1"}, "myorg/s:1"},
		// Credential-bearing forms the grammar must reject outright.
		{"userinfo", []string{"run", "user:secret@reg/img"}, ""},
		{"no run subcommand", []string{"pull", "myorg/s:1"}, ""},
	} {
		if got := dockerRunIdentity(testCase.args); got != testCase.want {
			t.Errorf("%s: %v -> %q, want %q", testCase.name, testCase.args, got, testCase.want)
		}
	}
}

// Every state the envelope parser distinguishes, in one table.
//
// This path has changed on four separate review rounds, and each change broke a state the
// previous one had working: presence conflated with decodability, then a valid empty envelope
// reported as malformed, then a malformed envelope discarding a healthy sibling envelope. The
// states were described in comments and verified by throwaway checks that were then deleted,
// which is why they kept regressing. Pinned here instead.
//
// The distinctions that matter, and why:
//
//   - No recognised key: the only case where reading the document as flat is legitimate.
//   - Present but empty, `{}` or `null`: a valid configuration with no servers. Must not
//     error, and must not fall through to flat either, or an unrelated sibling object gets
//     attributed as a server.
//   - Present but the wrong type: that envelope is malformed. The *other* envelope, if there
//     is one, is unaffected.
//   - Present with entries that all fail: nothing usable, so a file-level error.
//   - Malformed alongside healthy: keep the healthy rows and report the failure beside them.
func TestEnvelopeStates(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		doc          string
		wantErr      bool
		wantServers  []string
		wantWarnings int
	}{
		{
			name:        "no recognised key reads as flat",
			doc:         `{"flat-server":{"command":"npx","args":["x"]}}`,
			wantServers: []string{"flat-server"},
		},
		{
			name: "empty object is a valid zero-server configuration",
			doc:  `{"mcpServers":{}}`,
		},
		{
			name: "null is a valid zero-server configuration",
			doc:  `{"mcpServers":null}`,
		},
		{
			name: "empty envelope does not fall through to flat",
			doc:  `{"mcpServers":{},"other":{"command":"node"}}`,
			// Specifically NOT ["other"]: the envelope was present and said there are none.
		},
		{
			name: "null envelope does not fall through to flat",
			doc:  `{"mcpServers":null,"other":{"command":"node"}}`,
		},
		{
			name:    "wrong-shaped envelope with nothing else is an error",
			doc:     `{"mcpServers":[]}`,
			wantErr: true,
		},
		{
			name:         "wrong-shaped envelope must not erase a healthy sibling envelope",
			doc:          `{"mcpServers":[],"servers":{"healthy":{"command":"node"}}}`,
			wantServers:  []string{"healthy"},
			wantWarnings: 1,
		},
		{
			name:    "wrong-shaped envelope with no usable alternate is an error",
			doc:     `{"mcpServers":"nope","other":{"command":"node"}}`,
			wantErr: true,
		},
		{
			name:    "every entry failing is an error",
			doc:     `{"mcpServers":{"a":{"command":1},"b":{"args":2}}}`,
			wantErr: true,
		},
		{
			name:         "one entry failing keeps its siblings and reports itself",
			doc:          `{"mcpServers":{"good":{"command":"npx"},"bad":{"command":1}}}`,
			wantServers:  []string{"good"},
			wantWarnings: 1,
		},
		{
			name:        "healthy envelope",
			doc:         `{"mcpServers":{"ok":{"command":"npx"}}}`,
			wantServers: []string{"ok"},
		},
		{
			name:        "servers spelling is equally recognised",
			doc:         `{"servers":{"ok":{"command":"npx"}}}`,
			wantServers: []string{"ok"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			rows, err := extractEnvelopeSimple([]byte(testCase.doc))
			if (err != nil) != testCase.wantErr {
				t.Fatalf("err = %v, wantErr = %v (rows=%+v)", err, testCase.wantErr, rows)
			}
			var names []string
			warnings := 0
			for _, row := range rows {
				if row.Warning.empty() == false {
					warnings++
					continue
				}
				names = append(names, row.ServerName)
			}
			sort.Strings(names)
			want := append([]string(nil), testCase.wantServers...)
			sort.Strings(want)
			if !reflect.DeepEqual(names, want) {
				t.Errorf("servers = %v, want %v", names, want)
			}
			if warnings != testCase.wantWarnings {
				t.Errorf("warnings = %d, want %d (rows=%+v)", warnings, testCase.wantWarnings, rows)
			}
		})
	}
	// Invalid JSON is a parse failure regardless of envelope reasoning.
	if _, err := extractEnvelopeSimple([]byte(`{not json`)); err == nil {
		t.Error("invalid JSON should error")
	}
}

// The identity columns are derived from user-controlled arguments, and a blacklist of rejected
// prefixes accepted everything it had not anticipated -- which included credentials.
// user:opaque-password@registry/image was emitted as package_name=user:opaque-password: an
// actual password in a row, not the documented opaque-value caveat, because the final redactor
// only recognises issuer-prefixed token shapes and a password is not one.
//
// A positive grammar is what fixes it: a colon cannot appear in a package name, and a Docker
// port must be numeric, so every userinfo form is rejected without enumerating them.
func TestCredentialBearingFormsNeverReachIdentityColumns(t *testing.T) {
	for _, candidate := range []string{
		"user:opaque-password@registry/image",
		"https:user:secret@host",
		"a:b@c",
		"user:pw@host:1234/img",
		"//user:pw@host/img",
	} {
		if looksLikePackageSpec(candidate) {
			t.Errorf("looksLikePackageSpec(%q) = true: a colon cannot appear in a package name",
				candidate)
		}
		for _, command := range []string{"uvx", "npx", "bunx", "docker"} {
			args := []string{candidate}
			if command == "docker" {
				args = []string{"run", candidate}
			}
			server := Server{Command: command, Args: args, Transport: "stdio"}
			inferIdentity(&server)
			for column, value := range map[string]string{
				"package_name":   server.PackageName,
				"requested_spec": server.RequestedSpec,
				"pinned_version": server.PinnedVersion,
			} {
				if strings.Contains(value, "password") || strings.Contains(value, "secret") ||
					strings.Contains(value, "pw@") || strings.Contains(value, ":b@") {
					t.Errorf("%s %q: %s = %q", command, candidate, column, value)
				}
			}
		}
	}
	// The forms that must still be accepted, so the grammar is not merely strict.
	for _, valid := range []string{
		"@scope/pkg@1.0.0", "real-server@1.2.3", "mcp-server-time", "pkg==1.2",
		"awslabs.aws-documentation-mcp-server",
	} {
		if !looksLikePackageSpec(valid) {
			t.Errorf("looksLikePackageSpec(%q) = false, want true", valid)
		}
	}
}

// null and {} decode without error into a zero entry, and the envelope path had no shape check
// where the flat path did. They became rows with a server name, transport unknown, and no
// warning: servers that were never configured.
//
// Distinct from an envelope that is itself null or empty, which TestEnvelopeStates covers.
// This is a null *entry inside* a healthy envelope.
func TestZeroValuedEntriesAreNotEmittedAsServers(t *testing.T) {
	rows, err := extractEnvelopeSimple([]byte(
		`{"mcpServers":{"nullish":null,"empty":{},"real":{"command":"npx"}}}`))
	if err != nil {
		t.Fatalf("two unusable entries must not fail the file: %v", err)
	}
	var names []string
	diagnostics := 0
	for _, row := range rows {
		if row.Warning.empty() == false {
			diagnostics++
			continue
		}
		names = append(names, row.ServerName)
	}
	if len(names) != 1 || names[0] != "real" {
		t.Errorf("servers = %v, want only \"real\"", names)
	}
	if diagnostics != 1 {
		t.Errorf("the two skipped entries should be reported, got %d diagnostics", diagnostics)
	}
}

// One project whose value is the wrong shape must not take the file with it. The projects map
// was decoded into a typed struct, so a single bad project failed the whole Unmarshal --
// including the global mcpServers -- on the file that holds the most servers on a real machine.
func TestOneMalformedClaudeProjectKeepsTheRest(t *testing.T) {
	rows, err := extractClaudeCode([]byte(`{
		"mcpServers": {"global": {"command": "npx"}},
		"projects": {
			"/a": {"mcpServers": {"healthy": {"command": "node"}}},
			"/b": {"mcpServers": "not-an-object"}
		}
	}`))
	if err != nil {
		t.Fatalf("one malformed project must not fail the file: %v", err)
	}
	found := map[string]bool{}
	diagnostics := 0
	for _, row := range rows {
		if row.Warning.empty() == false {
			diagnostics++
			continue
		}
		found[row.ServerName] = true
	}
	for _, want := range []string{"global", "healthy"} {
		if !found[want] {
			t.Errorf("%q was lost with the malformed project; found %v", want, found)
		}
	}
	if diagnostics != 1 {
		t.Errorf("the malformed project should be reported, got %d diagnostics", diagnostics)
	}
}

// TestClaudeCodeSectionsFailIndependently pins that a malformed top-level container in
// ~/.claude.json costs only that container. The file is the one place where two independent
// sources of servers share a document -- the user-scope `mcpServers` and the per-project
// `projects` map -- and binding either to a typed map made its shape a precondition of
// decoding the other: a global `"mcpServers": "broken"` failed the outer Unmarshal and the
// early return dropped every healthy project server on the machine.
func TestClaudeCodeSectionsFailIndependently(t *testing.T) {
	// Fragments are the inside of the object; the test body adds the outer braces. Balancing
	// them by hand here made three cases unparseable rather than merely malformed, which the
	// test then reported as an implementation failure.
	const healthyProject = `"projects": {"/Users/alice/repo": {"mcpServers": ` +
		`{"proj-server": {"command": "npx", "args": ["-y", "pkg"]}}}}`
	const healthyGlobal = `"mcpServers": {"global-server": {"command": "node"}}`

	for _, tc := range []struct {
		name         string
		doc          string
		wantServers  []string
		wantWarnings int
	}{
		{
			name:         "malformed global keeps project servers",
			doc:          `"mcpServers": "broken", ` + healthyProject,
			wantServers:  []string{"proj-server"},
			wantWarnings: 1,
		},
		{
			name:         "malformed projects keeps global servers",
			doc:          healthyGlobal + `, "projects": "broken"`,
			wantServers:  []string{"global-server"},
			wantWarnings: 1,
		},
		{
			// An array is a different type error than a string, and the array form is what a
			// config-writing tool is most likely to emit by mistake.
			name:         "array in place of the global object keeps project servers",
			doc:          `"mcpServers": [], ` + healthyProject,
			wantServers:  []string{"proj-server"},
			wantWarnings: 1,
		},
		{
			name:         "both sections healthy warns about neither",
			doc:          healthyGlobal + `, ` + healthyProject,
			wantServers:  []string{"global-server", "proj-server"},
			wantWarnings: 0,
		},
		{
			name:         "both sections malformed reports loss without erroring",
			doc:          `"mcpServers": 7, "projects": false`,
			wantServers:  nil,
			wantWarnings: 1, // one row, reporting two skipped items
		},
		{
			name:         "absent sections are not a failure",
			doc:          `"numStartups": 42, "theme": "dark"`,
			wantServers:  nil,
			wantWarnings: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			document := "{" + tc.doc + "}"
			if !json.Valid([]byte(document)) {
				t.Fatalf("test fixture is not valid JSON, so it would not exercise "+
					"container recovery: %s", document)
			}
			rows, err := extractClaudeCode([]byte(document))
			if err != nil {
				t.Fatalf("extractClaudeCode returned an error for recoverable input: %v", err)
			}
			var gotServers []string
			gotWarnings := 0
			for _, row := range rows {
				if row.Warning.empty() == false {
					gotWarnings++
					continue
				}
				gotServers = append(gotServers, row.ServerName)
			}
			sort.Strings(gotServers)
			want := append([]string(nil), tc.wantServers...)
			sort.Strings(want)
			if !reflect.DeepEqual(gotServers, want) {
				t.Errorf("servers = %v, want %v", gotServers, want)
			}
			if gotWarnings != tc.wantWarnings {
				t.Errorf("warning rows = %d, want %d (rows: %+v)", gotWarnings, tc.wantWarnings, rows)
			}
		})
	}
}

// TestClaudeCodeInvalidJSONStillErrors guards the other side of the change above: making the
// containers independently recoverable must not make an unparseable document look healthy.
func TestClaudeCodeInvalidJSONStillErrors(t *testing.T) {
	if _, err := extractClaudeCode([]byte(`{"mcpServers": {`)); err == nil {
		t.Fatal("truncated JSON should return an error so the caller emits a parse warning")
	}
}

// TestEnvelopeCollisionUsesDeclaredNamesNotDecodedOnes pins the precedence contract against
// the state where it used to invert: `mcpServers` wins on collision, but the suppression list
// was built from the entries that *decoded*, so a malformed higher-priority entry dropped out
// of the list and the lower-priority `servers` row survived under it. The file then reported
// the shadowed configuration as though it were the effective one.
func TestEnvelopeCollisionUsesDeclaredNamesNotDecodedOnes(t *testing.T) {
	for _, tc := range []struct {
		name        string
		doc         string
		wantServers []string
		wantErr     bool
	}{
		{
			// The shadowed `servers.dup` must not stand in for the broken authoritative
			// entry. Nothing is recoverable, so this is the no-decodable-entries case.
			name:    "malformed mcpServers entry does not promote its servers twin",
			doc:     `{"mcpServers":{"dup":{"command":123}},"servers":{"dup":{"command":"npx"}}}`,
			wantErr: true,
		},
		{
			// Same collision, but a healthy sibling in the same envelope means the file is
			// not a total loss: "ok" survives and "dup" stays suppressed.
			name: "healthy sibling survives while the collision stays suppressed",
			doc: `{"mcpServers":{"dup":{"command":123},"ok":{"command":"node"}},` +
				`"servers":{"dup":{"command":"npx"}}}`,
			wantServers: []string{"ok"},
		},
		{
			// A shape-invalid entry (null decodes without error but is not a server) takes
			// the same path as a decode failure and must suppress identically.
			name:    "shape-invalid mcpServers entry also suppresses",
			doc:     `{"mcpServers":{"dup":null},"servers":{"dup":{"command":"npx"}}}`,
			wantErr: true,
		},
		{
			// Control: with no higher-priority declaration at all, the servers entry is the
			// effective configuration and must be reported.
			name:        "servers entry with no mcpServers twin is reported",
			doc:         `{"mcpServers":{"other":{"command":"node"}},"servers":{"solo":{"command":"npx"}}}`,
			wantServers: []string{"other", "solo"},
		},
		{
			// Control: a healthy collision resolves to the mcpServers side, as before.
			name:        "healthy collision resolves to mcpServers",
			doc:         `{"mcpServers":{"dup":{"command":"node"}},"servers":{"dup":{"command":"npx"}}}`,
			wantServers: []string{"dup"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := extractEnvelopeSimple([]byte(tc.doc))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want an error, got rows %+v", rows)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			var got []string
			for _, row := range rows {
				if row.Warning.empty() == false {
					continue
				}
				got = append(got, row.ServerName)
			}
			sort.Strings(got)
			want := append([]string(nil), tc.wantServers...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("servers = %v, want %v", got, want)
			}
		})
	}
}

// TestByteOrderMarkedConfigsParse pins the BOM strip.
//
// Go's encoding/json rejects a UTF-8 BOM outright, so a JSON or JSONC config carrying one
// was reported as malformed rather than read -- the file is valid and only the marker is in
// the way. BurntSushi/toml already tolerates it, so the Codex case below passes with or
// without the strip; it is here to keep the shared preprocessing consistent and to catch
// the decoder becoming stricter or a refactor routing TOML around it.
//
// This is a Windows shape above all: Notepad has historically written UTF-8 with a BOM, and
// Windows PowerShell 5.1's `Set-Content -Encoding utf8` still does, so the most likely way
// for a hand-written config to reach this table on Windows is with one attached.
func TestByteOrderMarkedConfigsParse(t *testing.T) {
	bom := []byte{0xEF, 0xBB, 0xBF}

	for _, tc := range []struct {
		name    string
		body    string
		jsonc   bool
		extract func([]byte) ([]Server, error)
		want    string
	}{
		{
			name: "json envelope", jsonc: false, extract: extractEnvelopeSimple,
			body: `{"mcpServers":{"bommed":{"command":"npx"}}}`, want: "bommed",
		},
		{
			name: "jsonc with a comment", jsonc: true, extract: extractEnvelopeSimple,
			body: "// a comment\n{\"servers\":{\"bommed\":{\"command\":\"npx\"}}}", want: "bommed",
		},
		{
			// This case passes with or without the strip: BurntSushi/toml tolerates a
			// leading BOM where encoding/json does not. Worth keeping anyway -- it pins
			// that a Codex config is unaffected either way, and it would catch the
			// dependency becoming stricter or a refactor routing TOML around the shared
			// preprocessing. Adding it also corrected the claim above: the original
			// comment asserted the TOML decoder rejected a BOM, and writing the test is
			// what showed otherwise.
			name: "codex toml", jsonc: false, extract: extractCodexTOML,
			body: "[mcp_servers.bommed]\ncommand = \"npx\"\n", want: "bommed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := finishProcessing("", append(bom, []byte(tc.body)...), nil,
				"/p/mcp.json", "alice", "cursor", tc.jsonc, MaxFileSize, tc.extract)
			var found bool
			for _, row := range rows {
				if row.Warning.empty() == false {
					t.Errorf("a byte-order mark produced a diagnostic: %s", row.Warning.render())
				}
				if row.ServerName == tc.want {
					found = true
				}
			}
			if !found {
				t.Errorf("server %q not found; rows=%+v", tc.want, rows)
			}
		})
	}
}

// TestJSONCAcceptsTrailingCommas pins the three Copilot findings that were about a valid
// config being rejected rather than about a crash.
//
// The VS Code family documents mcp.json as JSON-with-comments and accepts trailing commas,
// so a file the editor itself wrote and considers valid reached encoding/json, which
// refuses them, and the whole file became one parse-warning row. Losing every server in a
// file because of a comma is exactly the silent-incompleteness this table exists to avoid.
func TestJSONCAcceptsTrailingCommas(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"object", `{"servers":{"a":{"command":"npx"},}}`},
		{"array", `{"servers":{"a":{"command":"npx","args":["x",]}}}`},
		{"nested and spaced", "{\"servers\":{\n \"a\":{\"command\":\"npx\"} ,\n}\n}"},
		{"with a comment too", "// note\n{\"servers\":{\"a\":{\"command\":\"npx\"},}}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := finishProcessing("", []byte(tc.body), nil, "/p/mcp.json", "alice", "vscode",
				true, MaxFileSize, extractEnvelopeSimple)
			for _, row := range rows {
				if row.Warning.empty() == false {
					t.Errorf("a trailing comma produced a diagnostic: %s", row.Warning.render())
				}
			}
			if len(rows) != 1 || rows[0].ServerName != "a" {
				t.Errorf("want one server named a, got %+v", rows)
			}
		})
	}
}

// TestTrailingCommaStripIsStringAware guards the other direction: a comma inside a string
// value is data, and removing it would corrupt the configuration this is meant to rescue.
func TestTrailingCommaStripIsStringAware(t *testing.T) {
	body := `{"servers":{"a":{"command":"npx","args":["a,}","b, ]"],}}}`
	rows := finishProcessing("", []byte(body), nil, "/p/mcp.json", "alice", "vscode",
		true, MaxFileSize, extractEnvelopeSimple)
	if len(rows) != 1 || rows[0].Warning.empty() == false {
		t.Fatalf("want one clean row, got %+v", rows)
	}
	// The exact values, not the count. An implementation that stripped commas inside
	// strings would yield "a}" and "b ]", the JSON would still parse, the count would
	// still be two, and a length check would pass while the data was corrupted.
	if !reflect.DeepEqual(rows[0].Args, []string{"a,}", "b, ]"}) {
		t.Errorf("args were corrupted: %q", rows[0].Args)
	}
}

// An option's value must not be reported as the package, and a boolean must not cost the
// package its row. Both directions are pinned because the fix for one is the bug for the
// other: listing a flag in runnerValueFlags skips the token after it, so listing a boolean
// swallows the real package and omitting a value option donates its value to package_name.
func TestRunnerValueFlagsSkipValuesWithoutSwallowingPackages(t *testing.T) {
	cases := []struct {
		name, want string
		args       []string
	}{
		// The reported case: --color takes a separate value and was not listed, so the
		// choice was reported as the package at medium confidence.
		{"a listed value option", "real-server", []string{"--color", "always", "real-server"}},
		{"another listed value option", "real-server", []string{"--python", "3.12", "real-server"}},
		// --from is the option whose value IS the package, so it must stay unlisted.
		{"--from names the package", "httpx", []string{"--from", "httpx", "httpx-cli"}},
		// Booleans: listing any of these would consume the package.
		{"a boolean long flag", "real-server", []string{"--quiet", "real-server"}},
		{"a boolean short flag", "real-server", []string{"-q", "real-server"}},
		{"another boolean", "real-server", []string{"--no-cache", "real-server"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got, _ := firstPositional(testCase.args); got != testCase.want {
				t.Errorf("firstPositional(%q) = %q, want %q", testCase.args, got, testCase.want)
			}
		})
	}
}

// A launcher's option scan stops at the first positional, because everything past it belongs
// to the program the launcher started.
//
// Every scanner read the whole argument list, so an MCP server that happens to accept
// --package, --from, --spec or -m had its argument reported as what was installed. The
// launched program's flags are outside this table's control, which is exactly why the scan
// cannot extend into them.
func TestLauncherOptionScansStopAtTheFirstPositional(t *testing.T) {
	t.Run("launched program options are not read", func(t *testing.T) {
		if spec, _, _ := npxIdentity([]string{"real-package", "--package", "evilpkg"}); spec != "real-package" {
			t.Errorf("npx spaced form = %q, want real-package", spec)
		}
		if spec, _, _ := npxIdentity([]string{"real-package", "--package=evilpkg"}); spec != "real-package" {
			t.Errorf("npx inline form = %q, want real-package", spec)
		}
		if got := pythonModule([]string{"-u", "script.py", "-m", "evilmod"}); got != "" {
			t.Errorf("python = %q, want empty: -m after the script is the script's argument", got)
		}
		if got, _ := uvRunIdentity([]string{"run", "server", "--from", "evilpkg"}); got != "" {
			t.Errorf("uv = %q, want empty", got)
		}
		if got, _ := pipxIdentity([]string{"run", "server", "--spec", "evilpkg"}); got != "server" {
			t.Errorf("pipx = %q, want server", got)
		}
	})
	// The other direction, which the bound must not break: an option before the first
	// positional is the launcher's own and still decides identity.
	t.Run("launcher options are still honoured", func(t *testing.T) {
		if spec, _, _ := npxIdentity([]string{"--package", "realpkg", "cmd"}); spec != "realpkg" {
			t.Errorf("npx spaced = %q, want realpkg", spec)
		}
		if spec, _, _ := npxIdentity([]string{"--package=realpkg@1.2.3"}); spec != "realpkg@1.2.3" {
			t.Errorf("npx inline = %q, want realpkg@1.2.3", spec)
		}
		if spec, _, _ := npxIdentity([]string{"real-package"}); spec != "real-package" {
			t.Errorf("npx bare positional = %q, want real-package", spec)
		}
		if got := pythonModule([]string{"-m", "realmod"}); got != "realmod" {
			t.Errorf("python = %q, want realmod", got)
		}
		for _, args := range [][]string{
			{"run", "--from", "realpkg", "cmd"},
			{"tool", "run", "realpkg"},
			{"tool", "run", "--python", "3.12", "realpkg"},
		} {
			if got, _ := uvRunIdentity(args); got != "realpkg" {
				t.Errorf("uv %q = %q, want realpkg", args, got)
			}
		}
		for _, args := range [][]string{{"run", "--spec", "realpkg", "cmd"}, {"run", "realpkg"}} {
			if got, _ := pipxIdentity(args); got != "realpkg" {
				t.Errorf("pipx %q = %q, want realpkg", args, got)
			}
		}
	})
}

// Four more ways a launcher's option list ends, each of which the first attempt at this
// boundary walked straight through.
//
// A returned index was not enough: the caller rescanned the prefix without knowing which
// tokens had already been consumed as values, so `python -c -m evilmod` read -c's argument a
// second time as python's own -m. The walk answers the question itself now.
func TestLauncherOptionWalkRespectsTerminatorsAndValues(t *testing.T) {
	t.Run("a subcommand word is only a subcommand in its own position", func(t *testing.T) {
		// After `run`, `tool` is the command uv was asked to launch.
		if got, _ := uvRunIdentity([]string{"run", "tool", "--from", "evilpkg"}); got != "" {
			t.Errorf("uv = %q, want empty", got)
		}
	})
	t.Run("a double dash ends the options", func(t *testing.T) {
		if got := pythonModule([]string{"--", "-m", "evilmod"}); got != "" {
			t.Errorf("python = %q, want empty: past -- it is a filename", got)
		}
	})
	t.Run("a lone dash is an operand", func(t *testing.T) {
		if got := pythonModule([]string{"-", "-m", "evilmod"}); got != "" {
			t.Errorf("python = %q, want empty: - selects stdin", got)
		}
	})
	t.Run("an option value is consumed even when it looks like an option", func(t *testing.T) {
		if got := pythonModule([]string{"-c", "-m", "evilmod"}); got != "" {
			t.Errorf("python = %q, want empty: -m there is the argument of -c", got)
		}
	})
	// None of the above may cost a legitimate reading.
	t.Run("the launcher's own options still resolve", func(t *testing.T) {
		if got := pythonModule([]string{"-u", "-m", "realmod"}); got != "realmod" {
			t.Errorf("python = %q, want realmod", got)
		}
		if got, _ := uvRunIdentity([]string{"tool", "run", "realpkg"}); got != "realpkg" {
			t.Errorf("uv tool run = %q, want realpkg", got)
		}
		if got, _ := uvRunIdentity([]string{"run", "--from=realpkg", "cmd"}); got != "realpkg" {
			t.Errorf("uv inline --from = %q, want realpkg", got)
		}
		if spec, _, _ := npxIdentity([]string{"-y", "--package", "realpkg", "cmd"}); spec != "realpkg" {
			t.Errorf("npx after a boolean = %q, want realpkg", spec)
		}
	})
}

// uvx's --from names the package; the token after it names the command inside it.
//
// firstPositional was right only while the package happened to be package-shaped. Give
// --from a value the grammar rejects -- the Git-backed form Astral documents -- and the scan
// walked past it and reported the exported command as the package. When --from is present it
// is the identity, and an identity that cannot be represented is empty rather than the next
// thing along.
func TestUvxFromNamesThePackageNotTheCommand(t *testing.T) {
	identity := func(args []string) (string, string) {
		server := Server{}
		launcherIdentity["uvx"](&server, args)
		return server.PackageName, server.RequestedSpec
	}
	const gitSpec = "git+https://github.com/acme/mcp-suite.git"
	for _, args := range [][]string{
		{"--from", gitSpec, "actual-server"},
		{"--from=" + gitSpec, "actual-server"},
	} {
		name, spec := identity(args)
		if name != "" || spec != "" {
			t.Errorf("uvx %q reported name=%q spec=%q; the command is not the package and "+
				"a Git spec is not representable, so both must be empty", args, name, spec)
		}
	}
	// A representable --from is still the identity, inline form included.
	for _, testCase := range []struct {
		args               []string
		wantName, wantSpec string
	}{
		{[]string{"--from", "httpx", "httpx-cli"}, "httpx", "httpx"},
		{[]string{"--from=httpx==1.2", "httpx-cli"}, "httpx", "httpx==1.2"},
		{[]string{"real-server"}, "real-server", "real-server"},
		{[]string{"--python", "3.12", "real-server"}, "real-server", "real-server"},
	} {
		name, spec := identity(testCase.args)
		if name != testCase.wantName || spec != testCase.wantSpec {
			t.Errorf("uvx %q = (%q, %q), want (%q, %q)", testCase.args, name, spec,
				testCase.wantName, testCase.wantSpec)
		}
	}
}

// uv's subcommand is recognised in its own position and nowhere else, and global options may
// precede it.
//
// The tool-run fallback rescanned the whole vector for an adjacent `tool run`, so
// `uv run actual-command tool run fake-package` found the pair inside the launched command's
// arguments. The opposite direction failed too: subcommands were matched only at argument
// zero, so a leading global option lost the identity entirely.
func TestUvSubcommandIsPositional(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"a later tool run belongs to the launched command",
			[]string{"run", "actual-command", "tool", "run", "fake-package"}, ""},
		{"global options may precede the subcommand",
			[]string{"--color", "always", "run", "--from", "real-package", "command"}, "real-package"},
		{"and before tool run as well",
			[]string{"--color", "always", "tool", "run", "realpkg"}, "realpkg"},
		{"plain run without --from names no package",
			[]string{"run", "actual-command"}, ""},
		{"tool is not a subcommand after run",
			[]string{"run", "tool", "--from", "evilpkg"}, ""},
		{"the launched server's own --from is not uv's",
			[]string{"run", "server", "--from", "evil"}, ""},
		{"ordinary forms still resolve",
			[]string{"run", "--from", "realpkg", "cmd"}, "realpkg"},
		{"inline from", []string{"run", "--from=realpkg", "cmd"}, "realpkg"},
		{"tool run", []string{"tool", "run", "realpkg"}, "realpkg"},
		{"tool run with a value option", []string{"tool", "run", "--python", "3.12", "realpkg"}, "realpkg"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got, _ := uvRunIdentity(testCase.args); got != testCase.want {
				t.Errorf("uvRunIdentity(%q) = %q, want %q", testCase.args, got, testCase.want)
			}
		})
	}
}

// Python attaches a short option's argument to the option itself, which the generic option
// walk cannot express.
//
// `-mhttp.server` is one token and read as a boolean, so the module went unreported.
// `-cprint(123) -m evilmod` is an interpreter command followed by that command's own argv,
// and the trailing -m was read as python's.
func TestPythonCompactOptionForms(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"attached module", []string{"-mhttp.server"}, "http.server"},
		{"attached command ends interpreter options", []string{"-cprint(123)", "-m", "evilmod"}, ""},
		{"separate command ends them too", []string{"-c", "-m", "evilmod"}, ""},
		{"double dash", []string{"--", "-m", "evilmod"}, ""},
		{"lone dash", []string{"-", "-m", "evilmod"}, ""},
		{"a script's own arguments", []string{"-u", "script.py", "-m", "evilmod"}, ""},
		{"separate module", []string{"-m", "realmod"}, "realmod"},
		{"after a boolean", []string{"-u", "-m", "realmod"}, "realmod"},
		{"after a value option", []string{"-W", "ignore", "-m", "realmod"}, "realmod"},
		// Clusters, all verified against python3 3.9.6 rather than read off the grammar.
		// Each of these runs the module.
		{"cluster ending in m", []string{"-um", "http.server"}, "http.server"},
		{"cluster with the module attached", []string{"-umhttp.server"}, "http.server"},
		{"repeated boolean in the cluster", []string{"-OOm", "http.server"}, "http.server"},
		{"several booleans", []string{"-qIm", "http.server"}, "http.server"},
		{"a value option ending a cluster", []string{"-uW", "ignore", "-m", "realmod"}, "realmod"},
		{"and the other one", []string{"-uX", "dev", "-m", "realmod"}, "realmod"},
		// The false positive this parser exists to prevent. python runs the -c command and
		// `-m evilmod` is that command's argv -- confirmed: the interpreter prints 9.
		{"a c hidden in a cluster ends inference", []string{"-ucprint(9)", "-m", "evilmod"}, ""},
		// Nothing is run, so nothing is installed.
		{"a terminating option", []string{"-V", "-m", "evilmod"}, ""},
		// Fail closed rather than let a later -m manufacture an identity.
		{"an unmodelled letter", []string{"-Z", "-m", "evilmod"}, ""},
		{"a trailing -m names nothing", []string{"-m"}, ""},
		// Long options. Only --check-hash-based-pycs leaves the run going; the rest print
		// and exit, and an unrecognised one is an error. Verified against python3 3.9.6:
		// `--version -m this` prints the version and never runs the module.
		{"a long terminating option", []string{"--version", "-m", "evilmod"}, ""},
		{"long help", []string{"--help", "-m", "evilmod"}, ""},
		{"a long help variant", []string{"--help-env", "-m", "evilmod"}, ""},
		{"an unrecognised long option", []string{"--definitely-unknown", "-m", "evilmod"}, ""},
		{"the one long option that continues",
			[]string{"--check-hash-based-pycs", "always", "-m", "ok"}, "ok"},
		{"and its inline form", []string{"--check-hash-based-pycs=always", "-m", "ok"}, "ok"},
		// -P arrived in CPython 3.11 and this table resolves no interpreter version, so
		// the letter is not accepted: on 3.9.6 the invocation exits with "Unknown option".
		// -R has been valid throughout and stays.
		{"a version-gated letter is not assumed", []string{"-Pm", "this"}, ""},
		{"a long-standing letter still clusters", []string{"-Rm", "this"}, "this"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := pythonModule(testCase.args); got != testCase.want {
				t.Errorf("pythonModule(%q) = %q, want %q", testCase.args, got, testCase.want)
			}
		})
	}
}

// A launcher's first operand is the package, or there is no package.
//
// The scan used to walk past an operand that failed the package grammar and report a later
// one instead. That crossed the launcher boundary in the same way reading the launched
// program's --package or --from did: `npx ./server.js real-package` reported real-package,
// which is an argument to the script npx ran. The justification on record -- that a
// credential URL before the package should not mask inference -- was already handled by
// arity, since --registry consumes its own value.
func TestFirstOperandDecidesIdentity(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"a script path is not a package and ends the scan",
			[]string{"./server.js", "real-package"}, ""},
		{"an absolute script path likewise",
			[]string{"/abs/path/server.js", "somepkg"}, ""},
		{"a tarball URL is the operand and is not representable",
			[]string{"https://example.com/tarball.tgz", "pkg"}, ""},
		// Arity, not walking past, is what protects these.
		{"a known value option's value is consumed",
			[]string{"--registry", "https://u:p@h", "pkg"}, "pkg"},
		{"a credential-named option's value is skipped",
			[]string{"--auth-token", "opaquevalue", "real-server"}, "real-server"},
		{"an ordinary value option", []string{"--python", "3.12", "real-server"}, "real-server"},
		{"a boolean flag", []string{"-y", "pkg"}, "pkg"},
		{"the plain case", []string{"pkg"}, "pkg"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got, _ := firstPositional(testCase.args); got != testCase.want {
				t.Errorf("firstPositional(%q) = %q, want %q", testCase.args, got, testCase.want)
			}
		})
	}
}

// --pip-args takes a value, and listing it among the value-less options is how that value
// reached the identity columns. pipx documents it as the arguments to hand on to pip, which is
// where an authenticated index URL or a token is passed, so the operand scan read the
// credential as the first package-shaped token and copied it into package_name and
// requested_spec -- the one value the final redactor, which recognises known token shapes,
// cannot catch on the way out.
func TestPipxPipArgsConsumesItsValue(t *testing.T) {
	const opaqueSecret = "s3cr3tIndexT0ken"
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"a separated value is consumed, not reported",
			[]string{"run", "--pip-args", "verbose", "real-package"}, "real-package"},
		{"an opaque value never becomes the package",
			[]string{"run", "--pip-args", opaqueSecret, "real-package"}, "real-package"},
		{"the inline form carries its own value",
			[]string{"run", "--pip-args=--no-deps", "real-package"}, "real-package"},
		// A separated value that begins with a dash is indistinguishable from an option to
		// the operand scan, which keeps no state for "the previous token was consumed as a
		// value", so the scan fails closed: an empty identity and warnUnknownLauncherOption
		// rather than a guess. That is the same answer it gave before this fix, and the half
		// that matters is that the pip argument is not what lands in the column.
		{"a value beginning with a dash empties the identity instead",
			[]string{"run", "--pip-args", "--no-deps", "real-package"}, ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, _ := pipxIdentity(testCase.args)
			if got != testCase.want {
				t.Errorf("pipxIdentity(%q) = %q, want %q", testCase.args, got, testCase.want)
			}
		})
	}
	// End to end as well, because the defect was in the published columns rather than in the
	// scan: redactArgs leaves this value alone, --pip-args not being a credential-named
	// option, so nothing downstream would have recognised it.
	t.Run("the published columns never carry the value", func(t *testing.T) {
		server := Server{
			Command: "pipx",
			Args:    []string{"run", "--pip-args", opaqueSecret, "real-package"},
		}
		inferIdentity(&server)
		if server.PackageName != "real-package" || server.RequestedSpec != "real-package" {
			t.Errorf("package_name=%q requested_spec=%q, want real-package for both",
				server.PackageName, server.RequestedSpec)
		}
		if strings.Contains(server.PackageName+server.RequestedSpec, opaqueSecret) {
			t.Error("the pip arguments reached the identity columns")
		}
	})
}

// An option is either value-less or value-taking, and the two tables disagreeing about one is
// not something the compiler can object to. --pip-args was in launcherBooleanFlags while pipx
// documents a value, and every scanner shares both tables, so one wrong entry was wrong for
// all four launchers at once.
func TestBooleanAndValueFlagTablesAreDisjoint(t *testing.T) {
	for name := range launcherBooleanFlags {
		if _, alsoValue := runnerValueFlags[name]; alsoValue {
			t.Errorf("%q is listed as both value-less and value-taking", name)
		}
	}
	if _, boolean := launcherBooleanFlags["--pip-args"]; boolean {
		t.Error("--pip-args takes a value: pipx hands it to pip")
	}
	if _, value := runnerValueFlags["--pip-args"]; !value {
		t.Error("--pip-args must be known to take a value, or its value is read as the package")
	}
}

// Identity inference assigned its warning unconditionally, erasing whatever parsing or
// materialization had already found -- an environment variable name that is not an identifier,
// or a TOML header holding the credential itself. Those name something in the file to go and
// change; warnUnknownLauncherOption says only that a command line could not be read. A row
// carries one warning, so the more specific and earlier finding is the one that survives.
func TestIdentityInferenceKeepsAnEarlierWarning(t *testing.T) {
	// One unrecognised option, spelled into each launcher's own grammar so that every
	// scanner actually reaches the refusal: the npx closure assigns the warning itself and
	// the rest route through assignIfClean, and a launcher whose arguments never reached an
	// operand would pass this test without exercising anything. The paired control below is
	// what proves each case does.
	const unknown = "--option-this-table-does-not-know"
	launchers := []struct {
		command string
		args    []string
	}{
		{"npx", []string{unknown, "value", "pkg"}},
		{"uvx", []string{unknown, "value", "pkg"}},
		{"bunx", []string{unknown, "value", "pkg"}},
		{"pipx", []string{"run", unknown, "value", "pkg"}},
		{"uv", []string{"tool", "run", unknown, "value", "pkg"}},
	}
	earlier := warning{Code: warnEnvHeaderLiteral, Count: 2}
	for _, launcher := range launchers {
		t.Run(launcher.command+" keeps the earlier finding", func(t *testing.T) {
			server := Server{
				Command: launcher.command,
				Args:    launcher.args,
				Warning: earlier,
			}
			inferIdentity(&server)
			if server.Warning != earlier {
				t.Errorf("warning = %+v, want the earlier finding %+v",
					server.Warning, earlier)
			}
			// The identity stays empty: keeping the earlier warning is about what the row
			// reports, not about trusting an argument list this table cannot read.
			if server.PackageName != "" || server.RequestedSpec != "" {
				t.Errorf("package_name=%q requested_spec=%q, want both empty",
					server.PackageName, server.RequestedSpec)
			}
		})
		// The control, and the proof that the case above refused for the reason claimed:
		// with nothing to displace, the finding is still reported. A fix that simply
		// stopped recording it would pass the half above and silence the fail-closed path
		// this warning exists to explain.
		t.Run(launcher.command+" still reports the unknown option", func(t *testing.T) {
			server := Server{Command: launcher.command, Args: launcher.args}
			inferIdentity(&server)
			if server.Warning.Code != warnUnknownLauncherOption {
				t.Errorf("warning = %+v, want %s", server.Warning,
					warnUnknownLauncherOption)
			}
		})
	}
}

// Only `==` pins a version; every other PEP 440 operator bounds a set.
//
// The column is `pinned_version` -- what the configuration pins -- and returning the number
// beside a range operator asserted a version the config never chose, at high confidence,
// since confidence is derived from having both a name and a version. `pkg!=1.5` was the
// clearest case: an exclusion reported as the pin, so a vulnerability-feed correlation would
// read the one version ruled out as the one in use.
func TestSplitPyPISpecOnlyPinsExactVersions(t *testing.T) {
	for _, tc := range []struct {
		spec, name, ver string
	}{
		// Exact equality pins.
		{"pkg==1.2.3", "pkg", "1.2.3"},
		{"pkg==1.0", "pkg", "1.0"},
		// Ranges and exclusions name the package and pin nothing.
		{"pkg>=1.0", "pkg", ""},
		{"pkg<=2.0", "pkg", ""},
		{"pkg~=1.4", "pkg", ""},
		{"pkg!=1.5", "pkg", ""},
		{"pkg>1.0", "pkg", ""},
		{"pkg<2.0", "pkg", ""},
		// `@` pins when its operand is one version.
		{"pkg@1.2.3", "pkg", "1.2.3"},
		// And does not when the operand selects a set. This assertion previously expected
		// "latest", because the finding that introduced this test scoped itself to the
		// comparison operators and said to leave `@` alone; a later finding reversed that,
		// on the same reasoning the comparison operators were changed for -- a dist-tag
		// names whatever was published most recently, so it is not a pin.
		{"pkg@latest", "pkg", ""},
		{"pkg@next", "pkg", ""},
		// Wildcard equality is PEP 440-legal and selects a range.
		{"pkg==1.*", "pkg", ""},
		// No operator at all.
		{"pkg", "pkg", ""},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			name, ver := splitPyPISpec(tc.spec)
			if name != tc.name || ver != tc.ver {
				t.Errorf("splitPyPISpec(%q) = (%q, %q), want (%q, %q)",
					tc.spec, name, ver, tc.name, tc.ver)
			}
		})
	}
}

// And the consequence the change exists for: a range leaves confidence at medium rather than
// claiming high on a version the configuration did not choose.
func TestRangeSpecsReportMediumConfidence(t *testing.T) {
	for _, tc := range []struct {
		spec, wantVersion, wantConfidence string
	}{
		{"pkg==1.2.3", "1.2.3", "high"},
		{"pkg>=1.0", "", "medium"},
		{"pkg!=1.5", "", "medium"},
		{"pkg~=1.4", "", "medium"},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			server := Server{Command: "uvx", Args: []string{tc.spec}, Transport: "stdio"}
			inferIdentity(&server)
			if server.PackageName != "pkg" {
				t.Fatalf("package_name = %q, want pkg", server.PackageName)
			}
			if server.PinnedVersion != tc.wantVersion {
				t.Errorf("pinned_version = %q, want %q",
					server.PinnedVersion, tc.wantVersion)
			}
			if server.Confidence != tc.wantConfidence {
				t.Errorf("confidence = %q, want %q", server.Confidence, tc.wantConfidence)
			}
			// The spec itself is still reported verbatim, so the range is not lost -- it
			// moves from a column that claims a pin to one that describes the request.
			if server.RequestedSpec != tc.spec {
				t.Errorf("requested_spec = %q, want %q", server.RequestedSpec, tc.spec)
			}
		})
	}
}

// A credential-named option consumes its value in launcherOptionValue too, so one appearing
// before `--package` no longer hides it.
//
// The option was treated as value-less, so its value landed on the scan's default branch as a
// bare positional -- which ends the walk, because a positional is where the launched program
// begins. Any credential-named option before the wanted one therefore hid it completely, and
// the operand fallback skipped the real package as a consumed value, so the row came back with
// no identity at all. knownLauncherOption already documented the arity as known from the name;
// this scanner was the one not honouring it.
//
// Not a leak in either direction: a value is not an option name, so it could never have been
// returned as one. The cost was a missing identity.
func TestSecretNamedOptionsConsumeTheirValueInOptionScan(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		wantSpec string
		wantVer  string
	}{
		{"credential option before --package",
			[]string{"--auth-token", "s3cret", "--package", "real-pkg"}, "real-pkg", ""},
		{"and with a pinned version",
			[]string{"--token", "s3cret", "--package", "real-pkg@1.2.3"},
			"real-pkg@1.2.3", "1.2.3"},
		{"after a boolean, and with the short package flag",
			[]string{"-y", "--api-key", "s3cret", "-p", "real-pkg"}, "real-pkg", ""},
		// Two of them, so the walk has to keep consuming rather than recover by luck.
		{"two credential options",
			[]string{"--token", "a", "--client-secret", "b", "--package", "real-pkg"},
			"real-pkg", ""},
		// The inline form carries its own value and consumes nothing, which must not
		// regress into consuming the following token.
		{"inline credential option",
			[]string{"--token=s3cret", "--package", "real-pkg"}, "real-pkg", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, found := launcherOptionValue(tc.args, npxGrammar, npxPackageFlags)
			if !found {
				t.Fatalf("launcherOptionValue found nothing; --package was hidden")
			}
			if value != tc.wantSpec {
				t.Errorf("value = %q, want %q", value, tc.wantSpec)
			}
			// And the whole way through to the row.
			server := Server{Command: "npx", Args: tc.args, Transport: "stdio"}
			inferIdentity(&server)
			if server.RequestedSpec != tc.wantSpec {
				t.Errorf("requested_spec = %q, want %q", server.RequestedSpec, tc.wantSpec)
			}
			if server.PinnedVersion != tc.wantVer {
				t.Errorf("pinned_version = %q, want %q", server.PinnedVersion, tc.wantVer)
			}
			// The credential never reaches a column, which was true before and must stay so.
			row := serverToRow(server)
			for column, emitted := range row {
				for _, secret := range []string{"s3cret"} {
					if emitted != "" && emitted == secret {
						t.Errorf("%s carries the credential: %q", column, emitted)
					}
				}
			}
		})
	}
}

// npm partial versions are ranges, and Python's `==1.0` is not.
//
// pinsOneVersion was shared by both ecosystems, and npm's X-ranges make a missing component a
// wildcard -- so `@1` and `@1.2` were reported as exact pins at high confidence, since neither
// contains a wildcard character to notice. PEP 440 `==1.0` is exact against the release it
// names, so holding Python to npm's three-component rule would discard a real pin. The two
// recognisers are separate for that reason.
func TestNPMPartialVersionsAreNotPinsButPythonExactIs(t *testing.T) {
	for _, tc := range []struct {
		name, command, spec, wantVer, wantConfidence string
	}{
		{"npx major only", "npx", "real-package@1", "", "medium"},
		{"npx major.minor", "npx", "real-package@1.2", "", "medium"},
		{"npx complete version", "npx", "real-package@1.2.3", "1.2.3", "high"},
		{"npx prerelease", "npx", "real-package@1.2.3-rc.1", "1.2.3-rc.1", "high"},
		{"npx dist-tag", "npx", "real-package@latest", "", "medium"},
		// Python keeps its own semantics: `==1.0` names one release.
		{"pypi exact two-component", "uvx", "real-package==1.0", "1.0", "high"},
		{"pypi exact three-component", "uvx", "real-package==1.0.0", "1.0.0", "high"},
		{"pypi wildcard equality", "uvx", "real-package==1.*", "", "medium"},
		{"pypi range", "uvx", "real-package>=1.0", "", "medium"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := Server{Command: tc.command, Args: []string{tc.spec}, Transport: "stdio"}
			inferIdentity(&server)
			if server.PackageName != "real-package" {
				t.Fatalf("package_name = %q, want real-package", server.PackageName)
			}
			if server.PinnedVersion != tc.wantVer {
				t.Errorf("pinned_version = %q, want %q", server.PinnedVersion, tc.wantVer)
			}
			if server.Confidence != tc.wantConfidence {
				t.Errorf("confidence = %q, want %q", server.Confidence, tc.wantConfidence)
			}
			// The selector always survives in requested_spec, so nothing is lost.
			if server.RequestedSpec != tc.spec {
				t.Errorf("requested_spec = %q, want %q", server.RequestedSpec, tc.spec)
			}
		})
	}
}
