package mcp_servers

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// tomlCorpus is the shared input for the A/B comparison. Each case is a real shape a Codex
// config.toml can take, including the ones most likely to separate a hand-rolled reader from a
// real parser: quoted section names, escapes, comments in awkward places, and keys the table
// does not care about sitting alongside ones it does.
var tomlCorpus = []struct {
	name string
	doc  string
}{
	{"minimal", `
[mcp_servers.node_repl]
command = "node"
`},
	{"args and env subtable", `
[mcp_servers.node_repl]
command = "node"
args = ["--experimental-repl-await", "server.js"]

[mcp_servers.node_repl.env]
NODE_ENV = "production"
API_TOKEN = "unused-value"
`},
	{"multiple servers", `
[mcp_servers.first]
command = "npx"
args = ["-y", "first-mcp@1.0.0"]

[mcp_servers.second]
command = "uvx"
args = ["second-mcp"]
`},
	{"remote with type", `
[mcp_servers.remote]
type = "http"
url = "https://example.test/mcp"
`},
	{"remote sse by path", `
[mcp_servers.events]
url = "https://example.test/sse"
`},
	{"disabled flag", `
[mcp_servers.off]
command = "node"
disabled = true
`},
	{"quoted section name with dash", `
[mcp_servers."computer-use"]
command = "node"
`},
	{"comments everywhere", `
# leading comment
[mcp_servers.commented]   # trailing on header
command = "node"  # trailing on value
# full line
args = ["a", "b"]
`},
	{"unrelated sections present", `
model = "gpt-5"
[tui]
theme = "dark"

[mcp_servers.real]
command = "node"

[history]
persistence = "save-all"
`},
	{"timeouts alongside", `
[mcp_servers.slow]
command = "node"
startup_timeout_ms = 30000
tool_timeout_sec = 120
`},
	{"empty args array", `
[mcp_servers.noargs]
command = "node"
args = []
`},
	{"no mcp section at all", `
model = "gpt-5"
[tui]
theme = "dark"
`},
	{"hash inside a string value", `
[mcp_servers.hashy]
command = "node"
args = ["--flag=a#b"]
`},
}

// fingerprint renders a []Server as a stable string so two parsers' output can be compared
// without depending on map iteration order.
func fingerprint(servers []Server) string {
	lines := make([]string, 0, len(servers))
	for _, server := range servers {
		envKeys := append([]string(nil), server.EnvKeys...)
		sort.Strings(envKeys)
		lines = append(lines, fmt.Sprintf(
			"name=%q cmd=%q args=%v url=%q transport=%q disabled=%v env=%v",
			server.ServerName, server.Command, server.Args, server.URL,
			server.Transport, server.Disabled, envKeys))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// The A/B correctness comparison. Both parsers see the same corpus and must produce the same
// rows. A disagreement names the case, which is the evidence needed to decide whether the
// dependency is carrying its weight or the narrow reader is good enough to replace it.
func TestCodexTOMLParsersAgree(t *testing.T) {
	for _, testCase := range tomlCorpus {
		t.Run(testCase.name, func(t *testing.T) {
			library, libErr := extractCodexTOML([]byte(testCase.doc))
			narrow, narrowErr := extractCodexTOMLNarrow([]byte(testCase.doc))
			if (libErr == nil) != (narrowErr == nil) {
				t.Fatalf("error disagreement: library=%v narrow=%v", libErr, narrowErr)
			}
			if libErr != nil {
				return
			}
			if got, want := fingerprint(narrow), fingerprint(library); got != want {
				t.Errorf("parsers disagree\n library:\n%s\n narrow:\n%s", want, got)
			}
		})
	}
}

// Whichever parser ships, the rows have to come out sanitized the same way a JSON-sourced row
// does: env values dropped, endpoint reduced to scheme and host, transport inferred.
func TestCodexTOMLIsSanitizedLikeJSON(t *testing.T) {
	// Valid https, credential in the userinfo and a token in the query -- the shape this
	// reduction exists for, not malformed input. See the note in TestSanitizeRemoteURL:
	// quoted with the credential masked, this line reads as though it had no scheme.
	servers, err := extractCodexTOML([]byte(`
[mcp_servers.remote]
url = "https://user:pw@example.test/sse?token=abc"

[mcp_servers.remote.env]
API_TOKEN = "super-secret-value"
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("got %d servers: %+v", len(servers), servers)
	}
	server := servers[0]
	if server.URL != "https://example.test" {
		t.Errorf("endpoint not reduced to scheme+host: %q", server.URL)
	}
	if server.Transport != "sse" {
		t.Errorf("transport = %q, want sse inferred from the path", server.Transport)
	}
	if server.SourceContext != "mcp_servers" {
		t.Errorf("source_context = %q, want the TOML section name", server.SourceContext)
	}
	if len(server.EnvKeys) != 1 || server.EnvKeys[0] != "API_TOKEN" {
		t.Errorf("env keys = %v, want just the name", server.EnvKeys)
	}
	row := serverToRow(server)
	if strings.Contains(row["url_endpoint"], "token") || strings.Contains(row["url_endpoint"], "pw") {
		t.Errorf("url_endpoint leaked credentials: %q", row["url_endpoint"])
	}
	for name, value := range row {
		if strings.Contains(value, "super-secret-value") {
			t.Errorf("column %q leaked an env value: %q", name, value)
		}
	}
}

// extractCodexTOMLNarrow is the no-dependency comparison implementation for the A/B below.
//
// It lives in the test file on purpose. It is not used by discovery, so shipping it as
// production source would mean ~190 lines of parser that maintainers have to understand
// without any runtime relying on it. Here it earns its place: it keeps the option of dropping
// the TOML dependency open, and it is what the library parser is diffed against over a corpus
// rather than trusted blind. It models only the subset a [mcp_servers.*] section uses, so the
// corpus is bounded to that subset too -- inline tables and multi-line arrays are outside what
// it claims to handle, and any case needing them belongs in a library-only test.
func extractCodexTOMLNarrow(data []byte) ([]Server, error) {
	entries := map[string]*tomlServerEntry{}
	var current *tomlServerEntry
	var currentEnv bool

	for lineNumber, rawLine := range strings.Split(string(data), "\n") {
		line := stripTOMLComment(rawLine)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, fmt.Errorf("line %d: unterminated section header", lineNumber+1)
			}
			path, err := splitTOMLSectionPath(line[1 : len(line)-1])
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNumber+1, err)
			}
			current, currentEnv = nil, false
			// [mcp_servers.<name>] or [mcp_servers.<name>.env]; anything else is another
			// part of config.toml and is skipped along with its keys.
			if len(path) >= 2 && path[0] == "mcp_servers" {
				name := path[1]
				if entries[name] == nil {
					entries[name] = &tomlServerEntry{}
				}
				switch {
				case len(path) == 2:
					current = entries[name]
				case len(path) == 3 && path[2] == "env":
					current, currentEnv = entries[name], true
				}
			}
			continue
		}
		if current == nil {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		applyTOMLKey(current, currentEnv, unquoteTOML(strings.TrimSpace(key)), strings.TrimSpace(value))
	}

	if len(entries) == 0 {
		return nil, nil
	}
	flattened := make(map[string]tomlServerEntry, len(entries))
	for name, entry := range entries {
		flattened[name] = *entry
	}
	return materializeTOML(flattened), nil
}

func applyTOMLKey(entry *tomlServerEntry, inEnv bool, key, value string) {
	if inEnv {
		if entry.Env == nil {
			entry.Env = map[string]string{}
		}
		entry.Env[key] = "" // values are never retained, only key names
		return
	}
	switch key {
	case "command":
		entry.Command = unquoteTOML(value)
	case "url":
		entry.URL = unquoteTOML(value)
	case "type":
		entry.Type = unquoteTOML(value)
	case "transport":
		entry.Transport = unquoteTOML(value)
	case "args":
		entry.Args = parseTOMLStringArray(value)
	case "disabled":
		parsed := value == "true"
		entry.Disabled = &parsed
	}
}

// stripTOMLComment removes a trailing # comment that is not inside a string, and trims.
func stripTOMLComment(line string) string {
	inString := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			// A quote preceded by a backslash is escaped and does not toggle.
			if i == 0 || line[i-1] != '\\' {
				inString = !inString
			}
		case '#':
			if !inString {
				return strings.TrimSpace(line[:i])
			}
		}
	}
	return strings.TrimSpace(line)
}

// splitTOMLSectionPath splits a dotted header into components, honouring quoted segments so
// [mcp_servers."my.server"] is two components rather than three.
func splitTOMLSectionPath(header string) ([]string, error) {
	var parts []string
	var current strings.Builder
	inQuote := false
	for i := 0; i < len(header); i++ {
		switch character := header[i]; character {
		case '"':
			inQuote = !inQuote
		case '.':
			if inQuote {
				current.WriteByte(character)
				continue
			}
			parts = append(parts, strings.TrimSpace(current.String()))
			current.Reset()
		default:
			current.WriteByte(character)
		}
	}
	if inQuote {
		return nil, errors.New("unterminated quoted key in section header")
	}
	parts = append(parts, strings.TrimSpace(current.String()))
	for _, part := range parts {
		if part == "" {
			return nil, errors.New("empty component in section header")
		}
	}
	return parts, nil
}

func parseTOMLStringArray(value string) []string {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
		return nil
	}
	inner := strings.TrimSpace(value[1 : len(value)-1])
	if inner == "" {
		return nil
	}
	var out []string
	for _, element := range splitTOMLArrayElements(inner) {
		element = strings.TrimSpace(element)
		if element != "" {
			out = append(out, unquoteTOML(element))
		}
	}
	return out
}

// splitTOMLArrayElements splits on commas that are not inside a quoted string.
func splitTOMLArrayElements(inner string) []string {
	var parts []string
	var current strings.Builder
	inQuote := false
	for i := 0; i < len(inner); i++ {
		character := inner[i]
		switch {
		case character == '"' && (i == 0 || inner[i-1] != '\\'):
			inQuote = !inQuote
			current.WriteByte(character)
		case character == ',' && !inQuote:
			parts = append(parts, current.String())
			current.Reset()
		default:
			current.WriteByte(character)
		}
	}
	parts = append(parts, current.String())
	return parts
}

func unquoteTOML(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		unquoted := value[1 : len(value)-1]
		unquoted = strings.ReplaceAll(unquoted, `\"`, `"`)
		return strings.ReplaceAll(unquoted, `\\`, `\`)
	}
	if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
		return value[1 : len(value)-1] // literal string, no escapes
	}
	return value
}

// Codex spells it `enabled`, and the two keys mean opposite things. A real config.toml on the
// development machine carried 11 `enabled` keys and zero `disabled`, so reading only
// `disabled` reported every switched-off server as active.
func TestCodexEnabledAndDisabledKeys(t *testing.T) {
	for _, testCase := range []struct {
		name, doc string
		want      bool
	}{
		{"enabled false", "[mcp_servers.s]\ncommand=\"x\"\nenabled = false\n", true},
		{"enabled true", "[mcp_servers.s]\ncommand=\"x\"\nenabled = true\n", false},
		{"disabled true", "[mcp_servers.s]\ncommand=\"x\"\ndisabled = true\n", true},
		{"neither", "[mcp_servers.s]\ncommand=\"x\"\n", false},
		{"enabled wins", "[mcp_servers.s]\ncommand=\"x\"\nenabled = true\ndisabled = true\n", false},
	} {
		servers, err := extractCodexTOML([]byte(testCase.doc))
		if err != nil || len(servers) != 1 {
			t.Fatalf("%s: n=%d err=%v", testCase.name, len(servers), err)
		}
		if servers[0].Disabled != testCase.want {
			t.Errorf("%s: Disabled = %v, want %v", testCase.name, servers[0].Disabled, testCase.want)
		}
	}
}

// Codex's schema allows a float for tool_timeout_sec. Declaring it as an int made one valid
// fractional value fail the whole document and collapse every server in the file into a single
// parse-warning row. The fields are unused, so the fix was to stop declaring them at all.
func TestCodexTOMLUnknownAndFractionalFieldsDoNotFailTheDocument(t *testing.T) {
	servers, err := extractCodexTOML([]byte(`
[mcp_servers.alpha]
command = "server-a"

[mcp_servers.beta]
command = "server-b"
tool_timeout_sec = 0.5
startup_timeout_ms = 30000
some_future_key = { nested = "value" }
`))
	if err != nil {
		t.Fatalf("a valid config must not fail on fields the table does not use: %v", err)
	}
	if len(servers) != 2 {
		t.Errorf("got %d servers, want both: %+v", len(servers), servers)
	}
}

// Codex names environment variables in four places, and three of them were ignored. A remote
// server authenticated through bearer_token_env_var reported no credential dependency at all.
func TestCodexEnvKeysCoverEveryReference(t *testing.T) {
	servers, err := extractCodexTOML([]byte(`
[mcp_servers.remote]
url = "https://example.test/mcp"
env_vars = ["FROM_ENV_VARS"]
bearer_token_env_var = "FROM_BEARER"

[mcp_servers.remote.env]
FROM_ENV = "value-never-read"

[mcp_servers.remote.env_http_headers]
X-Api-Key = "FROM_HEADER_VAR"
`))
	if err != nil || len(servers) != 1 {
		t.Fatalf("n=%d err=%v", len(servers), err)
	}
	got := map[string]bool{}
	for _, key := range servers[0].EnvKeys {
		got[key] = true
	}
	for _, want := range []string{"FROM_ENV", "FROM_ENV_VARS", "FROM_BEARER", "FROM_HEADER_VAR"} {
		if !got[want] {
			t.Errorf("env_keys missing %q: %v", want, servers[0].EnvKeys)
		}
	}
	// The header *value* names a variable; the inline env value is never read.
	for _, key := range servers[0].EnvKeys {
		if key == "value-never-read" || key == "X-Api-Key" {
			t.Errorf("env_keys should hold variable names only, got %q", key)
		}
	}
}

// Codex's schema allows each env_vars item to be a bare string or an object of the form
// { name, source }. Decoding as []string made one valid object-form entry fail the whole
// document, hiding every other server in the file behind a single warning row -- the second
// time a too-narrow type here cost an entire file, after tool_timeout_sec.
func TestCodexEnvVarsAcceptsStringAndObjectForms(t *testing.T) {
	for _, testCase := range []struct {
		name, doc string
		want      []string
	}{
		{"string only", `
[mcp_servers.s]
command = "x"
env_vars = ["PLAIN_ONE", "PLAIN_TWO"]
`, []string{"PLAIN_ONE", "PLAIN_TWO"}},
		{"object only", `
[mcp_servers.s]
command = "x"
env_vars = [{ name = "OBJECT_ONE", source = "keychain" }]
`, []string{"OBJECT_ONE"}},
		{"mixed", `
[mcp_servers.s]
command = "x"
env_vars = ["PLAIN_ONE", { name = "OBJECT_ONE", source = "env" }]
`, []string{"PLAIN_ONE", "OBJECT_ONE"}},
	} {
		servers, err := extractCodexTOML([]byte(testCase.doc))
		if err != nil {
			t.Errorf("%s: %v", testCase.name, err)
			continue
		}
		if len(servers) != 1 {
			t.Errorf("%s: got %d servers", testCase.name, len(servers))
			continue
		}
		got := map[string]bool{}
		for _, key := range servers[0].EnvKeys {
			got[key] = true
		}
		for _, want := range testCase.want {
			if !got[want] {
				t.Errorf("%s: env_keys missing %q: %v", testCase.name, want, servers[0].EnvKeys)
			}
		}
	}
}

// The failure that mattered: an object-form entry on one server must not hide its siblings.
func TestCodexEnvVarsObjectFormDoesNotHideSiblingServers(t *testing.T) {
	servers, err := extractCodexTOML([]byte(`
[mcp_servers.alpha]
command = "server-a"

[mcp_servers.beta]
command = "server-b"
env_vars = [{ name = "TOKEN_VAR", source = "keychain" }]

[mcp_servers.gamma]
command = "server-c"
`))
	if err != nil {
		t.Fatalf("object-form env_vars must not fail the document: %v", err)
	}
	if len(servers) != 3 {
		t.Errorf("got %d servers, want all three: %+v", len(servers), servers)
	}
}

// An env_vars shape the schema does not describe is skipped rather than allowed to fail the
// file, for the same reason: losing one reference beats losing every server.
func TestCodexEnvVarsUnknownShapeIsSkippedNotFatal(t *testing.T) {
	servers, err := extractCodexTOML([]byte(`
[mcp_servers.s]
command = "x"
env_vars = [42, "REAL_ONE"]
`))
	if err != nil {
		t.Fatalf("an unrecognised env_vars element must not fail the document: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("got %d servers", len(servers))
	}
	var found bool
	for _, key := range servers[0].EnvKeys {
		if key == "REAL_ONE" {
			found = true
		}
	}
	if !found {
		t.Errorf("the usable reference should survive: %v", servers[0].EnvKeys)
	}
}

// An empty [mcp_servers.name] table decodes without error into a zero entry. Emitting it
// produced a clean row with a server name and nothing else -- a server that was never
// configured. The JSON extractors already rejected the equivalent {}.
func TestCodexTOMLRejectsEmptyServerTables(t *testing.T) {
	servers, err := extractCodexTOML([]byte(`
[mcp_servers.placeholder]

[mcp_servers.real]
command = "node"
`))
	if err != nil {
		t.Fatalf("one empty table must not fail the file: %v", err)
	}
	var healthy, diagnostics int
	for _, server := range servers {
		switch {
		case server.Warning.empty() == false:
			diagnostics++
		case server.ServerName == "real":
			healthy++
		default:
			t.Errorf("phantom server emitted: %+v", server)
		}
	}
	if healthy != 1 {
		t.Errorf("the real server should survive, got %d: %+v", healthy, servers)
	}
	if diagnostics != 1 {
		t.Errorf("the skipped placeholder should be reported, got %d", diagnostics)
	}
}

// A file whose every server table is empty is a file with nothing usable in it.
func TestCodexTOMLAllEmptyTablesErrors(t *testing.T) {
	if _, err := extractCodexTOML([]byte("[mcp_servers.a]\n\n[mcp_servers.b]\n")); err == nil {
		t.Error("a file with no usable entries should report a parse failure")
	}
}

// And one malformed entry beside a healthy one keeps the healthy one.
func TestCodexTOMLMalformedEntryKeepsSiblings(t *testing.T) {
	servers, err := extractCodexTOML([]byte(`
[mcp_servers.good]
command = "node"

[mcp_servers.broken]
command = 123
`))
	if err != nil {
		t.Fatalf("one malformed entry must not fail the file: %v", err)
	}
	var names []string
	for _, server := range servers {
		if server.Warning.empty() {
			names = append(names, server.ServerName)
		}
	}
	if len(names) != 1 || names[0] != "good" {
		t.Errorf("want only the healthy server, got %v", names)
	}
}

// An env_vars list whose entries decoded to nothing does not declare a server.
//
// UnmarshalTOML yields an empty name for a shape it does not recognise rather than failing
// the file -- deliberately, because one bad reference must not hide every other server. But
// the entry check counted the slice length, so `env_vars = [123]` made a table a server:
// a row with a name, no command, no endpoint and no env keys, and no warning to say it was
// nothing. The same phantom the zero-valued JSON entries produced.
func TestEnvVarsOnlyDeclaresAServerWhenItNamesOne(t *testing.T) {
	cases := []struct {
		name, doc string
		servers   int
		envKeys   []string
	}{
		{"an unrecognised env_vars shape declares nothing",
			"[mcp_servers.ghost]\nenv_vars = [123]\n", 0, nil},
		{"a bare string names a variable",
			"[mcp_servers.real]\nenv_vars = [\"API_TOKEN\"]\n", 1, []string{"API_TOKEN"}},
		{"the object form names one too",
			"[mcp_servers.obj]\nenv_vars = [{name = \"API_TOKEN\"}]\n", 1, []string{"API_TOKEN"}},
		// A real reference beside an unreadable one still declares a server, and the
		// unreadable one is simply absent from env_keys.
		{"a real reference beside an unreadable one",
			"[mcp_servers.mixed]\nenv_vars = [123, \"API_TOKEN\"]\n", 1, []string{"API_TOKEN"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			rows, err := extractCodexTOML([]byte(testCase.doc))
			if testCase.servers == 0 {
				if err == nil {
					t.Fatalf("expected no decodable entries, got %+v", rows)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			var servers int
			for _, row := range rows {
				if row.Warning.empty() == false {
					continue
				}
				servers++
				if !reflect.DeepEqual(row.EnvKeys, testCase.envKeys) {
					t.Errorf("env_keys = %v, want %v", row.EnvKeys, testCase.envKeys)
				}
			}
			if servers != testCase.servers {
				t.Errorf("got %d server rows, want %d: %+v", servers, testCase.servers, rows)
			}
		})
	}
}

// Every environment variable name an entry supplies is reported when this table refuses to
// publish it, and the count is the real one.
//
// tomlEnvKeys discarded a rejected name silently, so an invalid key in env, in env_vars or in
// bearer_token_env_var left no trace in the row at all, while materialize() reported the
// identical JSON configuration as a drop count. Visibility depended on which file format the
// user's client happened to write.
func TestCodexEnvKeyDropsAreCountedAcrossEverySource(t *testing.T) {
	servers, err := extractCodexTOML([]byte(`
[mcp_servers.messy]
command = "server"
env_vars = ["GOOD_ONE", "bad-name"]
bearer_token_env_var = "9NOT_AN_IDENTIFIER"

[mcp_servers.messy.env]
GOOD_TWO = "never read"
"not a name" = "never read"
`))
	if err != nil || len(servers) != 1 {
		t.Fatalf("n=%d err=%v", len(servers), err)
	}
	server := servers[0]
	if server.Warning.Code != warnEnvKeyDropped {
		t.Fatalf("warning = %+v, want %s", server.Warning, warnEnvKeyDropped)
	}
	// One from each source: the quoted env key, the dashed env_vars entry, and the bearer
	// token variable that starts with a digit.
	if server.Warning.Count != 3 {
		t.Errorf("Count = %d, want 3: one rejected name per source", server.Warning.Count)
	}
	sort.Strings(server.EnvKeys)
	if !reflect.DeepEqual(server.EnvKeys, []string{"GOOD_ONE", "GOOD_TWO"}) {
		t.Errorf("env_keys = %v, want the two publishable names", server.EnvKeys)
	}
}

// A literal header value means the configuration file itself holds the credential, so the
// count is how many credentials are sitting in the file. It was hardcoded to 1 however many
// there were, which understates exactly the finding an operator has to act on.
func TestCodexLiteralHeadersAreCountedIndividually(t *testing.T) {
	servers, err := extractCodexTOML([]byte(`
[mcp_servers.remote]
url = "https://example.test/mcp"

[mcp_servers.remote.env_http_headers]
Authorization = "Bearer literal-value-one"
X-Other-Auth = "literal value two"
`))
	if err != nil || len(servers) != 1 {
		t.Fatalf("n=%d err=%v", len(servers), err)
	}
	if code := servers[0].Warning.Code; code != warnEnvHeaderLiteral {
		t.Fatalf("warning = %+v, want %s", servers[0].Warning, warnEnvHeaderLiteral)
	}
	if count := servers[0].Warning.Count; count != 2 {
		t.Errorf("Count = %d, want 2: both headers hold a value rather than a name", count)
	}
	if len(servers[0].EnvKeys) != 0 {
		t.Errorf("env_keys = %v, want empty: neither value names a variable",
			servers[0].EnvKeys)
	}
}

// When an entry does both things the row reports the literal header, because a credential in
// the file outranks a name this column could not publish, and a row carries one warning.
func TestCodexLiteralHeaderOutranksADroppedKey(t *testing.T) {
	servers, err := extractCodexTOML([]byte(`
[mcp_servers.both]
url = "https://example.test/mcp"
env_vars = ["bad-name"]

[mcp_servers.both.env_http_headers]
Authorization = "Bearer literal-value"
`))
	if err != nil || len(servers) != 1 {
		t.Fatalf("n=%d err=%v", len(servers), err)
	}
	if servers[0].Warning.Code != warnEnvHeaderLiteral || servers[0].Warning.Count != 1 {
		t.Errorf("warning = %+v, want %s with Count 1",
			servers[0].Warning, warnEnvHeaderLiteral)
	}
}

// And an entry whose names are all publishable reports neither code, so the two warnings stay
// evidence of something rather than noise every Codex row carries.
func TestCodexCleanEnvReferencesRaiseNoWarning(t *testing.T) {
	servers, err := extractCodexTOML([]byte(`
[mcp_servers.clean]
command = "server"
env_vars = ["FROM_ENV_VARS"]
bearer_token_env_var = "FROM_BEARER"

[mcp_servers.clean.env]
FROM_ENV = "never read"

[mcp_servers.clean.env_http_headers]
X-Api-Key = "FROM_HEADER_VAR"
`))
	if err != nil || len(servers) != 1 {
		t.Fatalf("n=%d err=%v", len(servers), err)
	}
	if !servers[0].Warning.empty() {
		t.Errorf("warning = %+v, want none", servers[0].Warning)
	}
	if len(servers[0].EnvKeys) != 4 {
		t.Errorf("env_keys = %v, want all four references", servers[0].EnvKeys)
	}
}
