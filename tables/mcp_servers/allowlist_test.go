package mcp_servers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/macadmins/osquery-extension/pkg/devclients"
	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/macadmins/osquery-extension/pkg/redact"
	"github.com/macadmins/osquery-extension/pkg/testutil"
)

// Four configurations a user can write that would put a credential in a column, asserted end
// to end through the row builder.
//
// Redaction catches known token formats, and these values have none, so each column applies
// an allowlist instead. They are asserted together because one mechanism covers all four.
func TestTheFourNamedLeakCases(t *testing.T) {
	// Shapeless on purpose. A recognisable issuer prefix would be redacted on the way out
	// and every case below would pass without its allowlist doing anything.
	const secret = "Zq7xPlmNvBc2WdEr9TyUiOp0AsDfGhJk"

	t.Run("env = { TOKEN = <bare> } in TOML", func(t *testing.T) {
		// Invalid TOML -- a bare value -- so the parser fails, and its message quotes the
		// token. The warning catalogue reports a position instead.
		doc := "[mcp_servers.x]\ncommand = \"npx\"\nenv = { TOKEN = " + secret + " }\n"
		rows := finishProcessing("/home/alice", []byte(doc), nil, "/home/alice/.codex/config.toml",
			"alice", "codex", false, MaxFileSize, extractCodexTOML)
		if len(rows) == 0 {
			t.Fatal("a malformed config must still produce a row saying so")
		}
		assertNoSecret(t, rows, secret)

		// And the valid spelling, where the key is the secret rather than the value. Values
		// are never read; the key is, so it needs the identifier grammar.
		valid := "[mcp_servers.x]\ncommand = \"npx\"\nenv = { \"" + secret + " \" = \"v\" }\n"
		rows = finishProcessing("/home/alice", []byte(valid), nil,
			"/home/alice/.codex/config.toml", "alice", "codex", false, MaxFileSize, extractCodexTOML)
		assertNoSecret(t, rows, secret)
	})

	t.Run(`"command": "API_KEY=xyz npx -y pkg"`, func(t *testing.T) {
		// The command field carries an environment assignment rather than a program. The
		// basename of the first field is `API_KEY=xyz`, which cannot be a filename.
		doc := `{"mcpServers":{"x":{"command":"API_KEY=` + secret + ` npx -y pkg"}}}`
		rows := finishProcessing("/home/alice", []byte(doc), nil, "/home/alice/.mcp.json",
			"alice", "claude_code", true, MaxFileSize, extractEnvelopeSimple)
		if len(rows) != 1 {
			t.Fatalf("rows = %+v", rows)
		}
		row := serverToRow(rows[0])
		if strings.Contains(strings.Join(values(row), "\x00"), secret) {
			t.Errorf("a command-field assignment leaked: %v", row)
		}
		// Dropped rather than published, and the row says why.
		if row["command_basename"] != "" {
			t.Errorf("command_basename = %q, want empty: an assignment is not a filename",
				row["command_basename"])
		}
		if row["warning"] == "" {
			t.Error("a dropped column must say so; an empty column is otherwise " +
				"indistinguishable from a config that declared nothing")
		}
		// The identity triple is suppressed with the basename, because a command this
		// table could not publish is one it could not parse with confidence either.
		for _, column := range []string{"package_name", "requested_spec", "pinned_version"} {
			if row[column] != "" {
				t.Errorf("%s = %q, want empty alongside a dropped basename", column, row[column])
			}
		}
		if row["confidence"] != "low" {
			t.Errorf("confidence = %q, want low", row["confidence"])
		}
	})

	t.Run("npx -y --pat <secret> pkg", func(t *testing.T) {
		// npx does not list --pat, and it is not credential-named by the redactor's
		// patterns either. Treated as taking no value, it would leave the secret as the
		// first operand, copied into package_name and requested_spec.
		doc := `{"mcpServers":{"x":{"command":"npx","args":["-y","--pat","` + secret + `","pkg"]}}}`
		rows := finishProcessing("/home/alice", []byte(doc), nil, "/home/alice/.mcp.json",
			"alice", "claude_code", true, MaxFileSize, extractEnvelopeSimple)
		if len(rows) != 1 {
			t.Fatalf("rows = %+v", rows)
		}
		row := serverToRow(rows[0])
		if strings.Contains(strings.Join(values(row), "\x00"), secret) {
			t.Errorf("an unrecognised option's value leaked: %v", row)
		}
		// Fails closed: no identity rather than a wrong one. The cost is recorded in
		// identity.go -- a legitimate unlisted boolean empties the identity too.
		if row["package_name"] != "" {
			t.Errorf("package_name = %q, want empty: the operand after an unrecognised "+
				"option cannot be identified", row["package_name"])
		}
		if row["confidence"] != "low" {
			t.Errorf("confidence = %q, want low", row["confidence"])
		}
		// The launcher itself is still reported, which is the part that was unambiguous.
		if row["command_basename"] != "npx" {
			t.Errorf("command_basename = %q, want npx", row["command_basename"])
		}
	})

	t.Run(`env_http_headers = { Authorization = "Bearer abc" }`, func(t *testing.T) {
		// env_http_headers maps a header name to the NAME of the variable holding its
		// value, so the variable names are the map's values. A literal credential there is
		// a user mistake and real signal: the config file itself holds the secret.
		doc := "[mcp_servers.x]\nurl = \"https://example.test/mcp\"\n" +
			"env_http_headers = { Authorization = \"Bearer " + secret + "\" }\n"
		rows := finishProcessing("/home/alice", []byte(doc), nil,
			"/home/alice/.codex/config.toml", "alice", "codex", false, MaxFileSize, extractCodexTOML)
		if len(rows) == 0 {
			t.Fatal("no rows")
		}
		assertNoSecret(t, rows, secret)
		var sawLiteral bool
		for _, server := range rows {
			row := serverToRow(server)
			// `Bearer <secret>` is not a C identifier, so it cannot be published as an
			// env key.
			if strings.Contains(row["env_keys"], "Bearer") {
				t.Errorf("a literal header value was published as an env key: %q",
					row["env_keys"])
			}
			if server.Warning.Code == warnEnvHeaderLiteral {
				sawLiteral = true
			}
		}
		if !sawLiteral {
			t.Error("a literal header value must raise its own code, not a generic drop " +
				"count: it means the config file holds a credential, which is a finding " +
				"rather than a formatting problem")
		}
	})
}

// assertNoSecret checks the rendered row of every server.
func assertNoSecret(t *testing.T, servers []Server, secret string) {
	t.Helper()
	for _, server := range servers {
		row := serverToRow(server)
		for column, value := range row {
			if strings.Contains(value, secret) {
				t.Errorf("%s leaked the secret: %q", column, value)
			}
		}
	}
}

func values(row map[string]string) []string {
	out := make([]string, 0, len(row))
	for _, value := range row {
		out = append(out, value)
	}
	return out
}

// One table per column, over the shapes that must pass and the shapes that must not.
func TestColumnAllowlists(t *testing.T) {
	t.Run("command_basename", func(t *testing.T) {
		for candidate, want := range map[string]string{
			// Real basenames from the machine this was developed on, including the two the
			// old schema comment cited as the reason an allowlist was rejected.
			"npx": "npx", "uvx": "uvx", "node": "node", "python3": "python3",
			"terraform-mcp-server":         "terraform-mcp-server",
			"computer-use-client-launcher": "computer-use-client-launcher",
			"atlassian.sh":                 "atlassian.sh",
			"npx.cmd":                      "npx.cmd",
			"llvm-gcc++":                   "llvm-gcc++",
			// An environment assignment is not a filename.
			"API_KEY=xyz": "",
			// Leading dash is an option, not a program. Stricter than the review's
			// suggested pattern, which would have admitted this.
			"-foo": "",
			// A path is not a basename; this column is the basename only.
			"/usr/bin/npx": "",
			// Non-ASCII is dropped, and the loss is deliberate: admitting Unicode letters
			// reopens homoglyph confusion, and `nрx` with a Cyrillic er reads as `npx` in
			// any console.
			"nрx": "",
			"":    "",
			strings.Repeat("a", maxCommandBasename+1): "",
		} {
			got, _ := allowedCommandBasename(candidate)
			if got != want {
				t.Errorf("allowedCommandBasename(%q) = %q, want %q", candidate, got, want)
			}
		}
	})

	t.Run("env_keys", func(t *testing.T) {
		for candidate, want := range map[string]bool{
			"GITHUB_TOKEN": true, "PATH": true, "_X": true, "A1": true,
			// The four Codex sources all funnel here, and these are the shapes that arrive
			// when a user puts a value where a name belongs.
			"Bearer abc123":                  false,
			"TOKEN=abc123":                   false,
			"with-a-hyphen":                  false, // not a C identifier; no runtime would read it
			"1LEADING_DIGIT":                 false,
			"":                               false,
			strings.Repeat("A", maxEnvKey+1): false,
		} {
			if got := envKeyAllowed(candidate); got != want {
				t.Errorf("envKeyAllowed(%q) = %v, want %v", candidate, got, want)
			}
		}
	})

	t.Run("url_endpoint", func(t *testing.T) {
		for candidate, want := range map[string]string{
			"https://example.test":      "https://example.test",
			"http://localhost:3000":     "http://localhost:3000",
			"wss://mcp.example.test":    "wss://mcp.example.test",
			"ws://127.0.0.1:8080":       "ws://127.0.0.1:8080",
			"https://[2001:db8::1]:443": "https://[2001:db8::1]:443",
			// A DNS-embedded token. DNS rules admit it as a hostname, and so does this
			// grammar, so validatedEndpoint returns it unchanged. In serverToRow,
			// redact.Secret runs first and removes the key, and the redacted host then
			// fails this grammar.
			"https://aws.AKIAIOSFODNN7EXAMPLE.example.test": "https://aws.AKIAIOSFODNN7EXAMPLE.example.test",
			// Schemes that are not MCP transports.
			"file:///etc/passwd":    "",
			"javascript:alert(1)":   "",
			"ftp://example.test":    "",
			"":                      "",
			"https://host with spc": "",
			// Userinfo, which sanitizeRemoteURL strips before this runs; asserted here so
			// the two gates are known to compose.
			"https://user:pass@example.test": "",
		} {
			if got := validatedEndpoint(candidate); got != want {
				t.Errorf("validatedEndpoint(%q) = %q, want %q", candidate, got, want)
			}
		}
	})

	t.Run("pinned_version", func(t *testing.T) {
		for candidate, want := range map[string]bool{
			"1.2.3": true, "latest": true, "1.0.0-beta.1": true, "2.0": true,
			"1.2.3+build5": true,
			// A bare `*` is not producible: packageSpecRe requires a version to start with
			// an alphanumeric, so `pkg@*` fails looksLikePackageSpec before it gets here.
			// A wildcard inside a version is producible and does pass.
			"*": false, "1.*": true,
			// A digest is the single reason a colon is admitted, and it is admitted as a
			// closed alternative rather than as a character in the general pattern.
			"sha256:" + strings.Repeat("a", 64): true,
			// Which is what keeps userinfo out. In the general pattern a colon would
			// readmit exactly the shape packageSpecRe became a grammar to reject.
			"user:password":                     false,
			"sha256:" + strings.Repeat("a", 63): false,
			"sha512:" + strings.Repeat("a", 64): false,
			"-leading-dash":                     false,
			"":                                  false,
		} {
			if got := pinnedVersionRe.MatchString(candidate); got != want {
				t.Errorf("pinnedVersionRe(%q) = %v, want %v", candidate, got, want)
			}
		}
	})

	t.Run("the identity triple is all-or-nothing", func(t *testing.T) {
		// A partial identity reads as a complete one: a name with no version is what an
		// unpinned package looks like, so publishing a name whose version failed states
		// something the config did not.
		name, spec, version, dropped := allowedIdentity("pkg", "pkg@user:password", "user:password")
		if !dropped || name != "" || spec != "" || version != "" {
			t.Errorf("a bad version kept part of the triple: %q %q %q (dropped=%v)",
				name, spec, version, dropped)
		}
		// And a clean triple survives intact.
		name, spec, version, dropped = allowedIdentity("pkg", "pkg@1.2.3", "1.2.3")
		if dropped || name != "pkg" || spec != "pkg@1.2.3" || version != "1.2.3" {
			t.Errorf("a clean triple was altered: %q %q %q (dropped=%v)",
				name, spec, version, dropped)
		}
		// A remote endpoint is its own requested_spec and is checked against the endpoint
		// grammar rather than a package one. Without that branch every mcp-remote row lost
		// its spec.
		_, spec, _, dropped = allowedIdentity("", "https://example.test", "")
		if dropped || spec != "https://example.test" {
			t.Errorf("a validated endpoint was refused as a spec: %q (dropped=%v)", spec, dropped)
		}
	})

	t.Run("uid", func(t *testing.T) {
		rows := stampUserID([]Server{{}, {UserID: "kept"}}, "S-1-5-21-1-2-3-1001", "1001")
		for _, row := range rows {
			if row.UserID != "S-1-5-21-1-2-3-1001" || row.UID != "1001" {
				t.Errorf("stampUserID left %+v, want the SID and the uid on every row", row)
			}
		}
	})

	t.Run("source_context", func(t *testing.T) {
		home := testutil.AbsPath("Users", "alice")
		repo := filepath.Join("code", "repo")
		for _, tc := range []struct{ context, want string }{
			// The fixed tokens pass unchanged.
			{"mcpServers", "mcpServers"},
			{"servers", "servers"},
			{"mcp_servers", "mcp_servers"},
			{"project.mcp_json", "project.mcp_json"},
			// A contained project keeps its path, which is the only record of which project
			// declared an inline server -- source_path names ~/.claude.json for all of them.
			{"projects[" + filepath.Join(home, repo) + "].mcpServers", "projects[" + repo + "].mcpServers"},
			{"project.cursor_mcp_json[" + repo + "]", "project.cursor_mcp_json[" + repo + "]"},
			// A path that fails containment loses the path and keeps the section.
			{"projects[" + testutil.AbsPath("Users", "other", "secret") + "].mcpServers", "projects"},
			{"projects[" + testutil.AbsPath("tmp", "--api-key=abc") + "].mcpServers", "projects"},
			// Neither a token nor a path-bearing form.
			{"something invented", ""},
		} {
			if got, _ := allowedSourceContext(tc.context, home); got != tc.want {
				t.Errorf("allowedSourceContext(%q) = %q, want %q", tc.context, got, tc.want)
			}
		}
	})
}

// Every value the package can produce for an enum column is in that column's allowed set.
//
// The check turns a documented claim into an enforced one, and this test is what stops the
// enforcement from becoming a bug: a set that is missing a real value silently rewrites valid
// rows to "unknown", which is worse than the unenforced claim was.
func TestEveryProducibleEnumValueIsAllowed(t *testing.T) {
	for _, src := range append(append([]probe{}, homeProbes...), projectProbes...) {
		if _, ok := allowedClients[src.client]; !ok {
			t.Errorf("probe client %q is not in allowedClients", src.client)
		}
	}
	for _, fork := range devclients.VSCodeFamily {
		if _, ok := allowedClients[fork.Client]; !ok {
			t.Errorf("devclients.VSCodeFamily client %q is not in allowedClients", fork.Client)
		}
	}
	// package_manager: every launcher the identity table dispatches, plus the remote
	// pseudo-manager inferIdentity sets.
	for launcher := range launcherIdentity {
		server := Server{Command: launcher, Transport: "stdio"}
		inferIdentity(&server)
		if server.PackageManager == "" {
			continue // python claims none unless its arguments say what is being run
		}
		if _, ok := allowedPackageManagers[server.PackageManager]; !ok {
			t.Errorf("launcher %q produces package_manager %q, which is not allowed",
				launcher, server.PackageManager)
		}
	}
	remote := Server{URL: "https://example.test", Transport: "http"}
	inferIdentity(&remote)
	if _, ok := allowedPackageManagers[remote.PackageManager]; !ok {
		t.Errorf("a remote server produces package_manager %q, which is not allowed",
			remote.PackageManager)
	}
	// approval_state: all four, since every one is reachable.
	for _, state := range []approvalState{
		approvalEnabled, approvalNotApproved, approvalDisabled, approvalNotApplicable,
	} {
		if _, ok := allowedApprovalStates[string(state)]; !ok {
			t.Errorf("approval state %q is not allowed", state)
		}
	}
	// transport and confidence, from the values the code writes.
	for _, transport := range []string{"stdio", "http", "sse", "unknown"} {
		if _, ok := allowedTransports[transport]; !ok {
			t.Errorf("transport %q is not allowed", transport)
		}
	}
	for _, confidence := range []string{"low", "medium", "high"} {
		if _, ok := allowedConfidences[confidence]; !ok {
			t.Errorf("confidence %q is not allowed", confidence)
		}
	}
}

// The server_name placeholder: stable, distinct, and not an oracle.
func TestServerNamePlaceholder(t *testing.T) {
	home := t.TempDir()
	// Two names that cannot be published: one that redacts to nothing but the marker, and
	// one carrying a control character.
	doc := `{"mcpServers":{` +
		`"sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH":{"command":"npx","args":["x"]},` +
		`"name\u0001with-control":{"command":"uvx","args":["y"]},` +
		`"ordinary":{"command":"node","args":["z"]}}}`
	path := filepath.Join(home, "code", "repo", ".mcp.json")

	render := func() map[string]string {
		rows := finishProcessing(home, []byte(doc), nil, path, "alice", "claude_code",
			true, MaxFileSize, extractEnvelopeSimple)
		out := map[string]string{}
		for _, server := range rows {
			row := serverToRow(server)
			out[row["server_name"]] = row["warning"]
		}
		return out
	}

	first := render()
	// Identical across two runs over one fixture. Map iteration is random, so an
	// unstable assignment would swap the two placeholders between runs -- which
	// differential logging reports as rows removed and re-added on an unchanged host.
	for attempt := 0; attempt < 5; attempt++ {
		if got := render(); len(got) != len(first) {
			t.Fatalf("placeholder set changed between runs: %v vs %v", first, got)
		} else {
			for name := range first {
				if _, ok := got[name]; !ok {
					t.Fatalf("placeholder %q did not recur: %v", name, got)
				}
			}
		}
	}

	rel := filepath.Join("code", "repo", ".mcp.json")
	base := "[redacted:" + filepath.ToSlash(rel) + "]"
	// One file, two unrepresentable names, so they are distinguished by index -- and the
	// first gets no suffix, because `#1` on a file with one such name is noise.
	if _, ok := first[base]; !ok {
		t.Errorf("no unsuffixed placeholder naming the source file: %v", first)
	}
	if _, ok := first[base+"#2"]; !ok {
		t.Errorf("a second unrepresentable name was not distinguished: %v", first)
	}
	// The ordinary name is untouched.
	if _, ok := first["ordinary"]; !ok {
		t.Errorf("a publishable name was replaced: %v", first)
	}
	// And no part of either original name survives. A truncated digest of a short server
	// name is brute-forceable offline, which is the oracle the placeholder must not be; a
	// positional name cannot be one at all.
	for name := range first {
		for _, fragment := range []string{"sk-ant", "AAAABBBB", "with-control"} {
			if strings.Contains(name, fragment) {
				t.Errorf("placeholder %q carries part of the original name", name)
			}
		}
	}
}

// scan_complete: a source-scope finding marks its own file, and a user-scope one is a row of
// its own that leaves the server rows alone.
func TestScanComplete(t *testing.T) {
	t.Run("an oversized project list is a row of its own", func(t *testing.T) {
		home := t.TempDir()
		// Past devclients.ClaudeListMaxSize. The project list is this file, so an oversized one
		// costs the account every project-local config and the whole approval state, which a
		// project_list_unreadable row for the user says.
		padding := strings.Repeat("x", devclients.ClaudeListMaxSize+1024)
		doc, err := json.Marshal(map[string]any{
			"mcpServers": map[string]any{},
			"padding":    padding,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".claude.json"), doc, 0o644); err != nil {
			t.Fatal(err)
		}
		// A healthy config elsewhere in the same home, which is still listed and complete: its
		// own file was read in full.
		if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".cursor", "mcp.json"),
			[]byte(`{"mcpServers":{"healthy":{"command":"npx","args":["x"]}}}`), 0o644); err != nil {
			t.Fatal(err)
		}

		rows := withoutStandingNotes(discoverForTest("alice", home))
		var sawOversize, sawListLost, sawHealthy bool
		for _, row := range rows {
			switch {
			case row.Warning.Code == warnSourceTooLarge:
				sawOversize = true
				if row.Warning.Limit != devclients.ClaudeListMaxSize {
					t.Errorf("the oversize report names limit %d, want %d",
						row.Warning.Limit, devclients.ClaudeListMaxSize)
				}
			case row.Warning.Code == warnProjectListUnreadable:
				sawListLost = true
			case row.ServerName == "healthy":
				sawHealthy = true
				if !row.ScanComplete {
					t.Error("a server from a file read in full is marked incomplete because " +
						"another file, the project list, could not be read")
				}
			}
		}
		if !sawOversize {
			t.Error("an oversized project list was not reported")
		}
		if !sawListLost {
			t.Error("no project_list_unreadable row says the account's projects were not found")
		}
		if !sawHealthy {
			t.Error("the healthy config was lost")
		}
	})

	t.Run("a malformed sibling degrades only its own source", func(t *testing.T) {
		home := t.TempDir()
		// One entry in this file cannot be decoded; its healthy sibling can.
		doc := `{"mcpServers":{"good":{"command":"npx","args":["x"]},"broken":{"command":123}}}`
		if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".cursor", "mcp.json"),
			[]byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		// A second, entirely healthy source in the same home, which must stay complete.
		if err := os.WriteFile(filepath.Join(home, ".claude.json"),
			[]byte(`{"mcpServers":{"elsewhere":{"command":"uvx","args":["y"]}}}`), 0o644); err != nil {
			t.Fatal(err)
		}

		rows := withoutStandingNotes(discoverForTest("alice", home))
		byName := map[string]Server{}
		for _, row := range rows {
			byName[row.ServerName] = row
		}
		if row, ok := byName["good"]; !ok {
			t.Error("the healthy sibling was lost")
		} else if row.ScanComplete {
			t.Error("a server from a file with an undecodable entry must not be marked " +
				"complete: its file's listing is short")
		}
		if row, ok := byName["elsewhere"]; !ok {
			t.Error("the unaffected source was lost")
		} else if !row.ScanComplete {
			t.Error("a source-scope loss must not degrade an unrelated file in the same " +
				"home; that makes the column almost always zero and therefore useless")
		}
	})

	t.Run("diagnostic rows are never complete", func(t *testing.T) {
		row := diagnosticRow("alice", "/home/alice", "", warning{Code: warnHomeUnreadable})
		if row.ScanComplete {
			t.Error("a diagnostic row claims to be a complete listing")
		}
		if serverToRow(row)["scan_complete"] != "0" {
			t.Error("scan_complete must emit 0 for a diagnostic row")
		}
	})
}

// An unrecognised launcher option empties the identity and says why.
//
// The cost of the fail-closed decision, asserted in both directions. A row carrying an
// ordinary unlisted boolean loses its package columns, which is the accepted direction of
// error recorded in identity.go, and a row carrying a known option keeps them, which stops
// the refusal from firing on the common case.
func TestUnrecognisedLauncherOptionEmptiesTheIdentity(t *testing.T) {
	for _, tc := range []struct {
		name        string
		args        []string
		wantPackage string
		wantCode    warnCode
	}{
		// The named case. npx does not list --pat, and the redactor's patterns do not name it
		// as a credential, so without the refusal its value would become the operand.
		{"an unrecognised option before the package", []string{"-y", "--pat", "s3cret", "pkg"},
			"", warnUnknownLauncherOption},
		// A credential-named option's name says it takes a value, so the scan knows the token
		// after it is a value and the real package is still found. Without this the
		// refusal would fire on the configurations it was added to protect.
		{"a credential-named option", []string{"--auth-token", "s3cret", "real-server"},
			"real-server", ""},
		// A listed value option and a listed boolean both keep working.
		{"a listed value option", []string{"--registry", "https://registry.example", "real-server"},
			"real-server", ""},
		{"a listed boolean", []string{"-y", "real-server"}, "real-server", ""},
		// An inline assignment consumes nothing, so an unrecognised one is harmless.
		{"an unrecognised inline option", []string{"--weird=1", "real-server"},
			"real-server", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := Server{Command: "npx", Args: tc.args, Transport: "stdio"}
			inferIdentity(&server)
			if server.PackageName != tc.wantPackage {
				t.Errorf("package_name = %q, want %q", server.PackageName, tc.wantPackage)
			}
			if server.Warning.Code != tc.wantCode {
				t.Errorf("warning code = %q, want %q", server.Warning.Code, tc.wantCode)
			}
			if tc.wantPackage == "" && server.Confidence != "low" {
				t.Errorf("confidence = %q, want low for an unidentified package",
					server.Confidence)
			}
		})
	}
}

// No env-key producer can bypass the grammar, because the column is built in one place.
func TestEnvKeysGateIsUnbypassable(t *testing.T) {
	// Built by hand, as a producer that forgot its own gate would.
	row := serverToRow(Server{
		ServerName: "x",
		EnvKeys:    []string{"GOOD_KEY", "Bearer abc123", "has-a-hyphen", "TOKEN=xyz"},
	})
	if row["env_keys"] != `["GOOD_KEY"]` {
		t.Errorf("env_keys = %q, want only the identifier-shaped key", row["env_keys"])
	}
}

// A row that never named a server emits an empty server_name, not a placeholder.
//
// Every diagnostic row has no server name, and "" is one of the conditions
// serverNameUnrepresentable reports -- so the placeholder fired on all of them and the table
// emitted `server_name = "[redacted:]"`: a stand-in for a name that never existed, naming a
// file that was never read. Every unit test asserting on a placeholder supplied a real name,
// so none of them caught it; running the table did.
func TestDiagnosticRowsHaveNoServerName(t *testing.T) {
	for _, w := range []warning{
		{Code: warnHomeUnreadable},
		{Code: warnAccountsHomeUnusable, Count: 1},
		{Code: warnProjectOutsideHome, Count: 3},
		{Code: warnRosterUnreachable},
	} {
		row := serverToRow(diagnosticRow("alice", "/home/alice", "", w))
		if row["server_name"] != "" {
			t.Errorf("%s: server_name = %q, want empty", w.Code, row["server_name"])
		}
		if row["warning"] == "" {
			t.Errorf("%s: the row must still explain itself", w.Code)
		}
	}
}

// A recorded project this table does not read does not make the account's inventory
// incomplete.
//
// Opening a project outside your home is ordinary -- /tmp, /Volumes, a shared checkout -- and
// once you have, the client's project list records it permanently: on the development machine
// 4 of 30 recorded projects are outside the home. A project stored with a cloud provider or on
// a userspace filesystem is inventoried where it is stored. Each describes what the table
// reads.
//
// The descriptive codes and the losses are asserted together, because the distinction is the
// whole point and either one alone would pass with the scopes swapped.
func TestDescriptiveFindingsDoNotDegradeCompleteness(t *testing.T) {
	// Out of scope by definition: not a loss.
	for _, code := range []warnCode{
		warnProjectOutsideHome, warnProjectRemoteOrigin, warnProjectMalformed,
		warnProjectCloudPlaceholder, warnProjectUserspaceFS,
	} {
		if code.degradesCompleteness() {
			t.Errorf("%s degrades completeness; a recorded project this table declines to "+
				"read is the definition of what is searched, not a scan cut short", code)
		}
	}
	// In scope and not read: a real loss.
	for _, code := range []warnCode{
		warnProjectRefused, warnProjectListUnreadable, warnProjectListTruncated,
	} {
		if !code.degradesCompleteness() {
			t.Errorf("%s does not degrade completeness; a configuration inside the home "+
				"that was not read is a short inventory", code)
		}
	}
}

// End to end: a home whose only finding is an out-of-scope project still reports its servers
// as a complete listing.
func TestOutOfScopeProjectsLeaveRowsComplete(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".cursor", "mcp.json"),
		[]byte(`{"mcpServers":{"healthy":{"command":"npx","args":["pkg@1.0.0"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Three recorded projects outside the home and one remote, which is roughly the shape of
	// a real long-lived workstation.
	recorded, err := json.Marshal(map[string]any{"projects": map[string]any{
		testutil.AbsPath("tmp", "scratch"):            map[string]any{},
		testutil.AbsPath("Volumes", "share", "repo"):  map[string]any{},
		testutil.AbsPath("Users", "someoneelse", "p"): map[string]any{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), recorded, 0o644); err != nil {
		t.Fatal(err)
	}

	rows := withoutStandingNotes(discoverForTest("alice", home))
	var sawHealthy, sawOutside bool
	for _, row := range rows {
		if row.ServerName == "healthy" {
			sawHealthy = true
			if !row.ScanComplete {
				t.Error("a server row is marked incomplete because the account has " +
					"projects outside its home, which is ordinary and permanent")
			}
		}
		if row.Warning.Code == warnProjectOutsideHome {
			sawOutside = true
			// One row, with the total, rather than one per lister.
			if row.Warning.Count != 3 {
				t.Errorf("outside-home count = %d, want 3 aggregated across listers",
					row.Warning.Count)
			}
		}
	}
	if !sawHealthy {
		t.Error("the healthy server was not found")
	}
	if !sawOutside {
		t.Error("the out-of-scope projects were not reported at all; they are not a loss " +
			"but they are still worth saying")
	}
}

// A credential-shaped assignment in a project directory name must not reach any column.
//
// Containment and redaction are independent gates, and conflating them cost a credential: a
// project directory named `repo --token=opaqueSecret` is perfectly well contained -- inside
// the home, no traversal -- so it passed the containment check and was emitted verbatim in
// source_context and inside the placeholder server name, while the same bytes in source_path
// were redacted because that column runs redact.Secret. This is the known shape the redactor
// explicitly recognises, not the documented residual risk about opaque directory names.
func TestProjectDirectoryNamesAreRedactedInEveryColumn(t *testing.T) {
	const secret = "opaqueSecretValue123"
	home := t.TempDir()
	// The directory name carries the assignment, and the server name is unpublishable so
	// the placeholder -- built from that path -- is exercised too.
	project := filepath.Join(home, "code", "repo --token="+secret)
	testutil.WriteFile(t, filepath.Join(project, ".mcp.json"),
		`{"mcpServers":{"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA":{"command":"npx","args":["x"]}}}`)
	recorded, err := json.Marshal(map[string]any{
		"projects": map[string]any{project: map[string]any{}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), recorded, 0o644); err != nil {
		t.Fatal(err)
	}

	var checked bool
	for _, server := range discoverForTest("alice", home) {
		row := serverToRow(server)
		for column, value := range row {
			if strings.Contains(value, secret) {
				t.Errorf("%s leaked the directory name's assignment: %q", column, value)
			}
		}
		if server.rawName != "" {
			checked = true
			// The placeholder must still name the file well enough to find it, so the
			// marker has to be present rather than the whole value dropped.
			if !strings.Contains(row["server_name"], redact.RedactedMark) {
				t.Errorf("server_name = %q, expected the redaction marker",
					row["server_name"])
			}
			if row["source_context"] == "" {
				t.Error("source_context was dropped entirely; the section token is not " +
					"user-controlled and should survive")
			}
		}
	}
	if !checked {
		t.Fatal("the project's server was not discovered")
	}
}

// Every source_context a producer can emit is in the allowed set.
//
// The plugin token was declared, assigned, and never registered, so every healthy plugin row
// reached publication and was emitted with an empty source_context plus a warning claiming
// its project path could not be published -- about a row that has no project path. A set that
// must agree with its producers needs a test that compares them.
func TestEveryProducibleSourceContextIsAllowed(t *testing.T) {
	// The fixed tokens every producer in the package can assign.
	producible := []string{
		"mcpServers", "servers", "mcp_servers", pluginSourceContext,
	}
	for _, token := range projectContextTokens {
		producible = append(producible, token)
	}
	for _, token := range producible {
		if _, ok := sourceContextTokens[token]; !ok {
			t.Errorf("source_context %q can be produced but is not allowed, so rows "+
				"carrying it lose the column and gain a spurious warning", token)
		}
	}
	// And the project-rooted forms, which carry a path, must survive their own pattern.
	for _, token := range projectContextTokens {
		context := token + "[" + filepath.Join("code", "repo") + "]"
		if got, dropped := allowedSourceContext(context, testutil.AbsPath("home", "alice")); dropped {
			t.Errorf("allowedSourceContext(%q) dropped the path, got %q", context, got)
		}
	}
}

// A credential-shaped server *key* must not reach the column.
//
// server_name was the last free-text column checked only negatively -- empty, marker-only,
// control characters, too long -- so anything else passed. A configuration whose key was
// `API_KEY=opaqueValue` or `Authorization: Bearer opaqueValue` published it verbatim, with no
// warning and scan_complete = 1, because every secret pattern redaction knows needs a leading
// `-` or a recognised prefix and a bare assignment has neither.
//
// Driven from the parser through row emission rather than against the predicate, because that
// is the path that was broken: the predicate was reached, it simply said yes.
func TestServerNameRefusesCredentialShapedKeys(t *testing.T) {
	for _, tc := range []struct {
		name      string
		key       string
		published bool
	}{
		{"assignment", "API_KEY=opaqueSecretValue123", false},
		{"authorization header", "Authorization: Bearer opaqueSecretValue123", false},
		{"bare space", "my server", false},
		{"shell metacharacter", "srv;rm -rf /", false},
		{"non-ascii homoglyph", "nрx-server", false},
		// Legitimate names, which the grammar must not cost. These are the shapes clients
		// and marketplaces actually produce.
		{"hyphenated", "crystal-mcp", true},
		{"underscored", "node_repl", true},
		{"dotted reverse-dns", "io.github.example", true},
		{"leading digit", "1password", true},
		{"plain", "terraform", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := fmt.Sprintf(`{"mcpServers":{%q:{"command":"npx","args":["x"]}}}`, tc.key)
			rows := finishProcessing("/home/alice", []byte(doc), nil,
				"/home/alice/.cursor/mcp.json", "alice", "cursor", false, MaxFileSize,
				extractEnvelopeSimple)
			if len(rows) != 1 {
				t.Fatalf("expected one row, got %d", len(rows))
			}
			published := serverToRow(rows[0])
			if tc.published {
				if published["server_name"] != tc.key {
					t.Errorf("a legitimate name was refused: server_name = %q, want %q",
						published["server_name"], tc.key)
				}
				return
			}
			if published["server_name"] == tc.key {
				t.Fatalf("the key reached the column verbatim: %q", published["server_name"])
			}
			// Refused names are replaced by the positional placeholder, never emptied, so
			// the server is still inventoried and still counted.
			if published["server_name"] == "" {
				t.Error("a refused name emptied the column instead of using a placeholder")
			}
			// And the refusal is reported, so the row is not mistaken for a clean one.
			if published["warning"] == "" {
				t.Error("a refused name produced no warning")
			}
			// Still complete, deliberately. scan_complete means every server declared in
			// this source was listed, and it was -- the name is positional rather than
			// missing. A refused column is scope-descriptive for exactly this reason, so
			// `WHERE scan_complete = 1` keeps selecting rows whose source was fully read.
			if published["scan_complete"] != "1" {
				t.Errorf("scan_complete = %q: a refused name does not make the listing "+
					"incomplete, the server is still inventoried",
					published["scan_complete"])
			}
			// The original is kept internally, because approval lookup and the placeholder
			// tie-break both key on the name the file spelled.
			if rows[0].rawName != tc.key {
				t.Errorf("rawName = %q, want the original %q", rows[0].rawName, tc.key)
			}
		})
	}
}

// A name redaction has already cleaned keeps its marker rather than losing the readable half.
func TestPartiallyRedactedServerNameKeepsItsMarker(t *testing.T) {
	key := "release-ghp_" + strings.Repeat("A", 36)
	doc := fmt.Sprintf(`{"mcpServers":{%q:{"command":"npx"}}}`, key)
	rows := finishProcessing("/home/alice", []byte(doc), nil,
		"/home/alice/.cursor/mcp.json", "alice", "cursor", false, MaxFileSize,
		extractEnvelopeSimple)
	if len(rows) != 1 {
		t.Fatalf("expected one row, got %d", len(rows))
	}
	published := serverToRow(rows[0])["server_name"]
	if !strings.Contains(published, redact.RedactedMark) {
		t.Errorf("server_name = %q, expected the readable half plus the marker", published)
	}
	if strings.Contains(published, "ghp_") {
		t.Errorf("the credential survived: %q", published)
	}
	if strings.HasPrefix(published, "[redacted:") {
		t.Errorf("a cleaned name was sent down the placeholder path: %q", published)
	}
}

// TestAnOverlongInlineProjectKeyIsDropped: an inline server under a ~/.claude.json project key
// longer than devclients.MaxProjectPathLen keeps its row, and its source_context keeps only the
// section name, with the drop reported, so a key of any length never reaches the column.
func TestAnOverlongInlineProjectKeyIsDropped(t *testing.T) {
	home := "/home/alice"
	key := home + "/" + strings.Repeat("a", devclients.MaxProjectPathLen)
	data := `{"projects":{"` + key + `":{"mcpServers":{"a":{"command":"npx"},"b":{"command":"uvx"}}}}}`
	servers, err := extractClaudeCode([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 2 {
		t.Fatalf("servers = %+v, want both inline servers", servers)
	}
	for _, s := range servers {
		s.Home = home
		row := serverToRow(s)
		if row["source_context"] != "projects" || !strings.HasPrefix(row["warning"], warnSentences[warnSourceContextPathDropped]) {
			t.Errorf("source_context = %q, warning = %q; want the section name and source_context_path_dropped",
				row["source_context"], row["warning"])
		}
	}
	if got, dropped := allowedSourceContext("projects["+key+"].mcpServers", home); got != "projects" || !dropped {
		t.Errorf("allowedSourceContext with an overlong key = %q, %v; want the section name, dropped", got, dropped)
	}
}

// TestAKeyThatCleansToTheCapKeepsItsPath: the collector bounds a key's contained form, not its
// raw form, so a key over the limit only because of doubled separators names a project the table
// reads, and its source_context keeps the path.
func TestAKeyThatCleansToTheCapKeepsItsPath(t *testing.T) {
	home := testutil.AbsPath("home", "alice")
	rel := strings.Repeat("a", devclients.MaxProjectPathLen-len(home)-1)
	key := home + strings.Repeat(string(filepath.Separator), 20) + rel
	if len(key) <= devclients.MaxProjectPathLen || len(filepath.Join(home, rel)) != devclients.MaxProjectPathLen {
		t.Fatalf("fixture: raw %d bytes, contained %d; want over and exactly at the cap",
			len(key), len(filepath.Join(home, rel)))
	}
	want := "projects[" + rel + "].mcpServers"
	if got, dropped := allowedSourceContext("projects["+key+"].mcpServers", home); got != want || dropped {
		t.Errorf("allowedSourceContext = %q, %v; want %q, kept", got, dropped, want)
	}
}

// TestSourcePathIsAbsoluteAndCleanWithoutAHome: a row with no home, which is a row about the
// roster, still publishes source_path only when it is absolute and clean. The check returned
// before either test when the home was empty, so a relative or `..` directory the roster declared
// for a skipped account was published as written.
func TestSourcePathIsAbsoluteAndCleanWithoutAHome(t *testing.T) {
	base, other := t.TempDir(), t.TempDir()
	separator := string(filepath.Separator)
	for _, testCase := range []struct {
		path, home string
		want       bool
	}{
		{"", "", true},
		{base, "", true},
		{"relative" + separator + "home", "", false},
		{base + separator + "a" + separator + ".." + separator + "b", "", false},
		{filepath.Join(base, "x"), base, true},
		{other, base, false},
	} {
		if got := structurallySoundPath(testCase.path, testCase.home); got != testCase.want {
			t.Errorf("structurallySoundPath(%q, %q) = %v, want %v", testCase.path, testCase.home, got,
				testCase.want)
		}
	}
	rows := DiscoverAll(context.Background(), rosterFrom(map[string]string{
		"uid": "501", "username": "bob", "directory": "relative" + separator + "bob", "shell": "/bin/zsh",
	}), map[string]struct{}{"bob": {}})
	if len(rows) != 1 || rows[0].Warning.Code != warnAccountHomeNotAbsolute {
		t.Fatalf("rows = %+v, want one account_home_not_absolute row", rows)
	}
	if published := serverToRow(rows[0])["source_path"]; published != "" {
		t.Errorf("source_path = %q, want empty for a relative directory", published)
	}
}

// TestEveryRowCarriesItsHome: every row a home produces carries that home, whichever pass made
// it, so publication holds its source_path to the home. Most diagnostic rows were built without
// one, which skipped the containment check for them.
func TestEveryRowCarriesItsHome(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	testutil.WriteFile(t, filepath.Join(home, ".cursor", "mcp.json"), `{not json`)
	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"), `null`)
	testutil.WriteFile(t, filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0",
		".claude-plugin", "plugin.json"), `{"mcpServers":"./missing.json"}`)
	rows := withoutStandingNotes(DiscoverAll(context.Background(), rosterOf(t, root), nil))
	direct := discoverForHome(context.Background(), fsscan.UserHome{Name: "alice", Path: home},
		time.Now().Add(time.Minute))
	if len(rows) < 3 || len(direct) < 3 {
		t.Fatalf("rows = %+v, direct = %+v, want the parse, settings and manifest diagnostics", rows, direct)
	}
	for _, row := range append(rows, direct...) {
		if row.Home != home {
			t.Errorf("%s row has home %q, want %q", row.Warning.Code, row.Home, home)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, row := range DiscoverAll(cancelled, rosterOf(t, root), nil) {
		if row.Warning.Code == warnCancelledPreHome && row.Home != home {
			t.Errorf("cancelled_before_home row has home %q, want %q", row.Home, home)
		}
	}
}

// TestPlaceholderIndexesStayDistinct: the index past the thousandth is published as written, so
// two unrepresentable names from one file never share a placeholder. Every index from 999 up
// published as #999.
func TestPlaceholderIndexesStayDistinct(t *testing.T) {
	for index, want := range map[int]string{
		999: "[redacted:a/b.json]#999", 1000: "[redacted:a/b.json]#1000", 1001: "[redacted:a/b.json]#1001",
	} {
		if got := serverNamePlaceholder(filepath.Join("a", "b.json"), index); got != want {
			t.Errorf("index %d: %q, want %q", index, got, want)
		}
	}
}

// TestSourceContextPathsKeepTheirSectionsForm: a ~/.claude.json key is published only when it is
// an absolute path contained in the home, and a probe's path only when it is a relative one, with
// a `..` refused rather than cleaned away. A relative key such as `opaquesecret123`, which the
// collector refuses as malformed and never reads, was published as projects[opaquesecret123],
// and `code/../x` was cleaned to `x` before the check that refuses `..` saw it.
func TestSourceContextPathsKeepTheirSectionsForm(t *testing.T) {
	home := t.TempDir()
	for _, testCase := range []struct {
		context, want string
		dropped       bool
	}{
		{"projects[opaquesecret123].mcpServers", "projects", true},
		{"projects[../alice/x].mcpServers", "projects", true},
		{"projects[" + filepath.Join(home, "code") + "].mcpServers", "projects[code].mcpServers", false},
		{"project.mcp_json[code]", "project.mcp_json[code]", false},
		{"project.mcp_json[code/../x]", "project.mcp_json", true},
		{"project.mcp_json[" + filepath.Join(home, "code") + "]", "project.mcp_json", true},
	} {
		got, dropped := allowedSourceContext(testCase.context, home)
		if got != testCase.want || dropped != testCase.dropped {
			t.Errorf("%s: %q, dropped %v; want %q, %v", testCase.context, got, dropped, testCase.want,
				testCase.dropped)
		}
	}
	body := `{"projects":{"opaquesecret123":{"mcpServers":{"s":{"command":"npx","args":["real-pkg"]}}}}}`
	rows := finishProcessing(home, []byte(body), nil, filepath.Join(home, ".claude.json"), "alice",
		"claude_code", false, MaxFileSize, extractClaudeCode)
	if len(rows) != 1 {
		t.Fatalf("%d rows", len(rows))
	}
	row := serverToRow(rows[0])
	if row["source_context"] != "projects" ||
		!strings.HasPrefix(row["warning"], warnSentences[warnSourceContextPathDropped]) {
		t.Errorf("source_context %q, warning %q; want projects and source_context_path_dropped",
			row["source_context"], row["warning"])
	}
}
