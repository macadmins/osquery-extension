package mcp_servers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/macadmins/osquery-extension/pkg/redact"
	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
)

// A token shape the redactor is expected to recognise, used wherever a test needs to prove a
// value passed through redaction rather than reaching the row verbatim.
const fakeToken = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// Every key serverToRow emits has to be a declared column and every declared column has to be
// emitted. osquery drops row keys that name no column and reports a declared column with no
// key as NULL, and both failures are silent. Asserting in both directions means a column added
// to the schema without a mapper entry, or a mapper entry left behind after a column is
// renamed, fails here rather than in a query nobody is watching.
func TestServerToRowCoversExactlyTheDeclaredColumns(t *testing.T) {
	declared := make(map[string]struct{})
	for _, column := range MCPServersColumns() {
		declared[column.Name] = struct{}{}
	}
	row := serverToRow(Server{})
	for name := range declared {
		if _, ok := row[name]; !ok {
			t.Errorf("column %q is declared but serverToRow never sets it", name)
		}
	}
	for name := range row {
		if _, ok := declared[name]; !ok {
			t.Errorf("serverToRow sets %q, which is not a declared column", name)
		}
	}
}

// The table's whole credential posture is that no user-writable value reaches a row intact.
// This checks the three shapes that carry the most risk: the command (reduced to a basename),
// a token planted in a field that is otherwise passed through, and the argument vector (never
// emitted, only counted).
func TestServerToRowStripsCredentialBearingValues(t *testing.T) {
	row := serverToRow(Server{
		Command:       "/opt/homebrew/bin/npx --api-key=" + fakeToken,
		Args:          []string{"--token", fakeToken, "server"},
		ServerName:    "svc-" + fakeToken,
		PinnedVersion: fakeToken,
	})
	if row["command_basename"] != "npx" {
		t.Errorf("command_basename = %q, want the bare executable name", row["command_basename"])
	}
	if row["args_count"] != "3" {
		t.Errorf("args_count = %q, want 3", row["args_count"])
	}
	for _, column := range []string{"server_name", "pinned_version"} {
		if strings.Contains(row[column], fakeToken) {
			t.Errorf("%s = %q, want the token redacted", column, row[column])
		}
	}
	// The arguments themselves must not appear under any column, whatever it is named.
	for name, value := range row {
		if strings.Contains(value, fakeToken) {
			t.Errorf("column %q leaked the token: %q", name, value)
		}
	}
}

// env_keys is JSON so a consumer can unpack it, sorted so a row is stable across runs (Go map
// iteration is not), and redacted per element so a variable *named* after a token shape does
// not smuggle one into the array.
func TestRedactedJSONStringArray(t *testing.T) {
	// Empty is "[]" rather than "": the column is documented as JSON, so every row should
	// unpack the same way instead of the empty case needing its own branch in every consumer.
	if got := redactedJSONStringArray(nil); got != "[]" {
		t.Errorf("empty input = %q, want an empty JSON array", got)
	}
	got := redactedJSONStringArray([]string{"ZED_TOKEN", "API_KEY", fakeToken})
	var keys []string
	if err := json.Unmarshal([]byte(got), &keys); err != nil {
		t.Fatalf("not valid JSON: %v (%q)", err, got)
	}
	if len(keys) != 3 {
		t.Fatalf("got %d keys, want 3: %v", len(keys), keys)
	}
	if keys[0] > keys[1] || keys[1] > keys[2] {
		t.Errorf("keys are not sorted: %v", keys)
	}
	for _, key := range keys {
		if strings.Contains(key, fakeToken) {
			t.Errorf("element %q was not redacted", key)
		}
	}
}

// The generator narrows its walk to the users named in the query, so it has to read equality
// constraints and ignore everything else. A LIKE or a > must leave the filter empty, because
// a filter built from a constraint the generator cannot honour would drop real rows.
func TestUserConstraintTakesOnlyEqualityMatches(t *testing.T) {
	constraints := func(list ...table.Constraint) table.QueryContext {
		return table.QueryContext{
			Constraints: map[string]table.ConstraintList{
				"user": {Constraints: list},
			},
		}
	}
	if got := userConstraint(table.QueryContext{}); got != nil {
		t.Errorf("no constraint at all: got %v, want nil", got)
	}
	if got := userConstraint(constraints(table.Constraint{
		Operator: table.OperatorLike, Expression: "a%",
	})); got != nil {
		t.Errorf("LIKE only: got %v, want nil so the walk is not wrongly narrowed", got)
	}
	// An unsupported operator alongside equality abandons narrowing entirely. Keeping the
	// equality values and ignoring the rest can under-scan: QueryContext does not carry
	// enough boolean structure to prove the subset is sufficient, so `user = 'alice' OR user
	// LIKE 'b%'` would be answered with alice alone. An earlier version of this test asserted
	// that unsafe behaviour as correct.
	if got := userConstraint(constraints(
		table.Constraint{Operator: table.OperatorEquals, Expression: "alice"},
		table.Constraint{Operator: table.OperatorGreaterThan, Expression: "c"},
	)); got != nil {
		t.Errorf("mixed operators must not narrow: %v", got)
	}

	// All-equality still narrows, which is the case worth having.
	got := userConstraint(constraints(
		table.Constraint{Operator: table.OperatorEquals, Expression: "alice"},
		table.Constraint{Operator: table.OperatorEquals, Expression: "bob"},
	))
	if len(got) != 2 {
		t.Fatalf("got %d users, want alice and bob: %v", len(got), got)
	}
	for _, want := range []string{"alice", "bob"} {
		if _, ok := got[want]; !ok {
			t.Errorf("%q missing from the filter", want)
		}
	}
}

func TestBoolToStr(t *testing.T) {
	if boolToStr(true) != "1" || boolToStr(false) != "0" {
		t.Error("disabled must render as the 1/0 integers osquery expects, not true/false")
	}
}

// MCPServersGenerate is the only function osquery ever calls, and every piece it is built from
// is tested above or in discover_integration_test.go. What is not otherwise covered is the
// wiring: that the constraint reaches discovery, that every discovered server becomes exactly
// one row, and that the rows are shaped the way the schema promises. A fake users root makes
// that checkable without touching the real /Users.
func TestMCPServersGenerateWiresConstraintsToDiscovery(t *testing.T) {
	root := t.TempDir()
	for _, user := range []string{"alice", "bob"} {
		dir := filepath.Join(root, user, ".cursor")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		config := `{"mcpServers":{"` + user + `-srv":{"command":"npx","args":["-y","x-mcp@2.1.0"]}}}`
		if err := os.WriteFile(filepath.Join(dir, "mcp.json"), []byte(config), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	declared := make(map[string]struct{})
	for _, column := range MCPServersColumns() {
		declared[column.Name] = struct{}{}
	}

	rows, err := generate(context.Background(), table.QueryContext{}, rosterOf(t, root))
	if err != nil {
		t.Fatalf("unconstrained: %v", err)
	}
	rows = serverRowsOnly(rows)
	if len(rows) != 2 {
		t.Fatalf("unconstrained: got %d rows, want one per user: %v", len(rows), rows)
	}
	// Whatever osquery is handed has to match the schema, or it silently drops the extras.
	for _, row := range rows {
		for name := range row {
			if _, ok := declared[name]; !ok {
				t.Errorf("row carries undeclared column %q", name)
			}
		}
		if row["warning"] != "" {
			t.Errorf("clean fixture produced a warning: %q", row["warning"])
		}
		if row["command_basename"] != "npx" || row["args_count"] != "2" {
			t.Errorf("identity not populated: %v", row)
		}
	}

	// The narrowing path. This is the half that silently does nothing if the column is not
	// indexed, so asserting the generator honours the constraint is the half worth having.
	narrowed, err := generate(context.Background(), table.QueryContext{
		Constraints: map[string]table.ConstraintList{
			"user": {Constraints: []table.Constraint{
				{Operator: table.OperatorEquals, Expression: "alice"},
			}},
		},
	}, rosterOf(t, root))
	if err != nil {
		t.Fatalf("constrained: %v", err)
	}
	// Same filter as above. A constrained query repeats a roster-level note under each
	// requested username, so on Linux the narrowed result carries alice's server *and* a
	// note addressed to alice -- which is the designed behaviour, not a constraint being
	// ignored.
	narrowed = serverRowsOnly(narrowed)
	if len(narrowed) != 1 || narrowed[0]["user"] != "alice" {
		t.Fatalf("user constraint not honoured: %v", narrowed)
	}
}

// An empty account roster is a failure, not an answer.
//
// This previously asserted the opposite: that zero users was "a real answer" producing no
// rows and no error. It is not. No supported OS genuinely has no accounts, and a virtual
// table can log an internal error -- an OpenDirectory failure, seen on osquery 5.23.1 --
// while still returning an empty result set with no SQL error. Normalising that as a clean
// result is the exact silent-empty failure this table exists to prevent.
func TestGenerateWithAnEmptyRosterReportsItRatherThanReturningNothing(t *testing.T) {
	rows, err := generate(context.Background(), table.QueryContext{}, rosterFrom())
	if err != nil {
		t.Fatalf("an unavailable roster must not error the table: %v", err)
	}
	if len(rows) != 1 || rows[0]["warning"] == "" {
		t.Fatalf("want one row carrying a warning about the roster, got %v", rows)
	}
}

// Pins the boundary the schema comment documents, so the residual risk stays a known,
// deliberate property rather than something rediscovered later as a surprise.
//
// Two halves. A secret shaped like a known issuer token is removed wherever it appears, and
// an opaque one is not removed anywhere. The second half is the limit of regex redaction, and
// it is uniform across every column whose value a user chooses rather than specific to
// command_basename.
func TestRedactionRemovesKnownShapesButNotOpaqueOnes(t *testing.T) {
	opaque := "my-opaque-secret-value"
	shaped := "ghp_" + strings.Repeat("B", 36)

	shapedRow := serverToRow(Server{
		Command: "/tmp/" + shaped, ServerName: shaped, SourcePath: "/Users/x/" + shaped + "/.mcp.json",
		PackageName: shaped, EnvKeys: []string{shaped},
	})
	for _, column := range []string{"command_basename", "server_name", "source_path", "package_name", "env_keys"} {
		if strings.Contains(shapedRow[column], shaped) {
			t.Errorf("%s kept a known-shape token: %q", column, shapedRow[column])
		}
	}

	opaqueRow := serverToRow(Server{Command: "/tmp/" + opaque, SourcePath: "/Users/x/" + opaque + "/.mcp.json"})
	if opaqueRow["command_basename"] != opaque {
		t.Errorf("command_basename = %q; the documented behaviour is that an opaque value "+
			"passes through. If this changed deliberately, update the schema comment too.",
			opaqueRow["command_basename"])
	}
	if !strings.Contains(opaqueRow["source_path"], opaque) {
		t.Error("source_path no longer passes an opaque value through, so the comment's claim " +
			"that the limit is uniform across columns is now wrong")
	}
}

// A credential-named assignment is caught in every column a user's file can reach, however
// the option is delimited -- which is the claim the schema comment and the README both make.
//
// Two gaps produced this test. The embedded pattern was bounded on the left by `\s`, so an
// option introduced by a path separator, a bracket or non-ASCII whitespace was not an option
// as far as the regexp was concerned and its value survived. And source_path and warning are
// assembled after parsing, so they never passed through redactSecret at all: a project
// directory literally named `--token=<secret>` reached the row intact. Both are emission-time
// properties, so this asserts on serverToRow rather than on the redactor.
func TestServerToRowRedactsDelimitedAssignmentsInEveryColumnAUserControls(t *testing.T) {
	const secret = "opaqueSecretValue123"
	row := serverToRow(Server{
		SourcePath:    "/Users/alice/--token=" + secret + "/project/.mcp.json",
		SourceContext: "projects[/tmp/--api-key=" + secret + "].mcpServers",
		ServerName:    "group/--api-key=" + secret,
		Command:       "/opt/--dd-key=" + secret + "/bin/tool",
		URL:           "https://host/--token=" + secret,
		PackageName:   "pkg/--token=" + secret,
		RequestedSpec: "pkg@--token=" + secret,
		PinnedVersion: "1.0.0-\u00a0--token=" + secret,
		EnvKeys:       []string{"A=--token=" + secret},
		Home:          "/Users/alice",
		Warning:       warning{Code: warnSourceUnreadable, Class: fsscan.ClassDenied},
	})
	for column, value := range row {
		if strings.Contains(value, secret) {
			t.Errorf("%s leaked a credential-named assignment: %q", column, value)
		}
	}
	// Each column is now either dropped by its allowlist or redacted, and which of the two
	// is itself the assertion.
	//
	// The original version of this test required the redaction marker in every column, on
	// the reasoning that a column which lost everything would be a different bug -- a reader
	// could not tell a redacted value from an empty one. That was right while redaction was
	// the only defence. It is the wrong assertion now: a value that fails its column's
	// format is *supposed* to be dropped whole, and the row says why in `warning` rather
	// than by leaving a marker behind. So the columns split in two.
	//
	// command_basename needs no drop here and that is worth being explicit about: the
	// secret is in a *directory* component, and reducing the field to its basename removes
	// every directory component by construction. `/opt/--dd-key=<secret>/bin/tool` arrives
	// as `tool`. The allowlist is the second line of defence for this column, not the
	// first, and it fires on a secret in the filename itself -- `API_KEY=xyz npx -y pkg`,
	// which cannot be a filename because of the `=`.
	if row["command_basename"] != "tool" {
		t.Errorf("command_basename = %q, want \"tool\": reducing to a basename drops the "+
			"directory components the secret was in", row["command_basename"])
	}
	// Dropped, because the value does not match the column's format: a package name cannot
	// contain `/--token`, an env key must be a C identifier, an endpoint's host must be
	// hostname-shaped.
	for _, column := range []string{
		"package_name", "requested_spec", "pinned_version", "url_endpoint",
	} {
		if row[column] != "" {
			t.Errorf("%s = %q, expected the allowlist to drop it entirely", column, row[column])
		}
	}
	if row["env_keys"] != "[]" {
		t.Errorf("env_keys = %q, expected the non-identifier key to be dropped", row["env_keys"])
	}
	// Reduced to the part that is not user-controlled. source_context keeps which *section*
	// declared the server and drops the path, because the path failed containment.
	if row["source_context"] != "projects" {
		t.Errorf("source_context = %q, expected the bare section token", row["source_context"])
	}
	// Redacted rather than dropped, because there is no format available: a path's
	// directory names are the user's to choose.
	if !strings.Contains(row["source_path"], redact.RedactedMark) {
		t.Errorf("source_path = %q, expected the redaction marker", row["source_path"])
	}
	// server_name keeps redaction, so a name that is partly a credential survives with the
	// marker rather than becoming a placeholder.
	if !strings.Contains(row["server_name"], redact.RedactedMark) {
		t.Errorf("server_name = %q, expected the redaction marker", row["server_name"])
	}
	// And the warning is built from the catalogue, so it never held the value at all.
	if row["warning"] == "" {
		t.Error("warning = empty; the row must still explain itself")
	}
}

// The same guarantee for a value carrying a newline, taken from JSON rather than built in Go
// so the escape is the one a real config would use.
//
// A newline defeated both halves of the redactor at once: the whole-value pattern was a
// regexp whose `.` does not cross one, and the embedded pattern's value has to start at a
// non-space character. `"--token=\nsecret"` is a legal server name and reached the row with
// the credential intact.
func TestServerToRowRedactsAnAssignmentCarryingANewline(t *testing.T) {
	const secret = "opaqueSecretValue123"
	data := []byte(`{"mcpServers":{"--token=\n` + secret + `":{"command":"npx","args":["x"]}}}`)
	servers, err := extractEnvelopeSimple(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("got %d servers, want 1: %+v", len(servers), servers)
	}
	row := serverToRow(servers[0])
	for column, value := range row {
		if strings.Contains(value, secret) {
			t.Errorf("%s leaked a credential across a newline: %q", column, value)
		}
	}
	if !strings.Contains(row["server_name"], redact.RedactedMark) {
		t.Errorf("server_name = %q, expected the redaction marker", row["server_name"])
	}

	// The same value in the two columns assembled after parsing, which no parse-time
	// sanitization reaches. Without the emission-boundary pass these carry the credential
	// even though the identically-shaped server name above does not.
	built := serverToRow(Server{
		SourcePath: "/Users/alice/--token=\n" + secret + "/.mcp.json",
		Home:       "/Users/alice",
		Warning:    warning{Code: warnSourceUnreadable, Class: fsscan.ClassDenied},
	})
	if strings.Contains(built["source_path"], secret) {
		t.Errorf("source_path leaked a credential across a newline: %q", built["source_path"])
	}
	if !strings.Contains(built["source_path"], redact.RedactedMark) {
		t.Errorf("source_path = %q, expected the redaction marker", built["source_path"])
	}
	// warning is no longer assembled from an error message, so there is nothing for a
	// newline to hide inside: the column is a sentence chosen by code, plus integers and
	// closed-enum spellings. Asserted as the absence of the whole secret rather than as the
	// presence of a marker, because the value never entered the column to be marked.
	if strings.Contains(built["warning"], secret) {
		t.Errorf("warning carried a credential: %q", built["warning"])
	}
}

// Every row the table emits has to satisfy the identity columns' documented sets, including
// the rows that report a problem instead of a server. Diagnostics are built outside
// inferIdentity, so they were leaving transport and confidence empty -- a value in neither
// documented set, which made the rows whose entire purpose is to be noticed invisible to
// `WHERE transport = 'unknown'` and to `WHERE confidence IN ('high','medium','low')`.
func TestDiagnosticRowsSatisfyTheIdentityColumnContract(t *testing.T) {
	transports := map[string]bool{"stdio": true, "http": true, "sse": true, "unknown": true}
	confidences := map[string]bool{"high": true, "medium": true, "low": true}

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "alice", "code"), 0o755); err != nil {
		t.Fatal(err)
	}

	inspect := func(label string, rows []Server) {
		t.Helper()
		var diagnostics int
		for _, row := range rows {
			if row.Warning.empty() {
				continue
			}
			diagnostics++
			if !transports[row.Transport] {
				t.Errorf("%s: transport = %q, not one of stdio/http/sse/unknown", label, row.Transport)
			}
			if !confidences[row.Confidence] {
				t.Errorf("%s: confidence = %q, not one of high/medium/low", label, row.Confidence)
			}
		}
		if diagnostics == 0 {
			t.Errorf("%s: expected at least one diagnostic row to check", label)
		}
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	inspect("cancelled query", DiscoverAll(cancelled, rosterOf(t, root), nil))

	t.Setenv(fsscan.WalkTimeoutEnv, "1ns")
	inspect("budget exhausted", DiscoverAll(context.Background(), rosterOf(t, root), nil))
	t.Setenv(fsscan.WalkTimeoutEnv, "")

	// The roster is a query now, so "unreadable" means osquery could not answer. A clienter
	// that fails to connect is the honest stand-in for that.
	inspect("osquery unreachable", DiscoverAll(context.Background(), failingClienter{}, nil))

	inspect("parse failure", finishProcessing("", []byte(`{not json`), nil,
		"/p/mcp.json", "alice", "cursor", false, MaxFileSize, extractEnvelopeSimple))
	inspect("unterminated comment", finishProcessing("", []byte(`{"a":1} /*`), nil,
		"/p/mcp.json", "alice", "cursor", true, MaxFileSize, extractEnvelopeSimple))
	inspect("read failure", finishProcessing("", nil, errors.New("boom"),
		"/p/mcp.json", "alice", "cursor", false, MaxFileSize, extractEnvelopeSimple))
	inspect("skipped entries", finishProcessing("",
		[]byte(`{"mcpServers":{"ok":{"command":"npx"},"bad":{"command":1}}}`), nil,
		"/p/mcp.json", "alice", "cursor", false, MaxFileSize, extractEnvelopeSimple))
}

// TestRosterFailureNamesEachRequestedUser pins the roster-unreachable path against the
// defect the per-account rows already fixed: a single aggregate diagnostic with an empty
// user is discarded by `WHERE user = '<name>'`, so a constrained query was handed a clean
// empty result for the one failure that can say nothing about any account at all.
func TestRosterFailureNamesEachRequestedUser(t *testing.T) {
	t.Run("constrained query gets the diagnostic under each name it asked about", func(t *testing.T) {
		rows := DiscoverAll(context.Background(), failingClienter{}, map[string]struct{}{
			"erin": {}, "carol": {}, "alice": {}, "dave": {}, "bob": {},
		})
		var users []string
		for _, row := range rows {
			if row.Warning.empty() {
				t.Errorf("every row on this path must carry a warning; got %+v", row)
			}
			users = append(users, row.User)
		}
		// Asserted before sorting: these rows go straight to osquery, so a nondeterministic
		// order makes the same query return the same rows differently each run.
		if !sort.StringsAreSorted(users) {
			t.Errorf("rows are not in a deterministic order: %q", users)
		}
		sort.Strings(users)
		if !reflect.DeepEqual(users, []string{"alice", "bob", "carol", "dave", "erin"}) {
			t.Errorf("users = %q, want all five requested; an empty user here is invisible "+
				"to the constraint that asked the question", users)
		}
	})

	t.Run("unconstrained query keeps one aggregate row", func(t *testing.T) {
		rows := DiscoverAll(context.Background(), failingClienter{}, nil)
		if len(rows) != 1 {
			t.Fatalf("want exactly one aggregate row, got %d: %+v", len(rows), rows)
		}
		if rows[0].User != "" {
			t.Errorf("aggregate row user = %q, want empty: no account was confirmed or "+
				"ruled out, so naming one would be a claim we cannot make", rows[0].User)
		}
	})
}

// The roster answering "no such account" is not the same as the account having no MCP
// servers, and returning nothing says the second. Every other branch of DiscoverAll already
// refuses that trade -- a skipped home, an unreachable roster, a budget that ran out -- and
// the requested name the roster never mentioned was the one route still taking it.
func TestQueryForANameTheRosterDoesNotHaveSaysSo(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "alice", "code"), 0o755); err != nil {
		t.Fatal(err)
	}

	rows := DiscoverAll(context.Background(), rosterOf(t, root), map[string]struct{}{
		"nosuchuser": {},
	})
	var named int
	for _, row := range rows {
		if row.User != "nosuchuser" {
			t.Errorf("a query for one name returned a row for %q: %+v", row.User, row)
			continue
		}
		if row.Warning.empty() {
			t.Errorf("no account of this name exists, so any row for it must explain "+
				"itself: %+v", row)
			continue
		}
		named++
	}
	if named == 0 {
		t.Error("a query for an account the roster does not have returned nothing, which " +
			"reads as the account having no MCP servers")
	}

	// The other half: a name the roster does have must not draw the same row, or every
	// ordinary constrained query carries a warning that is not true of it.
	for _, row := range DiscoverAll(context.Background(), rosterOf(t, root),
		map[string]struct{}{"alice": {}}) {
		if row.Warning.Code == warnAccountNotInRoster {
			t.Errorf("an account that exists was reported as missing: %+v", row)
		}
	}

	// And an account the walk never reached is still an account. The budget and
	// cancellation branches report on it themselves, so treating "not scanned" as "not
	// found" would hand one query two contradictory warnings about the same user.
	t.Setenv(fsscan.WalkTimeoutEnv, "1ns")
	for _, row := range DiscoverAll(context.Background(), rosterOf(t, root),
		map[string]struct{}{"alice": {}}) {
		if row.Warning.Code == warnAccountNotInRoster {
			t.Errorf("an account the budget never reached was reported as missing: %+v", row)
		}
	}
}

// A rostered account that cannot log in is not an account the roster never mentioned, and
// saying so was a false statement about what osquery returned.
//
// homesFromUsers drops non-login accounts on purpose: they keep no editor or agent
// configuration, and a row each would bury the omissions that matter. But they were dropped
// from the accounting as well as from the scan, so `WHERE user = 'daemon'` fell through to
// the unanswered branch and came back "no account of this name is in the roster osquery
// returned" -- about an account that was in the roster osquery returned.
func TestQueryForANonLoginAccountIsNotToldItIsAbsent(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "daemon")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	roster := rosterFrom(map[string]string{
		"uid": "1", "uuid": "", "username": "daemon", "directory": home,
		"shell": "/usr/bin/false",
	})

	rows := withoutStandingNotes(DiscoverAll(context.Background(), roster,
		map[string]struct{}{"daemon": {}}))
	if len(rows) == 0 {
		t.Fatal("a query for a rostered non-login account returned nothing, which reads " +
			"as the account having no MCP servers")
	}
	for _, row := range rows {
		if row.Warning.Code == warnAccountNotInRoster {
			t.Errorf("a rostered account was reported as absent from the roster: %+v", row)
		}
		if row.User != "daemon" {
			t.Errorf("row for %q in a query constrained to daemon: %+v", row.User, row)
		}
		if row.UserID != "1" {
			t.Errorf("row carries user_id %q, want the roster's identity: %+v", row.UserID, row)
		}
	}

	// The other half of the trade: unconstrained, these stay quiet. A host carries dozens
	// of service accounts and a row each would drown the inventory.
	unconstrained := withoutStandingNotes(DiscoverAll(context.Background(), roster, nil))
	for _, row := range unconstrained {
		if row.Warning.Code == warnAccountNonLogin {
			t.Errorf("an unconstrained inventory reported a service account: %+v", row)
		}
	}
}

// The missing-name diagnostic must only claim a companion warning exists when one does.
//
// It used to close with "a roster-level warning alongside this row says which" whatever the
// roster had done, so on a complete roster the sentence sent an operator looking for a row
// that is not there. The fix was two near-identical paragraphs differing in one clause, which
// the warning catalogue does not admit -- one sentence per code -- so the distinction is now
// carried as a count on the code instead, and the sentence says neither thing.
//
// What has to hold is the same property, asserted structurally: Count is set exactly when a
// roster-level row was also emitted.
func TestMissingNameDiagnosticOnlyPromisesAWarningThatExists(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "alice"), 0o755); err != nil {
		t.Fatal(err)
	}

	// A roster that reported no limits of its own. There is no companion row, so the
	// diagnostic must not claim one.
	//
	// This case changed with the removal of the always-on Linux note: that note made every
	// Linux run roster-uncertain, so the claim was truthful there and false everywhere else,
	// which is why the old test had a platform-dependent branch. With the note gone, a
	// healthy roster is uncertain on no platform and the assertion is the same everywhere.
	rows := DiscoverAll(context.Background(), rosterOf(t, root),
		map[string]struct{}{"nosuchuser": {}})
	var missing *Server
	rosterLevel := 0
	for i, row := range rows {
		if row.Warning.Code == warnAccountNotInRoster {
			missing = &rows[i]
			continue
		}
		// The missing-name row carries the users root as its path too, having no home to
		// name, so it would otherwise count as its own corroboration.
		if !row.Warning.empty() && row.SourcePath == fsscan.UsersRoot {
			rosterLevel++
		}
	}
	if missing == nil {
		t.Fatal("no missing-name diagnostic was emitted")
	}
	if rosterLevel != 0 {
		t.Fatalf("a healthy roster emitted %d roster-level warnings; the fixture is wrong",
			rosterLevel)
	}
	if missing.Warning.Count != 0 {
		t.Errorf("the diagnostic claims a companion roster-level warning, but none was "+
			"emitted: %+v", missing.Warning)
	}

	// And a roster that was short must flag it, or the one case the distinction exists for
	// loses it.
	short := rosterFrom(map[string]string{
		"uid": "", "uuid": "", "username": "", "directory": "", "shell": "/bin/zsh",
	})
	var pointed bool
	for _, row := range DiscoverAll(context.Background(), short,
		map[string]struct{}{"nosuchuser": {}}) {
		if row.Warning.Code == warnAccountNotInRoster && row.Warning.Count > 0 {
			pointed = true
		}
	}
	if !pointed {
		t.Error("with roster-level uncertainty reported, the missing-name diagnostic no " +
			"longer flags that a companion row explains it")
	}
}

// failingClienter stands in for an osquery that cannot be reached.
type failingClienter struct{}

func (failingClienter) NewOsqueryClient() (utils.OsqueryClient, error) {
	return nil, errors.New("dial: connection refused")
}

func TestEnvKeysColumnIsStableAcrossRepeatedParses(t *testing.T) {
	// Enough keys that an unsorted order is overwhelmingly unlikely to repeat by chance:
	// with 8 keys there are 40320 orderings.
	config := []byte(`{"mcpServers":{"s":{"command":"npx","env":{
		"ZULU":"1","ALPHA":"2","MIKE":"3","BRAVO":"4",
		"YANKEE":"5","CHARLIE":"6","XRAY":"7","DELTA":"8"}}}}`)

	var first string
	for attempt := 0; attempt < 20; attempt++ {
		servers, err := extractEnvelopeSimple(config)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if len(servers) != 1 {
			t.Fatalf("got %d servers, want 1", len(servers))
		}
		row := serverToRow(servers[0])
		var keys []string
		if err := json.Unmarshal([]byte(row["env_keys"]), &keys); err != nil {
			t.Fatalf("env_keys is not valid JSON: %v (%q)", err, row["env_keys"])
		}
		if len(keys) != 8 {
			t.Fatalf("got %d keys, want 8: %v", len(keys), keys)
		}
		if !sort.StringsAreSorted(keys) {
			t.Fatalf("env_keys is not sorted: %v", keys)
		}
		if attempt == 0 {
			first = row["env_keys"]
			continue
		}
		if row["env_keys"] != first {
			t.Fatalf("env_keys differs between parses of an identical config:\n  %s\n  %s",
				first, row["env_keys"])
		}
	}
}

// serverRowsOnly drops diagnostics describing the roster as a whole rather than one account.
//
// On Linux every run carries one, because osquery's users table omits directory-served
// accounts unless an expensive option is set, and the table says so. That is correct and
// must keep firing; it is simply not what a test counting discovered servers measures.
// Identified structurally rather than by message: a roster-level row names the users root as
// its source, because there is no single home it belongs to.
// serverRowsOnly is withoutStandingNotes for the generate path, which has already rendered
// rows as the string maps osquery consumes. Same two platform notes, same reasons.
func serverRowsOnly(rows []map[string]string) []map[string]string {
	out := make([]map[string]string, 0, len(rows))
	for _, row := range rows {
		if row["warning"] != "" && row["source_path"] == fsscan.UsersRoot {
			continue
		}
		if row["warning"] == (warning{Code: warnAppDataUndetermined}).render() {
			continue
		}
		out = append(out, row)
	}
	return out
}

// A flat-shape entry that names a server key but decodes to nothing must be counted, the way
// the envelope shapes already count theirs.
//
// extractFlat applied looksLikeServerEntry and then dropped the failures in silence, so
// {"broken":{"command":null},"good":{...}} returned one row and no notice, and a file holding
// only the broken entry returned nothing at all -- indistinguishable from a file with no MCP
// servers in it. Metadata siblings must still be ignored, or every config carrying a
// "$schema" key would grow a spurious "could not be decoded" row.
func TestFlatShapeCountsEntriesThatNameAServerKey(t *testing.T) {
	cases := []struct {
		name, doc      string
		wantServers    int
		wantDiagnostic bool
	}{
		{"broken beside healthy", `{"broken":{"command":null},"good":{"command":"npx"}}`, 1, true},
		{"broken alone", `{"broken":{"command":null}}`, 0, true},
		{"metadata sibling is not a broken entry", `{"note":{"text":"hi"},"good":{"command":"npx"}}`, 1, false},
		{"healthy only", `{"good":{"command":"npx"}}`, 1, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			rows, err := extractEnvelopeSimple([]byte(testCase.doc))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			var servers, diagnostics int
			for _, row := range rows {
				if row.Warning.empty() {
					servers++
					continue
				}
				diagnostics++
			}
			if servers != testCase.wantServers {
				t.Errorf("servers = %d, want %d (rows %+v)", servers, testCase.wantServers, rows)
			}
			if got := diagnostics > 0; got != testCase.wantDiagnostic {
				t.Errorf("diagnostic present = %v, want %v (rows %+v)", got, testCase.wantDiagnostic, rows)
			}
		})
	}
}

// A transport the file declares and this table does not recognise is reported as unknown,
// not replaced with a guess.
//
// normalizeTransport returned "" for both "absent" and "unrecognised", and the caller reads
// "" as permission to infer from the URL or the command. `{"type":"websocket","url":"wss://..."}`
// was therefore reported as transport=http: a protocol the file does not name, stated with
// the same confidence as one it does. The next transport MCP adds would arrive disguised as
// an existing one rather than as something to look at.
// A transport is only guessed from an http or https endpoint.
//
// Any non-empty URL without an SSE marker became transport=http, so `wss://example.test/mcp`
// was reported as HTTP and a URL with no recoverable host was reported as HTTP with no
// endpoint at all. `WHERE transport = 'http'` then returned endpoints that are not HTTP.
// This is the same answer normalizeTransport gives for a declared transport the table does
// not support; the scheme deserves it too.
func TestTransportIsGuessedOnlyFromHTTPSchemes(t *testing.T) {
	cases := []struct{ name, doc, transport, endpoint string }{
		{"a websocket endpoint", `{"mcpServers":{"x":{"url":"wss://example.test/mcp"}}}`,
			"unknown", "wss://example.test"},
		{"a file URL", `{"mcpServers":{"x":{"url":"file:///etc/passwd"}}}`, "unknown", ""},
		{"no recoverable host", `{"mcpServers":{"x":{"url":"not a url"}}}`, "unknown", ""},
		{"an ordinary https endpoint", `{"mcpServers":{"x":{"url":"https://example.test/mcp"}}}`,
			"http", "https://example.test"},
		{"sse is still detected", `{"mcpServers":{"x":{"url":"https://example.test/sse"}}}`,
			"sse", "https://example.test"},
		{"http with a port", `{"mcpServers":{"x":{"url":"http://localhost:8080/foo"}}}`,
			"http", "http://localhost:8080"},
		// A declared transport still wins: the file said sse, so the row says sse whatever
		// the scheme is.
		{"an explicit transport overrides the scheme",
			`{"mcpServers":{"x":{"type":"sse","url":"wss://example.test/mcp"}}}`,
			"sse", "wss://example.test"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			rows, err := extractEnvelopeSimple([]byte(testCase.doc))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(rows) != 1 {
				t.Fatalf("got %d rows, want 1: %+v", len(rows), rows)
			}
			row := rows[0]
			inferIdentity(&row)
			if row.Transport != testCase.transport {
				t.Errorf("transport = %q, want %q", row.Transport, testCase.transport)
			}
			if row.URL != testCase.endpoint {
				t.Errorf("endpoint = %q, want %q", row.URL, testCase.endpoint)
			}
		})
	}
}

func TestDeclaredUnknownTransportIsNotReplacedByAGuess(t *testing.T) {
	cases := []struct{ name, doc, want string }{
		{"unknown type beside a url", `{"mcpServers":{"w":{"type":"websocket","url":"wss://mcp.example.test"}}}`, "unknown"},
		{"unknown type beside a command", `{"mcpServers":{"w":{"type":"websocket","command":"npx"}}}`, "unknown"},
		// Absent is still an invitation to infer, which is the whole point of the distinction.
		{"absent type infers from the url", `{"mcpServers":{"w":{"url":"https://mcp.example.test"}}}`, "http"},
		{"recognised type is honoured", `{"mcpServers":{"w":{"type":"sse","url":"https://mcp.example.test"}}}`, "sse"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			rows, err := extractEnvelopeSimple([]byte(testCase.doc))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(rows) != 1 {
				t.Fatalf("got %d rows, want 1: %+v", len(rows), rows)
			}
			if rows[0].Transport != testCase.want {
				t.Errorf("transport = %q, want %q", rows[0].Transport, testCase.want)
			}
		})
	}
}

// A home already scanned for one account is reported for the next one that shares it, even
// once the walk budget is gone.
//
// The budget check ran before the cache lookup, so two accounts sharing a home -- routine on
// macOS, where /var/root is listed for both root and daemon -- had the second told "walk
// budget exhausted before this user was scanned" about a home the first had just scanned in
// full. The claim was false, and it cost that account every row the cache was already
// holding. Restamping a cached result is not filesystem work and the budget has no say in it.
func TestASharedHomeIsReportedForBothAccountsAfterTheBudgetIsGone(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "shared")
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".cursor", "mcp.json"),
		[]byte(`{"mcpServers":{"seeded":{"command":"npx","args":["pkg"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Two accounts, one home, distinct identities.
	roster := rosterFrom(
		map[string]string{"uid": "501", "uuid": "", "username": "alice", "directory": home, "shell": "/bin/zsh"},
		map[string]string{"uid": "502", "uuid": "", "username": "bob", "directory": home, "shell": "/bin/zsh"},
	)
	// Enough recorded projects that probing them outlasts the budget, so the deadline is
	// gone by the time the second account is considered but the first has already been
	// scanned and cached. The home-rooted pass runs before the project pass, so the seeded
	// row above survives the truncation.
	//
	// A long project list rather than a deep directory tree, which is what the old version
	// built. That is the same substitution the discovery change made everywhere: what makes
	// one home expensive is no longer how much source code is under it -- nothing walks --
	// but how many projects its clients have recorded, because each one costs a probe per
	// known filename.
	projects := make(map[string]any, maxProjects)
	for i := range maxProjects {
		rel := filepath.Join("code", fmt.Sprintf("p%03d", i))
		if err := os.MkdirAll(filepath.Join(home, rel), 0o755); err != nil {
			t.Fatal(err)
		}
		projects[filepath.Join(home, rel)] = map[string]any{}
	}
	recorded, err := json.Marshal(map[string]any{"projects": projects})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), recorded, 0o644); err != nil {
		t.Fatal(err)
	}
	// Sized so the cheap pass fits and the expensive one does not: pass 1 is about thirty
	// probes of which all but one are missing, and the project pass is 200 projects times
	// four filenames. The ratio between them is what this depends on, not the absolute
	// number, which is why both preconditions are checked below rather than assumed.
	t.Setenv(fsscan.WalkTimeoutEnv, "25ms")

	rows := withoutStandingNotes(DiscoverAll(context.Background(), roster, nil))
	// Equality on codes rather than substring matches on "budget" and "truncated", which
	// matched any sentence containing either word and would have gone on passing if the
	// cause changed underneath them.
	budgetCodes := map[warnCode]struct{}{
		warnBudgetExhaustedPreHome: {}, warnBudgetExhaustedOpening: {},
		warnBudgetExhaustedInHome: {}, warnCancelledInHome: {},
	}
	// Two preconditions, both checked, because this test can only observe the behaviour it
	// is about when the budget runs out in a particular window: after the first account's
	// home was scanned in full and before the second account is considered. Whether that
	// window is hit depends on machine speed, and `-race` moves it -- the first version of
	// this test asserted on the result unconditionally and failed under the race detector
	// because the budget expired during pass 1, so the seeded row the assertions need was
	// never produced.
	//
	// Skipping is the honest outcome when the window is missed. The alternative -- tuning
	// the budget until it passes on one machine -- produces a test that asserts nothing
	// anywhere else and fails in CI.
	var exhausted, scannedFirstHome bool
	for _, row := range rows {
		if _, isBudget := budgetCodes[row.Warning.Code]; isBudget {
			exhausted = true
		}
		if row.ServerName == "seeded" {
			scannedFirstHome = true
		}
	}
	switch {
	case !exhausted:
		t.Skip("the scan finished inside the budget on this machine, so the case this test " +
			"is about -- a second account meeting an exhausted budget -- did not arise")
	case !scannedFirstHome:
		t.Skip("the budget ran out before the first account's home-rooted pass completed, " +
			"so nothing was cached and the case this test is about did not arise")
	}
	seen := map[string]bool{}
	for _, row := range rows {
		// The one statement that must never be made about an account whose home was
		// already scanned: the cache lookup has to come before the budget check, or the
		// second account is told nothing was looked at while the rows sit in hand.
		if row.Warning.Code == warnBudgetExhaustedPreHome ||
			row.Warning.Code == warnCancelledPreHome {
			t.Errorf("an account sharing an already-scanned home was told it was never "+
				"scanned: %+v", row)
		}
		if row.Warning.empty() {
			seen[row.User] = true
		}
	}
	for _, user := range []string{"alice", "bob"} {
		if !seen[user] {
			t.Errorf("no server row for %q; a shared home has to be reported for every "+
				"account that shares it", user)
		}
	}
}
