package go_modules

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/osquery/osquery-go/plugin/table"

	"github.com/macadmins/osquery-extension/pkg/devclients"
	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/macadmins/osquery-extension/pkg/testutil"
	"github.com/macadmins/osquery-extension/pkg/utils"
)

// roster answers the users query with one login account per home.
func roster(homes map[string]string) utils.OsqueryClienter {
	names := make([]string, 0, len(homes))
	for name := range homes {
		names = append(names, name)
	}
	sort.Strings(names)
	var rows []map[string]string
	for index, name := range names {
		rows = append(rows, map[string]string{
			"uid": strconv.Itoa(501 + index), "username": name,
			"directory": homes[name], "shell": "/bin/zsh",
		})
	}
	return &utils.MockOsqueryClienter{Data: map[string][]map[string]string{fsscan.UsersQuery: rows}}
}

type unreachable struct{}

func (unreachable) NewOsqueryClient() (utils.OsqueryClient, error) {
	return nil, errors.New("no socket")
}

type failingClient struct{}

func (failingClient) QueryRows(string) ([]map[string]string, error) { return nil, errors.New("x") }
func (failingClient) QueryRow(string) (map[string]string, error)    { return nil, errors.New("x") }
func (failingClient) Close()                                        {}

type queryFails struct{}

func (queryFails) NewOsqueryClient() (utils.OsqueryClient, error) { return failingClient{}, nil }

func run(t *testing.T, clienter utils.OsqueryClienter, qc table.QueryContext) []map[string]string {
	t.Helper()
	rows, err := generate(context.Background(), qc, clienter)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func onUser(names ...string) table.QueryContext {
	var constraints []table.Constraint
	for _, name := range names {
		constraints = append(constraints, table.Constraint{Operator: table.OperatorEquals, Expression: name})
	}
	return table.QueryContext{Constraints: map[string]table.ConstraintList{"user": {Constraints: constraints}}}
}

// claudeList writes a ~/.claude.json recording the given project directories.
func claudeList(t testing.TB, home string, projects ...string) {
	t.Helper()
	var entries []string
	for _, project := range projects {
		entries = append(entries, strconv.Quote(project)+`:{"lastSessionFirstPrompt":"never read"}`)
	}
	testutil.WriteFile(t, filepath.Join(home, ".claude.json"), `{"projects":{`+strings.Join(entries, ",")+`}}`)
}

const goMod = `module example.com/svc

go 1.25

toolchain go1.25.4

require (
	github.com/direct/one v1.2.3
	github.com/indirect/two v0.4.0 // indirect
)

replace github.com/direct/one => github.com/fork/one v1.2.4
`

var goSum = "github.com/direct/one v1.2.3 " + validHashField + "\n" +
	"github.com/direct/one v1.2.3/go.mod " + validHashField + "\n" +
	"github.com/indirect/two v0.4.0/go.mod " + validHashField + "\n"

// modules returns "<module>@<version> <mod_relationship> <go.sum kinds>" for each module row,
// where the kinds are "module", "go.mod" or both joined by "+", and "-" stands for empty.
func modules(rows []map[string]string) []string {
	var out []string
	orDash := func(value string) string {
		if value == "" {
			return "-"
		}
		return value
	}
	for _, r := range rows {
		if r["module_path"] != "" {
			out = append(out, r["module_path"]+"@"+r["version"]+" "+orDash(r["mod_relationship"])+" "+
				orDash(publishedKinds(r)))
		}
	}
	sort.Strings(out)
	return out
}

func warnings(rows []map[string]string) []string {
	var out []string
	for _, r := range rows {
		if r["warning"] != "" {
			out = append(out, r["warning"])
		}
	}
	return out
}

// TestDiscoversModulesFromEveryClientList builds one home whose projects are recorded by
// Claude Code, Codex and VS Code, and checks each project's modules are listed. GoLand has its own
// test, TestAGoLandProjectIsListed.
func TestDiscoversModulesFromEveryClientList(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	claudeProject := filepath.Join(home, "code", "svc")
	codexProject := filepath.Join(home, "code", "tool")
	vscodeProject := filepath.Join(home, "code", "ws")
	claudeList(t, home, claudeProject, filepath.Join(home, "code", "not-go"))
	testutil.WriteFile(t, filepath.Join(home, ".codex", "config.toml"),
		"[projects."+strconv.Quote(codexProject)+"]\ntrust_level = \"untrusted\"\n")
	storage := filepath.Join(home, devclients.AppSupportFork("Code", "User", "workspaceStorage")[0])
	testutil.WriteFile(t, filepath.Join(storage, "abc", "workspace.json"),
		`{"folder":"`+testutil.FileURL(vscodeProject)+`"}`)

	testutil.WriteFile(t, filepath.Join(claudeProject, "go.mod"), goMod)
	testutil.WriteFile(t, filepath.Join(claudeProject, "go.sum"), goSum)
	testutil.WriteFile(t, filepath.Join(codexProject, "go.mod"), "module example.com/tool\n\nrequire github.com/codex/dep v0.1.0\n")
	testutil.WriteFile(t, filepath.Join(vscodeProject, "go.mod"), "module example.com/ws\n\nrequire github.com/vscode/dep v0.2.0\n")
	if err := os.MkdirAll(filepath.Join(home, "code", "not-go"), 0o755); err != nil {
		t.Fatal(err)
	}

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	want := []string{
		"github.com/codex/dep@v0.1.0 direct -",
		"github.com/direct/one@v1.2.3 direct module+go.mod",
		"github.com/indirect/two@v0.4.0 indirect go.mod",
		"github.com/vscode/dep@v0.2.0 direct -",
	}
	if got := modules(rows); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("modules =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, r := range rows {
		if r["user"] != "alice" || r["uid"] != "501" || r["user_id"] != "501" {
			t.Errorf("row identity = %q %q %q", r["user"], r["uid"], r["user_id"])
		}
		if r["module_path"] == "github.com/direct/one" {
			if r["replace_module"] != "github.com/fork/one" || r["replace_version"] != "v1.2.4" {
				t.Errorf("replacement = %q %q", r["replace_module"], r["replace_version"])
			}
			if r["project_path"] != claudeProject || r["project_module"] != "example.com/svc" {
				t.Errorf("project = %q %q, want %q example.com/svc", r["project_path"], r["project_module"], claudeProject)
			}
			if r["go_directive"] != "1.25" || r["toolchain_directive"] != "go1.25.4" {
				t.Errorf("directives = %q %q, want 1.25 and go1.25.4", r["go_directive"], r["toolchain_directive"])
			}
			if r["module_hash"] != validHashField || r["go_mod_hash"] != validHashField {
				t.Errorf("hashes %q %q", r["module_hash"], r["go_mod_hash"])
			}
		}
		if r["module_path"] != "" && r["scan_complete"] != "1" {
			t.Errorf("a clean home's module row is incomplete: %v", r)
		}
	}
	if got := warnings(rows); len(got) != 0 {
		t.Errorf("warnings = %v, want none", got)
	}
}

// TestAProjectOutsideTheHomeIsDescriptive: a recorded project outside the home is reported
// and does not mark the home's rows incomplete, because it defines what is searched.
func TestAProjectOutsideTheHomeIsDescriptive(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	project := filepath.Join(home, "svc")
	claudeList(t, home, project, filepath.Join(root, "shared-checkout"))
	testutil.WriteFile(t, filepath.Join(project, "go.mod"), "module x\n\nrequire github.com/a/b v1.0.0\n")

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	got := warnings(rows)
	if len(got) != 1 || !strings.HasPrefix(got[0], warnSentences[warnProjectOutsideHome]) ||
		!strings.Contains(got[0], "count=1") {
		t.Errorf("warnings = %v", got)
	}
	for _, r := range rows {
		if r["module_path"] != "" && r["scan_complete"] != "1" {
			t.Error("a descriptive finding marked a module row incomplete")
		}
	}
}

// TestAnUnreadableProjectListIsReported: a list that exists and cannot be read, or is null, means
// projects in it are missing, which one warning row for the user says. The project found through
// another client's list was read in full, so its rows stay complete: scan_complete describes a
// project's own files, not the user's discovery.
func TestAnUnreadableProjectListIsReported(t *testing.T) {
	for _, document := range []string{"{not json --token=opaqueSecret", "null"} {
		t.Run(document, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "alice")
			testutil.WriteFile(t, filepath.Join(home, ".claude.json"), document)
			project := filepath.Join(home, "tool")
			testutil.WriteFile(t, filepath.Join(home, ".codex", "config.toml"), "[projects."+strconv.Quote(project)+"]\n")
			testutil.WriteFile(t, filepath.Join(project, "go.mod"), "module x\n\nrequire github.com/a/b v1.0.0\n")

			rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
			if len(modules(rows)) != 1 {
				t.Fatalf("modules = %v, want the Codex project's one module", modules(rows))
			}
			for _, r := range rows {
				if r["module_path"] != "" && r["scan_complete"] != "1" {
					t.Errorf("a project read in full is marked incomplete by another list's failure: %v", r)
				}
				for column, value := range r {
					if strings.Contains(value, "opaqueSecret") {
						t.Errorf("%s carries file text: %q", column, value)
					}
				}
			}
			if got := warnings(rows); len(got) != 1 || !strings.HasPrefix(got[0], warnSentences[warnProjectListUnreadable]) ||
				!strings.Contains(got[0], "source=claude_json") {
				t.Errorf("warnings = %v, want one project_list_unreadable naming claude_json", got)
			}
		})
	}
}

// TestAFileFindingMarksItsProjectsRows: a go.sum with a malformed line marks every row of its
// project incomplete, because each row's columns can come from both files, and names the file in
// its diagnostic row. Another project in the same home is left alone.
func TestAFileFindingMarksItsProjectsRows(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	project := filepath.Join(home, "svc")
	clean := filepath.Join(home, "tool")
	claudeList(t, home, project, clean)
	testutil.WriteFile(t, filepath.Join(project, "go.mod"), goMod)
	testutil.WriteFile(t, filepath.Join(project, "go.sum"), goSum+"two fields\n")
	testutil.WriteFile(t, filepath.Join(clean, "go.mod"), "module example.com/tool\n\nrequire github.com/a/b v1.0.0\n")

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	for _, r := range rows {
		switch {
		case r["module_path"] == "":
			if !strings.HasPrefix(r["warning"], "go.sum: "+warnSentences[warnGoSumMalformed]) || r["scan_complete"] != "0" {
				t.Errorf("diagnostic row = %v", r)
			}
		case r["project_path"] == project && r["scan_complete"] != "0":
			t.Errorf("a row is complete despite a malformed go.sum in its project: %v", r)
		case r["project_path"] == clean && r["scan_complete"] != "1":
			t.Errorf("another project's row was marked by this one's problem: %v", r)
		}
	}
}

// TestAReplacedRequirementAndItsTarget: go.sum hashes the module the go command downloads, so
// with no record for the original version, a requirement replaced by another module has empty
// go.sum columns and the replacement is its own row. A project with a go.sum and no go.mod is
// listed with no project module, complete.
func TestAReplacedRequirementAndItsTarget(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	project := filepath.Join(home, "svc")
	sumOnly := filepath.Join(home, "vendored")
	claudeList(t, home, project, sumOnly)
	testutil.WriteFile(t, filepath.Join(project, "go.mod"), "module example.com/svc\n\nrequire gopkg.in/old.v1 v1.0.0\n\n"+
		"replace gopkg.in/old.v1 v1.0.0 => github.com/new/old v1.5.3\n")
	testutil.WriteFile(t, filepath.Join(project, "go.sum"), "github.com/new/old v1.5.3 "+validHashField+"\n"+
		"github.com/new/old v1.5.3/go.mod "+validHashField+"\n")
	testutil.WriteFile(t, filepath.Join(sumOnly, "go.sum"), "example.com/x v1.0.0/go.mod "+validHashField+"\n")

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	want := []string{
		"example.com/x@v1.0.0 - go.mod",
		"github.com/new/old@v1.5.3 - module+go.mod",
		"gopkg.in/old.v1@v1.0.0 direct -",
	}
	if got := modules(rows); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("modules =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, r := range rows {
		if r["scan_complete"] != "1" {
			t.Errorf("row is incomplete: %v", r)
		}
		switch r["module_path"] {
		case "gopkg.in/old.v1":
			if r["replace_module"] != "github.com/new/old" || r["module_hash"] != "" || r["go_mod_hash"] != "" {
				t.Errorf("replaced requirement = %v", r)
			}
		case "example.com/x":
			if r["project_module"] != "" || r["go_mod_hash"] != validHashField || r["module_hash"] != "" {
				t.Errorf("go.sum-only project row = %v", r)
			}
		}
	}
}

// TestACraftedModulePathNeverReachesAColumn runs the crafted go.mod through the whole table.
func TestACraftedModulePathNeverReachesAColumn(t *testing.T) {
	const opaque = "opaqueSecretValue"
	home := filepath.Join(t.TempDir(), "alice")
	project := filepath.Join(home, "svc")
	claudeList(t, home, project)
	testutil.WriteFile(t, filepath.Join(project, "go.mod"),
		"module x\n\nrequire \"--token="+opaque+"\" v1.0.0\n\nrequire github.com/ok/ok v1.0.0\n")

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	for _, r := range rows {
		for column, value := range r {
			if strings.Contains(value, opaque) {
				t.Errorf("%s = %q carries the crafted value", column, value)
			}
		}
	}
	if got := warnings(rows); len(got) != 1 || !strings.Contains(got[0], "count=1") {
		t.Errorf("warnings = %v, want one entries_dropped row", got)
	}
}

// TestRosterFailures: an unreachable osquery and a failed users query each produce one row,
// or one per requested name so a `WHERE user = ...` query still sees it.
func TestRosterFailures(t *testing.T) {
	rows := run(t, unreachable{}, table.QueryContext{})
	if len(rows) != 1 || !strings.HasPrefix(rows[0]["warning"], warnSentences[warnRosterUnreachable]) {
		t.Errorf("unreachable: %v", rows)
	}
	rows = run(t, queryFails{}, onUser("bob", "alice"))
	if len(rows) != 2 || rows[0]["user"] != "alice" || rows[1]["user"] != "bob" ||
		!strings.HasPrefix(rows[0]["warning"], warnSentences[warnRosterQueryFailed]) {
		t.Errorf("query failed: %v", rows)
	}
}

// TestRequestedAccounts: a name the roster does not have gets a row saying so, and a home two
// accounts share is reported under each.
func TestRequestedAccounts(t *testing.T) {
	home := filepath.Join(t.TempDir(), "shared")
	project := filepath.Join(home, "svc")
	claudeList(t, home, project)
	testutil.WriteFile(t, filepath.Join(project, "go.mod"), "module x\n\nrequire github.com/a/b v1.0.0\n")
	clienter := roster(map[string]string{"alice": home, "build": home})

	rows := run(t, clienter, onUser("alice", "build", "nobody"))
	users := map[string]int{}
	for _, r := range rows {
		users[r["user"]]++
		if r["user"] == "nobody" && !strings.HasPrefix(r["warning"], warnSentences[warnAccountNotInRoster]) {
			t.Errorf("missing account row = %v", r)
		}
	}
	if users["alice"] != 1 || users["build"] != 1 || users["nobody"] != 1 {
		t.Errorf("rows per user = %v", users)
	}
}

func TestACancelledQueryReportsEachAccount(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rows, err := generate(ctx, table.QueryContext{}, roster(map[string]string{"alice": home}))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || !strings.HasPrefix(rows[0]["warning"], warnSentences[warnCancelledPreHome]) ||
		rows[0]["uid"] != "501" {
		t.Errorf("rows = %v, want one cancelled_before_home row carrying uid 501", rows)
	}
}

// TestEveryRowHasEveryColumn guards the schema against a publish map that drifts from it.
func TestEveryRowHasEveryColumn(t *testing.T) {
	published := publish(row{})
	for _, column := range GoModulesColumns() {
		if _, ok := published[column.Name]; !ok {
			t.Errorf("publish has no %q", column.Name)
		}
	}
	if len(published) != len(GoModulesColumns()) {
		t.Errorf("publish has %d columns, schema has %d", len(published), len(GoModulesColumns()))
	}
}

// TestPublicationRules covers each column rule that publish applies.
func TestPublicationRules(t *testing.T) {
	// From t.TempDir, so the home is absolute on Windows too, where a path with no volume is not.
	home := filepath.Join(t.TempDir(), "alice")
	for _, tc := range []struct{ name, path, want string }{
		{"inside the home", filepath.Join(home, "code", "svc"), filepath.Join(home, "code", "svc")},
		{"outside the home", filepath.Join(filepath.Dir(home), "bob", "svc"), ""},
		{"not clean", home + string(filepath.Separator) + "code" + string(filepath.Separator) + ".." + string(filepath.Separator) + "x", ""},
		{"relative", filepath.Join("code", "svc"), ""},
		{"credential in a directory name", filepath.Join(home, "repo --token=opaque"), filepath.Join(home, "repo --token=[REDACTED]")},
	} {
		if got := publishedPath(tc.path, home); got != tc.want {
			t.Errorf("%s: publishedPath(%q) = %q, want %q", tc.name, tc.path, got, tc.want)
		}
	}
	r := publish(row{UserID: "not-an-id", Entry: moduleEntry{
		ModRelationship: "module_checksum",
		ModuleHash:      "h1:short", GoModHash: "h2:" + strings.TrimPrefix(validHashField, "h1:")}})
	for _, column := range []string{"user_id", "mod_relationship", "module_hash", "go_mod_hash"} {
		if r[column] != "" {
			t.Errorf("%s = %q, a value outside its form was published", column, r[column])
		}
	}
	if r := publish(row{Entry: moduleEntry{ModuleHash: validHashField}}); r["module_hash"] != validHashField {
		t.Errorf("a valid hash was dropped: %q", r["module_hash"])
	}
	finding := warning{Code: warnSourceUnreadable}
	if got := publish(row{SourceFile: goSumFile, Warning: finding})["warning"]; got != "go.sum: "+finding.render() {
		t.Errorf("a finding about go.sum = %q, want the go.sum: prefix", got)
	}
	if got := publish(row{SourceFile: "../go.mod", Warning: finding})["warning"]; got != finding.render() {
		t.Errorf("a file name outside the closed set was published as a prefix: %q", got)
	}
	if got := publish(row{SourceFile: goModFile})["warning"]; got != "" {
		t.Errorf("a module row with a file name got a warning: %q", got)
	}
	for uid, want := range map[string]string{"501": "501", "-2": "-2", "S-1-5-21-1": "", "five": ""} {
		if got := publish(row{UID: uid})["uid"]; got != want {
			t.Errorf("uid %q published as %q, want %q", uid, got, want)
		}
	}
	if r := publish(row{UserID: "S-1-12-1-4"}); r["user_id"] != "S-1-12-1-4" {
		t.Errorf("a SID was dropped: %q", r["user_id"])
	}
}

// TestEveryWarningHasASentence: every code in the list renders as its sentence, so no code can
// reach the warning column as the unclassified fallback.
func TestEveryWarningHasASentence(t *testing.T) {
	for code, sentence := range warnSentences {
		if sentence == "" || !strings.HasPrefix((warning{Code: code}).render(), sentence) {
			t.Errorf("%s does not render as its sentence", code)
		}
	}
}

func TestWarningRender(t *testing.T) {
	w := warning{Code: warnWorkspaceListTruncated, Count: 3, Limit: 500, Line: 7,
		Class: fsscan.ClassTooLarge, Reason: fsscan.OmittedHomeMissing}
	want := warnSentences[warnWorkspaceListTruncated] +
		" [count=3; limit=500; line=7; reason=" + string(fsscan.ClassTooLarge) + "; reason=home_missing]"
	if got := w.render(); got != want {
		t.Errorf("render = %q, want %q", got, want)
	}
	if got := (warning{}).render(); got != "" {
		t.Errorf("empty warning rendered %q", got)
	}
	if got := (warning{Code: "invented"}).render(); got != "unclassified finding (invented)" {
		t.Errorf("unknown code rendered %q", got)
	}
}

// TestReadFailureClassification maps each refusal fsscan can return for a module file onto the
// catalog. Absence is silent; a file that exists and was deliberately not read leaves the
// project's listing short; anything else is one file that could not be read. A cloud
// placeholder is not a finding: TestProjectsStoredElsewhereAreCounted covers it.
func TestReadFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		err    error
		code   warnCode
		report bool
	}{
		{os.ErrNotExist, "", false},
		{fsscan.ErrUserspaceFilesystem, warnSourceUserspaceFS, true},
		{fsscan.ErrHardLink, warnProjectRefused, true},
		{fsscan.ErrForeignOwner, warnProjectRefused, true},
		{fsscan.ErrTooLarge, warnSourceTooLarge, true},
		{fsscan.ErrNotRegular, warnSourceUnreadable, true},
		{os.ErrPermission, warnSourceUnreadable, true},
	} {
		w, report := readFailure(tc.err)
		if report != tc.report || w.Code != tc.code {
			t.Errorf("readFailure(%v) = %q %v, want %q %v", tc.err, w.Code, report, tc.code, tc.report)
		}
	}
	if w, _ := readFailure(fsscan.ErrTooLarge); w.Limit != maxGoFileSize {
		t.Errorf("an oversized file reports limit %d, want %d", w.Limit, maxGoFileSize)
	}
}

// TestAReplaceConflictReachesTheTable: the requirement is listed with no replacement, a
// go_mod_replace_conflict row says why, and the file's rows are marked incomplete.
func TestAReplaceConflictReachesTheTable(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	project := filepath.Join(home, "svc")
	claudeList(t, home, project)
	testutil.WriteFile(t, filepath.Join(project, "go.mod"), "module x\n\nrequire example.com/dep v1.0.0\n\n"+
		"replace example.com/dep => example.com/a v1.0.0\nreplace example.com/dep => example.com/b v1.0.0\n")

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	for _, r := range rows {
		if r["module_path"] == "example.com/dep" && (r["replace_module"] != "" || r["scan_complete"] != "0") {
			t.Errorf("conflicted requirement = %v, want no replacement and incomplete", r)
		}
	}
	if got := warnings(rows); len(got) != 1 || !strings.HasPrefix(got[0], "go.mod: "+warnSentences[warnReplaceConflict]) {
		t.Errorf("warnings = %v", got)
	}
}

// TestRowLimitIsReported: rows past the query's limit are not returned, the project cut short
// keeps the rows that fit, marked incomplete, with a row saying so for the user, and a user the
// limit never reached gets a row saying why.
func TestRowLimitIsReported(t *testing.T) {
	root := t.TempDir()
	homes := map[string]string{"alice": filepath.Join(root, "alice"), "bob": filepath.Join(root, "bob")}
	for _, home := range homes {
		project := filepath.Join(home, "svc")
		claudeList(t, home, project)
		testutil.WriteFile(t, filepath.Join(project, "go.mod"), goMod) // two requirements
		testutil.WriteFile(t, filepath.Join(project, "go.sum"), goSum) // records for both, so two rows
	}
	found := discoverWithin(context.Background(), roster(homes), nil, nil, outputLimits{rows: 1, bytes: maxOutputBytes})
	rows := make([]map[string]string, 0, len(found))
	for _, r := range found {
		rows = append(rows, publish(r))
	}
	byUser := map[string][]map[string]string{}
	for _, r := range rows {
		byUser[r["user"]] = append(byUser[r["user"]], r)
	}
	if got := modules(byUser["alice"]); len(got) != 1 {
		t.Errorf("alice modules = %v, want the one that fits", got)
	}
	for _, r := range byUser["alice"] {
		if r["scan_complete"] != "0" {
			t.Errorf("alice row is complete despite the limit: %v", r)
		}
	}
	if got := warnings(byUser["alice"]); len(got) != 1 || !strings.HasPrefix(got[0], warnSentences[warnRowLimitInHome]) {
		t.Errorf("alice warnings = %v", got)
	}
	if len(byUser["bob"]) != 1 || !strings.HasPrefix(byUser["bob"][0]["warning"], warnSentences[warnRowLimitPreHome]) ||
		byUser["bob"][0]["uid"] != "502" {
		t.Errorf("bob rows = %v, want one row_limit_reached_before_home carrying uid 502", byUser["bob"])
	}
}

// TestFileFindingsReachTheTable: a checksum conflict and an over-long file each produce their
// row, and the file's module rows are marked incomplete.
// TestADroppedValueKeepsItsRows: a replacement target or a go line that fails its check is a
// values_dropped finding, not entries_dropped, because its rows are still listed: the requirement
// without the replacement, and every row without go_directive. The go line is its own project,
// because a go.mod that fails the strict parse is read leniently, which skips replace.
func TestADroppedValueKeepsItsRows(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	replaced := filepath.Join(home, "replaced")
	rewritten := filepath.Join(home, "rewritten")
	claudeList(t, home, replaced, rewritten)
	testutil.WriteFile(t, filepath.Join(replaced, "go.mod"), "module example.com/replaced\n\ngo 1.24\n\n"+
		"require example.com/dep v1.0.0\n\nreplace example.com/dep => \"--token=opaqueSecret\" v1.0.0\n")
	testutil.WriteFile(t, filepath.Join(rewritten, "go.mod"), "module example.com/rewritten\n\n"+
		"go 1.24+--token=opaqueSecret\n\nrequire example.com/other v1.0.0\n")

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	if got := modules(rows); len(got) != 2 {
		t.Errorf("modules = %v, want both requirements listed", got)
	}
	want := map[string]string{
		replaced:  "values_dropped",
		rewritten: "go_mod_partial,values_dropped",
	}
	got := map[string][]string{}
	for _, r := range rows {
		if strings.Contains(r["go_directive"]+r["replace_module"]+r["replace_version"], "opaqueSecret") {
			t.Errorf("a dropped value was published: %v", r)
		}
		if r["module_path"] != "" && r["scan_complete"] != "0" {
			t.Errorf("a row beside a dropped value reads as complete: %v", r)
		}
		switch {
		case r["warning"] == "":
		case strings.HasPrefix(r["warning"], "go.mod: "+warnSentences[warnValuesDropped]):
			got[r["project_path"]] = append(got[r["project_path"]], "values_dropped")
		case strings.HasPrefix(r["warning"], "go.mod: "+warnSentences[warnGoModPartial]):
			got[r["project_path"]] = append(got[r["project_path"]], "go_mod_partial")
		default:
			got[r["project_path"]] = append(got[r["project_path"]], r["warning"])
		}
	}
	for project, codes := range want {
		sort.Strings(got[project])
		if strings.Join(got[project], ",") != codes {
			t.Errorf("%s: warnings = %v, want %s", filepath.Base(project), got[project], codes)
		}
	}
}

func TestFileFindingsReachTheTable(t *testing.T) {
	other := "h1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, sha256.Size))
	var long []string
	for index := 0; index <= maxEntriesPerFile; index++ {
		long = append(long, "example.com/m"+strconv.Itoa(index)+" v1.0.0 "+validHashField)
	}
	for _, tc := range []struct {
		name string
		sum  string
		code warnCode
	}{
		{"checksum conflict", "example.com/a v1.0.0 " + validHashField + "\nexample.com/a v1.0.0 " + other + "\n", warnChecksumConflict},
		{"too many entries", strings.Join(long, "\n") + "\n", warnEntriesTruncated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "alice")
			project := filepath.Join(home, "svc")
			claudeList(t, home, project)
			testutil.WriteFile(t, filepath.Join(project, "go.sum"), tc.sum)
			rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
			if got := warnings(rows); len(got) != 1 || !strings.HasPrefix(got[0], "go.sum: "+warnSentences[tc.code]) {
				t.Errorf("warnings = %v, want one %s", got, tc.code)
			}
			for _, r := range rows {
				if r["scan_complete"] != "0" {
					t.Errorf("a go.sum row is complete despite %s: %v", tc.code, r)
					break
				}
				if r["module_path"] == "example.com/a" && (r["module_hash"] != "" || r["module_hash_recorded"] != "1") {
					t.Errorf("a conflicted record published a hash, or lost its version: %v", r)
				}
			}
		})
	}
}

// TestASharedHomeIsReusedAfterTheDeadline: when two accounts share a home and the deadline
// passes after the first scan, the second account still gets the cached rows, because reusing
// them is no filesystem work. A home not yet scanned is refused once the deadline has passed,
// and a cancelled query gets nothing back even from the cache. On Windows the scan is keyed by
// account as well as home, so the second account's scan is its own and the deadline refuses it.
func TestASharedHomeIsReusedAfterTheDeadline(t *testing.T) {
	home := filepath.Join(t.TempDir(), "shared")
	project := filepath.Join(home, "svc")
	claudeList(t, home, project)
	testutil.WriteFile(t, filepath.Join(project, "go.mod"), "module x\n\nrequire github.com/a/b v1.0.0\n")
	alice := fsscan.UserHome{Name: "alice", ID: "501", Path: home}
	build := fsscan.UserHome{Name: "build", ID: "502", Path: home}
	other := fsscan.UserHome{Name: "other", ID: "503", UID: "503", Path: filepath.Join(t.TempDir(), "other")}
	scanned := map[string][]row{}

	limits := outputLimits{rows: 100, bytes: maxOutputBytes}
	first := rowsForHome(context.Background(), alice, time.Now().Add(time.Minute), limits, limits, nil, scanned)
	if moduleRows(first) != 1 {
		t.Fatalf("first account rows = %+v", first)
	}
	expired := time.Now().Add(-time.Second)
	second := rowsForHome(context.Background(), build, expired, limits, limits, nil, scanned)
	if runtime.GOOS == "windows" {
		if len(second) != 1 || second[0].Warning.Code != warnBudgetExhaustedPreHome {
			t.Errorf("second account rows = %+v, want its own scan refused by the deadline", second)
		}
	} else if moduleRows(second) != 1 || second[0].User != "build" || second[0].UserID != "502" {
		t.Errorf("second account rows = %+v, want the cached row labeled for build", second)
	}
	if rows := rowsForHome(context.Background(), other, expired, limits, limits, nil, scanned); len(rows) != 1 ||
		rows[0].Warning.Code != warnBudgetExhaustedPreHome || rows[0].UID != "503" {
		t.Errorf("an unscanned home after the deadline = %+v", rows)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if rows := rowsForHome(cancelled, build, time.Now().Add(time.Minute), limits, limits, nil, scanned); len(rows) != 1 ||
		rows[0].Warning.Code != warnCancelledPreHome {
		t.Errorf("a cancelled query reused the cache: %+v", rows)
	}
}

// TestAGoLandProjectIsListed: a project recorded only in GoLand's recent-projects list, in the
// format GoLand 2026.2 writes, is found and read.
func TestAGoLandProjectIsListed(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	project := filepath.Join(home, "go", "src", "svc")
	testutil.WriteFile(t, filepath.Join(home, devclients.AppSupportDir(), "JetBrains", "GoLand2026.2", "options", "recentProjects.xml"),
		`<application><component name="RecentProjectsManager"><option name="additionalInfo"><map>`+
			`<entry key="$USER_HOME$/go/src/svc"><value><RecentProjectMetaInfo opened="true" /></value></entry>`+
			`<entry key="$APPLICATION_CONFIG_DIR$/projects/GoLandWorkspace"><value><RecentProjectMetaInfo hidden="true" /></value></entry>`+
			`</map></option></component></application>`)
	testutil.WriteFile(t, filepath.Join(project, "go.mod"), "module x\n\nrequire github.com/goland/dep v1.0.0\n")

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	if got := modules(rows); len(got) != 1 || !strings.Contains(got[0], "github.com/goland/dep") {
		t.Errorf("modules = %v", got)
	}
	if got := warnings(rows); len(got) != 0 {
		t.Errorf("warnings = %v, want none", got)
	}
}

// TestTheProjectCapIsReported: a user recording more distinct projects than devclients.MaxProjects gets one
// project_list_truncated row with the limit. The projects that were read keep complete rows.
func TestTheProjectCapIsReported(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	projects := make([]string, 0, devclients.MaxProjects+1)
	for index := 0; index <= devclients.MaxProjects; index++ {
		projects = append(projects, filepath.Join(home, "p", strconv.Itoa(index)))
	}
	claudeList(t, home, projects...)
	testutil.WriteFile(t, filepath.Join(projects[0], "go.mod"), "module x\n\nrequire github.com/a/b v1.0.0\n")

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	got := warnings(rows)
	if len(got) != 1 || !strings.HasPrefix(got[0], warnSentences[warnProjectListTruncated]) ||
		!strings.Contains(got[0], "limit="+strconv.Itoa(devclients.MaxProjects)) {
		t.Errorf("warnings = %v, want one project_list_truncated with limit=%d", got, devclients.MaxProjects)
	}
	for _, r := range rows {
		if r["module_path"] != "" && r["scan_complete"] != "1" {
			t.Errorf("a project read in full is marked incomplete by the cap: %v", r)
		}
	}
}

// TestTheProjectCapKeepsTheMostUsedClients: the lists fill in the order Go developers use the
// clients, so when the cap is reached a VS Code project and JetBrains projects are kept and a
// Claude Code project past the cap is the one dropped.
func TestTheProjectCapKeepsTheMostUsedClients(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	vscodeProject := filepath.Join(home, "vscode", "svc")
	claudeProject := filepath.Join(home, "claude", "svc")
	storage := filepath.Join(home, devclients.AppSupportFork("Code", "User", "workspaceStorage")[0])
	testutil.WriteFile(t, filepath.Join(storage, "abc", "workspace.json"), `{"folder":"`+testutil.FileURL(vscodeProject)+`"}`)
	var entries strings.Builder
	for index := 0; index < devclients.MaxProjects-1; index++ {
		entries.WriteString(`<entry key="$USER_HOME$/jb/` + strconv.Itoa(index) + `"><value><RecentProjectMetaInfo /></value></entry>`)
	}
	testutil.WriteFile(t, filepath.Join(home, devclients.AppSupportDir(), "JetBrains", "GoLand2026.2", "options", "recentProjects.xml"),
		`<application><component name="RecentProjectsManager"><option name="additionalInfo"><map>`+entries.String()+
			`</map></option></component></application>`)
	claudeList(t, home, claudeProject)
	testutil.WriteFile(t, filepath.Join(vscodeProject, "go.mod"), "module x\n\nrequire github.com/vscode/dep v1.0.0\n")
	testutil.WriteFile(t, filepath.Join(claudeProject, "go.mod"), "module y\n\nrequire github.com/claude/dep v1.0.0\n")

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	if got := modules(rows); len(got) != 1 || !strings.Contains(got[0], "github.com/vscode/dep") {
		t.Errorf("modules = %v, want only the VS Code project's", got)
	}
	if got := warnings(rows); len(got) != 1 || !strings.HasPrefix(got[0], warnSentences[warnProjectListTruncated]) {
		t.Errorf("warnings = %v, want one project_list_truncated", got)
	}
}

// TestTheAgentListsRespectTheBudget: once the budget is gone, neither fixed-path list is read and
// the stop is reported; with budget left, both are read.
func TestTheAgentListsRespectTheBudget(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	claudeList(t, home, filepath.Join(home, "svc"))
	var noted []warning
	note := func(w warning) { noted = append(noted, w) }

	collector := devclients.NewCollector(home, devclients.MaxProjects)
	if addAgentLists(context.Background(), home, fsscan.ClassNone, time.Now().Add(-time.Second), collector, note) {
		t.Error("the lists were read after the deadline")
	}
	if len(collector.Projects()) != 0 || len(noted) != 1 || noted[0].Code != warnBudgetExhaustedInHome {
		t.Errorf("projects %v notes %+v, want none and one budget_exhausted_during_home", collector.Projects(), noted)
	}

	noted = nil
	collector = devclients.NewCollector(home, devclients.MaxProjects)
	if !addAgentLists(context.Background(), home, fsscan.ClassNone, time.Now().Add(time.Minute), collector, note) ||
		len(collector.Projects()) != 1 || len(noted) != 0 {
		t.Errorf("projects %v notes %+v, want the Claude project and no notes", collector.Projects(), noted)
	}
}

// TestProjectsStoredElsewhereAreCounted: a project in a cloud provider's folder, a project whose
// directory a provider holds, a project on a network filesystem, and a project with a module
// file whose content is not on this disk are each counted into one descriptive row and not read.
// The project stored locally is listed and stays complete.
func TestProjectsStoredElsewhereAreCounted(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	local := filepath.Join(home, "local")
	cloudFolder := filepath.Join(home, "cloud")
	held := filepath.Join(home, "held")
	network := filepath.Join(home, "network")
	evicted := filepath.Join(home, "evicted")
	for _, project := range []string{local, cloudFolder, held, network, evicted} {
		testutil.WriteFile(t, filepath.Join(project, "go.mod"), "module x\n\nrequire github.com/"+filepath.Base(project)+"/dep v1.0.0\n")
	}
	claudeList(t, home, local, cloudFolder, held, network, evicted)

	savedCloud, savedProbe, savedPlaceholder := underCloudStorage, probeProject, cloudPlaceholder
	t.Cleanup(func() { underCloudStorage, probeProject, cloudPlaceholder = savedCloud, savedProbe, savedPlaceholder })
	underCloudStorage = func(rel string) bool { return rel == "cloud" }
	probeProject = func(home, rel string) error {
		switch rel {
		case "network":
			return fsscan.ErrNetworkFilesystem
		case "held":
			// What the probe reports on Windows for a directory that is a provider's reparse point.
			return fsscan.ErrCloudPlaceholder
		}
		return savedProbe(home, rel)
	}
	cloudPlaceholder = func(file *os.File) (bool, error) {
		return strings.Contains(file.Name(), "evicted"), nil
	}

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	if got := modules(rows); len(got) != 1 || !strings.Contains(got[0], "github.com/local/dep") {
		t.Errorf("modules = %v, want only the local project's", got)
	}
	got := warnings(rows)
	sort.Strings(got)
	if len(got) != 2 || !strings.HasPrefix(got[0], warnSentences[warnProjectOnNetworkFS]) ||
		!strings.Contains(got[0], "count=1") || !strings.HasPrefix(got[1], warnSentences[warnProjectInCloudStorage]) ||
		!strings.Contains(got[1], "count=3") {
		t.Errorf("warnings = %v, want one network row with count=1 and one cloud row with count=3", got)
	}
	for _, r := range rows {
		if r["module_path"] != "" && r["scan_complete"] != "1" {
			t.Errorf("a descriptive count marked the local project incomplete: %v", r)
		}
	}
}

// publishedKinds names the kinds of go.sum line a published row records, from its
// module_hash_recorded and go_mod_hash_recorded columns.
func publishedKinds(r map[string]string) string {
	var kinds []string
	if r["module_hash_recorded"] == "1" {
		kinds = append(kinds, "module")
	}
	if r["go_mod_hash_recorded"] == "1" {
		kinds = append(kinds, "go.mod")
	}
	return strings.Join(kinds, "+")
}

// TestAWorkspaceIsReported: a project with a go.work is counted in one descriptive row, whether
// its root has a go.mod or not. The root module of the second is listed, and the project with
// no go.work is not counted.
func TestAWorkspaceIsReported(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	workspaceOnly := filepath.Join(home, "mono")
	workspaceAndModule := filepath.Join(home, "mixed")
	plain := filepath.Join(home, "plain")
	testutil.WriteFile(t, filepath.Join(workspaceOnly, "go.work"), "go 1.25\n\nuse ./svc\n")
	testutil.WriteFile(t, filepath.Join(workspaceAndModule, "go.work"), "go 1.25\n\nuse .\n")
	testutil.WriteFile(t, filepath.Join(workspaceAndModule, "go.mod"), "module x\n\nrequire github.com/mixed/dep v1.0.0\n")
	testutil.WriteFile(t, filepath.Join(plain, "go.mod"), "module y\n\nrequire github.com/plain/dep v1.0.0\n")
	claudeList(t, home, workspaceOnly, workspaceAndModule, plain)

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	if got := modules(rows); len(got) != 2 {
		t.Errorf("modules = %v, want the mixed and plain projects' requirements", got)
	}
	if got := warnings(rows); len(got) != 1 || !strings.HasPrefix(got[0], warnSentences[warnWorkspaceUnsupported]) ||
		!strings.Contains(got[0], "count=2") {
		t.Errorf("warnings = %v, want one go_workspace_unsupported row with count=2", got)
	}
	for _, r := range rows {
		if r["module_path"] != "" && r["scan_complete"] != "1" {
			t.Errorf("a workspace count marked a module row incomplete: %v", r)
		}
	}
}

// TestAProviderHeldGoWorkIsCounted: a go.work that Windows refuses as a storage provider's
// reparse point exists, so it is counted unopened, whether its root has a go.mod or not, and the
// root module is still listed.
func TestAProviderHeldGoWorkIsCounted(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	workspaceOnly := filepath.Join(home, "mono")
	workspaceAndModule := filepath.Join(home, "mixed")
	plain := filepath.Join(home, "plain")
	testutil.WriteFile(t, filepath.Join(workspaceOnly, "go.work"), "go 1.25\n\nuse ./svc\n")
	testutil.WriteFile(t, filepath.Join(workspaceAndModule, "go.work"), "go 1.25\n\nuse .\n")
	testutil.WriteFile(t, filepath.Join(workspaceAndModule, "go.mod"), "module x\n\nrequire github.com/mixed/dep v1.0.0\n")
	testutil.WriteFile(t, filepath.Join(plain, "go.mod"), "module y\n\nrequire github.com/plain/dep v1.0.0\n")
	claudeList(t, home, workspaceOnly, workspaceAndModule, plain)
	saved := openGoWork
	t.Cleanup(func() { openGoWork = saved })
	openGoWork = func(base, rel string) (*os.File, error) {
		if _, err := os.Lstat(filepath.Join(base, rel)); err != nil {
			return saved(base, rel)
		}
		return nil, fsscan.ErrCloudPlaceholder
	}

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	if got := modules(rows); len(got) != 2 {
		t.Errorf("modules = %v, want the mixed and plain projects' requirements", got)
	}
	if got := warnings(rows); len(got) != 1 || !strings.HasPrefix(got[0], warnSentences[warnWorkspaceUnsupported]) ||
		!strings.Contains(got[0], "count=2") {
		t.Errorf("warnings = %v, want one go_workspace_unsupported row with count=2", got)
	}
	for _, r := range rows {
		if r["module_path"] != "" && r["scan_complete"] != "1" {
			t.Errorf("a provider's go.work marked a module row incomplete: %v", r)
		}
	}
}

// TestABudgetStopBetweenFilesMarksThatProjectIncomplete: when the query stops after a project's
// go.mod and before its go.sum, the go.mod rows are listed and marked incomplete, because the
// project's other file was not read.
func TestABudgetStopBetweenFilesMarksThatProjectIncomplete(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	project := filepath.Join(home, "svc")
	testutil.WriteFile(t, filepath.Join(project, "go.mod"), goMod)
	testutil.WriteFile(t, filepath.Join(project, "go.sum"), goSum)
	claudeList(t, home, project)

	// The cloud-attribute check runs inside the go.mod read, so cancelling there makes the
	// budget check before go.sum the first to fail.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	saved := cloudPlaceholder
	t.Cleanup(func() { cloudPlaceholder = saved })
	cloudPlaceholder = func(file *os.File) (bool, error) {
		if strings.HasSuffix(file.Name(), "go.mod") {
			cancel()
		}
		return false, nil
	}
	account := fsscan.UserHome{Name: "alice", ID: "501", Path: home}
	limits := outputLimits{rows: maxRows, bytes: maxOutputBytes}
	rows := discoverHome(ctx, account, time.Now().Add(time.Hour), limits, limits, nil)
	if moduleRows(rows) == 0 {
		t.Fatalf("rows = %+v, want the go.mod rows", rows)
	}
	for _, r := range rows {
		if r.Entry.Path != "" && r.ScanComplete {
			t.Errorf("a row of a half-read project is complete: %+v", r)
		}
	}
}

// TestAccountDiagnosticsKeepTheirUID: a requested account omitted for its home carries its uid,
// and an account the roster returned with no username is reported to each requested user as
// uncertainty about the roster, not as that user's account going uninspected.
func TestAccountDiagnosticsKeepTheirUID(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	clienter := &utils.MockOsqueryClienter{Data: map[string][]map[string]string{fsscan.UsersQuery: {
		{"uid": "501", "username": "alice", "directory": home, "shell": "/bin/zsh"},
		{"uid": "502", "username": "carol", "directory": filepath.Join(filepath.Dir(home), "gone"), "shell": "/bin/zsh"},
		{"uid": "600", "username": "", "directory": home, "shell": "/bin/zsh"},
	}}}
	rows := run(t, clienter, onUser("alice", "carol"))
	notInspected, unnamed := map[string]int{}, map[string]int{}
	for _, r := range rows {
		switch {
		case strings.HasPrefix(r["warning"], warnSentences[warnAccountNotInspected]):
			notInspected[r["user"]]++
			if r["uid"] != "502" {
				t.Errorf("an omitted account's row lost its uid: %v", r)
			}
		case strings.HasPrefix(r["warning"], warnSentences[warnRosterAccountUnnamed]):
			unnamed[r["user"]]++
		}
	}
	if notInspected["carol"] != 1 || notInspected["alice"] != 0 {
		t.Errorf("account_not_inspected rows per user = %v, want carol's only", notInspected)
	}
	if unnamed["alice"] != 1 || unnamed["carol"] != 1 {
		t.Errorf("roster_account_unnamed rows per user = %v, want one under each requested name", unnamed)
	}
}

// TestAnEmptyUserConstraintScansEveryAccount: a user constraint naming the empty string asks for
// the rows that belong to no account, so it gets the full scan's accounts_home_unusable row, not
// an account_not_in_roster row for an account named "".
func TestAnEmptyUserConstraintScansEveryAccount(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	clienter := &utils.MockOsqueryClienter{Data: map[string][]map[string]string{fsscan.UsersQuery: {
		{"uid": "501", "username": "alice", "directory": home, "shell": "/bin/zsh"},
		{"uid": "502", "username": "carol", "directory": filepath.Join(filepath.Dir(home), "gone"), "shell": "/bin/zsh"},
	}}}
	var accountless []string
	for _, r := range run(t, clienter, onUser("")) {
		if r["user"] == "" {
			accountless = append(accountless, r["warning"])
		}
	}
	if len(accountless) != 1 || !strings.HasPrefix(accountless[0], warnSentences[warnAccountsHomeUnusable]) {
		t.Errorf("rows with no user = %q, want the one accounts_home_unusable row a full scan gives", accountless)
	}
}

// TestDescriptiveSentencesShareAPrefix: the eight descriptive sentences, and no others, start with
// "recorded project", which is the one predicate the README gives for a complete inventory.
func TestDescriptiveSentencesShareAPrefix(t *testing.T) {
	descriptive := map[warnCode]bool{
		warnProjectOutsideHome: true, warnProjectRemoteOrigin: true, warnProjectMalformed: true,
		warnProjectInCloudStorage: true, warnProjectOnNetworkFS: true, warnProjectOnUserspaceFS: true,
		warnWorkspaceUnsupported: true, warnWorkspaceRecordsOlder: true,
	}
	for code, sentence := range warnSentences {
		if strings.HasPrefix(sentence, "recorded project") != descriptive[code] {
			t.Errorf("%s: starts with \"recorded project\" = %v, want %v", code,
				strings.HasPrefix(sentence, "recorded project"), descriptive[code])
		}
	}
}

// TestOutputSizeIsBounded: rows past the query's byte limit are not returned. The project cut
// short keeps the rows that fit, marked incomplete, with a row saying so for the user, and a user
// the limit never reached gets a row saying why.
func TestOutputSizeIsBounded(t *testing.T) {
	root := t.TempDir()
	homes := map[string]string{"alice": filepath.Join(root, "alice"), "bob": filepath.Join(root, "bob")}
	for _, home := range homes {
		project := filepath.Join(home, "svc")
		claudeList(t, home, project)
		testutil.WriteFile(t, filepath.Join(project, "go.mod"), goMod) // two requirements
		testutil.WriteFile(t, filepath.Join(project, "go.sum"), goSum)
	}
	unlimited := discoverWithin(context.Background(), roster(homes), nil, nil,
		outputLimits{rows: maxRows, bytes: maxOutputBytes})
	alice := fsscan.UserHome{Name: "alice", UID: "501", ID: "501"}
	var oneRow int
	for _, r := range unlimited {
		if r.User == "alice" && r.Entry.Path != "" {
			oneRow = rowBytes(r, alice)
			break
		}
	}
	// Room for one of alice's rows and a byte more, so her second does not fit and bob, although
	// a byte remains, gets nothing: a cap reached part way through a home leaves nothing over.
	found := discoverWithin(context.Background(), roster(homes), nil, nil, outputLimits{rows: maxRows, bytes: oneRow + 1})
	byUser := map[string][]map[string]string{}
	for _, r := range found {
		published := publish(r)
		byUser[published["user"]] = append(byUser[published["user"]], published)
	}
	if got := modules(byUser["alice"]); len(got) != 1 {
		t.Errorf("alice modules = %v, want the one that fits", got)
	}
	if got := warnings(byUser["alice"]); len(got) != 1 || !strings.HasPrefix(got[0], warnSentences[warnOutputSizeInHome]) {
		t.Errorf("alice warnings = %v, want one output_size_reached_during_home", got)
	}
	if len(byUser["bob"]) != 1 || !strings.HasPrefix(byUser["bob"][0]["warning"], warnSentences[warnOutputSizePreHome]) {
		t.Errorf("bob rows = %v, want one output_size_reached_before_home", byUser["bob"])
	}
}

// TestStorageIsJudgedAgainstTheHome: a project on a network filesystem is read when the home is
// on one too, and a project on a userspace filesystem is counted in its own descriptive row when
// the home is not.
func TestStorageIsJudgedAgainstTheHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	network := filepath.Join(home, "network")
	fuse := filepath.Join(home, "fuse")
	for _, project := range []string{network, fuse} {
		testutil.WriteFile(t, filepath.Join(project, "go.mod"), "module x\n\nrequire github.com/"+filepath.Base(project)+"/dep v1.0.0\n")
	}
	claudeList(t, home, network, fuse)
	saved := probeProject
	t.Cleanup(func() { probeProject = saved })
	probeProject = func(home, rel string) error {
		switch rel {
		case ".", "network":
			return fsscan.ErrNetworkFilesystem
		case "fuse":
			return fsscan.ErrUserspaceFilesystem
		}
		return saved(home, rel)
	}

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	if got := modules(rows); len(got) != 1 || !strings.Contains(got[0], "github.com/network/dep") {
		t.Errorf("modules = %v, want the network project's, read because the home is on a network filesystem too", got)
	}
	if got := warnings(rows); len(got) != 1 || !strings.HasPrefix(got[0], warnSentences[warnProjectOnUserspaceFS]) ||
		!strings.Contains(got[0], "count=1") {
		t.Errorf("warnings = %v, want one project_on_userspace_filesystem row with count=1", got)
	}
}

// TestAnOverlongRecordedPathIsNeverPublished: a recorded project path longer than
// devclients.MaxProjectPathLen is counted in the fixed-size project_path_malformed row, so a list
// the user writes cannot put a path of any length on a diagnostic row, which the output caps
// never drop.
func TestAnOverlongRecordedPathIsNeverPublished(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	long := filepath.Join(home, strings.Repeat("a", devclients.MaxProjectPathLen))
	kept := filepath.Join(home, "svc")
	claudeList(t, home, long, kept)
	testutil.WriteFile(t, filepath.Join(kept, "go.mod"), "module x\n\nrequire github.com/a/b v1.0.0\n")

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	for _, r := range rows {
		if len(r["project_path"]) > devclients.MaxProjectPathLen {
			t.Errorf("a %d-byte project_path was published", len(r["project_path"]))
		}
	}
	if got := warnings(rows); len(got) != 1 || !strings.HasPrefix(got[0], warnSentences[warnProjectMalformed]) ||
		!strings.Contains(got[0], "count=1") {
		t.Errorf("warnings = %v, want one project_path_malformed row with count=1", got)
	}
	if got := modules(rows); len(got) != 1 {
		t.Errorf("modules = %v, want the ordinary project's", got)
	}
}

// TestASharedHomeStoppedByACapIsNotReused: a scan a cap stopped is one account's share of the
// output, so another account sharing the home is told the cap was reached before its scan,
// rather than inheriting the first account's rows and warning.
func TestASharedHomeStoppedByACapIsNotReused(t *testing.T) {
	root := t.TempDir()
	shared, other := filepath.Join(root, "shared"), filepath.Join(root, "bob")
	for _, home := range []string{shared, other} {
		project := filepath.Join(home, "svc")
		claudeList(t, home, project)
		testutil.WriteFile(t, filepath.Join(project, "go.mod"), goMod)
		testutil.WriteFile(t, filepath.Join(project, "go.sum"), goSum)
	}
	// alice (uid 501), bob (502) and carol (503) are scanned in that order; alice and carol
	// share a home. One byte stops alice's scan before her first row.
	homes := map[string]string{"alice": shared, "bob": other, "carol": shared}
	found := discoverWithin(context.Background(), roster(homes), nil, nil, outputLimits{rows: maxRows, bytes: 1})
	byUser := map[string][]string{}
	for _, r := range found {
		published := publish(r)
		byUser[published["user"]] = append(byUser[published["user"]], published["warning"])
	}
	if got := byUser["alice"]; len(got) != 1 || !strings.HasPrefix(got[0], warnSentences[warnOutputSizeInHome]) {
		t.Errorf("alice = %v, want one output_size_reached_during_home", got)
	}
	for _, name := range []string{"bob", "carol"} {
		if got := byUser[name]; len(got) != 1 || !strings.HasPrefix(got[0], warnSentences[warnOutputSizePreHome]) {
			t.Errorf("%s = %v, want one output_size_reached_before_home", name, got)
		}
	}
}

// TestBothCapsAreReportedWhenBothAreSpent: when the rows kept fill the row cap and the byte cap
// at once, the user cut short gets both during-home rows and the next user both before-home rows.
func TestBothCapsAreReportedWhenBothAreSpent(t *testing.T) {
	root := t.TempDir()
	homes := map[string]string{"alice": filepath.Join(root, "alice"), "bob": filepath.Join(root, "bob")}
	for _, home := range homes {
		project := filepath.Join(home, "svc")
		claudeList(t, home, project)
		testutil.WriteFile(t, filepath.Join(project, "go.mod"), goMod)
		testutil.WriteFile(t, filepath.Join(project, "go.sum"), goSum)
	}
	unlimited := discoverWithin(context.Background(), roster(homes), nil, nil,
		outputLimits{rows: maxRows, bytes: maxOutputBytes})
	alice := fsscan.UserHome{Name: "alice", UID: "501", ID: "501"}
	var oneRow int
	for _, r := range unlimited {
		if r.User == "alice" && r.Entry.Path != "" {
			oneRow = rowBytes(r, alice)
			break
		}
	}
	found := discoverWithin(context.Background(), roster(homes), nil, nil, outputLimits{rows: 1, bytes: oneRow})
	byUser := map[string][]string{}
	for _, r := range found {
		published := publish(r)
		if published["warning"] != "" {
			byUser[published["user"]] = append(byUser[published["user"]], published["warning"])
		}
	}
	for user, codes := range map[string][]warnCode{
		"alice": {warnRowLimitInHome, warnOutputSizeInHome},
		"bob":   {warnRowLimitPreHome, warnOutputSizePreHome},
	} {
		got := strings.Join(byUser[user], "\n")
		for _, code := range codes {
			if !strings.Contains(got, warnSentences[code]) {
				t.Errorf("%s warnings = %v, want %s among them", user, byUser[user], code)
			}
		}
	}
}

// TestJSONWidth: the byte cap charges a value what it can take in JSON.
func TestJSONWidth(t *testing.T) {
	for value, want := range map[string]int{
		"plain": 5, "a<b": 8, `q"b\`: 6, string([]byte{0xff}): 6, "é": 2, "\u2028": 6,
		"a\tb\n": 6, "\x01": 6, "\x1f\r": 8,
	} {
		if got := jsonWidth(value); got != want {
			t.Errorf("jsonWidth(%q) = %d, want %d", value, got, want)
		}
	}
}

// TestACompleteSharedHomeIsReusedAfterACap: accounts that share a home directory are scanned once.
// A finished scan of that home is reused for the second account without consulting the caps or
// the deadline, because reusing it is no filesystem work and the answer is complete: a shared
// home with no Go projects gives the second account no rows and no warning, even after a cap is
// spent, rather than a row saying modules went unlisted when there were none. On Windows the
// scan is keyed by account as well as home, so the second account's scan is its own and meets
// the spent cap.
func TestACompleteSharedHomeIsReusedAfterACap(t *testing.T) {
	root := t.TempDir()
	shared, other := filepath.Join(root, "shared"), filepath.Join(root, "bob")
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(other, "svc")
	claudeList(t, other, project)
	testutil.WriteFile(t, filepath.Join(project, "go.mod"), goMod)
	// alice (501), bob (502) and carol (503) in that order; alice and carol share an empty home,
	// and bob's project spends the one-row cap.
	homes := map[string]string{"alice": shared, "bob": other, "carol": shared}
	found := discoverWithin(context.Background(), roster(homes), nil, nil, outputLimits{rows: 1, bytes: maxOutputBytes})
	var carol []row
	for _, r := range found {
		if r.User == "carol" {
			carol = append(carol, r)
		}
	}
	if runtime.GOOS == "windows" {
		if len(carol) != 1 || carol[0].Warning.Code != warnRowLimitPreHome {
			t.Errorf("carol got %+v, want her own scan refused by the spent cap", carol)
		}
	} else if len(carol) != 0 {
		t.Errorf("carol, whose shared home was scanned in full and holds nothing, got %+v", carol)
	}
}

// TestAProjectRecordedInTwoCases: on Windows, where Codex records every project in lowercase, a
// project recorded as `Code\Repo` and as `code\repo` is one project, and its modules are listed
// once. Elsewhere the spellings stay two projects, because a case-sensitive volume can hold both
// as directories: on a case-insensitive volume, macOS's default, the modules are listed twice,
// and on a case-sensitive one the second spelling names nothing.
func TestAProjectRecordedInTwoCases(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	project, respelled := filepath.Join(home, "Code", "Repo"), filepath.Join(home, "code", "repo")
	claudeList(t, home, project, respelled)
	testutil.WriteFile(t, filepath.Join(project, "go.mod"), "module x\n\nrequire github.com/a/b v1.0.0\n")
	want := 1
	if runtime.GOOS != "windows" && testutil.SameFile(t, project, respelled) {
		want = 2
	}

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	if got := modules(rows); len(got) != want {
		t.Errorf("modules = %v, want the requirement listed %d times on this %s volume", got, want, runtime.GOOS)
	}
}

// onPath is a query constrained to project_path equal to each of paths.
func onPath(paths ...string) table.QueryContext {
	var constraints []table.Constraint
	for _, path := range paths {
		constraints = append(constraints, table.Constraint{Operator: table.OperatorEquals, Expression: path})
	}
	return table.QueryContext{Constraints: map[string]table.ConstraintList{"project_path": {Constraints: constraints}}}
}

// TestANamedRecordedProjectIsReadAlone: `project_path = X` reads that one project and no client
// list, so a project opened only from a terminal is reachable, and a lost list costs nothing.
// An empty project_path selects user rows, so it is a full scan.
func TestANamedRecordedProjectIsReadAlone(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	recorded := filepath.Join(home, "recorded")
	terminal := filepath.Join(home, "terminal")
	testutil.WriteFile(t, filepath.Join(recorded, "go.mod"), "module r\n\nrequire github.com/recorded/dep v1.0.0\n")
	testutil.WriteFile(t, filepath.Join(terminal, "go.mod"), "module t\n\nrequire github.com/terminal/dep v1.0.0\n")
	claudeList(t, home, recorded)
	// An unreadable Codex list, which a full scan reports and a named project never reads.
	if err := os.MkdirAll(filepath.Join(home, ".codex", "config.toml"), 0o755); err != nil {
		t.Fatal(err)
	}
	clienter := roster(map[string]string{"alice": home})

	for _, tc := range []struct {
		named []string
		want  string
	}{
		{[]string{recorded}, "github.com/recorded/dep"},
		{[]string{terminal}, "github.com/terminal/dep"},
	} {
		rows := run(t, clienter, onPath(tc.named...))
		if got := modules(rows); len(got) != 1 || !strings.Contains(got[0], tc.want) {
			t.Errorf("%v: modules = %v, want %s alone", tc.named, got, tc.want)
		}
		if got := warnings(rows); len(got) != 0 {
			t.Errorf("%v: warnings = %v, want none: no list is read", tc.named, got)
		}
		for _, r := range rows {
			if r["project_path"] != tc.named[0] {
				t.Errorf("%v: a row for %q", tc.named, r["project_path"])
			}
		}
	}

	full := run(t, clienter, onPath(""))
	if got := warnings(full); len(got) != 1 || !strings.HasPrefix(got[0], warnSentences[warnProjectListUnreadable]) {
		t.Errorf("project_path = '': warnings = %v, want the full scan's project_list_unreadable", got)
	}
}

// TestANamedPathOutsideEveryHomeReadsNothing: a named path that no account's home contains is
// decided by a string comparison, so no home is opened, and the one row returned says so,
// carrying the named path so SQLite's filter keeps it.
func TestANamedPathOutsideEveryHomeReadsNothing(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	testutil.WriteFile(t, filepath.Join(home, "svc", "go.mod"), "module s\n")
	claudeList(t, home, filepath.Join(home, "svc"))
	clienter := roster(map[string]string{"alice": home})
	opened := 0
	saved := probeProject
	t.Cleanup(func() { probeProject = saved })
	probeProject = func(home, rel string) error {
		opened++
		return saved(home, rel)
	}
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	rows := run(t, clienter, onPath(elsewhere))
	if len(rows) != 1 || opened != 0 || rows[0]["project_path"] != elsewhere || rows[0]["user"] != "" ||
		rows[0]["warning"] != warnSentences[warnNamedPathOutsideHomes] {
		t.Errorf("rows = %v after %d opens, want one project_path_outside_scanned_homes row and no open",
			rows, opened)
	}
	run(t, clienter, table.QueryContext{})
	if opened == 0 {
		t.Error("a full scan opened nothing, so the count above proves nothing")
	}
}

// TestANamedPathWithNoRowsIsReported: a named path inside a home that yields no module row, here a
// directory with no module files, gets a row for the owning account carrying the path as written.
// A named path outside every home is reported under each user a user constraint names, so that
// constraint keeps the row too.
func TestANamedPathWithNoRowsIsReported(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	empty := filepath.Join(home, "notgo")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	clienter := roster(map[string]string{"alice": home, "bob": filepath.Join(root, "bob")})

	var reported []map[string]string
	for _, r := range run(t, clienter, onPath(empty)) {
		if r["project_path"] == empty {
			reported = append(reported, r)
		}
	}
	if len(reported) != 1 || reported[0]["user"] != "alice" || reported[0]["uid"] == "" ||
		reported[0]["warning"] != warnSentences[warnNamedPathNoRows] {
		t.Errorf("rows carrying the named path = %v, want one project_path_without_rows row for alice",
			reported)
	}

	qc := onPath(filepath.Join(root, "elsewhere"))
	qc.Constraints["user"] = onUser("alice", "bob").Constraints["user"]
	users := map[string]bool{}
	for _, r := range run(t, clienter, qc) {
		if r["warning"] == warnSentences[warnNamedPathOutsideHomes] {
			users[r["user"]] = true
		}
	}
	if !users["alice"] || !users["bob"] || len(users) != 2 {
		t.Errorf("outside-every-home rows under %v, want one under each requested user", users)
	}
}

// TestANamedPathIsAnsweredPerAccount: two accounts share a home, and a one-row cap stops the first
// one's scan of the named project, so the second is not scanned and its cap row has an empty
// project_path, which SQLite's filter drops. The second account still gets a row carrying the
// path. A match for the first account suppressed it, and the second account's incomplete answer
// disappeared from the path-constrained query.
func TestANamedPathIsAnsweredPerAccount(t *testing.T) {
	shared := filepath.Join(t.TempDir(), "shared")
	project := filepath.Join(shared, "svc")
	testutil.WriteFile(t, filepath.Join(project, "go.mod"), goMod)
	testutil.WriteFile(t, filepath.Join(project, "go.sum"), goSum)
	found := discoverWithin(context.Background(), roster(map[string]string{"alice": shared, "bob": shared}),
		nil, map[string]struct{}{project: {}}, outputLimits{rows: 1, bytes: maxOutputBytes})
	kept := map[string][]string{}
	for _, r := range found {
		// What SQLite's `project_path = ?` filter keeps.
		if published := publish(r); published["project_path"] == project {
			kept[published["user"]] = append(kept[published["user"]], published["module_path"]+published["warning"])
		}
	}
	if len(kept["alice"]) != 1 || !strings.HasPrefix(kept["alice"][0], "github.com/") {
		t.Errorf("alice = %v, want her one module row", kept["alice"])
	}
	if got := kept["bob"]; len(got) != 1 || got[0] != warnSentences[warnNamedPathNoRows] {
		t.Errorf("bob = %v, want one project_path_without_rows row", got)
	}
}

// TestANamedPathInAnotherCaseIsNotRead: a project_path constraint that spells the home in
// another case is not the form project_path publishes, so nothing is read for it and it is
// reported as outside the scanned homes. Containment folds case on macOS and Windows, so the
// project was read, its rows published the roster's spelling, which SQLite's filter drops, and
// project_path_without_rows then said the files were not read when they were.
func TestANamedPathInAnotherCaseIsNotRead(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "Alice")
	testutil.WriteFile(t, filepath.Join(home, "svc", "go.mod"), "module s\n\nrequire github.com/a/b v1.0.0\n")
	other := filepath.Join(root, "alice", "svc")
	opened := 0
	saved := probeProject
	t.Cleanup(func() { probeProject = saved })
	probeProject = func(home, rel string) error {
		opened++
		return saved(home, rel)
	}
	var kept []string
	for _, r := range run(t, roster(map[string]string{"alice": home}), onPath(other)) {
		if r["project_path"] == other {
			kept = append(kept, r["module_path"]+r["warning"])
		}
	}
	if opened != 0 || len(kept) != 1 || kept[0] != warnSentences[warnNamedPathOutsideHomes] {
		t.Errorf("rows %v after %d opens, want one project_path_outside_scanned_homes row and no open",
			kept, opened)
	}
}

// TestANamedPathNoPublishedPathCanEqualIsNotRead: a named path that is not absolute and clean,
// that redaction would change, or that is longer than the collector admits, cannot equal any
// published project_path, so nothing is opened for it. The first kind gets a project_path_not_published_form row carrying the path as written; the
// second gets no row, because carrying it would publish what redaction removes, though the
// project it names has module rows under the redacted path.
func TestANamedPathNoPublishedPathCanEqualIsNotRead(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	project := filepath.Join(home, "svc")
	tokenDir := filepath.Join(home, "ghp_"+strings.Repeat("a1B2", 9))
	for _, dir := range []string{project, tokenDir} {
		testutil.WriteFile(t, filepath.Join(dir, "go.mod"), "module s\n\nrequire github.com/a/b v1.0.0\n")
	}
	clienter := roster(map[string]string{"alice": home})
	opened := 0
	saved := probeProject
	t.Cleanup(func() { probeProject = saved })
	probeProject = func(home, rel string) error {
		opened++
		return saved(home, rel)
	}

	unpublished := []string{project + string(filepath.Separator), project + "/.", "svc"}
	if runtime.GOOS == "windows" {
		// The prefix Codex records is not part of the published form.
		unpublished = append(unpublished, `\\?\`+project)
	}
	for _, unclean := range unpublished {
		opened = 0
		rows := run(t, clienter, onPath(unclean))
		if len(rows) != 1 || opened != 0 || rows[0]["project_path"] != unclean ||
			rows[0]["warning"] != warnSentences[warnNamedPathNotPublished] {
			t.Errorf("%q: rows = %v after %d opens, want one project_path_not_published_form row and no open",
				unclean, rows, opened)
		}
	}

	opened = 0
	if rows := run(t, clienter, onPath(tokenDir)); len(rows) != 0 || opened != 0 {
		t.Errorf("a path redaction changes: rows = %v after %d opens, want none and no open", rows, opened)
	}

	// Longer than any project_path the collector admits, so the home is not opened for it.
	opened = 0
	long := filepath.Join(home, strings.Repeat("d", devclients.MaxProjectPathLen))
	if rows := run(t, clienter, onPath(long)); len(rows) != 0 || opened != 0 {
		t.Errorf("an overlong path: rows = %v after %d opens, want none and no open", rows, opened)
	}
}

// TestRowBytesBoundsTheEncodedRow: the estimate the byte cap charges is never smaller than the
// published row's JSON encoding, for a project path redaction lengthens, values full of
// characters JSON escapes, and an otherwise empty row. It summed the stored values, so a path
// redaction expanded by half again, and the column names it approximated, were undercounted.
func TestRowBytesBoundsTheEncodedRow(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	expanding := filepath.Join(home, strings.Repeat("--key=x ", 100))
	for name, testCase := range map[string]struct {
		r       row
		account fsscan.UserHome
	}{
		"redaction lengthens the path": {row{Home: home, ProjectPath: expanding,
			Entry: moduleEntry{Path: "github.com/a/b", Version: "v1.0.0"}}, fsscan.UserHome{Name: "alice"}},
		"escapes": {row{Home: home, ProjectPath: filepath.Join(home, `<&>"q`),
			Entry: moduleEntry{Path: "github.com/a/b", Version: "v1.0.0"}},
			fsscan.UserHome{Name: "a\"<>&\u2028\x01\xff", UID: "<1>", ID: "S-1-5-21-&"}},
		"empty": {row{}, fsscan.UserHome{}},
	} {
		labeled := testCase.r
		labeled.User, labeled.UID, labeled.UserID = testCase.account.Name, testCase.account.UID,
			testCase.account.ID
		encoded, err := json.Marshal(publish(labeled))
		if err != nil {
			t.Fatal(err)
		}
		if estimate := rowBytes(testCase.r, testCase.account); estimate < len(encoded) {
			t.Errorf("%s: estimate %d, encoded %d bytes", name, estimate, len(encoded))
		}
	}
	if published := publish(row{Home: home, ProjectPath: expanding})["project_path"]; len(published) <= len(expanding) {
		t.Fatalf("the fixture must lengthen under redaction: %d bytes published from %d", len(published),
			len(expanding))
	}
}
