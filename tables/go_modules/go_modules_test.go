package go_modules

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/osquery/osquery-go/plugin/table"

	"github.com/macadmins/osquery-extension/pkg/devclients"
	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/macadmins/osquery-extension/pkg/utils"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

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
func claudeList(t *testing.T, home string, projects ...string) {
	t.Helper()
	var entries []string
	for _, project := range projects {
		entries = append(entries, strconv.Quote(project)+`:{"lastSessionFirstPrompt":"never read"}`)
	}
	writeFile(t, filepath.Join(home, ".claude.json"), `{"projects":{`+strings.Join(entries, ",")+`}}`)
}

const goMod = `module example.com/svc

go 1.25

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
	writeFile(t, filepath.Join(home, ".codex", "config.toml"),
		"[projects."+strconv.Quote(codexProject)+"]\ntrust_level = \"untrusted\"\n")
	storage := filepath.Join(home, devclients.AppSupportFork("Code", "User", "workspaceStorage")[0])
	writeFile(t, filepath.Join(storage, "abc", "workspace.json"),
		`{"folder":"`+fileURL(vscodeProject)+`"}`)

	writeFile(t, filepath.Join(claudeProject, "go.mod"), goMod)
	writeFile(t, filepath.Join(claudeProject, "go.sum"), goSum)
	writeFile(t, filepath.Join(codexProject, "go.mod"), "module example.com/tool\n\nrequire github.com/codex/dep v0.1.0\n")
	writeFile(t, filepath.Join(vscodeProject, "go.mod"), "module example.com/ws\n\nrequire github.com/vscode/dep v0.2.0\n")
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
	writeFile(t, filepath.Join(project, "go.mod"), "module x\n\nrequire github.com/a/b v1.0.0\n")

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

// TestAnUnreadableProjectListIsReported: a list that exists and cannot be read means projects in
// it are missing, which one warning row for the user says. The project found through another
// client's list was read in full, so its rows stay complete: scan_complete describes a
// project's own files, not the user's discovery.
func TestAnUnreadableProjectListIsReported(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	writeFile(t, filepath.Join(home, ".claude.json"), "{not json --token=opaqueSecret")
	project := filepath.Join(home, "tool")
	writeFile(t, filepath.Join(home, ".codex", "config.toml"), "[projects."+strconv.Quote(project)+"]\n")
	writeFile(t, filepath.Join(project, "go.mod"), "module x\n\nrequire github.com/a/b v1.0.0\n")

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
	if got := warnings(rows); len(got) != 1 || !strings.HasPrefix(got[0], warnSentences[warnProjectListUnreadable]) {
		t.Errorf("warnings = %v", got)
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
	writeFile(t, filepath.Join(project, "go.mod"), goMod)
	writeFile(t, filepath.Join(project, "go.sum"), goSum+"two fields\n")
	writeFile(t, filepath.Join(clean, "go.mod"), "module example.com/tool\n\nrequire github.com/a/b v1.0.0\n")

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
	writeFile(t, filepath.Join(project, "go.mod"), "module example.com/svc\n\nrequire gopkg.in/old.v1 v1.0.0\n\n"+
		"replace gopkg.in/old.v1 v1.0.0 => github.com/new/old v1.5.3\n")
	writeFile(t, filepath.Join(project, "go.sum"), "github.com/new/old v1.5.3 "+validHashField+"\n"+
		"github.com/new/old v1.5.3/go.mod "+validHashField+"\n")
	writeFile(t, filepath.Join(sumOnly, "go.sum"), "example.com/x v1.0.0/go.mod "+validHashField+"\n")

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
	writeFile(t, filepath.Join(project, "go.mod"),
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
	writeFile(t, filepath.Join(project, "go.mod"), "module x\n\nrequire github.com/a/b v1.0.0\n")
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
	if len(rows) != 1 || !strings.HasPrefix(rows[0]["warning"], warnSentences[warnCancelledPreHome]) {
		t.Errorf("rows = %v", rows)
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
	home := filepath.Join(string(filepath.Separator), "Users", "alice")
	for _, tc := range []struct{ name, path, want string }{
		{"inside the home", filepath.Join(home, "code", "svc"), filepath.Join(home, "code", "svc")},
		{"outside the home", filepath.Join(string(filepath.Separator), "Users", "bob", "svc"), ""},
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
		{fsscan.ErrUserspaceFilesystem, warnProjectUserspaceFS, true},
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
	writeFile(t, filepath.Join(project, "go.mod"), "module x\n\nrequire example.com/dep v1.0.0\n\n"+
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
		writeFile(t, filepath.Join(project, "go.mod"), goMod) // two requirements
		writeFile(t, filepath.Join(project, "go.sum"), goSum) // records for both, so two rows
	}
	found := discoverWithin(context.Background(), roster(homes), nil, 1)
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
	if len(byUser["bob"]) != 1 || !strings.HasPrefix(byUser["bob"][0]["warning"], warnSentences[warnRowLimitPreHome]) {
		t.Errorf("bob rows = %v, want one row_limit_reached_before_home", byUser["bob"])
	}
}

// TestFileFindingsReachTheTable: a checksum conflict and an over-long file each produce their
// row, and the file's module rows are marked incomplete.
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
			writeFile(t, filepath.Join(project, "go.sum"), tc.sum)
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
// and a cancelled query gets nothing back even from the cache.
func TestASharedHomeIsReusedAfterTheDeadline(t *testing.T) {
	home := filepath.Join(t.TempDir(), "shared")
	project := filepath.Join(home, "svc")
	claudeList(t, home, project)
	writeFile(t, filepath.Join(project, "go.mod"), "module x\n\nrequire github.com/a/b v1.0.0\n")
	alice := fsscan.UserHome{Name: "alice", ID: "501", Path: home}
	build := fsscan.UserHome{Name: "build", ID: "502", Path: home}
	other := fsscan.UserHome{Name: "other", ID: "503", Path: filepath.Join(t.TempDir(), "other")}
	scanned := map[string][]row{}

	first := rowsForHome(context.Background(), alice, time.Now().Add(time.Minute), 100, 100, scanned)
	if moduleRows(first) != 1 {
		t.Fatalf("first account rows = %+v", first)
	}
	expired := time.Now().Add(-time.Second)
	second := rowsForHome(context.Background(), build, expired, 100, 100, scanned)
	if moduleRows(second) != 1 || second[0].User != "build" || second[0].UserID != "502" {
		t.Errorf("second account rows = %+v, want the cached row labeled for build", second)
	}
	if rows := rowsForHome(context.Background(), other, expired, 100, 100, scanned); len(rows) != 1 ||
		rows[0].Warning.Code != warnBudgetExhaustedPreHome {
		t.Errorf("an unscanned home after the deadline = %+v", rows)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if rows := rowsForHome(cancelled, build, time.Now().Add(time.Minute), 100, 100, scanned); len(rows) != 1 ||
		rows[0].Warning.Code != warnCancelledPreHome {
		t.Errorf("a cancelled query reused the cache: %+v", rows)
	}
}

// TestAGoLandProjectIsListed: a project recorded only in GoLand's recent-projects list, in the
// format GoLand 2026.2 writes, is found and read.
func TestAGoLandProjectIsListed(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	project := filepath.Join(home, "go", "src", "svc")
	writeFile(t, filepath.Join(home, devclients.AppSupportDir(), "JetBrains", "GoLand2026.2", "options", "recentProjects.xml"),
		`<application><component name="RecentProjectsManager"><option name="additionalInfo"><map>`+
			`<entry key="$USER_HOME$/go/src/svc"><value><RecentProjectMetaInfo opened="true" /></value></entry>`+
			`<entry key="$APPLICATION_CONFIG_DIR$/projects/GoLandWorkspace"><value><RecentProjectMetaInfo hidden="true" /></value></entry>`+
			`</map></option></component></application>`)
	writeFile(t, filepath.Join(project, "go.mod"), "module x\n\nrequire github.com/goland/dep v1.0.0\n")

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	if got := modules(rows); len(got) != 1 || !strings.Contains(got[0], "github.com/goland/dep") {
		t.Errorf("modules = %v", got)
	}
	if got := warnings(rows); len(got) != 0 {
		t.Errorf("warnings = %v, want none", got)
	}
}

// TestTheProjectCapIsReported: a user recording more distinct projects than maxProjects gets one
// project_list_truncated row with the limit. The projects that were read keep complete rows.
func TestTheProjectCapIsReported(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	projects := make([]string, 0, maxProjects+1)
	for index := 0; index <= maxProjects; index++ {
		projects = append(projects, filepath.Join(home, "p", strconv.Itoa(index)))
	}
	claudeList(t, home, projects...)
	writeFile(t, filepath.Join(projects[0], "go.mod"), "module x\n\nrequire github.com/a/b v1.0.0\n")

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	got := warnings(rows)
	if len(got) != 1 || !strings.HasPrefix(got[0], warnSentences[warnProjectListTruncated]) ||
		!strings.Contains(got[0], "limit="+strconv.Itoa(maxProjects)) {
		t.Errorf("warnings = %v, want one project_list_truncated with limit=%d", got, maxProjects)
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
	writeFile(t, filepath.Join(storage, "abc", "workspace.json"), `{"folder":"`+fileURL(vscodeProject)+`"}`)
	var entries strings.Builder
	for index := 0; index < maxProjects-1; index++ {
		entries.WriteString(`<entry key="$USER_HOME$/jb/` + strconv.Itoa(index) + `"><value><RecentProjectMetaInfo /></value></entry>`)
	}
	writeFile(t, filepath.Join(home, devclients.AppSupportDir(), "JetBrains", "GoLand2026.2", "options", "recentProjects.xml"),
		`<application><component name="RecentProjectsManager"><option name="additionalInfo"><map>`+entries.String()+
			`</map></option></component></application>`)
	claudeList(t, home, claudeProject)
	writeFile(t, filepath.Join(vscodeProject, "go.mod"), "module x\n\nrequire github.com/vscode/dep v1.0.0\n")
	writeFile(t, filepath.Join(claudeProject, "go.mod"), "module y\n\nrequire github.com/claude/dep v1.0.0\n")

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

	collector := devclients.NewCollector(home, maxProjects)
	if addAgentLists(context.Background(), home, time.Now().Add(-time.Second), collector, note) {
		t.Error("the lists were read after the deadline")
	}
	if len(collector.Projects()) != 0 || len(noted) != 1 || noted[0].Code != warnBudgetExhaustedInHome {
		t.Errorf("projects %v notes %+v, want none and one budget_exhausted_during_home", collector.Projects(), noted)
	}

	noted = nil
	collector = devclients.NewCollector(home, maxProjects)
	if !addAgentLists(context.Background(), home, time.Now().Add(time.Minute), collector, note) ||
		len(collector.Projects()) != 1 || len(noted) != 0 {
		t.Errorf("projects %v notes %+v, want the Claude project and no notes", collector.Projects(), noted)
	}
}

// TestProjectsStoredElsewhereAreCounted: a project in a cloud provider's folder, a project on a
// network filesystem, and a project with a module file whose content is not on this disk are
// each counted into one descriptive row and not read. The project stored locally is listed and
// stays complete.
func TestProjectsStoredElsewhereAreCounted(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	local := filepath.Join(home, "local")
	cloudFolder := filepath.Join(home, "cloud")
	network := filepath.Join(home, "network")
	evicted := filepath.Join(home, "evicted")
	for _, project := range []string{local, cloudFolder, network, evicted} {
		writeFile(t, filepath.Join(project, "go.mod"), "module x\n\nrequire github.com/"+filepath.Base(project)+"/dep v1.0.0\n")
	}
	claudeList(t, home, local, cloudFolder, network, evicted)

	savedCloud, savedProbe, savedPlaceholder := underCloudStorage, probeProject, cloudPlaceholder
	t.Cleanup(func() { underCloudStorage, probeProject, cloudPlaceholder = savedCloud, savedProbe, savedPlaceholder })
	underCloudStorage = func(rel string) bool { return rel == "cloud" }
	probeProject = func(home, rel string) error {
		if rel == "network" {
			return fsscan.ErrNetworkFilesystem
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
		!strings.Contains(got[1], "count=2") {
		t.Errorf("warnings = %v, want one network row with count=1 and one cloud row with count=2", got)
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
	writeFile(t, filepath.Join(workspaceOnly, "go.work"), "go 1.25\n\nuse ./svc\n")
	writeFile(t, filepath.Join(workspaceAndModule, "go.work"), "go 1.25\n\nuse .\n")
	writeFile(t, filepath.Join(workspaceAndModule, "go.mod"), "module x\n\nrequire github.com/mixed/dep v1.0.0\n")
	writeFile(t, filepath.Join(plain, "go.mod"), "module y\n\nrequire github.com/plain/dep v1.0.0\n")
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

// fileURL renders a path the way VS Code records a workspace folder: file:///Users/alice/x on
// POSIX and file:///C:/Users/alice/x on Windows, where the drive letter follows a third slash.
// Joining "file://" to a Windows path directly gives file://C:/..., whose host is "C:", which
// the reader correctly refuses as a remote location.
func fileURL(path string) string {
	slashed := filepath.ToSlash(path)
	if !strings.HasPrefix(slashed, "/") {
		slashed = "/" + slashed
	}
	return "file://" + slashed
}

// TestABudgetStopBetweenFilesMarksThatProjectIncomplete: when the query stops after a project's
// go.mod and before its go.sum, the go.mod rows are listed and marked incomplete, because the
// project's other file was not read.
func TestABudgetStopBetweenFilesMarksThatProjectIncomplete(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	project := filepath.Join(home, "svc")
	writeFile(t, filepath.Join(project, "go.mod"), goMod)
	writeFile(t, filepath.Join(project, "go.sum"), goSum)
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
	rows := discoverHome(ctx, account, time.Now().Add(time.Hour), maxRows, maxRows)
	if moduleRows(rows) == 0 {
		t.Fatalf("rows = %+v, want the go.mod rows", rows)
	}
	for _, r := range rows {
		if r.Entry.Path != "" && r.ScanComplete {
			t.Errorf("a row of a half-read project is complete: %+v", r)
		}
	}
}

// panickingClienter panics with a value that quotes input, as a parser panic can.
type panickingClienter struct{}

func (panickingClienter) NewOsqueryClient() (utils.OsqueryClient, error) {
	panic("unexpected token in TOKEN=opaqueSecret")
}

// TestAPanicReachesOsqueryAsFixedText: a panic is recovered into an error, and the panic value,
// which can quote a file the table was reading, does not reach osquery.
func TestAPanicReachesOsqueryAsFixedText(t *testing.T) {
	rows, err := generate(context.Background(), table.QueryContext{}, panickingClienter{})
	if err == nil || rows != nil {
		t.Fatalf("rows = %v, err = %v; want no rows and an error", rows, err)
	}
	if strings.Contains(err.Error(), "opaqueSecret") || strings.Contains(err.Error(), "goroutine") {
		t.Errorf("the error carries the panic value or the stack: %q", err)
	}
}
