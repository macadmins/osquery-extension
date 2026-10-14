package mcp_servers

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The invariant classify_test.go existed to protect, carried over to the design that
// replaced it.
//
// That test checked two lists agreed: walkableBasenames said which filenames the walker was
// allowed to collect, and classifyPath mapped a collected path back to a client. A basename
// in the first with no case in the second was found and silently dropped -- a real file,
// present on disk, absent from the table, with nothing saying why.
//
// There are no longer two lists. A file is either named in a probe list or it is not found,
// so the agreement is structural. What still needs asserting is the other half of the same
// property: that the project-rooted list covers every client capable of owning a
// project-local config, because a client missing from it is the same silent drop by a
// different route.
func TestProjectSourcesCoverEveryClient(t *testing.T) {
	// The clients that keep configuration inside a project directory, as opposed to only at
	// a fixed path under the home. Each is a documented convention:
	//   claude_code  <project>/.mcp.json
	//   vscode       <project>/.vscode/mcp.json
	//   cursor       <project>/.cursor/mcp.json
	//   codex        <project>/.codex/config.toml
	wantClients := []string{"claude_code", "codex", "cursor", "vscode"}

	var gotClients []string
	for _, src := range projectProbes {
		gotClients = append(gotClients, src.client)
		// Every probe must have an extractor, or the file is read and thrown away -- which
		// is the drop this test is about, one step later.
		if src.extract == nil {
			t.Errorf("project probe for %q has no extractor", src.client)
		}
		if src.relPath == "" {
			t.Errorf("project probe for %q has no path", src.client)
		}
	}
	sort.Strings(gotClients)
	if !reflect.DeepEqual(gotClients, wantClients) {
		t.Errorf("project probes cover %v, want %v", gotClients, wantClients)
	}

	// And every client a project probe reports must be in the emitted enum, or the row is
	// found, built, and then rewritten to "unknown" by validateEnum.
	for _, src := range projectProbes {
		if _, ok := allowedClients[src.client]; !ok {
			t.Errorf("project probe client %q is not in allowedClients, so its rows would "+
				"be emitted as unknown", src.client)
		}
	}
	// The same for the home-rooted list, which is the larger of the two.
	for _, src := range homeProbes {
		if _, ok := allowedClients[src.client]; !ok {
			t.Errorf("home probe client %q is not in allowedClients", src.client)
		}
		if src.extract == nil {
			t.Errorf("home probe for %q has no extractor", src.relPath)
		}
	}
}

// The rule on what may be read from a ~/.claude.json project entry.
//
// The same object that carries the server-name arrays also carries `lastSessionFirstPrompt`:
// the literal text of the last thing the user typed at the client. Reading the entry into a
// map would put that one field access away from a column. The production code decodes into a
// struct naming exactly the fields it needs, which cannot reach the rest; this asserts the
// property from the outside, by handing the lister a prompt containing a credential and
// checking no part of it survives anywhere in the result.
//
// The field count is not the invariant and has already changed once -- workspace trust was
// added when it turned out to decide whether a committed settings file may approve its own
// servers. What has to hold is that every field is named explicitly.
func TestClaudeProjectsReadsOnlyDeclaredFields(t *testing.T) {
	home := t.TempDir()
	const secret = "sk-ant-api03-ZZZZtotallyopaquesecretZZZZ"
	doc := map[string]any{
		"projects": map[string]any{
			filepath.Join(home, "code", "repo"): map[string]any{
				"enabledMcpjsonServers":  []string{"github"},
				"disabledMcpjsonServers": []string{"scary"},
				"hasTrustDialogAccepted": true,
				// The field that must never be read.
				"lastSessionFirstPrompt": "here is my key " + secret + " please use it",
				"history":                []string{"another prompt with " + secret},
				"exampleFiles":           []string{"/Users/someone/" + secret + ".txt"},
			},
		},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	refs, warnings := claudeProjects(home, data)
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if len(refs) != 1 {
		t.Fatalf("refs = %+v, want one project", refs)
	}
	if refs[0].Rel != filepath.Join("code", "repo") {
		t.Errorf("Rel = %q", refs[0].Rel)
	}
	// The two arrays that may be read were read.
	if !reflect.DeepEqual(refs[0].Approval.Certain.Enabled, []string{"github"}) {
		t.Errorf("Enabled = %v, want [github]", refs[0].Approval.Certain.Enabled)
	}
	if !reflect.DeepEqual(refs[0].Approval.Certain.Disabled, []string{"scary"}) {
		t.Errorf("Disabled = %v, want [scary]", refs[0].Approval.Certain.Disabled)
	}
	if !refs[0].TrustDialogAccepted {
		t.Error("the workspace trust flag was not read")
	}
	// And nothing else did. Asserted over the whole struct rather than field by field, so a
	// field added later is covered without anyone remembering to extend this.
	origins := make([]string, 0, len(refs[0].Origins))
	for origin := range refs[0].Origins {
		origins = append(origins, string(origin))
	}
	sort.Strings(origins)
	rendered := strings.Join([]string{
		refs[0].Rel, refs[0].Abs, strings.Join(origins, ","),
		strings.Join(refs[0].Approval.Certain.Enabled, ","),
		strings.Join(refs[0].Approval.Certain.Disabled, ","),
	}, "\x00")
	if strings.Contains(rendered, secret) {
		t.Errorf("the prompt's secret reached the project reference: %q", rendered)
	}
}

// Approval is per server, not per project, which is the shape of the two arrays.
func TestApprovalState(t *testing.T) {
	project := projectRef{
		Rel:      "code/repo",
		Approval: claudeApproval{Certain: approvalEvidence{Enabled: []string{"github"}, Disabled: []string{"scary"}}, Known: true},
	}
	for _, tc := range []struct {
		client, server string
		want           approvalState
	}{
		{"claude_code", "github", approvalEnabled},
		{"claude_code", "scary", approvalDisabled},
		// The value this column was added for: declared in .mcp.json, never approved, so
		// Claude Code will not run it. Reported as enabled before, which is a false
		// positive in a security inventory.
		{"claude_code", "pending", approvalNotApproved},
		// Another client's config in the same directory has no approval step and must not
		// borrow Claude's answer.
		{"cursor", "github", approvalNotApplicable},
		{"vscode", "pending", approvalNotApplicable},
	} {
		if got := project.approvalFor(tc.client, tc.server); got != tc.want {
			t.Errorf("approvalFor(%q, %q) = %q, want %q", tc.client, tc.server, got, tc.want)
		}
	}

	// Evidence that could not be read is unknown, not a decision. Checked here rather than
	// only end-to-end because this is the function that decides it.
	unreadable := projectRef{Approval: claudeApproval{Known: false}}
	if got := unreadable.approvalFor("claude_code", "anything"); got != approvalUnknown {
		t.Errorf("an undecodable project entry = %q, want %q", got, approvalUnknown)
	}

	// A name in both lists resolves to disabled. Reporting the more restrictive of a
	// contradictory pair is the safe direction: a server reported off that is on is a
	// missed row, one reported on that is off is a false positive.
	both := projectRef{Approval: claudeApproval{Certain: approvalEvidence{Enabled: []string{"x"}, Disabled: []string{"x"}}, Known: true}}
	if got := both.approvalFor("claude_code", "x"); got != approvalDisabled {
		t.Errorf("a name in both lists = %q, want %q", got, approvalDisabled)
	}
}

// A project outside the home is counted with no path, and a deleted one is silent.
func TestProjectCollectorReportsWithoutPaths(t *testing.T) {
	home := "/Users/alice"
	collector := newProjectCollector(home, originClaudeJSON)
	collector.add("/Users/alice/code/good", claudeApproval{Known: true})
	// Outside the home: a legitimate configuration this declines to follow.
	collector.add("/Users/other/secret-project-name", claudeApproval{Known: true})
	collector.add("/Users/Shared/another-secret", claudeApproval{Known: true})
	// Not a usable absolute path.
	collector.add("relative/path", claudeApproval{Known: true})
	// A remote origin, which is a different fact from being outside the home.
	collector.addFileURL("vscode-remote://ssh-remote+box/home/alice/p", originVSCodeWorkspace)

	refs, warnings := collector.result()
	if len(refs) != 1 || refs[0].Rel != "code/good" {
		t.Fatalf("refs = %+v, want the one contained project", refs)
	}

	byCode := make(map[warnCode]warning)
	for _, w := range warnings {
		byCode[w.Code] = w
	}
	if got := byCode[warnProjectOutsideHome].Count; got != 2 {
		t.Errorf("outside-home count = %d, want 2", got)
	}
	if got := byCode[warnProjectMalformed].Count; got != 1 {
		t.Errorf("malformed count = %d, want 1", got)
	}
	if got := byCode[warnProjectRemoteOrigin].Count; got != 1 {
		t.Errorf("remote-origin count = %d, want 1", got)
	}
	// The whole point: not one of these rendered warnings may carry a path from inside a
	// user's home. ScanResult.Inaccessible already established that reasoning in this
	// package, and a per-project diagnostic naming the directory would undo it.
	for _, w := range warnings {
		rendered := w.render()
		for _, leaked := range []string{"secret-project-name", "another-secret", "box", "alice"} {
			if strings.Contains(rendered, leaked) {
				t.Errorf("warning %q leaked %q", rendered, leaked)
			}
		}
	}
}

// A project recorded by two clients is probed once, keeping the approvals whichever list was
// read first.
func TestMergeProjectsDedupsAndKeepsApprovals(t *testing.T) {
	fromCodex := []projectRef{{Rel: "code/repo",
		Origins:  map[originCode]struct{}{originCodexTOML: {}},
		Approval: claudeApproval{Known: true}}}
	fromClaude := []projectRef{{Rel: "code/repo",
		Origins:  map[originCode]struct{}{originClaudeJSON: {}},
		Approval: claudeApproval{Certain: approvalEvidence{Enabled: []string{"github"}}, Known: true}}}

	merged, warnings := mergeProjects(fromCodex, fromClaude)
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if len(merged) != 1 {
		t.Fatalf("merged = %+v, want one project", merged)
	}
	// Codex's list was read first and carries no approvals. Keeping it as-is would have
	// silently lost the approval state for the project.
	if !reflect.DeepEqual(merged[0].Approval.Certain.Enabled, []string{"github"}) {
		t.Errorf("Enabled = %v, want [github] merged in from the later sighting",
			merged[0].Approval.Certain.Enabled)
	}
}

// The project list is capped, and exceeding the cap is reported rather than silently
// truncating -- which is the same shape of loss the walk's truncation was.
func TestProjectListCapIsReported(t *testing.T) {
	home := "/Users/alice"
	collector := newProjectCollector(home, originClaudeJSON)
	for i := 0; i < maxProjects+5; i++ {
		collector.add(filepath.Join(home, "p"+strconv.Itoa(i)), claudeApproval{Known: true})
	}
	refs, warnings := collector.result()
	if len(refs) != maxProjects {
		t.Errorf("refs = %d, want the cap of %d", len(refs), maxProjects)
	}
	var found bool
	for _, w := range warnings {
		if w.Code == warnProjectListTruncated {
			found = true
			if w.Limit != maxProjects {
				t.Errorf("truncation limit = %d, want %d", w.Limit, maxProjects)
			}
		}
	}
	if !found {
		t.Error("exceeding the project cap was not reported")
	}
}

// The listers are deterministic: the same file yields the same projects in the same order.
//
// Map iteration is random in Go, so a lister that did not sort would admit a different subset
// under the cap on every run and emit them in a different order -- which differential logging
// reports as rows removed and re-added on a host where nothing changed.
func TestProjectListersAreDeterministic(t *testing.T) {
	home := t.TempDir()
	projects := map[string]any{}
	for i := 0; i < 40; i++ {
		projects[filepath.Join(home, "p"+strconv.Itoa(i))] = map[string]any{}
	}
	data, err := json.Marshal(map[string]any{"projects": projects})
	if err != nil {
		t.Fatal(err)
	}
	first, _ := claudeProjects(home, data)
	for attempt := 0; attempt < 5; attempt++ {
		again, _ := claudeProjects(home, data)
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("project list differed between runs over identical bytes")
		}
	}
}

// Codex's project keys are read and its values are not.
func TestCodexProjectsReadsKeysOnly(t *testing.T) {
	home := t.TempDir()
	const secret = "ghp_ZZZZopaquesecretvaluethatmustnotescapeZZZZ"
	config := "[projects.\"" + filepath.Join(home, "code", "repo") + "\"]\n" +
		"trust_level = \"trusted\"\n" +
		// A value this table has no field for and must not decode.
		"notes = \"my token is " + secret + "\"\n"

	refs, warnings := codexProjects(home, []byte(config))
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if len(refs) != 1 || refs[0].Rel != filepath.Join("code", "repo") {
		t.Fatalf("refs = %+v", refs)
	}
	if strings.Contains(refs[0].Rel+refs[0].Abs, secret) {
		t.Error("a project value reached the reference")
	}
}

// vscodeWorkspaceProjects against a synthetic fixture.
//
// This machine has no workspaceStorage directory for any fork, so the lister cannot be
// verified against a real one and the fixture is the only coverage it has. Stated in the
// table README as well, because it is a limit of the verification rather than of the code.
func TestVSCodeWorkspaceProjects(t *testing.T) {
	home := t.TempDir()
	storage := filepath.Join(home, appSupport("Code", "User", "workspaceStorage"))
	// A generated directory name, which is why this needs a listing rather than a path.
	writeTestFile(t, filepath.Join(storage, "a1b2c3d4", "workspace.json"),
		`{"folder":"file://`+filepath.ToSlash(filepath.Join(home, "code", "repo"))+`"}`)
	// A multi-root workspace records `workspace`, not `folder`. Only `folder` is read, and
	// this entry is therefore skipped rather than guessed at.
	writeTestFile(t, filepath.Join(storage, "e5f6a7b8", "workspace.json"),
		`{"workspace":"file://`+filepath.ToSlash(filepath.Join(home, "multi.code-workspace"))+`"}`)
	// A remote workspace, which names a filesystem that is not this one.
	writeTestFile(t, filepath.Join(storage, "c9d0e1f2", "workspace.json"),
		`{"folder":"vscode-remote://ssh-remote%2Bbox/home/alice/p"}`)

	refs, _, _ := vscodeWorkspaceProjects(context.Background(), home, "",
		time.Now().Add(time.Minute))
	var rels []string
	for _, ref := range refs {
		rels = append(rels, ref.Rel)
	}
	if !reflect.DeepEqual(rels, []string{filepath.Join("code", "repo")}) {
		t.Errorf("rels = %v, want just the local folder", rels)
	}
}

// writeTestFile creates a file and every parent directory.
func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A directory holding more entries than the cap yields the capped list, not nothing.
//
// ListDirNamesUnder returns the names it could fit *and* ErrTooLarge, so the caller can use
// the partial listing and report the shortfall. All three callers in this package tested
// `err != nil` and skipped the level, so an over-cap directory produced zero entries instead
// of the cap's worth -- a bounded answer turned into a silently empty one, which is exactly
// the failure this table is written against. listCapped is the one place that contract is
// applied now.
func TestListCappedUsesThePartialListing(t *testing.T) {
	home := t.TempDir()
	for i := 0; i < 12; i++ {
		if err := os.MkdirAll(filepath.Join(home, "many", "d"+strconv.Itoa(i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Over the cap: the names must still come back, flagged short.
	names, truncated, err := listCapped(home, "many", 5)
	if err != nil {
		t.Fatalf("an over-cap listing must not be an error: %v", err)
	}
	if !truncated {
		t.Error("an over-cap listing was not flagged as short")
	}
	if len(names) != 5 {
		t.Errorf("names = %d, want the cap of 5; a short listing must not be empty", len(names))
	}

	// Within the cap: everything, not flagged.
	names, truncated, err = listCapped(home, "many", 50)
	if err != nil || truncated || len(names) != 12 {
		t.Errorf("a complete listing came back as (%d names, truncated=%v, err=%v)",
			len(names), truncated, err)
	}

	// Absent: silent, because most of these directories do not exist on most hosts.
	names, truncated, err = listCapped(home, "nothing-here", 50)
	if err != nil || truncated || len(names) != 0 {
		t.Errorf("an absent directory came back as (%d names, truncated=%v, err=%v)",
			len(names), truncated, err)
	}
}
