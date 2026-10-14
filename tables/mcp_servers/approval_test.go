package mcp_servers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
)

// The approval resolver, including the precedence rule that makes it safe.
//
// Claude documents that a `disabledMcpjsonServers` entry in ANY settings file rejects the
// server, so rejection is a union across sources and wins over every approval. Reading only
// the project-history arrays produced wrong answers in both directions: servers approved by
// `enableAllProjectMcpServers` reported not_approved, and a server rejected in settings while
// approved in history reported enabled.
func TestClaudeApprovalResolver(t *testing.T) {
	for _, tc := range []struct {
		name     string
		evidence claudeApproval
		server   string
		want     approvalState
	}{
		{"approved by name", claudeApproval{Certain: approvalEvidence{Enabled: []string{"srv"}}, Known: true},
			"srv", approvalEnabled},
		{"approved by enable-all", claudeApproval{Certain: approvalEvidence{EnableAll: boolPtr(true)}, Known: true},
			"srv", approvalEnabled},
		// An explicit false is not an omission, which is the distinction a plain bool lost.
		{"explicit false approves nothing",
			claudeApproval{Certain: approvalEvidence{EnableAll: boolPtr(false)}, Known: true}, "srv", approvalNotApproved},
		// And it does not revoke a name someone approved individually.
		{"explicit false with an individual approval", claudeApproval{Certain: approvalEvidence{EnableAll: boolPtr(false), Enabled: []string{"srv"}}, Known: true},
			"srv", approvalEnabled},
		{"rejected by name", claudeApproval{Certain: approvalEvidence{Disabled: []string{"srv"}}, Known: true},
			"srv", approvalDisabled},
		{"neither", claudeApproval{Known: true}, "srv", approvalNotApproved},
		// Rejection wins over an approval from another source, which is the documented
		// rule and the one that stops a rejected server reading as enabled.
		{"disabled beats enabled", claudeApproval{Certain: approvalEvidence{Enabled: []string{"srv"}, Disabled: []string{"srv"}}, Known: true},
			"srv", approvalDisabled},
		{"disabled beats enable-all", claudeApproval{Certain: approvalEvidence{EnableAll: boolPtr(true), Disabled: []string{"srv"}}, Known: true},
			"srv", approvalDisabled},
		// A rejection that was read is decisive even when another source was not, because
		// no unread source could license running a server this one rejects.
		{"disabled survives unknown", claudeApproval{Certain: approvalEvidence{Disabled: []string{"srv"}}},
			"srv", approvalDisabled},
		// Approving answers do not survive it: an approval this scan could not read is not
		// evidence of non-approval either way.
		{"unknown when a source failed", claudeApproval{Certain: approvalEvidence{Enabled: []string{"other"}}},
			"srv", approvalUnknown},
		{"enable-all does not survive unknown", claudeApproval{Certain: approvalEvidence{EnableAll: boolPtr(true)}},
			"srv", approvalUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.evidence.stateFor(tc.server); got != tc.want {
				t.Errorf("stateFor(%q) = %q, want %q", tc.server, got, tc.want)
			}
		})
	}
}

// merge is a union with conjunctive certainty, so no source's rejection is lost.
func TestClaudeApprovalMerge(t *testing.T) {
	a := claudeApproval{Certain: approvalEvidence{Enabled: []string{"one"}}, Known: true}
	b := claudeApproval{Certain: approvalEvidence{Disabled: []string{"two"}, EnableAll: boolPtr(true)}, Known: true}
	merged := a.merge(b)
	if merged.Certain.EnableAll == nil || !*merged.Certain.EnableAll || !merged.Known {
		t.Errorf("merged = %+v, want EnableAll set true and Known", merged)
	}
	if merged.stateFor("two") != approvalDisabled {
		t.Error("a rejection from the second source was lost")
	}
	if merged.stateFor("one") != approvalEnabled {
		t.Error("an approval from the first source was lost")
	}
	// One unreadable source makes the approving answers unknown.
	if a.merge(claudeApproval{}).stateFor("one") != approvalUnknown {
		t.Error("certainty is not conjunctive")
	}
}

// End to end: the three settings keys reach the column, from user scope and project scope.
func TestApprovalSettingsReachTheColumn(t *testing.T) {
	for _, tc := range []struct {
		name         string
		userSettings string
		projSettings string
		history      map[string]any
		want         approvalState
	}{
		{
			name:         "enableAllProjectMcpServers in user settings",
			userSettings: `{"enableAllProjectMcpServers":true}`,
			want:         approvalEnabled,
		},
		{
			name:         "enabledMcpjsonServers in user settings",
			userSettings: `{"enabledMcpjsonServers":["srv"]}`,
			want:         approvalEnabled,
		},
		{
			// The dangerous case: rejected in settings, approved in project history. The
			// old code read only the history and reported enabled.
			name:         "disabled in settings beats approved in history",
			userSettings: `{"disabledMcpjsonServers":["srv"]}`,
			history:      map[string]any{"enabledMcpjsonServers": []string{"srv"}},
			want:         approvalDisabled,
		},
		{
			// A project's own settings are in scope for that project, which is where
			// settings.local.json legitimately lives.
			name:         "disabled in the project's own settings",
			projSettings: `{"disabledMcpjsonServers":["srv"]}`,
			history:      map[string]any{"enabledMcpjsonServers": []string{"srv"}},
			want:         approvalDisabled,
		},
		{
			name:    "approved in project history alone",
			history: map[string]any{"enabledMcpjsonServers": []string{"srv"}},
			want:    approvalEnabled,
		},
		{
			name:    "no evidence anywhere",
			history: map[string]any{},
			want:    approvalNotApproved,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			project := filepath.Join(home, "code", "repo")
			writeTestFile(t, filepath.Join(project, ".mcp.json"),
				`{"mcpServers":{"srv":{"command":"npx","args":["x"]}}}`)
			entry := tc.history
			if entry == nil {
				entry = map[string]any{}
			}
			recorded, err := json.Marshal(map[string]any{
				"projects": map[string]any{project: entry}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(home, ".claude.json"), recorded, 0o644); err != nil {
				t.Fatal(err)
			}
			if tc.userSettings != "" {
				writeTestFile(t, filepath.Join(home, ".claude", "settings.json"), tc.userSettings)
			}
			if tc.projSettings != "" {
				writeTestFile(t, filepath.Join(project, ".claude", "settings.local.json"),
					tc.projSettings)
			}

			var got approvalState
			for _, row := range serversOnly(discoverForTest("alice", home)) {
				if row.ServerName == "srv" {
					got = row.Approval
				}
			}
			if got != tc.want {
				t.Errorf("approval = %q, want %q", got, tc.want)
			}
		})
	}
}

// An approved server whose legitimate name matches a token shape is still approved.
//
// Matching used the redacted name, so such a server became "[REDACTED]", matched nothing in
// its own approval list, and was reported not_approved though the user had approved it.
// Redaction is many-to-one, so it can never be an identity key.
func TestApprovalMatchesOnTheOriginalName(t *testing.T) {
	home := t.TempDir()
	// A name the redactor recognises as a token shape, used as a real server name.
	const tokenShaped = "ghp_ZZZZopaquelookingbutlegitimatenameZZZZ"
	project := filepath.Join(home, "code", "repo")
	writeTestFile(t, filepath.Join(project, ".mcp.json"),
		`{"mcpServers":{"`+tokenShaped+`":{"command":"npx","args":["x"]}}}`)
	recorded, err := json.Marshal(map[string]any{"projects": map[string]any{
		project: map[string]any{"enabledMcpjsonServers": []string{tokenShaped}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), recorded, 0o644); err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
		if row.rawName != tokenShaped {
			continue
		}
		found = true
		if row.Approval != approvalEnabled {
			t.Errorf("approval = %q, want %q: the approval list holds the original name",
				row.Approval, approvalEnabled)
		}
		// And the published name is still redacted, so fixing the match did not
		// un-redact the column.
		published := serverToRow(row)["server_name"]
		if strings.Contains(published, "opaquelookingbutlegitimate") {
			t.Errorf("server_name published the original name: %q", published)
		}
	}
	if !found {
		t.Fatal("the server was not found")
	}
}

// Two distinct token-shaped names get stable, distinct placeholders across repeated parses.
//
// Both redact to exactly "[REDACTED]", so sorting on the published name compared equal
// strings and inherited Go's randomised map order: the same server alternated between
// `[redacted:...]` and `[redacted:...]#2` across runs over identical bytes, which
// differential logging reports as churn on a configuration nobody touched.
func TestPlaceholderOrderingIsStableForCollidingRedactions(t *testing.T) {
	const docTemplate = `{"mcpServers":{` +
		`"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA":{"command":"npx","args":["a"]},` +
		`"ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB":{"command":"uvx","args":["b"]}}}`

	var first map[string]string
	for attempt := 0; attempt < 8; attempt++ {
		rows := finishProcessing("/home/alice", []byte(docTemplate), nil,
			"/home/alice/.cursor/mcp.json", "alice", "cursor", true, MaxFileSize,
			extractEnvelopeSimple)
		got := map[string]string{}
		for _, row := range rows {
			if row.rawName == "" {
				continue
			}
			got[row.rawName] = serverToRow(row)["server_name"]
		}
		if len(got) != 2 {
			t.Fatalf("expected two servers, got %v", got)
		}
		if first == nil {
			first = got
			continue
		}
		for name, placeholder := range first {
			if got[name] != placeholder {
				t.Fatalf("placeholder for %q changed between runs: %q then %q",
					name, placeholder, got[name])
			}
		}
	}
	// Distinct, so the two servers are distinguishable at all.
	var seen []string
	for _, placeholder := range first {
		for _, already := range seen {
			if already == placeholder {
				t.Errorf("two servers share the placeholder %q", placeholder)
			}
		}
		seen = append(seen, placeholder)
	}
}

// Cancellation stops the plugin and workspace passes rather than being noticed afterwards.
func TestPluginAndWorkspacePassesObserveCancellation(t *testing.T) {
	home := t.TempDir()
	for i := 0; i < 5; i++ {
		writeTestFile(t, filepath.Join(home, ".claude", "plugins", "cache", "mp",
			"p"+itoaPad(i), "1.0.0", ".mcp.json"),
			`{"mcpServers":{"s`+itoaPad(i)+`":{"command":"npx","args":["x"]}}}`)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	refs, _, stopped := claudePluginRefs(ctx, home, time.Now().Add(time.Minute))
	if !stopped {
		t.Error("an already-cancelled query did not stop the plugin enumeration")
	}
	if len(refs) != 0 {
		t.Errorf("enumeration returned %d refs after cancellation", len(refs))
	}

	// And an exhausted budget, which is the other way a pass must stop.
	_, _, budgetStopped := claudePluginRefs(context.Background(), home,
		time.Now().Add(-time.Second))
	if !budgetStopped {
		t.Error("an exhausted budget did not stop the plugin enumeration")
	}

	_, _, wsStopped := vscodeWorkspaceProjects(ctx, home, "", time.Now().Add(time.Minute))
	if !wsStopped {
		t.Error("an already-cancelled query did not stop the workspace enumeration")
	}
}

// boolPtr is the settings shape: these keys are tri-state, so the tests have to express
// "omitted" as distinct from "false".
func boolPtr(v bool) *bool { return &v }

// Settings precedence for the one scalar key.
//
// enableAllProjectMcpServers is a scalar, and Claude resolves scalars by settings precedence:
// project-local overrides user. Merging it with a Boolean OR made an explicit opt-out
// unrepresentable -- a project-local `false` against a user-level `true` still produced
// enabled, because an omitted key and a `false` had already collapsed to the same value.
func TestEnableAllFollowsSettingsPrecedence(t *testing.T) {
	user := claudeApproval{Certain: approvalEvidence{EnableAll: boolPtr(true)}, Known: true}
	for _, tc := range []struct {
		name    string
		project claudeApproval
		want    approvalState
	}{
		// The project says nothing, so the account-wide value stands.
		{"project omits the key", claudeApproval{Known: true}, approvalEnabled},
		// The project opts out, which must win.
		{"project sets false", claudeApproval{Certain: approvalEvidence{EnableAll: boolPtr(false)}, Known: true},
			approvalNotApproved},
		// The project opts out but approves this server by name.
		{"project sets false and names the server", claudeApproval{Certain: approvalEvidence{EnableAll: boolPtr(false), Enabled: []string{"srv"}}, Known: true},
			approvalEnabled},
		// A rejection beats everything, from any source.
		{"project rejects the server", claudeApproval{Certain: approvalEvidence{Disabled: []string{"srv"}}, Known: true}, approvalDisabled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := user.overlay(tc.project).stateFor("srv"); got != tc.want {
				t.Errorf("stateFor = %q, want %q", got, tc.want)
			}
		})
	}
}

// An untrusted workspace's committed settings cannot approve its own servers.
//
// Claude ignores repository-provided approvals until the trust dialog is accepted, which is
// what stops any repository approving its own MCP servers simply by shipping a
// `.claude/settings.json`. Rejections still apply: refusing to run something needs no trust.
func TestWorkspaceTrustGatesCommittedApprovals(t *testing.T) {
	for _, tc := range []struct {
		name      string
		trusted   bool
		committed string
		local     string
		want      approvalState
	}{
		{
			// The reproduction: untrusted, no other approval, and the repository's own
			// committed file turns everything on.
			name:      "untrusted committed enable-all cannot approve",
			committed: `{"enableAllProjectMcpServers":true}`,
			want:      approvalNotApproved,
		},
		{
			name:      "untrusted committed name list cannot approve",
			committed: `{"enabledMcpjsonServers":["srv"]}`,
			want:      approvalNotApproved,
		},
		{
			// Trust accepted, so the same file now counts.
			name: "trusted committed enable-all approves", trusted: true,
			committed: `{"enableAllProjectMcpServers":true}`,
			want:      approvalEnabled,
		},
		{
			// An ordinary untrusted project: Claude waits for the trust dialog before
			// applying the local file's approvals at all, so nothing is approved. This
			// assertion previously expected enabled, on the reasoning that an untracked
			// file belongs to whoever runs Claude -- which described the behaviour before
			// v2.1.207 and is no longer true.
			name:  "untrusted ordinary project: local file does not approve",
			local: `{"enabledMcpjsonServers":["srv"]}`,
			want:  approvalNotApproved,
		},
		{
			// Trusted, so Claude would apply the local file's approvals -- if the file is
			// untracked, which it establishes by running git. This table will not spawn git
			// per project per account per query, so the honest answer is that Claude may
			// well be running this server and the scan cannot tell.
			name: "trusted project: local file approval is uncertain", trusted: true,
			local: `{"enabledMcpjsonServers":["srv"]}`,
			want:  approvalUnknown,
		},
		{
			// enableAllProjectMcpServers from the local file is subject to the same
			// condition, so it reaches the same answer rather than granting outright.
			name: "trusted project: local enable-all is uncertain", trusted: true,
			local: `{"enableAllProjectMcpServers":true}`,
			want:  approvalUnknown,
		},
		{
			// A rejection from the committed file applies whatever the trust state.
			name:      "untrusted committed rejection still rejects",
			committed: `{"disabledMcpjsonServers":["srv"]}`,
			local:     `{"enabledMcpjsonServers":["srv"]}`,
			want:      approvalDisabled,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			const projRel = "code/repo"
			if tc.committed != "" {
				writeTestFile(t, filepath.Join(home, projRel, ".claude", "settings.json"),
					tc.committed)
			}
			if tc.local != "" {
				writeTestFile(t,
					filepath.Join(home, projRel, ".claude", "settings.local.json"), tc.local)
			}
			evidence, warnings := projectApprovalSettings(home, projRel, tc.trusted)
			if len(warnings) != 0 {
				t.Errorf("unexpected warnings: %v", warnings)
			}
			if got := evidence.stateFor("srv"); got != tc.want {
				t.Errorf("stateFor = %q, want %q", got, tc.want)
			}
		})
	}
}

// Project settings are read through the project guard, so the cloud refusal applies to them.
//
// They were read with ReadBoundedUnder, which skips the cloud-directory refusal and the
// placeholder check -- and because the settings pass runs before the configuration probes, it
// was the first thing to touch a provider-backed file and could start the download the later
// probe would have refused.
//
// Darwin-only, and that is the point rather than a convenience. `Library/Mobile Documents` is
// a macOS file-provider mount and the prefix rule fires only there; on Linux and Windows a
// directory of that name is an ordinary directory and must be read. An earlier version of
// this test asserted the refusal unconditionally, which passes on the development machine and
// fails the coverage workflow, which runs `go test ./...` on Ubuntu -- so it would have broken
// CI rather than caught anything. The companion test below covers the other platforms.
func TestProjectApprovalSettingsRespectCloudRefusal(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the Mobile Documents prefix is a macOS file-provider convention; " +
			"TestProjectApprovalSettingsReadOrdinaryDirectoriesElsewhere covers the rest")
	}
	home := t.TempDir()
	projRel := filepath.Join("Library", "Mobile Documents", "repo")
	writeTestFile(t, filepath.Join(home, projRel, ".claude", "settings.local.json"),
		`{"disabledMcpjsonServers":["srv"]}`)

	evidence, warnings := projectApprovalSettings(home, projRel, true)
	// The refusal is reported rather than silent, and the rejection the file carries does
	// not reach the result -- the file was never read.
	if evidence.stateFor("srv") == approvalDisabled {
		t.Error("settings inside a cloud provider directory were read")
	}
	var reported bool
	for _, w := range warnings {
		if w.Code == warnApprovalSettingsUnreadable {
			reported = true
			if w.Class != fsscan.ClassCloudPlaceholder {
				t.Errorf("class = %q, want %q", w.Class, fsscan.ClassCloudPlaceholder)
			}
		}
	}
	if !reported {
		t.Error("a refused settings read produced no diagnostic")
	}
}

// And off macOS the same fixture is an ordinary directory that must be read.
//
// The refusal rules are per-platform conventions, so asserting one platform's rule everywhere
// would both break CI and hide the case where a legitimate Linux or Windows project under a
// similarly named directory is wrongly refused.
func TestProjectApprovalSettingsReadOrdinaryDirectoriesElsewhere(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("covered by TestProjectApprovalSettingsRespectCloudRefusal")
	}
	home := t.TempDir()
	projRel := filepath.Join("Library", "Mobile Documents", "repo")
	writeTestFile(t, filepath.Join(home, projRel, ".claude", "settings.local.json"),
		`{"disabledMcpjsonServers":["srv"]}`)

	evidence, warnings := projectApprovalSettings(home, projRel, true)
	if len(warnings) != 0 {
		t.Errorf("an ordinary directory produced warnings: %v", warnings)
	}
	// A rejection always applies, and reading it here proves the directory was not refused.
	if got := evidence.stateFor("srv"); got != approvalDisabled {
		t.Errorf("stateFor = %q, want %q: this is an ordinary directory on %s",
			got, approvalDisabled, runtime.GOOS)
	}
}

// A settings file that exists and cannot be used says which evidence needs repair.
//
// Read and decode failures returned unknown approval and nothing else, so an administrator
// could not tell malformed JSON from denied access from an oversized file, nor which file to
// go and look at.
func TestUnusableApprovalSettingsAreDiagnosed(t *testing.T) {
	home := t.TempDir()
	const projRel = "code/repo"
	// The reproduction: a field of the wrong type, which decodes to an error.
	writeTestFile(t, filepath.Join(home, projRel, ".claude", "settings.local.json"),
		`{"enabledMcpjsonServers":123}`)

	evidence, warnings := projectApprovalSettings(home, projRel, true)
	if got := evidence.stateFor("srv"); got != approvalUnknown {
		t.Errorf("stateFor = %q, want %q", got, approvalUnknown)
	}
	if len(warnings) == 0 {
		t.Fatal("an unusable settings file produced no warning")
	}
	if warnings[0].Code != warnApprovalSettingsUnreadable {
		t.Errorf("code = %q, want %q", warnings[0].Code, warnApprovalSettingsUnreadable)
	}
	// The shape distinguishes a parse failure from a read failure, which have different
	// remedies, and the rendered text carries neither the file's bytes nor its path.
	// The real parser metadata rather than a blanket label. `{"enabledMcpjsonServers":123}`
	// is a valid top-level object with one wrongly-typed field, and calling that "top level
	// is not an object" sent an administrator after the wrong thing.
	if warnings[0].Shape != shapeWrongType {
		t.Errorf("shape = %q, want %q", warnings[0].Shape, shapeWrongType)
	}
	// And which of the two candidate files failed, since the row names only the directory.
	if warnings[0].Key != "settings_local_json" {
		t.Errorf("key = %q, want the failing file's identity", warnings[0].Key)
	}
	if rendered := warnings[0].render(); strings.Contains(rendered, "123") ||
		strings.Contains(rendered, projRel) {
		t.Errorf("the warning carries input or a path: %q", rendered)
	}
}

// Identical unpublishable names in different sections of one file get stable ordinals.
//
// Sorting by the original name alone left a tie whenever two project sections of
// ~/.claude.json declared the same token-shaped name, and the initial order came from map
// iteration -- so the two rows exchanged `[redacted:...]` and its `#2` variant across repeated
// parses of unchanged bytes, which differential logging reports as churn.
func TestPlaceholderOrderIsTotalAcrossSections(t *testing.T) {
	const shared = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	doc := `{"projects":{` +
		`"/home/alice/one":{"mcpServers":{"` + shared + `":{"command":"npx","args":["a"]}}},` +
		`"/home/alice/two":{"mcpServers":{"` + shared + `":{"command":"uvx","args":["b"]}}}}}`

	var first map[string]string
	for attempt := 0; attempt < 10; attempt++ {
		rows := finishProcessing("/home/alice", []byte(doc), nil,
			"/home/alice/.claude.json", "alice", "claude_code", false, claudeJSONMaxSize,
			extractClaudeCode)
		got := map[string]string{}
		for _, row := range rows {
			if row.rawName == "" {
				continue
			}
			// Keyed on the section, which is what distinguishes the two rows at all.
			got[row.SourceContext] = serverToRow(row)["server_name"]
		}
		if len(got) != 2 {
			t.Fatalf("expected two sections, got %v", got)
		}
		if first == nil {
			first = got
			continue
		}
		for section, placeholder := range first {
			if got[section] != placeholder {
				t.Fatalf("placeholder for %s changed between runs: %q then %q",
					section, placeholder, got[section])
			}
		}
	}
}

// A refused approval record leaves the answer unknown, not not_approved.
//
// IsExpectedAbsent covers a symlink refusal as well as a missing file, which is right for
// deciding whether to warn and wrong for deciding what is known. Returning Known for both
// turned "this record was deliberately not read" into "this record contains no approval": a
// symlinked settings file whose target approved every server produced a confident negative
// drawn from evidence the table declined to look at.
//
// Asserted on the server's approval state rather than on the reader's return value, because
// the reader's answer only matters through the row.
func TestRefusedApprovalRecordLeavesApprovalUnknown(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "code", "repo")
	writeTestFile(t, filepath.Join(project, ".mcp.json"),
		`{"mcpServers":{"srv":{"command":"npx","args":["x"]}}}`)
	recorded, err := json.Marshal(map[string]any{"projects": map[string]any{
		project: map[string]any{"hasTrustDialogAccepted": true}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), recorded, 0o644); err != nil {
		t.Fatal(err)
	}
	// The account-wide settings file is a symlink, which the traversal refuses. Its target
	// would have approved everything.
	target := filepath.Join(home, "elsewhere-settings.json")
	writeTestFile(t, target, `{"enableAllProjectMcpServers":true}`)
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home, ".claude", "settings.json")); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	var got approvalState
	var found bool
	for _, row := range serversOnly(discoverForTest("alice", home)) {
		if row.ServerName == "srv" {
			found, got = true, row.Approval
		}
	}
	if !found {
		t.Fatal("the server was not found")
	}
	if got != approvalUnknown {
		t.Errorf("approval = %q, want %q: the record was refused rather than absent, so "+
			"nothing is known about this server's approval", got, approvalUnknown)
	}
}

// Genuine absence stays known-empty, so an ordinary account does not report everything unknown.
func TestAbsentApprovalRecordStaysKnownEmpty(t *testing.T) {
	home := t.TempDir()
	evidence, warnings := userApprovalSettings(home)
	if len(warnings) != 0 {
		t.Errorf("an absent settings file produced warnings: %v", warnings)
	}
	if !evidence.Known {
		t.Error("an absent settings file must be known-empty, not unknown: most accounts " +
			"have no such file and every row would otherwise report unknown")
	}
	if got := evidence.stateFor("srv"); got != approvalNotApproved {
		t.Errorf("stateFor = %q, want %q", got, approvalNotApproved)
	}
}

// Both settings files failing produce distinguishable diagnostics.
//
// Every decode error was labelled top_level_is_not_an_object and every project diagnostic
// named only the directory, so two simultaneous failures were two identical rows that were
// both wrong about the cause.
func TestSimultaneousSettingsFailuresAreDistinguishable(t *testing.T) {
	home := t.TempDir()
	// A directory name no sentence in the catalogue could contain, so the leak assertion
	// below cannot collide with ordinary prose. An earlier version used "repo", which is a
	// substring of "reported" in the warning's own sentence -- the assertion failed on the
	// word, not on a leak.
	const projRel = "code/zqxjkprojectdir"
	// One a syntax error, one a field of the wrong type, so the shapes must differ too.
	writeTestFile(t, filepath.Join(home, projRel, ".claude", "settings.json"), `{ not json`)
	writeTestFile(t, filepath.Join(home, projRel, ".claude", "settings.local.json"),
		`{"enabledMcpjsonServers":123}`)

	_, warnings := projectApprovalSettings(home, projRel, true)
	if len(warnings) != 2 {
		t.Fatalf("got %d warnings, want one per failing file: %+v", len(warnings), warnings)
	}
	keys := map[string]parseShape{}
	for _, w := range warnings {
		if w.Code != warnApprovalSettingsUnreadable {
			t.Errorf("code = %q, want %q", w.Code, warnApprovalSettingsUnreadable)
		}
		keys[w.Key] = w.Shape
	}
	if len(keys) != 2 {
		t.Errorf("the two failures are indistinguishable: %v", keys)
	}
	if shape, ok := keys["settings_json"]; !ok {
		t.Error("the committed file's failure is unidentified")
	} else if shape == shapeWrongType {
		t.Error("a syntax error was reported as a field-type error")
	}
	if shape, ok := keys["settings_local_json"]; !ok {
		t.Error("the local file's failure is unidentified")
	} else if shape != shapeWrongType {
		t.Errorf("a field-type error was reported as %q", shape)
	}
	// Neither carries the input or the project path.
	for _, w := range warnings {
		if rendered := w.render(); strings.Contains(rendered, "123") ||
			strings.Contains(rendered, "zqxjkprojectdir") ||
			strings.Contains(rendered, "not json") {
			t.Errorf("the warning carries input or a path: %q", rendered)
		}
	}
}

// Placeholder ordinals stay put when two sections' internal contexts collide after redaction.
//
// The tie-break was the *published* SourceContext, which materialize has already redacted, and
// redaction is many-to-one. Two ~/.claude.json project paths that differ only inside a
// credential-shaped assignment become one string, so the sort compared equal keys and
// sort.SliceStable preserved whatever map iteration had produced: the two servers swapped
// ordinals across runs over unchanged bytes.
//
// The fixture has to collide on the *comparator's* key, which is the point an earlier version
// of this test missed. It used `a --token=AAAA` and `b --token=BBBB`, whose redacted forms are
// `projects[/home/alice/a --token=[REDACTED]` and `...b --token=[REDACTED]` -- still different,
// so the old comparator would have ordered them deterministically and the test protected
// nothing. It appeared to pass because it asserted collision on the value after serverToRow,
// where containment drops both contexts to "". Identical prefixes are what actually collide.
func TestPlaceholderOrderSurvivesContextRedaction(t *testing.T) {
	const shared = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	// Identical directory names; only the credential value differs, so redactSecret maps
	// both contexts to one string while the originals stay distinct.
	doc := `{"projects":{` +
		`"/home/alice/repo --token=AAAA":{"mcpServers":{"` + shared +
		`":{"command":"npx","args":["first"]}}},` +
		`"/home/alice/repo --token=BBBB":{"mcpServers":{"` + shared +
		`":{"command":"uvx","args":["second"]}}}}}`

	var first map[string]string
	for attempt := 0; attempt < 12; attempt++ {
		rows := finishProcessing("/home/alice", []byte(doc), nil,
			"/home/alice/.claude.json", "alice", "claude_code", false, claudeJSONMaxSize,
			extractClaudeCode)
		got := map[string]string{}
		var published, raw []string
		for _, row := range rows {
			if row.rawName == "" {
				continue
			}
			// Keyed on the launcher, the only thing distinguishing the two rows once both
			// names and both contexts have been redacted.
			got[row.Command] = serverToRow(row)["server_name"]
			published = append(published, row.SourceContext)
			raw = append(raw, row.rawContext)
		}
		if len(got) != 2 {
			t.Fatalf("expected two servers, got %v", got)
		}
		if attempt == 0 {
			// The fixture is only a regression if the old comparator's key really ties.
			if published[0] != published[1] {
				t.Fatalf("fixture wrong: the redacted contexts do not collide, so the "+
					"previous comparator would still have ordered these: %q vs %q",
					published[0], published[1])
			}
			// And only meaningful if the new key distinguishes them.
			if raw[0] == raw[1] {
				t.Fatalf("fixture wrong: the unredacted contexts are identical too, so "+
					"there is no total order to establish: %q", raw[0])
			}
		}
		if first == nil {
			first = got
			continue
		}
		for launcher, placeholder := range first {
			if got[launcher] != placeholder {
				t.Fatalf("placeholder for %s changed between runs: %q then %q",
					launcher, placeholder, got[launcher])
			}
		}
	}
}

// An uncertain opt-out makes the answer uncertain, rather than letting a lower-precedence
// blanket approval stand.
//
// `enableAllProjectMcpServers: false` in the local file was collapsed to a bool, so it became
// indistinguishable from an omitted key and the account-wide `true` survived: a clean
// `enabled` row. Both readings of that configuration are live -- if the file is eligible its
// opt-out wins, if not the account-wide value does -- so neither may be published as fact.
func TestUncertainScalarOverrideYieldsUnknown(t *testing.T) {
	yes, no := true, false
	for _, tc := range []struct {
		name  string
		lower approvalEvidence
		local approvalEvidence
		want  approvalState
	}{
		{
			// The reproduction.
			name:  "account true, uncertain local false",
			lower: approvalEvidence{EnableAll: &yes},
			local: approvalEvidence{EnableAll: &no},
			want:  approvalUnknown,
		},
		{
			name:  "account false, uncertain local true",
			lower: approvalEvidence{EnableAll: &no},
			local: approvalEvidence{EnableAll: &yes},
			want:  approvalUnknown,
		},
		{
			// Both outcomes agree, so a definite answer is honest.
			name:  "both true",
			lower: approvalEvidence{EnableAll: &yes},
			local: approvalEvidence{EnableAll: &yes},
			want:  approvalEnabled,
		},
		{
			name:  "both false",
			lower: approvalEvidence{EnableAll: &no},
			local: approvalEvidence{EnableAll: &no},
			want:  approvalNotApproved,
		},
		{
			// An individual approval from an eligible source survives an uncertain blanket
			// opt-out, because it holds under both readings.
			name:  "individual approval beside an uncertain opt-out",
			lower: approvalEvidence{Enabled: []string{"srv"}},
			local: approvalEvidence{EnableAll: &no},
			want:  approvalEnabled,
		},
		{
			// And a rejection is decisive whatever the uncertain source says.
			name:  "rejection beside an uncertain approval",
			lower: approvalEvidence{Disabled: []string{"srv"}},
			local: approvalEvidence{EnableAll: &yes},
			want:  approvalDisabled,
		},
		{
			// An uncertain source that says nothing leaves the certain answer alone.
			name:  "uncertain source is silent",
			lower: approvalEvidence{EnableAll: &yes},
			local: approvalEvidence{},
			want:  approvalEnabled,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evidence := claudeApproval{
				Certain: tc.lower, Pending: tc.local, HasPending: true, Known: true,
			}
			if got := evidence.stateFor("srv"); got != tc.want {
				t.Errorf("stateFor = %q, want %q", got, tc.want)
			}
		})
	}
}

// And the same through discovery, so the resolution is reached by the real path.
func TestUncertainLocalOptOutEndToEnd(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "code", "repo")
	writeTestFile(t, filepath.Join(project, ".mcp.json"),
		`{"mcpServers":{"srv":{"command":"npx","args":["x"]}}}`)
	// Account-wide blanket approval.
	writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enableAllProjectMcpServers":true}`)
	// The project's local file opts out, and its eligibility needs git.
	writeTestFile(t, filepath.Join(project, ".claude", "settings.local.json"),
		`{"enableAllProjectMcpServers":false}`)
	recorded, err := json.Marshal(map[string]any{"projects": map[string]any{
		project: map[string]any{"hasTrustDialogAccepted": true}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), recorded, 0o644); err != nil {
		t.Fatal(err)
	}

	var got approvalState
	var found bool
	for _, row := range serversOnly(discoverForTest("alice", home)) {
		if row.ServerName == "srv" {
			found, got = true, row.Approval
		}
	}
	if !found {
		t.Fatal("the server was not found")
	}
	if got != approvalUnknown {
		t.Errorf("approval = %q, want %q: the local opt-out decides the answer if that "+
			"file is eligible and does not if it is not, so the evidence supports neither "+
			"enabled nor not_approved", got, approvalUnknown)
	}
}

// A per-server lookup must not copy the approval lists.
//
// stateFor resolved the uncertain reading by building `Certain.overlay(Pending)` and throwing
// it away, so each row allocated both concatenated name lists. The lists are fixed while a
// project's rows are evaluated, so the cost was server count x list length -- an 889 KB
// settings file naming 100,000 servers, under the 1 MiB cap, copied 1.6 MB per lookup. A read
// cap bounds one input and not that product, which is why the bound is asserted here instead.
//
// Asserted as zero allocations rather than as a ratio: the resolution is membership tests over
// slices the caller already holds, so there is nothing it legitimately needs to allocate, and
// any number above zero means a copy came back.
func TestApprovalLookupDoesNotCopyLists(t *testing.T) {
	yes := true
	names := make([]string, 0, 20000)
	for index := range 20000 {
		names = append(names, fmt.Sprintf("server-%05d", index))
	}
	evidence := claudeApproval{
		Certain:    approvalEvidence{EnableAll: &yes, Enabled: names, Disabled: names},
		Pending:    approvalEvidence{Enabled: names, Disabled: names},
		HasPending: true,
		Known:      true,
	}
	// A name in neither list, so both resolutions run to completion rather than returning
	// from the first loop -- the worst case, and the one the overlay used to allocate for.
	const absent = "not-in-any-list"
	if state := evidence.stateFor(absent); state != approvalEnabled {
		t.Fatalf("fixture resolves to %q, so this is not measuring the two-outcome path", state)
	}
	perLookup := testing.AllocsPerRun(50, func() {
		evidence.stateFor(absent)
	})
	if perLookup > 0 {
		t.Errorf("a lookup allocated %.0f times; the approval lists are being copied per "+
			"server again", perLookup)
	}
}

// The same bound as a benchmark, so the figure is reportable rather than only asserted.
func BenchmarkApprovalStateFor(b *testing.B) {
	yes := true
	names := make([]string, 0, 20000)
	for index := range 20000 {
		names = append(names, fmt.Sprintf("server-%05d", index))
	}
	evidence := claudeApproval{
		Certain:    approvalEvidence{EnableAll: &yes, Enabled: names, Disabled: names},
		Pending:    approvalEvidence{Enabled: names, Disabled: names},
		HasPending: true,
		Known:      true,
	}
	for b.Loop() {
		evidence.stateFor("not-in-any-list")
	}
}
