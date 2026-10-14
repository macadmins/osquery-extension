package mcp_servers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// One client's evidence that a directory is a project does not license reporting another
// client's configuration in it.
//
// Every project used to be probed with all four project-rooted filenames, so a directory
// known only to Codex produced a vscode row because a dormant .vscode/mcp.json happened to
// sit in it. Nothing established that VS Code had ever opened the directory, let alone that
// it would load that file. The provenance a project was discovered with now decides which
// files are probed inside it.
func TestProjectProbesFollowDiscoveringClient(t *testing.T) {
	for _, tc := range []struct {
		name    string
		origins []originCode
		want    []string
	}{
		{"claude only", []originCode{originClaudeJSON}, []string{".mcp.json"}},
		// One origin per editor. Sharing the workspaceStorage layout establishes nothing
		// about which editor opened a project: a single origin for the whole family meant a
		// project recorded only under Code emitted a client=cursor row from a dormant
		// .cursor/mcp.json with no Cursor history on the host at all.
		{"vscode workspace only", []originCode{originVSCodeWorkspace}, []string{
			filepath.Join(".vscode", "mcp.json")}},
		{"cursor workspace only", []originCode{originCursorWorkspace}, []string{
			filepath.Join(".cursor", "mcp.json")}},
		// Windsurf records workspaces the same way and has no project-scoped path this
		// table reads, so its provenance licenses nothing. Asserted rather than left
		// implicit, because "no probes" is the easy thing to turn accidentally into "all
		// probes" by adding a map entry.
		{"windsurf workspace only", []originCode{originWindsurfWorkspace}, nil},
		// Both forks recorded it, so both files are in scope.
		{"vscode and cursor", []originCode{originVSCodeWorkspace, originCursorWorkspace},
			[]string{filepath.Join(".cursor", "mcp.json"), filepath.Join(".vscode", "mcp.json")}},
		{"codex only", []originCode{originCodexTOML}, []string{
			filepath.Join(".codex", "config.toml")}},
		// Recorded by two clients: both clients' files, and no others.
		{"claude and codex", []originCode{originClaudeJSON, originCodexTOML}, []string{
			".mcp.json", filepath.Join(".codex", "config.toml")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref := projectRef{Origins: map[originCode]struct{}{}}
			for _, o := range tc.origins {
				ref.Origins[o] = struct{}{}
			}
			got := ref.probesFor()
			sort.Strings(got)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("probesFor() = %v, want %v", got, want)
			}
		})
	}
}

// End to end: a Codex-only project with a dormant .vscode/mcp.json produces no vscode row.
func TestCodexOnlyProjectDoesNotActivateVSCodeConfig(t *testing.T) {
	home := t.TempDir()
	writeTestFile(t, filepath.Join(home, "code", "repo", ".codex", "config.toml"),
		"[mcp_servers.codex_server]\ncommand = \"npx\"\n")
	// Present on disk, belonging to no client's project history.
	writeTestFile(t, filepath.Join(home, "code", "repo", ".vscode", "mcp.json"),
		`{"mcpServers":{"dormant_vscode":{"command":"npx","args":["x"]}}}`)
	writeTestFile(t, filepath.Join(home, ".codex", "config.toml"),
		"[projects.\""+filepath.Join(home, "code", "repo")+"\"]\ntrust_level = \"trusted\"\n")

	var names []string
	for _, row := range serversOnly(discoverForTest("alice", home)) {
		names = append(names, row.ServerName)
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, []string{"codex_server"}) {
		t.Errorf("names = %v; only Codex recorded this project, so only its config is "+
			"configuration there", names)
	}
}

// Deduplication keeps every client's provenance rather than whichever was seen first.
func TestMergeKeepsAllProvenance(t *testing.T) {
	fromCodex := []projectRef{{Rel: "code/repo",
		Origins:    map[originCode]struct{}{originCodexTOML: {}},
		TrustKnown: true, Trusted: true, Approval: claudeApproval{Known: true}}}
	fromClaude := []projectRef{{Rel: "code/repo",
		Origins:  map[originCode]struct{}{originClaudeJSON: {}},
		Approval: claudeApproval{Certain: approvalEvidence{Enabled: []string{"github"}}, Known: true}}}

	merged, _ := mergeProjects(fromCodex, fromClaude)
	if len(merged) != 1 {
		t.Fatalf("merged = %+v, want one project", merged)
	}
	for _, origin := range []originCode{originClaudeJSON, originCodexTOML} {
		if _, ok := merged[0].Origins[origin]; !ok {
			t.Errorf("origin %q was lost in dedup; its probes would not run", origin)
		}
	}
	// Codex's list was read first and carries no approvals; keeping it as-is lost them.
	if !reflect.DeepEqual(merged[0].Approval.Certain.Enabled, []string{"github"}) {
		t.Errorf("Approved = %v, want [github]", merged[0].Approval.Certain.Enabled)
	}
	// And the trust Codex supplied survives a merge with a list that has none to report.
	if !merged[0].TrustKnown || !merged[0].Trusted {
		t.Errorf("trust was lost in dedup: known=%v trusted=%v",
			merged[0].TrustKnown, merged[0].Trusted)
	}
}

// Codex does not load project-scoped configuration for an untrusted project, so this table
// must not report servers from one.
func TestCodexTrustGatesProjectConfig(t *testing.T) {
	for _, tc := range []struct {
		name, trust string
		wantServer  bool
		wantCode    warnCode
	}{
		{"trusted", "trust_level = \"trusted\"\n", true, ""},
		{"untrusted", "trust_level = \"untrusted\"\n", false, warnProjectUntrusted},
		// Absent trust is not evidence of trust, and Codex's own default is to ask.
		{"missing", "", false, warnProjectTrustUnknown},
		// A value this table does not recognise must not read as trusted.
		{"unrecognised", "trust_level = \"something-new\"\n", false, warnProjectUntrusted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			project := filepath.Join(home, "code", "repo")
			writeTestFile(t, filepath.Join(project, ".codex", "config.toml"),
				"[mcp_servers.project_server]\ncommand = \"npx\"\n")
			writeTestFile(t, filepath.Join(home, ".codex", "config.toml"),
				"[projects.\""+project+"\"]\n"+tc.trust)

			var found bool
			var codes []warnCode
			for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
				if row.ServerName == "project_server" {
					found = true
				}
				if !row.Warning.empty() {
					codes = append(codes, row.Warning.Code)
				}
			}
			if found != tc.wantServer {
				t.Errorf("project server listed = %v, want %v", found, tc.wantServer)
			}
			if tc.wantCode != "" {
				var seen bool
				for _, c := range codes {
					if c == tc.wantCode {
						seen = true
					}
				}
				if !seen {
					t.Errorf("want code %q, got %v", tc.wantCode, codes)
				}
			}
		})
	}
}

// Approval that could not be read is reported as unknown, not as not_approved.
//
// An undecodable project entry left both name lists empty, and an empty list was indistinguishable
// from "the user approved nothing" -- so the table made a positive claim about a decision
// nobody could read, in the direction that invites ignoring a server that is running.
func TestUnreadableApprovalIsUnknown(t *testing.T) {
	t.Run("malformed claude project entry", func(t *testing.T) {
		home := t.TempDir()
		project := filepath.Join(home, "code", "repo")
		writeTestFile(t, filepath.Join(project, ".mcp.json"),
			`{"mcpServers":{"srv":{"command":"npx","args":["x"]}}}`)
		// The entry is a string where an object belongs, so it cannot be decoded.
		writeTestFile(t, filepath.Join(home, ".claude.json"),
			`{"projects":{"`+filepath.ToSlash(project)+`":"not-an-object"}}`)

		var got approvalState
		for _, row := range serversOnly(discoverForTest("alice", home)) {
			if row.ServerName == "srv" {
				got = row.Approval
			}
		}
		if got != approvalUnknown {
			t.Errorf("approval = %q, want %q", got, approvalUnknown)
		}
	})

	t.Run("malformed plugin settings", func(t *testing.T) {
		home := t.TempDir()
		writeTestFile(t, filepath.Join(home, ".claude", "settings.json"), `{ not json`)
		writeTestFile(t, filepath.Join(home, ".claude", "plugins", "cache", "mp", "p",
			"1.0.0", ".mcp.json"), `{"mcpServers":{"orphan":{"command":"npx","args":["x"]}}}`)
		writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

		var got approvalState
		for _, row := range serversOnly(discoverForTest("alice", home)) {
			if row.ServerName == "orphan" {
				got = row.Approval
			}
		}
		if got != approvalUnknown {
			t.Errorf("approval = %q, want %q: the row's own warning already says the "+
				"state is unknown, so the column must not contradict it", got, approvalUnknown)
		}
	})

	t.Run("absent settings means genuinely not enabled", func(t *testing.T) {
		// Absence is evidence: a user who has never enabled a plugin has no file, so an
		// installed plugin really is not enabled. This must not become unknown.
		home := t.TempDir()
		writeTestFile(t, filepath.Join(home, ".claude", "plugins", "cache", "mp", "p",
			"1.0.0", ".mcp.json"), `{"mcpServers":{"never":{"command":"npx","args":["x"]}}}`)
		writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

		var got approvalState
		for _, row := range serversOnly(discoverForTest("alice", home)) {
			if row.ServerName == "never" {
				got = row.Approval
			}
		}
		if got != approvalNotApproved {
			t.Errorf("approval = %q, want %q", got, approvalNotApproved)
		}
	})
}

// ~/.claude/settings.local.json must not be read as a user-wide plugin override.
//
// Claude Code's documented precedence puts settings.local.json at *project* scope; there is no
// user-scope version. The file appears in a home whenever that home has been opened as a
// project, which is common, and its per-project overrides were being applied to every plugin
// row for the account.
func TestHomeSettingsLocalIsNotAGlobalOverride(t *testing.T) {
	home := t.TempDir()
	// The user file enables the plugin.
	writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	// A project-local file that happens to sit in the home disables it. It must be ignored.
	writeTestFile(t, filepath.Join(home, ".claude", "settings.local.json"),
		`{"enabledPlugins":{"p@mp":false}}`)
	writeTestFile(t, filepath.Join(home, ".claude", "plugins", "cache", "mp", "p",
		"1.0.0", ".mcp.json"), `{"mcpServers":{"srv":{"command":"npx","args":["x"]}}}`)
	writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

	var got approvalState
	for _, row := range serversOnly(discoverForTest("alice", home)) {
		if row.ServerName == "srv" {
			got = row.Approval
		}
	}
	if got != approvalEnabled {
		t.Errorf("approval = %q, want %q: a project-local file in the home must not "+
			"override user-scope plugin enablement", got, approvalEnabled)
	}
}

// A descriptive warning explains a dropped column; it does not mean the listing was short.
//
// scan_complete was computed as `complete && Warning.empty()`, so any warning degraded it --
// including the ones classified descriptive. A row whose only finding was a dropped
// environment key reported scan_complete = 0 while every server in its file was listed.
func TestDescriptiveWarningsKeepScanComplete(t *testing.T) {
	home := t.TempDir()
	// An env key that is not a C identifier is dropped, with warnEnvKeyDropped.
	writeTestFile(t, filepath.Join(home, ".cursor", "mcp.json"),
		`{"mcpServers":{"srv":{"command":"npx","args":["x"],"env":{"not a key":"v"}}}}`)

	var checked bool
	for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
		if row.ServerName != "srv" {
			continue
		}
		checked = true
		if row.Warning.Code != warnEnvKeyDropped {
			t.Fatalf("warning = %q, want %q; fixture wrong", row.Warning.Code, warnEnvKeyDropped)
		}
		if row.Warning.Code.degradesCompleteness() {
			t.Fatal("warnEnvKeyDropped is classified as degrading; fixture wrong")
		}
		if !row.ScanComplete {
			t.Error("a descriptive warning degraded scan_complete; the row's source was " +
				"listed in full and the warning only explains one empty column")
		}
	}
	if !checked {
		t.Fatal("the server was not found")
	}
}

// The oversize diagnostic reports the cap that actually applied.
//
// It was reconstructed from the client name, so every claude_code source was reported against
// ~/.claude.json's raised 4 MiB cap -- telling an administrator a 1.5 MiB project file had
// exceeded 4 MiB, which is impossible.
func TestOversizeReportsTheRealCap(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "code", "repo")
	// Over the ordinary 1 MiB cap, well under ~/.claude.json's 4 MiB.
	big := make([]byte, MaxFileSize+2048)
	for i := range big {
		big[i] = 'x'
	}
	writeTestFile(t, filepath.Join(project, ".mcp.json"), string(big))
	recorded, err := json.Marshal(map[string]any{
		"projects": map[string]any{project: map[string]any{}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), recorded, 0o644); err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
		if row.Warning.Code != warnSourceTooLarge {
			continue
		}
		found = true
		if row.Warning.Limit != MaxFileSize {
			t.Errorf("reported limit = %d, want %d: the project source uses the ordinary "+
				"cap, not ~/.claude.json's raised one", row.Warning.Limit, MaxFileSize)
		}
	}
	if !found {
		t.Error("an oversized project source was not reported")
	}
}

// Both descriptive codes keep scan_complete = 1, asserted end to end rather than only
// against the classifier.
//
// Classifier unit tests prove degradesCompleteness() answers correctly for a code; they do
// not prove the discovery path consults it. The bug they missed was exactly that: the final
// assignment read `complete && Warning.empty()`, so a correctly-classified descriptive code
// still degraded the row. These two cases go through a real file to a real row.
func TestDescriptiveCodesKeepScanCompleteEndToEnd(t *testing.T) {
	for _, tc := range []struct {
		name, rel, body string
		wantCode        warnCode
	}{
		{
			// An env key that is not a C identifier: one column is emptied, every server
			// the file declared is still listed.
			name: "dropped env key", rel: filepath.Join(".cursor", "mcp.json"),
			body:     `{"mcpServers":{"srv":{"command":"npx","args":["x"],"env":{"not a key":"v"}}}}`,
			wantCode: warnEnvKeyDropped,
		},
		{
			// A literal credential where a variable name belongs. A finding worth raising,
			// and still not a short listing.
			name: "literal env header", rel: filepath.Join(".codex", "config.toml"),
			body: "[mcp_servers.srv]\nurl = \"https://example.test/mcp\"\n" +
				"env_http_headers = { Authorization = \"Bearer abc123\" }\n",
			wantCode: warnEnvHeaderLiteral,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			writeTestFile(t, filepath.Join(home, tc.rel), tc.body)

			var checked bool
			for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
				if row.ServerName != "srv" {
					continue
				}
				checked = true
				if row.Warning.Code != tc.wantCode {
					t.Fatalf("warning = %q, want %q; fixture wrong",
						row.Warning.Code, tc.wantCode)
				}
				if row.Warning.Code.degradesCompleteness() {
					t.Fatalf("%s is classified as degrading; fixture wrong", tc.wantCode)
				}
				if !row.ScanComplete {
					t.Error("a descriptive finding degraded scan_complete; the file's " +
						"servers were all listed and the warning only explains one " +
						"empty column")
				}
				if serverToRow(row)["scan_complete"] != "1" {
					t.Error("the emitted column disagrees with the row")
				}
			}
			if !checked {
				t.Fatal("the server was not found")
			}
		})
	}
}

// A project recorded by one editor fork does not activate another fork's configuration.
//
// End to end, because the unit test above proves the mapping and not that discovery consults
// it. Reproduced by the reviewer: a project recorded only under Code/User/workspaceStorage
// emitted a clean, complete client=cursor row from a dormant .cursor/mcp.json, with no Cursor
// history present anywhere.
func TestOneForkHistoryDoesNotActivateAnotherFork(t *testing.T) {
	for _, tc := range []struct {
		name, fork string
		want       []string
	}{
		{"Code history", "Code", []string{"vscode_server"}},
		{"Cursor history", "Cursor", []string{"cursor_server"}},
		// Windsurf has no project-scoped path this table reads, so a Windsurf-only history
		// yields neither file even though both sit in the directory.
		{"Windsurf history", "Windsurf", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			project := filepath.Join("code", "repo")
			writeTestFile(t, filepath.Join(home, project, ".vscode", "mcp.json"),
				`{"mcpServers":{"vscode_server":{"command":"npx","args":["x"]}}}`)
			writeTestFile(t, filepath.Join(home, project, ".cursor", "mcp.json"),
				`{"mcpServers":{"cursor_server":{"command":"uvx","args":["y"]}}}`)
			recordVSCodeWorkspace(t, home, tc.fork, project)

			var names []string
			for _, row := range serversOnly(discoverForTest("alice", home)) {
				names = append(names, row.ServerName)
			}
			sort.Strings(names)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if !reflect.DeepEqual(names, want) {
				t.Errorf("names = %v, want %v: only the recording fork's configuration is "+
					"evidence of anything", names, want)
			}
		})
	}
}

// A project outside the home does not also report a trust problem.
//
// Trust was counted while iterating the Codex file, before containment decided whether the
// project is inside the scanned home -- so an out-of-home entry produced both
// project_outside_home and project_trust_unknown, and the second is home-scope, which flipped
// an unrelated healthy row to scan_complete = 0. A project explicitly beyond the discovery
// boundary must not degrade the inventory that is inside it.
func TestOutOfScopeProjectsDoNotReportTrustProblems(t *testing.T) {
	home := t.TempDir()
	// A healthy in-scope source whose row must stay complete.
	writeTestFile(t, filepath.Join(home, ".cursor", "mcp.json"),
		`{"mcpServers":{"healthy":{"command":"npx","args":["x"]}}}`)
	// Two Codex entries outside the home, neither carrying trust.
	writeTestFile(t, filepath.Join(home, ".codex", "config.toml"),
		"[projects.\"/outside/no-trust\"]\n[projects.\"/elsewhere/also-none\"]\n")

	var sawOutside, sawTrust, checkedHealthy bool
	for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
		switch row.Warning.Code {
		case warnProjectOutsideHome:
			sawOutside = true
		case warnProjectTrustUnknown, warnProjectUntrusted:
			sawTrust = true
		}
		if row.ServerName == "healthy" {
			checkedHealthy = true
			if !row.ScanComplete {
				t.Error("an out-of-scope project degraded an unrelated healthy row")
			}
		}
	}
	if !sawOutside {
		t.Error("the out-of-home projects were not reported at all")
	}
	if sawTrust {
		t.Error("a project containment refused also reported a trust problem; trust is " +
			"only a question for projects this table would inspect")
	}
	if !checkedHealthy {
		t.Fatal("the healthy server was not found")
	}
}

// Workspace trust reaches the column end to end, including the reproduction.
func TestUntrustedProjectCannotApproveItsOwnServers(t *testing.T) {
	for _, tc := range []struct {
		name     string
		accepted bool
		want     approvalState
	}{
		// The reproduction: untrusted, no user or history approval, and the repository's
		// own committed settings turn everything on.
		{"trust dialog not accepted", false, approvalNotApproved},
		{"trust dialog accepted", true, approvalEnabled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			project := filepath.Join(home, "code", "repo")
			writeTestFile(t, filepath.Join(project, ".mcp.json"),
				`{"mcpServers":{"srv":{"command":"npx","args":["x"]}}}`)
			writeTestFile(t, filepath.Join(project, ".claude", "settings.json"),
				`{"enableAllProjectMcpServers":true}`)
			recorded, err := json.Marshal(map[string]any{"projects": map[string]any{
				project: map[string]any{"hasTrustDialogAccepted": tc.accepted}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(home, ".claude.json"), recorded, 0o644); err != nil {
				t.Fatal(err)
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

// Approval settings are read only for projects a Claude list recorded.
//
// They were read for every project, including ones recorded only by Codex or a VS Code fork
// where nothing in them could bear on the answer -- touching files inside a project this pass
// has no question about, ahead of the configuration probes.
func TestApprovalSettingsReadOnlyForClaudeProjects(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join("code", "repo")
	writeTestFile(t, filepath.Join(home, project, ".cursor", "mcp.json"),
		`{"mcpServers":{"cursor_server":{"command":"npx","args":["x"]}}}`)
	// A settings file that would grant approval if it were consulted. It must not be, and
	// the row's approval must stay not_applicable because Cursor has no approval step.
	writeTestFile(t, filepath.Join(home, project, ".claude", "settings.json"),
		`{"enableAllProjectMcpServers":true}`)
	recordVSCodeWorkspace(t, home, "Cursor", project)

	var checked bool
	for _, row := range serversOnly(discoverForTest("alice", home)) {
		if row.ServerName != "cursor_server" {
			continue
		}
		checked = true
		if row.Approval != approvalNotApplicable {
			t.Errorf("approval = %q, want %q: Cursor has no approval step, so Claude's "+
				"settings cannot speak for it", row.Approval, approvalNotApplicable)
		}
	}
	if !checked {
		t.Fatal("the cursor server was not found")
	}
}
