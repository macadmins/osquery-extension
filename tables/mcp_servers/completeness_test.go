package mcp_servers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/macadmins/osquery-extension/pkg/devclients"
	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/macadmins/osquery-extension/pkg/testutil"
)

// TestUserFindingsLeaveServerRowsComplete: a problem finding the user's configuration is a row
// for the user, and a server row read in full from its own file keeps scan_complete = 1 beside
// it. Each case pairs one user-level finding with a healthy ~/.cursor/mcp.json.
func TestUserFindingsLeaveServerRowsComplete(t *testing.T) {
	healthy := `{"mcpServers":{"healthy":{"command":"npx","args":["pkg@1.0.0"]}}}`
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, home string)
		want  warnCode
	}{
		{
			// A directory where ~/.codex/config.toml belongs: the list of Codex's projects
			// cannot be read.
			name: "an unreadable project list",
			setup: func(t *testing.T, home string) {
				if err := os.MkdirAll(filepath.Join(home, ".codex", "config.toml"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			want: warnProjectListUnreadable,
		},
		{
			// Settings that do not parse: plugin servers are listed with an unknown approval
			// state, and their own file was read in full.
			name: "an unreadable settings.json",
			setup: func(t *testing.T, home string) {
				testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"), `{"enabledPlugins":`)
				testutil.WriteFile(t, filepath.Join(home, ".claude", "plugins", "cache", "mp", "p",
					"1.0.0", ".mcp.json"), `{"mcpServers":{"plugin-srv":{"command":"npx","args":["x"]}}}`)
				writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})
			},
			want: warnPluginSettingsUnreadable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			testutil.WriteFile(t, filepath.Join(home, ".cursor", "mcp.json"), healthy)
			tc.setup(t, home)
			var sawFinding, sawHealthy bool
			for _, row := range discoverForTest("alice", home) {
				if row.Warning.Code == tc.want {
					sawFinding = true
				}
				if row.ServerName == "" {
					continue
				}
				if row.ServerName == "healthy" {
					sawHealthy = true
				}
				if row.ServerName == "plugin-srv" && row.Approval != approvalUnknown {
					t.Errorf("plugin-srv approval = %q, want unknown", row.Approval)
				}
				if !row.ScanComplete {
					t.Errorf("%s reads scan_complete = 0 beside a user-level %s; its own file "+
						"was read in full", row.ServerName, tc.want)
				}
			}
			if !sawFinding {
				t.Errorf("no %s row for the user", tc.want)
			}
			if !sawHealthy {
				t.Error("the healthy server was not listed")
			}
		})
	}

	// A budget stop between two files. The first file's extractor cancels the query, so the
	// stop falls after that file was read and before the second, on any machine.
	t.Run("a budget stop between files", func(t *testing.T) {
		home := t.TempDir()
		testutil.WriteFile(t, filepath.Join(home, ".cursor", "mcp.json"), healthy)
		testutil.WriteFile(t, filepath.Join(home, ".gemini", "settings.json"),
			`{"mcpServers":{"unread":{"command":"npx"}}}`)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		original := homeProbes
		homeProbes = []probe{
			{relPath: filepath.Join(".cursor", "mcp.json"), client: "cursor", jsonc: true,
				extract: func(data []byte) ([]Server, error) {
					defer cancel()
					return extractEnvelopeSimple(data)
				}},
			{relPath: filepath.Join(".gemini", "settings.json"), client: "gemini", jsonc: true,
				extract: extractGeminiSettings},
		}
		t.Cleanup(func() { homeProbes = original })

		rows := withoutStandingNotes(discoverForHome(ctx, fsscan.UserHome{Name: "alice", Path: home},
			time.Now().Add(time.Minute)))
		var stopped, sawHealthy bool
		for _, row := range rows {
			switch {
			case row.Warning.Code == warnCancelledInHome:
				stopped = true
			case row.ServerName == "unread":
				t.Error("the second file was read after the query was cancelled")
			case row.ServerName == "healthy":
				sawHealthy = true
				if !row.ScanComplete {
					t.Error("a server read in full before the stop reads scan_complete = 0")
				}
			}
		}
		if !stopped || !sawHealthy {
			t.Errorf("stopped = %v, healthy listed = %v; want both: %+v", stopped, sawHealthy, rows)
		}
	})
}

// TestAManifestFindingMarksOnlyItsPluginVersion: plugin_manifest_missing_source marks the server
// rows of the plugin version whose manifest names the missing file, and no other plugin's.
func TestAManifestFindingMarksOnlyItsPluginVersion(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"broken@mp":true,"sound@mp":true}}`)
	cache := filepath.Join(home, ".claude", "plugins", "cache", "mp")
	testutil.WriteFile(t, filepath.Join(cache, "broken", "1.0.0", ".mcp.json"),
		`{"mcpServers":{"from-broken":{"command":"npx","args":["x"]}}}`)
	testutil.WriteFile(t, filepath.Join(cache, "broken", "1.0.0", ".claude-plugin", "plugin.json"),
		`{"name":"broken","mcpServers":"./missing.json"}`)
	testutil.WriteFile(t, filepath.Join(cache, "sound", "1.0.0", ".mcp.json"),
		`{"mcpServers":{"from-sound":{"command":"npx","args":["y"]}}}`)
	writeInstalledPlugins(t, home, map[string]string{"broken@mp": "1.0.0", "sound@mp": "1.0.0"})
	testutil.WriteFile(t, filepath.Join(home, ".cursor", "mcp.json"),
		`{"mcpServers":{"elsewhere":{"command":"uvx","args":["z"]}}}`)

	complete := map[string]bool{}
	var reported bool
	for _, row := range discoverForTest("alice", home) {
		if row.Warning.Code == warnPluginManifestMissing {
			reported = true
		}
		if row.ServerName != "" {
			complete[row.ServerName] = row.ScanComplete
		}
	}
	if !reported {
		t.Fatal("the missing declared source was not reported")
	}
	for name, want := range map[string]bool{"from-broken": false, "from-sound": true, "elsewhere": true} {
		got, listed := complete[name]
		if !listed {
			t.Errorf("%s was not listed", name)
			continue
		}
		if got != want {
			t.Errorf("%s: scan_complete = %v, want %v", name, got, want)
		}
	}
}

// TestDescriptiveDiagnosticSentencesShareAPrefix: the descriptive codes that are rows of their
// own, and no other codes, start with "recorded project", which is the predicate the README
// gives for an incomplete inventory. The other descriptive codes sit on a server row that
// reads scan_complete = 1, which that predicate already excludes.
func TestDescriptiveDiagnosticSentencesShareAPrefix(t *testing.T) {
	ownRow := map[warnCode]bool{
		warnProjectOutsideHome: true, warnProjectRemoteOrigin: true, warnProjectMalformed: true,
		warnProjectCloudPlaceholder: true, warnProjectUserspaceFS: true,
		warnProjectUntrusted: true, warnApprovalSettingsUnreadable: true,
		warnWorkspaceRecordsOlder: true, warnProjectOnNetworkFS: true,
	}
	for code, sentence := range warnSentences {
		prefixed := strings.HasPrefix(sentence, "recorded project")
		if prefixed != ownRow[code] {
			t.Errorf("%s: starts with \"recorded project\" = %v, want %v", code, prefixed, ownRow[code])
		}
		if ownRow[code] && code.scope() != scopeDescriptive {
			t.Errorf("%s starts with \"recorded project\" and is not descriptive", code)
		}
	}
}

// TestEachUnreadableProjectListIsReportedWithItsSource: each project list that exists and could
// not be read is its own project_list_unreadable row, naming the list and, when the read failed,
// why.
func TestEachUnreadableProjectListIsReportedWithItsSource(t *testing.T) {
	t.Run("two unreadable lists", func(t *testing.T) {
		home := t.TempDir()
		// Directories where the two list files belong, which fail the read as not regular.
		for _, rel := range []string{".claude.json", filepath.Join(".codex", "config.toml")} {
			if err := os.MkdirAll(filepath.Join(home, rel), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		got := map[string]string{}
		for _, row := range discoverForTest("alice", home) {
			if row.Warning.Code == warnProjectListUnreadable {
				got[string(row.Warning.Source)] = row.Warning.render()
			}
		}
		for _, source := range []string{"claude_json", "codex_toml"} {
			rendered, ok := got[source]
			if !ok {
				t.Errorf("no project_list_unreadable row for %s; got %v", source, got)
				continue
			}
			if !strings.HasSuffix(rendered, "[reason=not_regular; source="+source+"]") {
				t.Errorf("%s renders %q, want reason= then source=", source, rendered)
			}
		}
		if len(got) != 2 {
			t.Errorf("got %d project_list_unreadable rows, want one per list", len(got))
		}
	})
	t.Run("a list that does not parse", func(t *testing.T) {
		home := t.TempDir()
		testutil.WriteFile(t, filepath.Join(home, ".claude.json"), `{"projects":`)
		var sources []string
		for _, row := range discoverForTest("alice", home) {
			if row.Warning.Code == warnProjectListUnreadable {
				sources = append(sources, row.Warning.render())
			}
		}
		if len(sources) != 1 || !strings.HasSuffix(sources[0], "[source=claude_json]") {
			t.Errorf("project_list_unreadable rows = %q, want one naming claude_json", sources)
		}
	})
}

// TestStorageRowsCountProjectsOnce: a project stored somewhere other than this machine's disk is
// counted once in its descriptive row, however many files its clients would load. A project in
// a cloud provider's folder is decided from its path, so nothing in it is opened: no server is
// listed and no settings file is reported. A project whose files the provider holds is decided
// file by file and still counted once.
func TestStorageRowsCountProjectsOnce(t *testing.T) {
	home := t.TempDir()
	server := `{"mcpServers":{"inside":{"command":"npx","args":["x"]}}}`
	var recorded []string
	var evicted []os.FileInfo
	for _, rel := range []string{"cloud/p", "evicted/p"} {
		project := filepath.Join(home, filepath.FromSlash(rel))
		for _, file := range []string{".mcp.json", filepath.Join(".vscode", "mcp.json")} {
			testutil.WriteFile(t, filepath.Join(project, file), server)
		}
		testutil.WriteFile(t, filepath.Join(project, ".claude", "settings.json"),
			`{"enabledMcpjsonServers":["inside"]}`)
		if rel == "evicted/p" {
			for _, file := range []string{".mcp.json", filepath.Join(".vscode", "mcp.json"),
				filepath.Join(".claude", "settings.json")} {
				info, err := os.Stat(filepath.Join(project, file))
				if err != nil {
					t.Fatal(err)
				}
				evicted = append(evicted, info)
			}
		}
		recorded = append(recorded, testutil.JSONString(project)+`:{}`)
		storage := filepath.Join(home, devclients.AppSupportFork("Code", "User", "workspaceStorage")[0])
		testutil.WriteFile(t, filepath.Join(storage, strings.ReplaceAll(rel, "/", "-"), "workspace.json"),
			`{"folder":"`+testutil.FileURL(project)+`"}`)
	}
	testutil.WriteFile(t, filepath.Join(home, ".claude.json"), `{"projects":{`+strings.Join(recorded, ",")+`}}`)
	savedCloud, savedPlaceholder := underCloudStorage, cloudPlaceholder
	t.Cleanup(func() { underCloudStorage, cloudPlaceholder = savedCloud, savedPlaceholder })
	underCloudStorage = func(rel string) bool { return strings.HasPrefix(filepath.ToSlash(rel), "cloud") }
	// By identity rather than by file.Name(): Go 1.25's os.Root on Windows names a root opened
	// inside another by the bare component, so a file opened beneath it is named `.vscode\mcp.json`
	// and holds no trace of the project.
	cloudPlaceholder = func(file *os.File) (bool, error) {
		info, err := file.Stat()
		if err != nil {
			return false, err
		}
		for _, held := range evicted {
			if os.SameFile(info, held) {
				return true, nil
			}
		}
		return false, nil
	}

	cloudCount, settingsRows := 0, 0
	for _, row := range discoverForTest("alice", home) {
		if row.ServerName == "inside" {
			t.Errorf("a server stored with the provider was listed from %s", row.SourcePath)
		}
		switch row.Warning.Code {
		case warnProjectCloudPlaceholder:
			cloudCount += row.Warning.Count
		case warnApprovalSettingsUnreadable:
			settingsRows++
		}
	}
	if cloudCount != 2 || settingsRows != 0 {
		t.Errorf("project_cloud_placeholder count %d, settings rows %d; want two projects and no "+
			"settings row", cloudCount, settingsRows)
	}
}

// TestApprovalSettingsAreReadOnlyForAProjectThatDeclaresServers: a Claude project's settings files
// bear only on the servers its .mcp.json declares, so a project with no .mcp.json, or one whose
// .mcp.json declares none, reads none, and an unreadable one there is not reported. With servers
// declared, the same unreadable settings file is reported.
func TestApprovalSettingsAreReadOnlyForAProjectThatDeclaresServers(t *testing.T) {
	home := t.TempDir()
	var recorded []string
	for _, name := range []string{"quiet", "none", "declares"} {
		project := filepath.Join(home, name)
		// A directory where the settings file belongs, which cannot be read as one.
		if err := os.MkdirAll(filepath.Join(project, ".claude", "settings.json"), 0o755); err != nil {
			t.Fatal(err)
		}
		recorded = append(recorded, testutil.JSONString(project)+`:{}`)
	}
	testutil.WriteFile(t, filepath.Join(home, "none", ".mcp.json"), `{"mcpServers":{}}`)
	testutil.WriteFile(t, filepath.Join(home, "declares", ".mcp.json"),
		`{"mcpServers":{"srv":{"command":"npx","args":["x"]}}}`)
	testutil.WriteFile(t, filepath.Join(home, ".claude.json"), `{"projects":{`+strings.Join(recorded, ",")+`}}`)

	reported := map[string]int{}
	for _, row := range discoverForTest("alice", home) {
		if row.Warning.Code == warnApprovalSettingsUnreadable {
			reported[filepath.Base(row.SourcePath)]++
		}
	}
	if reported["quiet"] != 0 || reported["none"] != 0 || reported["declares"] != 1 {
		t.Errorf("approval_settings_unreadable rows by project = %v, want one for the project "+
			"that declares a server and none for the one that does not", reported)
	}
}

// TestANullClaudeProjectEntryLeavesApprovalUnknown: a project entry that is JSON null records no
// approvals, so its servers read approval_state = 'unknown', not not_approved.
func TestANullClaudeProjectEntryLeavesApprovalUnknown(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "p")
	testutil.WriteFile(t, filepath.Join(project, ".mcp.json"),
		`{"mcpServers":{"srv":{"command":"npx","args":["x"]}}}`)
	testutil.WriteFile(t, filepath.Join(home, ".claude.json"), `{"projects":{`+testutil.JSONString(project)+`:null}}`)
	var found bool
	for _, row := range discoverForTest("alice", home) {
		if row.ServerName == "srv" {
			found = true
			if row.Approval != approvalUnknown {
				t.Errorf("approval_state = %q, want unknown for a null project entry", row.Approval)
			}
		}
	}
	if !found {
		t.Fatal("the server was not listed")
	}
}
