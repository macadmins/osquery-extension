//go:build unix

package mcp_servers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/macadmins/osquery-extension/pkg/testutil"
)

// A settings file that exists but was refused must not be read as "never enabled".
//
// fsscan.IsExpectedAbsent is true for a refused path as well as a missing one. That is right
// for a project config, where a planted symlink must not publish the attacker's path, and
// wrong for a file whose absence is itself read as evidence: this one drives a positive claim
// about every installed plugin. A `~/.claude/settings.json` symlinked into place by a dotfile
// manager -- chezmoi, stow and yadm all do this -- was refused by the no-follow traversal,
// counted as absent, and every plugin reported `not_approved` with no warning, about servers
// the file in fact enabled.
//
// Planted here rather than asserted against the predicate, because the bug was that the real
// filesystem produces ClassRefusedPath where the code expected ClassAbsent.
func TestRefusedSettingsDoNotReadAsNeverEnabled(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, "dotfiles-settings.json")
	if err := os.WriteFile(target, []byte(`{"enabledPlugins":{"p@mp":true}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home, ".claude", "settings.json")); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(home, ".claude", "plugins", "cache", "mp", "p",
		"1.0.0", ".mcp.json"), `{"mcpServers":{"srv":{"command":"npx","args":["x"]}}}`)
	writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

	enablement, known, warnings := enabledPlugins(home)
	if known {
		t.Error("a refused settings file was reported as known, so an empty enablement " +
			"map becomes a positive claim that no plugin was ever enabled")
	}
	if len(enablement) != 0 {
		t.Errorf("enablement = %v, want empty: nothing was read", enablement)
	}
	if len(warnings) == 0 {
		t.Error("a settings file that could not be read produced no warning")
	}
	if got := approvalForPlugin(enablement, known, "mp", "p"); got != approvalUnknown {
		t.Errorf("approval = %q, want %q: the server is in fact enabled, and reporting "+
			"not_approved invites ignoring a server that is running", got, approvalUnknown)
	}

	// And end to end. The explanation is carried by a diagnostic row rather than stamped on
	// every plugin row: a row holds one warning, so repeating a user-scope cause on each of
	// them would duplicate the diagnostic and crowd out whatever that row's own finding was.
	// The server row carries approval_state = 'unknown', and stays complete, because every
	// server its file declares is listed.
	var found, explained bool
	for _, row := range discoverForTest("alice", home) {
		if row.Warning.Code == warnPluginSettingsUnreadable {
			explained = true
		}
		if row.ServerName != "srv" {
			continue
		}
		found = true
		if row.Approval != approvalUnknown {
			t.Errorf("row approval = %q, want %q", row.Approval, approvalUnknown)
		}
		if !row.ScanComplete {
			t.Error("scan_complete = 0 on a row whose own file was read in full; an " +
				"unreadable settings file leaves approval_state unknown and the listing complete")
		}
	}
	if !found {
		t.Fatal("the server was not found")
	}
	if !explained {
		t.Error("no diagnostic row names the unreadable settings file, so the unknown " +
			"state has no stated cause anywhere in the result")
	}
}

// A refused orphan marker must not count as a marker that is not there.
func TestRefusedOrphanMarkerIsNotTreatedAsAbsent(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	testutil.WriteFile(t, filepath.Join(version, ".mcp.json"),
		`{"mcpServers":{"srv":{"command":"npx"}}}`)
	outside := filepath.Join(home, "marker-target")
	if err := os.WriteFile(outside, []byte("2026-01-01T00:00:00Z"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(version, ".orphaned_at")); err != nil {
		t.Fatal(err)
	}
	writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

	if got := versionSelection(home, filepath.Join(".claude", "plugins", "cache", "mp", "p",
		"1.0.0"), "mp", "p", map[string]map[string]struct{}{}, false); got != selectionUnknown {
		t.Errorf("selection = %v, want selectionUnknown: a marker this scan could not read "+
			"is not a marker that is absent", got)
	}
}

// A refused manifest is a manifest that exists, so its declarations are unlisted.
func TestRefusedManifestIsReported(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	testutil.WriteFile(t, filepath.Join(version, ".mcp.json"),
		`{"mcpServers":{"srv":{"command":"npx"}}}`)
	target := filepath.Join(home, "manifest-target.json")
	if err := os.WriteFile(target, []byte(`{"name":"p","mcpServers":{"hidden":{"command":"uvx"}}}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(version, ".claude-plugin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(version, ".claude-plugin", "plugin.json")); err != nil {
		t.Fatal(err)
	}
	writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

	var reported bool
	for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
		if row.Warning.Code == warnPluginManifestUnreadable {
			reported = true
		}
	}
	if !reported {
		t.Error("a manifest that exists and was refused produced no diagnostic, so its " +
			"declarations read as a plugin that declares nothing")
	}
}

// TestARefusedPluginCacheIsReported: a plugin cache reached through a symlink is reported as a
// listing that failed, not read as a host with no plugins.
func TestARefusedPluginCacheIsReported(t *testing.T) {
	home := t.TempDir()
	elsewhere := t.TempDir()
	testutil.WriteFile(t, filepath.Join(elsewhere, "mp", "p", "1.0.0", ".mcp.json"),
		`{"mcpServers":{"srv":{"command":"npx"}}}`)
	if err := os.MkdirAll(filepath.Join(home, ".claude", "plugins"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(home, ".claude", "plugins", "cache")); err != nil {
		t.Fatal(err)
	}
	var reported bool
	for _, row := range discoverForTest("alice", home) {
		if row.ServerName == "srv" {
			t.Error("a server behind a symlinked plugin cache was read")
		}
		if row.Warning.Code == warnPluginListUnreadable && row.Warning.Class == fsscan.ClassRefusedPath {
			reported = true
		}
	}
	if !reported {
		t.Error("a symlinked plugin cache produced no plugin_list_unreadable row")
	}
}

// A project list the read refuses because it is a symlink is reported, not read as absence.
// The list is the only record of the projects it names, so without a row the servers found
// through the other sources would read as the account's whole inventory.
func TestARefusedProjectListIsReported(t *testing.T) {
	for _, refused := range []string{".claude.json", ".codex"} {
		t.Run(refused, func(t *testing.T) {
			home := t.TempDir()
			elsewhere := t.TempDir()
			target := filepath.Join(elsewhere, refused)
			if refused == ".claude.json" {
				testutil.WriteFile(t, target, `{"projects":{}}`)
			} else {
				testutil.WriteFile(t, filepath.Join(target, "config.toml"), "")
			}
			if err := os.Symlink(target, filepath.Join(home, refused)); err != nil {
				t.Fatal(err)
			}
			var reported, profilesLost bool
			for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
				switch row.Warning.Code {
				case warnProjectListUnreadable:
					reported = true
				case warnProfileListUnreadable:
					profilesLost = row.Warning.Class == fsscan.ClassRefusedPath
				}
			}
			if !reported {
				t.Error("a symlinked project list produced no diagnostic, so the projects it " +
					"records read as never recorded")
			}
			// A symlinked ~/.codex also loses Codex's named profiles, a second thing, so it is
			// a second row.
			if refused == ".codex" && !profilesLost {
				t.Error("a symlinked ~/.codex did not report its named profiles as unlisted")
			}
		})
	}
}

// TestARefusedPluginConfigIsReportedAsItsOwnFile: a plugin's root .mcp.json that a read check
// refuses, here a hard link, is reported as a home config is, source_unreadable with the reason
// and the file's path, not with a sentence about project configuration files.
func TestARefusedPluginConfigIsReportedAsItsOwnFile(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"), `{"enabledPlugins":{"p@mp":true}}`)
	config := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0", ".mcp.json")
	testutil.WriteFile(t, config, `{"mcpServers":{"srv":{"command":"npx"}}}`)
	if err := os.Link(config, filepath.Join(home, "second-link.json")); err != nil {
		t.Skipf("hard links unavailable here: %v", err)
	}
	writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

	var reported bool
	for _, row := range discoverForTest("alice", home) {
		switch {
		case row.ServerName == "srv":
			t.Error("a hard-linked plugin config was read")
		case row.Warning.Code == warnProjectRefused || row.Warning.Code == warnProjectUserspaceFS:
			t.Errorf("the plugin config was reported as a project file: %s", row.Warning.render())
		case row.Warning.Code == warnSourceUnreadable:
			reported = row.SourcePath == config && row.Warning.Class == fsscan.ClassHardLink
		}
	}
	if !reported {
		t.Error("no source_unreadable row with reason=hard_link names the plugin config")
	}
}
