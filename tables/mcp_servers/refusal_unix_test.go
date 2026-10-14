//go:build unix

package mcp_servers

import (
	"os"
	"path/filepath"
	"testing"
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
	writeTestFile(t, filepath.Join(home, ".claude", "plugins", "cache", "mp", "p",
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
	// every plugin row: a row holds one warning, so repeating a home-scoped cause on each of
	// them would duplicate the diagnostic and crowd out whatever that row's own finding was.
	// What the server row must carry is scan_complete = 0, which is what stops it being
	// selected as trustworthy.
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
		if row.ScanComplete {
			t.Error("scan_complete = 1 on a row whose account's enablement could not be " +
				"read, so the row would be selected as trustworthy")
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
	writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	writeTestFile(t, filepath.Join(version, ".mcp.json"),
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
	writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	writeTestFile(t, filepath.Join(version, ".mcp.json"),
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
