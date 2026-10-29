//go:build unix

package mcp_servers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/macadmins/osquery-extension/pkg/testutil"
)

// symlink plants a link at path, creating its directory.
func symlink(t *testing.T, target, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

// TestAnInHomeConfigLinkIsFollowed: a home config, a project config and a plugin's root
// .mcp.json that a dotfile manager links to a file in the same home are read as that file, with
// source_path naming the link, where the client reads it. A link out of the home stays silent.
func TestAnInHomeConfigLinkIsFollowed(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	elsewhere := t.TempDir()
	dotfiles := filepath.Join(home, "dotfiles")
	testutil.WriteFile(t, filepath.Join(dotfiles, "cursor.json"),
		`{"mcpServers":{"linked-home":{"command":"npx","args":["a"]}}}`)
	symlink(t, filepath.Join(dotfiles, "cursor.json"), filepath.Join(home, ".cursor", "mcp.json"))

	project := filepath.Join(home, "code", "p")
	testutil.WriteFile(t, filepath.Join(dotfiles, "project.json"),
		`{"mcpServers":{"linked-project":{"command":"npx","args":["b"]}}}`)
	// Relative, climbing out of the project directory and back down within the home.
	symlink(t, filepath.Join("..", "..", "dotfiles", "project.json"), filepath.Join(project, ".mcp.json"))
	testutil.WriteFile(t, filepath.Join(home, ".claude.json"), `{"projects":{"`+project+`":{}}}`)

	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"), `{"enabledPlugins":{"p@mp":true}}`)
	testutil.WriteFile(t, filepath.Join(dotfiles, "plugin.json"),
		`{"mcpServers":{"linked-plugin":{"command":"npx","args":["c"]}}}`)
	symlink(t, filepath.Join(dotfiles, "plugin.json"),
		filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0", ".mcp.json"))
	writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

	testutil.WriteFile(t, filepath.Join(elsewhere, "gemini.json"),
		`{"mcpServers":{"outside":{"command":"npx"}}}`)
	symlink(t, filepath.Join(elsewhere, "gemini.json"), filepath.Join(home, ".gemini", "settings.json"))

	found := map[string]Server{}
	for _, row := range discoverForTest("alice", home) {
		if strings.Contains(row.SourcePath, ".gemini") {
			t.Errorf("a link out of the home produced a row: %+v", row)
		}
		if row.ServerName != "" {
			found[row.ServerName] = row
		}
	}
	for name, link := range map[string]string{
		"linked-home":    filepath.Join(home, ".cursor", "mcp.json"),
		"linked-project": filepath.Join(project, ".mcp.json"),
		"linked-plugin":  filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0", ".mcp.json"),
	} {
		row, ok := found[name]
		if !ok {
			t.Errorf("%s was not listed", name)
			continue
		}
		if row.SourcePath != link || !row.ScanComplete {
			t.Errorf("%s: source_path %q, scan_complete %v; want the link's path, complete",
				name, row.SourcePath, row.ScanComplete)
		}
	}
}

// TestAnInHomeSymlinkedProjectListIsFollowed: a ~/.claude.json linked to a file in the same home
// is read as that file, for its own servers and as the project list, and no list is reported
// lost.
func TestAnInHomeSymlinkedProjectListIsFollowed(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	project := filepath.Join(home, "code", "p")
	testutil.WriteFile(t, filepath.Join(project, ".mcp.json"),
		`{"mcpServers":{"from-project":{"command":"npx","args":["a"]}}}`)
	target := filepath.Join(home, "dotfiles", "claude.json")
	testutil.WriteFile(t, target, `{"mcpServers":{"from-list":{"command":"npx","args":["b"]}},`+
		`"projects":{"`+project+`":{"enabledMcpjsonServers":["from-project"]}}}`)
	symlink(t, target, filepath.Join(home, ".claude.json"))

	found := map[string]bool{}
	for _, row := range discoverForTest("alice", home) {
		if row.Warning.Code == warnProjectListUnreadable {
			t.Errorf("a list linked within the home was reported lost: %s", row.Warning.render())
		}
		found[row.ServerName] = true
	}
	if !found["from-list"] || !found["from-project"] {
		t.Errorf("servers found = %v, want the list's own and its project's", found)
	}
}

// TestADeclaredRootConfigIsNotFollowed: a plugin's root .mcp.json that links to a file in the
// home is followed, and a manifest that also declares ./.mcp.json gets that declaration read under
// the declared-source rules, which do not follow a link, so it reports
// plugin_manifest_missing_source. The declaration reused the root file's followed read.
func TestADeclaredRootConfigIsNotFollowed(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"), `{"enabledPlugins":{"p@mp":true}}`)
	testutil.WriteFile(t, filepath.Join(home, "dotfiles", "plugin.json"),
		`{"mcpServers":{"linked-plugin":{"command":"npx","args":["c"]}}}`)
	symlink(t, filepath.Join(home, "dotfiles", "plugin.json"), filepath.Join(version, ".mcp.json"))
	testutil.WriteFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
		`{"name":"p","mcpServers":"./.mcp.json"}`)
	writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

	listed, missing := false, 0
	for _, row := range discoverForTest("alice", home) {
		listed = listed || row.ServerName == "linked-plugin"
		if row.Warning.Code == warnPluginManifestMissing {
			missing++
		}
	}
	if !listed || missing != 1 {
		t.Errorf("listed = %v, plugin_manifest_missing_source rows = %d; want the root file's server "+
			"and one row for the declared link", listed, missing)
	}
}

// TestALinkedPluginCacheLevelIsReported: a marketplace, plugin or version directory that is a
// symlink is not listed through, and is reported as a plugin_list_unreadable row with
// reason=refused_path, as a refused listing is; a real plugin beside it is still listed.
func TestALinkedPluginCacheLevelIsReported(t *testing.T) {
	for _, level := range []string{"marketplace", "plugin", "version"} {
		t.Run(level, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "alice")
			cache := filepath.Join(home, ".claude", "plugins", "cache")
			testutil.WriteFile(t, filepath.Join(cache, "mp", "real", "1.0.0", ".mcp.json"),
				`{"mcpServers":{"real-srv":{"command":"npx","args":["r"]}}}`)
			elsewhere := filepath.Join(home, "elsewhere")
			// A configuration at each depth the link could stand for, so following it at any
			// level would list linked-srv.
			for _, rel := range []string{".mcp.json", filepath.Join("1.0.0", ".mcp.json"),
				filepath.Join("p", "1.0.0", ".mcp.json")} {
				testutil.WriteFile(t, filepath.Join(elsewhere, rel),
					`{"mcpServers":{"linked-srv":{"command":"npx","args":["l"]}}}`)
			}
			link := map[string]string{
				"marketplace": filepath.Join(cache, "linked-mp"),
				"plugin":      filepath.Join(cache, "mp", "linked"),
				"version":     filepath.Join(cache, "mp", "real", "2.0.0"),
			}[level]
			symlink(t, elsewhere, link)
			writeInstalledPlugins(t, home, map[string]string{"real@mp": "1.0.0"})

			listed, refused := false, 0
			for _, row := range discoverForTest("alice", home) {
				listed = listed || row.ServerName == "real-srv"
				if row.ServerName == "linked-srv" {
					t.Errorf("a server under the link was listed: %+v", row)
				}
				if row.Warning.Code == warnPluginListUnreadable && row.Warning.Class == fsscan.ClassRefusedPath {
					refused++
				}
			}
			if !listed || refused != 1 {
				t.Errorf("real plugin listed = %v, refused listings = %d; want true and 1", listed, refused)
			}
		})
	}
}
