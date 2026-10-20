package mcp_servers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/macadmins/osquery-extension/pkg/devclients"
	"github.com/macadmins/osquery-extension/pkg/testutil"
)

// writePluginFixture builds a ~/.claude plugin tree: a settings file recording enablement and
// one installed plugin per entry.
func writePluginFixture(t *testing.T, home string, enablement map[string]bool,
	configs map[string]string) {
	t.Helper()
	if enablement != nil {
		var pairs []string
		for name, on := range enablement {
			value := "false"
			if on {
				value = "true"
			}
			pairs = append(pairs, `"`+name+`":`+value)
		}
		sort.Strings(pairs)
		testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
			`{"theme":"dark","enabledPlugins":{`+joinComma(pairs)+`}}`)
	}
	installs := map[string]string{}
	for rel, content := range configs {
		testutil.WriteFile(t, filepath.Join(home, ".claude", "plugins", "cache", rel), content)
		// Records derived from the same paths, so a fixture declares the tree once and the
		// two stay consistent. A cache directory alone is not evidence that the client would
		// load that version, and a real host carries both.
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) >= 3 {
			installs[parts[1]+"@"+parts[0]] = parts[2]
		}
	}
	if len(installs) > 0 {
		writeInstalledPlugins(t, home, installs)
	}
}

func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out
}

// An enabled plugin's servers are listed, and enablement reaches approval_state.
//
// This is the gap the live run found: ~/.claude.json declared four servers and the session had
// eight, the other four coming from an enabled plugin's own .mcp.json. The previous design
// excluded that whole directory as marketplace catalog noise, which was right about the
// catalog and wrong about the installed copy.
func TestInstalledPluginServersAreListedWithEnablement(t *testing.T) {
	home := t.TempDir()
	writePluginFixture(t, home,
		map[string]bool{
			"data-plat@data-plat-marketplace": true,
			// Explicitly turned off, which is a different fact from never turned on.
			"legacy@data-plat-marketplace": false,
		},
		map[string]string{
			// The real shape, including the `//` inside a URL that a naive comment stripper
			// would cut the value at.
			filepath.Join("data-plat-marketplace", "data-plat", "1.1.0", ".mcp.json"): `{
				"mcpServers": {
					"datadog": {"type": "http", "url": "https://example.test/api/mcp"},
					"deepsearch": {"type": "http", "url": "https://example.test/ds"}
				}
			}`,
			filepath.Join("data-plat-marketplace", "legacy", "0.9.0", ".mcp.json"): `{
				"mcpServers": {"retired": {"command": "npx", "args": ["x"]}}
			}`,
			// Installed and never enabled.
			filepath.Join("other-marketplace", "vetting", "0.1.0", ".mcp.json"): `{
				"mcpServers": {"vetting": {"command": "uvx", "args": ["y"]}}
			}`,
			// A plugin that ships no MCP config at all, which is the common case: most
			// plugins carry skills or commands and no servers. Must be silent.
			filepath.Join("other-marketplace", "skills-only", "2.0.0", "SKILL.md"): `# nothing`,
		})

	byName := map[string]Server{}
	for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
		if row.ServerName != "" {
			byName[row.ServerName] = row
		}
	}

	for name, want := range map[string]approvalState{
		"datadog":    approvalEnabled,
		"deepsearch": approvalEnabled,
		"retired":    approvalDisabled,
		"vetting":    approvalNotApproved,
	} {
		row, found := byName[name]
		if !found {
			t.Errorf("plugin-declared server %q was not listed; found %v", name, keysOf(byName))
			continue
		}
		if row.Approval != want {
			t.Errorf("%s: approval = %q, want %q", name, row.Approval, want)
		}
		if row.Client != "claude_code" {
			t.Errorf("%s: client = %q, want claude_code", name, row.Client)
		}
		if row.SourceContext != pluginSourceContext {
			t.Errorf("%s: source_context = %q, want %q", name, row.SourceContext,
				pluginSourceContext)
		}
		// An enabled plugin's servers are ordinary configuration, so the row is a complete
		// listing of its source.
		if !row.ScanComplete {
			t.Errorf("%s: scan_complete is false for a cleanly read plugin config", name)
		}
	}
	// The URL survived the comment stripper, which is the detail that would break silently.
	if got := byName["datadog"].URL; got != "https://example.test" {
		t.Errorf("datadog url_endpoint = %q; the // inside the value was mishandled", got)
	}
}

// The marketplace checkout is not read, which is what keeps the catalog noise out.
//
// ~/.claude/plugins/marketplaces/<name>/ is the marketplace's own git checkout. It holds the
// plugin source, so reading it would both reintroduce the installable-catalog rows the
// previous design measured at 39 of 51 and double-count every plugin that is installed. Only
// plugins/cache/ -- which exists because the user installed something -- is probed.
func TestMarketplaceCatalogIsNotProbed(t *testing.T) {
	home := t.TempDir()
	writePluginFixture(t, home, map[string]bool{"real@mp": true}, map[string]string{
		filepath.Join("mp", "real", "1.0.0", ".mcp.json"): `{"mcpServers":{"installed":{"command":"npx","args":["x"]}}}`,
	})
	// The catalog copy, declaring the same server plus thirty others nobody installed.
	testutil.WriteFile(t, filepath.Join(home, ".claude", "plugins", "marketplaces", "mp", ".mcp.json"),
		`{"mcpServers":{"installed":{"command":"npx","args":["x"]},"catalog-only":{"command":"npx","args":["y"]}}}`)

	var names []string
	for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
		if row.ServerName != "" {
			names = append(names, row.ServerName)
		}
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, []string{"installed"}) {
		t.Errorf("names = %v; only the installed copy may be read, so a catalog entry "+
			"nobody installed must not appear and the installed one must not double", names)
	}
}

// Unreadable settings leave the servers listed and the approval state honest.
//
// A plugin config is still configuration whether or not its enablement can be read, so the
// servers must appear. What must not happen is a confident claim either way: not "enabled" on
// a guess, and not "not_approved" either, which is a positive finding about a decision that
// was never readable.
func TestUnreadablePluginSettingsStillListsServers(t *testing.T) {
	home := t.TempDir()
	// A settings file that exists and is not JSON.
	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"), `{ not json`)
	testutil.WriteFile(t, filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0", ".mcp.json"),
		`{"mcpServers":{"orphan":{"command":"npx","args":["x"]}}}`)

	var found bool
	var sawWarning bool
	for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
		if row.ServerName == "orphan" {
			found = true
			// Unknown, not notApproved. The settings file exists and could not be parsed,
			// so nothing is known about this plugin's state -- and the row's own warning
			// says exactly that, so the column must not contradict it by making a positive
			// claim about a decision nobody could read.
			if row.Approval != approvalUnknown {
				t.Errorf("approval = %q, want %q: unreadable settings are not evidence "+
					"of non-enablement", row.Approval, approvalUnknown)
			}
		}
		if row.Warning.Code == warnPluginSettingsUnreadable {
			sawWarning = true
		}
	}
	if !found {
		t.Error("the plugin's server was dropped because its enablement was unknown")
	}
	if !sawWarning {
		t.Error("unreadable plugin settings were not reported")
	}
}

// TestPluginEnumerationReportsTheLimitReached: each enumeration limit that drops part of the
// cache is reported with its own count and limit, so the row names the cap that was reached.
// One truncation flag reported every cause as the 200-version probe budget, with the count of
// versions found, so a marketplace with 51 plugins read count=50, limit=200.
func TestPluginEnumerationReportsTheLimitReached(t *testing.T) {
	type truncation struct{ count, limit int }
	for name, testCase := range map[string]struct {
		build func(t *testing.T, cache string)
		want  []truncation
	}{
		"marketplaces": {func(t *testing.T, cache string) {
			for index := 0; index <= maxPluginMarketplaces; index++ {
				mkdirs(t, filepath.Join(cache, fmt.Sprintf("m%02d", index), "p", "1.0.0"))
			}
		}, []truncation{{maxPluginMarketplaces, maxPluginMarketplaces}}},
		"plugins in a marketplace": {func(t *testing.T, cache string) {
			for index := 0; index <= maxPluginsPerMarket; index++ {
				mkdirs(t, filepath.Join(cache, "mp", fmt.Sprintf("p%02d", index), "1.0.0"))
			}
		}, []truncation{{maxPluginsPerMarket, maxPluginsPerMarket}}},
		"versions of a plugin": {func(t *testing.T, cache string) {
			for index := 0; index <= maxPluginVersions; index++ {
				mkdirs(t, filepath.Join(cache, "mp", "p", fmt.Sprintf("1.0.%d", index)))
			}
		}, []truncation{{maxPluginVersions, maxPluginVersions}}},
		"entries in a directory": {func(t *testing.T, cache string) {
			mkdirs(t, filepath.Join(cache, "mp", "p", "1.0.0"))
			for index := 0; index < maxPluginDirEntries; index++ {
				testutil.WriteFile(t, filepath.Join(cache, "mp", fmt.Sprintf("f%03d", index)), "")
			}
		}, []truncation{{maxPluginDirEntries, maxPluginDirEntries}}},
		"probe budget": {func(t *testing.T, cache string) {
			for market := 0; market < 5; market++ {
				for plugin := 0; plugin < 41; plugin++ {
					mkdirs(t, filepath.Join(cache, fmt.Sprintf("m%d", market), fmt.Sprintf("p%02d", plugin), "1.0.0"))
				}
			}
		}, []truncation{{maxPluginProbes, maxPluginProbes}}},
		// The probe budget stops the scan at the 41st of 51 plugins, so the 50-plugin cap was
		// never reached and only the budget is reported. Both were, because a level's cap was
		// reported when its names were listed, before its loop ran.
		"probe budget before a level cap": {func(t *testing.T, cache string) {
			for plugin := 0; plugin <= maxPluginsPerMarket; plugin++ {
				for version := 0; version < 5; version++ {
					mkdirs(t, filepath.Join(cache, "mp", fmt.Sprintf("p%02d", plugin), fmt.Sprintf("1.0.%d", version)))
				}
			}
		}, []truncation{{maxPluginProbes, maxPluginProbes}}},
		// The entries past the bound were never read, so the bound is reported however the
		// scan ends. The marketplace holds one directory more than the bound reads, and any 50
		// of them hold 500 versions, so the probe budget stops the plugin loop before it ends;
		// the bound was reported only when that loop finished.
		"entry bound and probe budget": {func(t *testing.T, cache string) {
			for plugin := 0; plugin <= maxPluginDirEntries; plugin++ {
				for version := 0; version < maxPluginVersions; version++ {
					mkdirs(t, filepath.Join(cache, "mp", fmt.Sprintf("p%03d", plugin), fmt.Sprintf("1.0.%d", version)))
				}
			}
		}, []truncation{{maxPluginDirEntries, maxPluginDirEntries}, {maxPluginProbes, maxPluginProbes}}},
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			testCase.build(t, filepath.Join(home, ".claude", "plugins", "cache"))
			refs, warnings, _ := claudePluginRefs(context.Background(), home, time.Now().Add(time.Minute))
			var got []truncation
			for _, w := range mergeWarnings(warnings) {
				if w.Code == warnPluginListTruncated {
					got = append(got, truncation{w.Count, int(w.Limit)})
				}
			}
			if !reflect.DeepEqual(got, testCase.want) || len(refs) > maxPluginProbes {
				t.Errorf("truncations = %v with %d refs, want %v", got, len(refs), testCase.want)
			}
		})
	}
}

// mkdirs creates a directory and its parents.
func mkdirs(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func keysOf(m map[string]Server) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func itoaPad(i int) string {
	const digits = "0123456789"
	return string([]byte{digits[(i/100)%10], digits[(i/10)%10], digits[i%10]})
}

// writeInstalledPlugins writes the install records for one plugin version.
//
// Every fixture that builds a plugin cache needs these, because a cache directory alone is not
// evidence that the client would load it. A real host with an installed plugin has both.
func writeInstalledPlugins(t *testing.T, home string, installs map[string]string) {
	t.Helper()
	plugins := make(map[string]any, len(installs))
	for id, version := range installs {
		// installPath is what selection is established from, so every record carries it.
		// Derived from the id so a test declares the tree once: the cache directory is
		// cache/<marketplace>/<plugin>/<version>/ and the id is <plugin>@<marketplace>.
		plugin, marketplace, found := strings.Cut(id, "@")
		if !found {
			t.Fatalf("plugin id %q is not <plugin>@<marketplace>", id)
		}
		plugins[id] = []any{map[string]any{
			"version": version,
			"scope":   "user",
			"installPath": filepath.Join(home, ".claude", "plugins", "cache",
				marketplace, plugin, version),
		}}
	}
	body, err := json.Marshal(map[string]any{"version": 2, "plugins": plugins})
	if err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(home, ".claude", "plugins", "installed_plugins.json"),
		string(body))
}

// A version the client would not load must not inherit the plugin's enabled state.
//
// Claude writes an `.orphaned_at` marker into the previous version's directory on update and
// removes the directory in a background sweep fourteen days later, so that a session which
// already loaded it keeps running. Both versions were probed and both were given the
// plugin-level enablement, so for two weeks after any update a server deleted in the new
// release was still reported as `enabled` with no warning.
func TestSupersededPluginVersionIsNotReportedEnabled(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	base := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p")
	testutil.WriteFile(t, filepath.Join(base, "1.0.0", ".mcp.json"),
		`{"mcpServers":{"old-only":{"command":"npx","args":["x"]}}}`)
	testutil.WriteFile(t, filepath.Join(base, "2.0.0", ".mcp.json"),
		`{"mcpServers":{"current":{"command":"npx","args":["x"]}}}`)
	// The records select 2.0.0 only.
	writeInstalledPlugins(t, home, map[string]string{"p@mp": "2.0.0"})

	states := map[string]approvalState{}
	warnings := map[string]warnCode{}
	for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
		if row.rawName == "" {
			continue
		}
		states[row.ServerName] = row.Approval
		warnings[row.ServerName] = row.Warning.Code
	}
	if states["current"] != approvalEnabled {
		t.Errorf("the selected version's server = %q, want %q",
			states["current"], approvalEnabled)
	}
	// Kept rather than dropped: the files are on disk and a session that loaded them may
	// still be running. What must not survive is the claim that it is enabled.
	if _, listed := states["old-only"]; !listed {
		t.Fatal("the superseded version's server vanished; it should be reported with " +
			"its state qualified, since a running session may still hold it")
	}
	if states["old-only"] == approvalEnabled {
		t.Errorf("a superseded version was reported as %q", approvalEnabled)
	}
	if states["old-only"] != approvalUnknown {
		t.Errorf("superseded approval = %q, want %q", states["old-only"], approvalUnknown)
	}
	if warnings["old-only"] != warnPluginSuperseded {
		t.Errorf("superseded warning = %q, want %q", warnings["old-only"], warnPluginSuperseded)
	}
}

// The orphan marker alone is sufficient, because it survives a records file that does not.
func TestOrphanMarkerSupersedesAVersion(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	dir := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	testutil.WriteFile(t, filepath.Join(dir, ".mcp.json"),
		`{"mcpServers":{"srv":{"command":"npx","args":["x"]}}}`)
	testutil.WriteFile(t, filepath.Join(dir, ".orphaned_at"), "2026-01-01T00:00:00.000Z")
	// The records still name this version, so only the marker distinguishes it.
	writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

	for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
		if row.ServerName != "srv" {
			continue
		}
		if row.Approval != approvalUnknown {
			t.Errorf("approval = %q, want %q: the directory is marked orphaned",
				row.Approval, approvalUnknown)
		}
		if row.Warning.Code != warnPluginSuperseded {
			t.Errorf("warning = %q, want %q", row.Warning.Code, warnPluginSuperseded)
		}
		return
	}
	t.Fatal("the server was not found")
}

// Unreadable records leave selection unknown, and say so rather than guessing either way.
func TestUnreadablePluginRecordsQualifyApproval(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	testutil.WriteFile(t, filepath.Join(home, ".claude", "plugins", "cache", "mp", "p",
		"1.0.0", ".mcp.json"), `{"mcpServers":{"srv":{"command":"npx","args":["x"]}}}`)
	testutil.WriteFile(t, filepath.Join(home, ".claude", "plugins", "installed_plugins.json"),
		`{"version":2,"plugins":{`)

	var found bool
	for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
		if row.ServerName != "srv" {
			continue
		}
		found = true
		if row.Approval != approvalUnknown {
			t.Errorf("approval = %q, want %q", row.Approval, approvalUnknown)
		}
		// The row says its selection could not be established; the records reader reports
		// the *cause* once, at account level. Selection also goes unknown for an unreadable
		// orphan marker and for a record with no installPath, neither of which is a
		// records-read failure, so the row does not name a cause.
		if row.Warning.Code != warnPluginSelectionUnknown {
			t.Errorf("row warning = %q, want %q", row.Warning.Code, warnPluginSelectionUnknown)
		}
	}
	if !found {
		t.Fatal("the server was not found")
	}
	var causeReported bool
	for _, row := range discoverForTest("alice", home) {
		if row.Warning.Code == warnPluginRecordsUnreadable {
			causeReported = true
		}
	}
	if !causeReported {
		t.Error("nothing reports that the install records could not be read, so the " +
			"unknown selection has no stated cause anywhere in the result")
	}
}

// A manifest-declared server must be inventoried, in every shape this table can read.
//
// Only `<version>/.mcp.json` was probed, so a plugin declaring its servers in
// `.claude-plugin/plugin.json` was omitted with no row and no diagnostic, while a sibling
// client's rows still reported scan_complete = 1. The manifest key is documented to take an
// inline map, a `./*.json` path, or an array mixing them.
func TestManifestDeclaredPluginServersAreListed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		manifest string
		extra    map[string]string
		want     []string
	}{
		{
			name:     "inline map",
			manifest: `{"name":"p","mcpServers":{"inline-srv":{"command":"npx","args":["x"]}}}`,
			want:     []string{"inline-srv"},
		},
		{
			name:     "json path",
			manifest: `{"name":"p","mcpServers":"./mcp/servers.json"}`,
			extra: map[string]string{
				"mcp/servers.json": `{"mcpServers":{"path-srv":{"command":"uvx"}}}`,
			},
			want: []string{"path-srv"},
		},
		{
			name: "array mixing both",
			manifest: `{"name":"p","mcpServers":[` +
				`"./mcp/servers.json",{"inline-srv":{"command":"npx"}}]}`,
			extra: map[string]string{
				"mcp/servers.json": `{"mcpServers":{"path-srv":{"command":"uvx"}}}`,
			},
			want: []string{"inline-srv", "path-srv"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
				`{"enabledPlugins":{"p@mp":true}}`)
			version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
			// Deliberately no .mcp.json at the plugin root: the manifest is the only
			// declaration, which is the case that produced nothing at all.
			testutil.WriteFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
				tc.manifest)
			for rel, body := range tc.extra {
				testutil.WriteFile(t, filepath.Join(version, filepath.FromSlash(rel)), body)
			}
			writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

			var got []string
			for _, row := range serversOnly(discoverForTest("alice", home)) {
				got = append(got, row.ServerName)
				if row.Approval != approvalEnabled {
					t.Errorf("%s: approval = %q, want %q",
						row.ServerName, row.Approval, approvalEnabled)
				}
			}
			sort.Strings(got)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("servers = %v, want %v", got, tc.want)
			}
		})
	}
}

// The manifest loads after `.mcp.json`, so a name it repeats replaces the earlier definition.
func TestManifestOverridesTheRootConfigForARepeatedName(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	testutil.WriteFile(t, filepath.Join(version, ".mcp.json"),
		`{"mcpServers":{"srv":{"command":"npx","args":["from-root"]}}}`)
	testutil.WriteFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
		`{"name":"p","mcpServers":{"srv":{"command":"uvx","args":["from-manifest"]}}}`)
	writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

	rows := serversOnly(discoverForTest("alice", home))
	if len(rows) != 1 {
		t.Fatalf("one name declared twice must yield one row, got %d: %+v", len(rows), rows)
	}
	if rows[0].Command != "uvx" {
		t.Errorf("command = %q, want the manifest's %q: the manifest loads after "+
			".mcp.json, so its definition is the one the client runs", rows[0].Command, "uvx")
	}
}

// A declaration this table will not follow is reported rather than passed over.
func TestUnsupportedManifestDeclarationIsReported(t *testing.T) {
	for _, declaration := range []string{
		`"./bundle.mcpb"`,
		`"./bundle.dxt"`,
		`"https://example.test/server.mcpb"`,
		`"../outside/servers.json"`,
	} {
		t.Run(declaration, func(t *testing.T) {
			home := t.TempDir()
			testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
				`{"enabledPlugins":{"p@mp":true}}`)
			version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
			testutil.WriteFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
				`{"name":"p","mcpServers":`+declaration+`}`)
			writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

			var reported bool
			for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
				if row.Warning.Code == warnPluginManifestUnsupported {
					reported = true
				}
			}
			if !reported {
				t.Error("a declaration that was not followed produced no diagnostic, so " +
					"the result reads as a plugin with no servers")
			}
		})
	}
}

// A record whose installPath names a different copy does not select this one.
//
// Selection matched on the version string, so any cached directory labelled `1.0.0` counted
// as selected even when the record pointed elsewhere. A version names a release; several
// directories can carry the same label.
func TestSelectionRequiresTheRecordedInstallPath(t *testing.T) {
	for _, tc := range []struct {
		name   string
		record map[string]any
		want   approvalState
	}{
		{
			name:   "path names this directory",
			record: map[string]any{"version": "1.0.0", "installPath": "CACHE"},
			want:   approvalEnabled,
		},
		{
			name: "same version, different path",
			record: map[string]any{"version": "1.0.0",
				"installPath": "/opt/elsewhere/mp/p/1.0.0"},
			want: approvalUnknown,
		},
		{
			name:   "version but no path is not evidence",
			record: map[string]any{"version": "1.0.0"},
			want:   approvalUnknown,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			cache := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
			testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
				`{"enabledPlugins":{"p@mp":true}}`)
			testutil.WriteFile(t, filepath.Join(cache, ".mcp.json"),
				`{"mcpServers":{"srv":{"command":"npx","args":["x"]}}}`)
			record := map[string]any{}
			for k, v := range tc.record {
				if v == "CACHE" {
					v = cache
				}
				record[k] = v
			}
			body, err := json.Marshal(map[string]any{"version": 2,
				"plugins": map[string]any{"p@mp": []any{record}}})
			if err != nil {
				t.Fatal(err)
			}
			testutil.WriteFile(t, filepath.Join(home, ".claude", "plugins",
				"installed_plugins.json"), string(body))

			var found bool
			for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
				if row.ServerName != "srv" {
					continue
				}
				found = true
				if row.Approval != tc.want {
					t.Errorf("approval = %q, want %q", row.Approval, tc.want)
				}
			}
			if !found {
				t.Fatal("the server was not found")
			}
		})
	}
}

// A malformed sibling declaration marks its whole source incomplete, not just its own row.
//
// Each array element went through finishProcessing separately, so completeness was computed
// per declaration. A manifest holding one healthy inline server and one with `"command": 123`
// produced the right diagnostic and left the healthy row from the same source_path at
// scan_complete = 1 -- a falsely complete listing of that file.
func TestMalformedSiblingDeclarationMarksTheSourceIncomplete(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	testutil.WriteFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
		`{"name":"p","mcpServers":[`+
			`{"healthy":{"command":"npx","args":["x"]}},`+
			`{"broken":{"command":123}}]}`)
	writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

	var healthy *Server
	for _, row := range discoverForTest("alice", home) {
		if row.ServerName == "healthy" {
			copied := row
			healthy = &copied
		}
	}
	if healthy == nil {
		t.Fatal("the healthy server was dropped; a malformed sibling must not hide it")
	}
	if healthy.ScanComplete {
		t.Error("scan_complete = 1 on a row whose source had a declaration that would " +
			"not parse, so `WHERE scan_complete = 1` returns a falsely complete listing")
	}
}

// Two rejected names in two inline maps must not publish the identical placeholder.
//
// Ordinals were assigned per finishProcessing call, so each saw one name and both got
// ordinal 1. The rows then differed in nothing an operator can see, which is exactly what
// the documented `#2`, `#3` suffix exists to prevent.
func TestPlaceholdersAreNumberedAcrossInlineDeclarations(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	// Two names the grammar refuses, in separate inline maps, with identical launch
	// configurations so the published rows have nothing else to tell them apart.
	testutil.WriteFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
		`{"name":"p","mcpServers":[`+
			`{"a one":{"command":"npx","args":["pkg"]}},`+
			`{"a two":{"command":"npx","args":["pkg"]}}]}`)
	writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

	published := map[string]int{}
	raw := map[string]struct{}{}
	for _, row := range discoverForTest("alice", home) {
		if row.rawName == "" {
			continue
		}
		raw[row.rawName] = struct{}{}
		published[serverToRow(row)["server_name"]]++
	}
	if len(raw) != 2 {
		t.Fatalf("expected two distinct raw names, got %v", raw)
	}
	for name, count := range published {
		if count > 1 {
			t.Errorf("%d rows published the identical server_name %q, so they cannot be "+
				"told apart", count, name)
		}
	}
}

// A file the manifest names and that cannot be read is reported, unlike the optional root.
func TestMissingDeclaredSourceIsReported(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	// A healthy root config, so the plugin is not simply empty.
	testutil.WriteFile(t, filepath.Join(version, ".mcp.json"),
		`{"mcpServers":{"srv":{"command":"npx","args":["x"]}}}`)
	testutil.WriteFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
		`{"name":"p","mcpServers":"./missing.json"}`)
	writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

	var reported bool
	for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
		if row.Warning.Code == warnPluginManifestMissing {
			reported = true
		}
	}
	if !reported {
		t.Error("a manifest naming a file that does not exist produced no diagnostic, so " +
			"the broken reference reads as a plugin with fewer servers")
	}
}

// A manifest cannot multiply reads without bound, and the loss is reported.
func TestManifestSourceCountIsBounded(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	var declarations []string
	for index := 0; index < 500; index++ {
		rel := fmt.Sprintf("mcp/servers-%03d.json", index)
		declarations = append(declarations, fmt.Sprintf("%q", "./"+rel))
		testutil.WriteFile(t, filepath.Join(version, filepath.FromSlash(rel)),
			fmt.Sprintf(`{"mcpServers":{"srv-%03d":{"command":"npx"}}}`, index))
	}
	testutil.WriteFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
		`{"name":"p","mcpServers":[`+strings.Join(declarations, ",")+`]}`)
	writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

	var servers, truncations int
	for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
		if row.rawName != "" {
			servers++
		}
		if row.Warning.Code == warnPluginManifestTruncated {
			truncations++
			if row.Warning.Count != 500 || row.Warning.Limit != maxManifestSourcesPerVersion {
				t.Errorf("truncation = count %d limit %d, want the manifest's 500 declarations against %d",
					row.Warning.Count, row.Warning.Limit, maxManifestSourcesPerVersion)
			}
		}
		if row.Warning.Code == warnPluginManifestExhausted {
			t.Errorf("one manifest within the per-pass bound reported the per-pass stop: %+v", row.Warning)
		}
	}
	if servers > maxManifestSourcesPerVersion {
		t.Errorf("%d servers from one manifest: the per-version cap of %d did not apply",
			servers, maxManifestSourcesPerVersion)
	}
	if truncations != 1 {
		t.Errorf("%d plugin_manifest_truncated rows, want one for the manifest that declared too many", truncations)
	}
}

// TestManifestReadsAcrossPluginsAreBounded: ten plugins declaring eight files each stay within
// the per-version cap but reach the per-pass bound of 64 declared reads. The stop is its own code,
// on each manifest left with an unread declared file, and not plugin_manifest_truncated, whose
// sentence says a manifest declares more than this table reads, which none of these does.
func TestManifestReadsAcrossPluginsAreBounded(t *testing.T) {
	home := t.TempDir()
	installs := map[string]string{}
	var enabled []string
	for plugin := 0; plugin < 10; plugin++ {
		id := fmt.Sprintf("p%d@mp", plugin)
		installs[id] = "1.0.0"
		enabled = append(enabled, fmt.Sprintf("%q:true", id))
		version := filepath.Join(home, ".claude", "plugins", "cache", "mp", fmt.Sprintf("p%d", plugin), "1.0.0")
		var declarations []string
		for index := 0; index < maxManifestSourcesPerVersion; index++ {
			rel := fmt.Sprintf("mcp/servers-%d.json", index)
			declarations = append(declarations, fmt.Sprintf("%q", "./"+rel))
			testutil.WriteFile(t, filepath.Join(version, filepath.FromSlash(rel)),
				fmt.Sprintf(`{"mcpServers":{"srv-%d-%d":{"command":"npx"}}}`, plugin, index))
		}
		testutil.WriteFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
			`{"name":"p","mcpServers":[`+strings.Join(declarations, ",")+`]}`)
	}
	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{`+strings.Join(enabled, ",")+`}}`)
	writeInstalledPlugins(t, home, installs)

	servers, exhausted := 0, map[string]bool{}
	for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
		if row.rawName != "" {
			servers++
		}
		switch row.Warning.Code {
		case warnPluginManifestTruncated:
			t.Errorf("a manifest within the per-version cap reported plugin_manifest_truncated: %s", row.SourcePath)
		case warnPluginManifestExhausted:
			if row.Warning.Limit != maxManifestSourcesPerPass || row.Warning.Count != 0 {
				t.Errorf("per-pass stop = count %d limit %d, want no count and limit %d",
					row.Warning.Count, row.Warning.Limit, maxManifestSourcesPerPass)
			}
			exhausted[row.SourcePath] = true
		}
	}
	if servers != maxManifestSourcesPerPass {
		t.Errorf("%d servers listed, want the %d the per-pass bound admits", servers, maxManifestSourcesPerPass)
	}
	if len(exhausted) != 2 {
		t.Errorf("per-pass stop reported on %d manifests, want the two left with unread files: %v", len(exhausted), exhausted)
	}
}

// TestRepeatedDeclarationsAreChargedOnce: nine plugins each declare one file and then one missing
// file seven times, eight declarations, so the scan needs 18 reads, well within the per-pass
// bound of 64. The bound was charged before the memoised read was consulted, and a failed read
// was not memoised, so either one spent 72 and the ninth plugin's server was not listed.
func TestRepeatedDeclarationsAreChargedOnce(t *testing.T) {
	home := t.TempDir()
	installs := map[string]string{}
	var enabled []string
	for plugin := 0; plugin < 9; plugin++ {
		id := fmt.Sprintf("p%d@mp", plugin)
		installs[id] = "1.0.0"
		enabled = append(enabled, fmt.Sprintf("%q:true", id))
		version := filepath.Join(home, ".claude", "plugins", "cache", "mp", fmt.Sprintf("p%d", plugin), "1.0.0")
		testutil.WriteFile(t, filepath.Join(version, "servers.json"),
			fmt.Sprintf(`{"mcpServers":{"srv-%d":{"command":"npx"}}}`, plugin))
		declarations := `"./servers.json"` + strings.Repeat(`,"./missing.json"`, 7)
		testutil.WriteFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
			`{"name":"p","mcpServers":[`+declarations+`]}`)
	}
	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{`+strings.Join(enabled, ",")+`}}`)
	writeInstalledPlugins(t, home, installs)

	servers := map[string]bool{}
	for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
		if row.rawName != "" {
			servers[row.rawName] = true
		}
		if row.Warning.Code == warnPluginManifestExhausted {
			t.Errorf("the per-pass bound was reached on %s", row.SourcePath)
		}
	}
	if len(servers) != 9 {
		t.Errorf("%d servers listed, want one per plugin: %v", len(servers), servers)
	}
}

// A repeated declaration is read once but still decides precedence.
func TestRepeatedDeclarationIsMemoisedWithoutChangingPrecedence(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	testutil.WriteFile(t, filepath.Join(version, ".mcp.json"),
		`{"mcpServers":{"srv":{"command":"npx","args":["from-root"]}}}`)
	testutil.WriteFile(t, filepath.Join(version, "mcp", "servers.json"),
		`{"mcpServers":{"srv":{"command":"uvx","args":["from-file"]}}}`)
	// The same path twice, then an inline map, then the path again: the last declaration of
	// `srv` is the file, so the file's definition must win over the inline one.
	testutil.WriteFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
		`{"name":"p","mcpServers":["./mcp/servers.json",`+
			`{"srv":{"command":"node","args":["inline"]}},"./mcp/servers.json"]}`)
	writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

	rows := serversOnly(discoverForTest("alice", home))
	if len(rows) != 1 {
		t.Fatalf("one name declared four times must yield one row, got %d", len(rows))
	}
	if rows[0].Command != "uvx" {
		t.Errorf("command = %q, want %q: the last declaration is the repeated file, so "+
			"memoising its bytes must not move it ahead of the inline map",
			rows[0].Command, "uvx")
	}
}

// An override that cannot be decoded must not leave the earlier definition looking clean.
//
// The merger keyed on names it decoded successfully, so a manifest declaring
// `"srv":{"command":123}` produced a parse diagnostic and left the root `.mcp.json`'s `srv`
// standing as enabled and complete with no warning. A query for trustworthy enabled servers
// then returned a definition that a higher-precedence declaration had replaced with something
// unreadable.
func TestUndecodableOverrideQualifiesTheEarlierDefinition(t *testing.T) {
	for _, tc := range []struct {
		name     string
		manifest string
		extra    map[string]string
	}{
		{
			name:     "inline override",
			manifest: `{"name":"p","mcpServers":{"srv":{"command":123}}}`,
		},
		{
			name:     "override in a named file",
			manifest: `{"name":"p","mcpServers":"./mcp/override.json"}`,
			extra: map[string]string{
				"mcp/override.json": `{"mcpServers":{"srv":{"command":123}}}`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
				`{"enabledPlugins":{"p@mp":true}}`)
			version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
			testutil.WriteFile(t, filepath.Join(version, ".mcp.json"),
				`{"mcpServers":{"srv":{"command":"npx","args":["old-package"]}}}`)
			testutil.WriteFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
				tc.manifest)
			for rel, body := range tc.extra {
				testutil.WriteFile(t, filepath.Join(version, filepath.FromSlash(rel)), body)
			}
			writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

			var found bool
			for _, row := range discoverForTest("alice", home) {
				if row.ServerName != "srv" {
					continue
				}
				found = true
				// Kept, because this table cannot tell whether the client rejected the bad
				// entry and kept this one or replaced it.
				if row.ScanComplete {
					t.Error("scan_complete = 1 on a definition whose higher-precedence " +
						"replacement could not be read, so it is selectable as trustworthy")
				}
				if row.Warning.empty() {
					t.Error("the row is incomplete with no warning saying why")
				}
			}
			if !found {
				t.Fatal("the earlier definition was dropped entirely; it should be " +
					"qualified, since the client may well still be running it")
			}
		})
	}
}

// A manifest element of the wrong type is reported, not skipped.
func TestInvalidManifestDeclarationIsReported(t *testing.T) {
	for _, declaration := range []string{`123`, `true`, `[["nested"]]`, `""`} {
		t.Run(declaration, func(t *testing.T) {
			home := t.TempDir()
			testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
				`{"enabledPlugins":{"p@mp":true}}`)
			version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
			testutil.WriteFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
				`{"name":"p","mcpServers":[{"healthy":{"command":"npx","args":["pkg"]}},`+
					declaration+`]}`)
			writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

			var reported, healthy bool
			for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
				if row.Warning.Code == warnPluginManifestInvalid {
					reported = true
				}
				if row.ServerName == "healthy" {
					healthy = true
				}
			}
			if !reported {
				t.Error("a declaration the client would reject at load produced no " +
					"diagnostic, so the manifest reads as fully understood")
			}
			// Recoverable entries are still reported: one bad element must not cost the
			// siblings that parsed.
			if !healthy {
				t.Error("the healthy sibling was dropped")
			}
		})
	}
}

// A declaration that genuinely declares nothing stays silent.
func TestEmptyManifestDeclarationIsSilent(t *testing.T) {
	for _, declaration := range []string{`null`, `{}`} {
		t.Run(declaration, func(t *testing.T) {
			home := t.TempDir()
			testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
				`{"enabledPlugins":{"p@mp":true}}`)
			version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
			testutil.WriteFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
				`{"name":"p","mcpServers":[{"healthy":{"command":"npx"}},`+declaration+`]}`)
			writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

			for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
				if row.Warning.Code == warnPluginManifestInvalid {
					t.Errorf("%s reported as invalid; it declares nothing, which is not "+
						"the same as being malformed", declaration)
				}
			}
		})
	}
}

// A successful override does not inherit the stale-definition warning, and a stale plugin
// definition does not mark another client's rows.
//
// Qualification runs before the merge: a successful override replaces one of the earlier
// positions in place, so qualifying afterwards would hand the authoritative definition the
// warning meant for the row it replaced. plugin_declaration_shadowed is source scope, so it
// marks only the rows it qualifies.
func TestHealthyOverrideBesideAMalformedSiblingStaysAuthoritative(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	// An unrelated client, healthy, for the same account.
	testutil.WriteFile(t, filepath.Join(home, ".gemini", "settings.json"),
		`{"mcpServers":{"gem":{"command":"npx","args":["g"]}}}`)
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	testutil.WriteFile(t, filepath.Join(version, ".mcp.json"),
		`{"mcpServers":{"srv":{"command":"npx","args":["old-package"]}}}`)
	// The manifest redefines srv successfully, and declares a malformed sibling.
	testutil.WriteFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
		`{"name":"p","mcpServers":{"srv":{"command":"uvx","args":["new-package"]},`+
			`"broken":{"command":123}}}`)
	writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

	var sawServer, sawGemini bool
	for _, row := range discoverForTest("alice", home) {
		published := serverToRow(row)
		switch row.ServerName {
		case "srv":
			sawServer = true
			// The replacement decoded, so it is authoritative.
			if published["package_name"] != "new-package" {
				t.Errorf("package_name = %q, want the override's %q",
					published["package_name"], "new-package")
			}
			if row.Warning.Code == warnPluginShadowedDecl {
				t.Error("a successfully decoded replacement inherited the " +
					"stale-definition warning meant for the row it replaced")
			}
		case "gem":
			sawGemini = true
			// An unrelated client's configuration is untouched by a plugin's problem.
			if !row.ScanComplete {
				t.Error("scan_complete = 0 on an unrelated client's healthy configuration, " +
					"so one stale plugin definition cost the whole account its inventory")
			}
			if !row.Warning.empty() {
				t.Errorf("unrelated row carries %q", row.Warning.Code)
			}
		}
	}
	if !sawServer || !sawGemini {
		t.Fatalf("fixture did not produce both rows: srv=%v gem=%v", sawServer, sawGemini)
	}
}

// A name the failed source did *not* redefine keeps its qualification.
func TestUnreplacedDefinitionKeepsItsQualification(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	// Two servers in the root; the manifest fails while redefining only one of them.
	testutil.WriteFile(t, filepath.Join(version, ".mcp.json"),
		`{"mcpServers":{"kept":{"command":"npx","args":["kept-pkg"]},`+
			`"replaced":{"command":"npx","args":["old-pkg"]}}}`)
	testutil.WriteFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
		`{"name":"p","mcpServers":{"replaced":{"command":"uvx","args":["new-pkg"]},`+
			`"broken":{"command":123}}}`)
	writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

	codes := map[string]warnCode{}
	for _, row := range discoverForTest("alice", home) {
		if row.rawName != "" {
			codes[row.ServerName] = row.Warning.Code
		}
	}
	if codes["kept"] != warnPluginShadowedDecl {
		t.Errorf("kept warning = %q, want %q: the failed source could have redefined this "+
			"name and this scan cannot tell", codes["kept"], warnPluginShadowedDecl)
	}
	if codes["replaced"] == warnPluginShadowedDecl {
		t.Error("the replaced name kept a qualification its successful override should " +
			"have cleared")
	}
}

// A null settings document is unknown, like one that does not parse; an object without
// enabledPlugins, or with a null one, records that no plugin is enabled.
func TestANullPluginSettingsDocumentIsUnknown(t *testing.T) {
	for _, testCase := range []struct {
		document string
		want     approvalState
		warned   bool
	}{
		{`null`, approvalUnknown, true},
		{"\xEF\xBB\xBF null\n", approvalUnknown, true},
		{`{}`, approvalNotApproved, false},
		{`{"enabledPlugins":null}`, approvalNotApproved, false},
	} {
		t.Run(testCase.document, func(t *testing.T) {
			home := t.TempDir()
			testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"), testCase.document)
			testutil.WriteFile(t, filepath.Join(home, ".claude", "plugins", "cache", "mp", "p",
				"1.0.0", ".mcp.json"), `{"mcpServers":{"srv":{"command":"npx","args":["x"]}}}`)
			writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})
			var found, warned bool
			for _, row := range discoverForTest("alice", home) {
				if row.ServerName == "srv" {
					found = true
					if row.Approval != testCase.want {
						t.Errorf("approval = %q, want %q", row.Approval, testCase.want)
					}
				}
				warned = warned || row.Warning.Code == warnPluginSettingsUnreadable
			}
			if !found || warned != testCase.warned {
				t.Errorf("found = %v, plugin_settings_unreadable = %v, want true, %v", found, warned,
					testCase.warned)
			}
		})
	}
}

// A null installation records file or plugin manifest is reported as unreadable, as one that does
// not parse is, rather than read as recording no plugins or declaring no servers.
func TestANullPluginRecordsOrManifestIsUnreadable(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, ".claude", "plugins", "installed_plugins.json"), "null")
	if _, known, warnings := selectedVersions(home); known || len(warnings) != 1 ||
		warnings[0].Code != warnPluginRecordsUnreadable {
		t.Errorf("records: known = %v, warnings = %+v", known, warnings)
	}
	versionRel := filepath.Join(".claude", "plugins", "cache", "mp", "p", "1.0.0")
	testutil.WriteFile(t, filepath.Join(home, versionRel, ".claude-plugin", "plugin.json"), " null ")
	if sources, warnings := pluginManifestSources(home, versionRel); sources != nil ||
		len(warnings) != 1 || warnings[0].Code != warnPluginManifestUnreadable {
		t.Errorf("manifest: sources = %+v, warnings = %+v", sources, warnings)
	}
}

// TestPluginEvidenceIsReadOnlyForInstalledPlugins: with no plugin cache, malformed enablement
// settings and installation records describe no plugin, so neither is reported; with one
// installed version, both are.
func TestPluginEvidenceIsReadOnlyForInstalledPlugins(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"), `{ not json`)
	testutil.WriteFile(t, filepath.Join(home, ".claude", "plugins", "installed_plugins.json"), `{ not json`)
	codes := func() map[warnCode]bool {
		found := map[warnCode]bool{}
		for _, row := range discoverForTest("alice", home) {
			found[row.Warning.Code] = true
		}
		return found
	}
	if found := codes(); found[warnPluginSettingsUnreadable] || found[warnPluginRecordsUnreadable] {
		t.Errorf("warnings = %v with no plugin installed, want neither plugin evidence warning", found)
	}
	testutil.WriteFile(t, filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0", ".mcp.json"),
		`{"mcpServers":{"srv":{"command":"npx","args":["x"]}}}`)
	if found := codes(); !found[warnPluginSettingsUnreadable] || !found[warnPluginRecordsUnreadable] {
		t.Errorf("warnings = %v with a plugin installed, want both plugin evidence warnings", found)
	}
}

// TestAFileInThePluginCacheIsNotAPlugin: a .DS_Store at the marketplace, plugin or version level
// is not a directory, so it is neither a plugin nor a version: no probe is spent on it, and the
// enablement settings and installation records, read only for an installed version, are not read.
func TestAFileInThePluginCacheIsNotAPlugin(t *testing.T) {
	home := t.TempDir()
	cache := filepath.Join(home, ".claude", "plugins", "cache")
	for _, dir := range []string{cache, filepath.Join(cache, "mp"), filepath.Join(cache, "mp", "p")} {
		testutil.WriteFile(t, filepath.Join(dir, ".DS_Store"), "")
	}
	testutil.WriteFile(t, filepath.Join(home, ".claude", "settings.json"), `{ not json`)
	refs, warnings, stopped := claudePluginRefs(context.Background(), home, time.Now().Add(time.Minute))
	if len(refs) != 0 || len(warnings) != 0 || stopped {
		t.Errorf("refs = %+v, warnings = %+v, stopped = %v; want nothing", refs, warnings, stopped)
	}
}

// TestManifestCapCountsOnlyUsableDeclarations: eight usable declarations followed by a null, an
// invalid element or an unsupported one are within the cap, and the other element keeps its own
// diagnostic. A ninth usable one is truncation, counted in usable declarations. The cap was
// checked before each element was classified, so any element after the eighth source read as
// truncation, with the array's length as the count.
func TestManifestCapCountsOnlyUsableDeclarations(t *testing.T) {
	versionRel := filepath.Join(".claude", "plugins", "cache", "mp", "p", "1.0.0")
	eight := strings.TrimSuffix(strings.Repeat(`"./s.json",`, maxManifestSourcesPerVersion), ",")
	for name, testCase := range map[string]struct {
		tail    string
		want    []warnCode
		count   int
		sources int
	}{
		"null":        {`null`, nil, 0, 8},
		"invalid":     {`123`, []warnCode{warnPluginManifestInvalid}, 1, 8},
		"unsupported": {`"https://host/server.mcpb"`, []warnCode{warnPluginManifestUnsupported}, 1, 8},
		"ninth usable": {`null,123,"./t.json"`, []warnCode{warnPluginManifestTruncated, warnPluginManifestInvalid},
			maxManifestSourcesPerVersion + 1, 8},
	} {
		home := t.TempDir()
		testutil.WriteFile(t, filepath.Join(home, versionRel, ".claude-plugin", "plugin.json"),
			`{"name":"p","mcpServers":[`+eight+`,`+testCase.tail+`]}`)
		sources, warnings := pluginManifestSources(home, versionRel)
		var codes []warnCode
		for _, w := range warnings {
			codes = append(codes, w.Code)
		}
		if len(sources) != testCase.sources || !reflect.DeepEqual(codes, testCase.want) ||
			(len(warnings) > 0 && warnings[0].Count != testCase.count) {
			t.Errorf("%s: %d sources, warnings %+v; want %d sources, codes %v, first count %d", name,
				len(sources), warnings, testCase.sources, testCase.want, testCase.count)
		}
	}
}

// TestAnOverlongDeclaredPathIsNotReadOrPublished: a manifest declaration whose absolute path is
// longer than devclients.MaxProjectPathLen, whether its text is nearly 1 MiB or short enough
// until it is joined to the home, is counted in one plugin_manifest_path_too_long row on the
// manifest and never read. Accepted, it reached source_path whole on a
// plugin_manifest_missing_source row.
func TestAnOverlongDeclaredPathIsNotReadOrPublished(t *testing.T) {
	home := t.TempDir()
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	huge := "./" + strings.Repeat("a", MaxFileSize-4096) + ".json"
	joined := "./" + strings.Repeat("b", devclients.MaxProjectPathLen-10) + ".json"
	testutil.WriteFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
		`{"name":"p","mcpServers":["`+huge+`","`+joined+`"]}`)
	writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})
	var tooLong []warning
	for _, row := range discoverForTest("alice", home) {
		if len(row.SourcePath) > devclients.MaxProjectPathLen ||
			len(serverToRow(row)["source_path"]) > devclients.MaxProjectPathLen {
			t.Errorf("%s row with a %d-byte source_path", row.Warning.Code, len(row.SourcePath))
		}
		if row.Warning.Code == warnPluginManifestMissing {
			t.Errorf("an overlong declaration was read: %.80s", row.SourcePath)
		}
		if row.Warning.Code == warnPluginManifestPathTooLong {
			tooLong = append(tooLong, row.Warning)
		}
	}
	if len(tooLong) != 1 || tooLong[0].Count != 2 || tooLong[0].Limit != devclients.MaxProjectPathLen {
		t.Errorf("plugin_manifest_path_too_long rows = %+v, want one counting both declarations", tooLong)
	}
}

// TestDeclarationsAfterTheReadBoundAreStillTaken: once eight plugins have spent the 64 declared
// reads, a later manifest's unread file is skipped and reported once, and the inline
// declarations around it are still taken in the manifest's order, so the last definition of a
// name wins. The first file over the bound ended the whole manifest, inline servers included.
func TestDeclarationsAfterTheReadBoundAreStillTaken(t *testing.T) {
	for name, testCase := range map[string]struct {
		declarations string
		want         map[string]string
	}{
		"file then inline": {`["./unread.json",{"inline-server":{"command":"npx"}}]`,
			map[string]string{"inline-server": "npx"}},
		"inline, file, inline": {`[{"srv":{"command":"node"}},"./unread.json",{"srv":{"command":"deno"}},"./unread-2.json"]`,
			map[string]string{"srv": "deno"}},
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			cache := filepath.Join(home, ".claude", "plugins", "cache", "mp")
			installs := map[string]string{"z@mp": "1.0.0"}
			for plugin := 0; plugin < maxManifestSourcesPerPass/maxManifestSourcesPerVersion; plugin++ {
				version := filepath.Join(cache, fmt.Sprintf("p%d", plugin), "1.0.0")
				installs[fmt.Sprintf("p%d@mp", plugin)] = "1.0.0"
				var declarations []string
				for index := 0; index < maxManifestSourcesPerVersion; index++ {
					rel := fmt.Sprintf("s%d.json", index)
					declarations = append(declarations, fmt.Sprintf("%q", "./"+rel))
					testutil.WriteFile(t, filepath.Join(version, rel),
						fmt.Sprintf(`{"mcpServers":{"srv-%d-%d":{"command":"npx"}}}`, plugin, index))
				}
				testutil.WriteFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
					`{"name":"p","mcpServers":[`+strings.Join(declarations, ",")+`]}`)
			}
			last := filepath.Join(cache, "z", "1.0.0")
			testutil.WriteFile(t, filepath.Join(last, "unread.json"), `{"mcpServers":{"unread":{"command":"npx"}}}`)
			testutil.WriteFile(t, filepath.Join(last, ".claude-plugin", "plugin.json"),
				`{"name":"z","mcpServers":`+testCase.declarations+`}`)
			writeInstalledPlugins(t, home, installs)

			got, exhausted := map[string]string{}, 0
			for _, row := range discoverForTest("alice", home) {
				if !strings.HasPrefix(row.SourcePath, last) {
					continue
				}
				if row.rawName != "" {
					got[row.rawName] = row.Command
				}
				if row.Warning.Code == warnPluginManifestExhausted {
					exhausted++
				}
			}
			if !reflect.DeepEqual(got, testCase.want) || exhausted != 1 {
				t.Errorf("servers %v with %d exhaustion rows, want %v and 1", got, exhausted, testCase.want)
			}
		})
	}
}

// TestADeclarationInTwoCases: on Windows a manifest that declares one file in two cases reads it
// once and reports its parse failure once. Elsewhere the spellings are two files: a
// case-insensitive volume reads the one file twice and reports it twice, and on a case-sensitive
// one the second spelling is a missing file.
func TestADeclarationInTwoCases(t *testing.T) {
	home := t.TempDir()
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	testutil.WriteFile(t, filepath.Join(version, "broken.json"), `{"mcpServers":`)
	testutil.WriteFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
		`{"name":"p","mcpServers":["./broken.json","./Broken.json"]}`)
	writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})
	want := 1
	if runtime.GOOS != "windows" &&
		testutil.SameFile(t, filepath.Join(version, "broken.json"), filepath.Join(version, "Broken.json")) {
		want = 2
	}
	failures := 0
	for _, row := range discoverForTest("alice", home) {
		if row.Warning.Code == warnParseFailed {
			failures++
		}
	}
	if failures != want {
		t.Errorf("parse_failed rows = %d, want %d on this %s volume", failures, want, runtime.GOOS)
	}
}

// TestAPluginInstalledUnderTwoCasesOfItsName: a plugin is found by listing the cache, which
// names each directory once, and its install record is looked up by that name, so two records
// whose names differ only in case add no second root on any platform, and the plugin's server is
// listed once.
func TestAPluginInstalledUnderTwoCasesOfItsName(t *testing.T) {
	home := t.TempDir()
	cache := filepath.Join(home, ".claude", "plugins", "cache", "mp")
	testutil.WriteFile(t, filepath.Join(cache, "p", "1.0.0", ".claude-plugin", "plugin.json"),
		`{"name":"p","mcpServers":{"srv":{"command":"npx","args":["x"]}}}`)
	writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0", "P@mp": "1.0.0"})
	listed := 0
	for _, row := range discoverForTest("alice", home) {
		if row.rawName == "srv" {
			listed++
		}
	}
	if listed != 1 {
		t.Errorf("srv listed %d times, want once", listed)
	}
}

// TestARepeatedDeclarationReportsItsFileOnce: a missing file, one that does not parse and one
// with an entry that does not decode, each declared more than once, get one row each about the
// file. Every cached repetition appended the row again, so seven declarations of one missing
// file gave seven identical rows. The healthy server is still listed once.
func TestARepeatedDeclarationReportsItsFileOnce(t *testing.T) {
	home := t.TempDir()
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	testutil.WriteFile(t, filepath.Join(version, "broken.json"), `{"mcpServers":`)
	testutil.WriteFile(t, filepath.Join(version, "skips.json"),
		`{"mcpServers":{"ok":{"command":"npx"},"bad":{"command":123}}}`)
	testutil.WriteFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
		`{"name":"p","mcpServers":["./missing.json","./broken.json","./skips.json",`+
			`"./missing.json","./broken.json","./skips.json","./missing.json"]}`)
	writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})
	type finding struct {
		code warnCode
		file string
	}
	counts, servers := map[finding]int{}, 0
	for _, row := range discoverForTest("alice", home) {
		if row.rawName == "ok" {
			servers++
		}
		if row.ServerName == "" && !row.Warning.empty() {
			counts[finding{row.Warning.Code, filepath.Base(row.SourcePath)}]++
		}
	}
	want := map[finding]int{
		{warnPluginManifestMissing, "missing.json"}: 1,
		{warnParseFailed, "broken.json"}:            1,
		{warnEntriesSkipped, "skips.json"}:          1,
	}
	for key, count := range want {
		if counts[key] != count {
			t.Errorf("%s about %s: %d rows, want %d", key.code, key.file, counts[key], count)
		}
	}
	if servers != 1 {
		t.Errorf("the healthy server was listed %d times, want once", servers)
	}
}
