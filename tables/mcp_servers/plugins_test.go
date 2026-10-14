package mcp_servers

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
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
		writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
			`{"theme":"dark","enabledPlugins":{`+joinComma(pairs)+`}}`)
	}
	installs := map[string]string{}
	for rel, content := range configs {
		writeTestFile(t, filepath.Join(home, ".claude", "plugins", "cache", rel), content)
		// Records derived from the same paths, so a fixture declares the tree once and the
		// two stay consistent. A cache directory is no longer evidence on its own that the
		// client would load that version, and a real host carries both.
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
	writeTestFile(t, filepath.Join(home, ".claude", "plugins", "marketplaces", "mp", ".mcp.json"),
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
	writeTestFile(t, filepath.Join(home, ".claude", "settings.json"), `{ not json`)
	writeTestFile(t, filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0", ".mcp.json"),
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

// The enumeration is bounded, and exceeding the bound is reported.
func TestPluginEnumerationIsBounded(t *testing.T) {
	home := t.TempDir()
	configs := map[string]string{}
	for i := 0; i < maxPluginProbes+20; i++ {
		rel := filepath.Join("mp", "p"+itoaPad(i), "1.0.0", ".mcp.json")
		configs[rel] = `{"mcpServers":{"s` + itoaPad(i) + `":{"command":"npx","args":["x"]}}}`
	}
	writePluginFixture(t, home, nil, configs)

	refs, warnings, _ := claudePluginRefs(context.Background(), home,
		time.Now().Add(time.Minute))
	if len(refs) > maxPluginProbes {
		t.Errorf("refs = %d, want at most the probe budget of %d", len(refs), maxPluginProbes)
	}
	// The per-marketplace cap bites first here, since all the plugins are under one
	// marketplace. Either way the loss has to be reported rather than silent.
	var reported bool
	for _, w := range warnings {
		if w.Code == warnPluginListTruncated {
			reported = true
		}
	}
	if len(refs) < maxPluginsPerMarket && !reported {
		t.Errorf("the enumeration returned %d refs with no truncation reported", len(refs))
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
// Every fixture that builds a plugin cache needs these, because a cache directory alone is no
// longer evidence that the client would load it -- which is the point of the change this
// helper exists for. A real host with an installed plugin has both.
func writeInstalledPlugins(t *testing.T, home string, installs map[string]string) {
	t.Helper()
	plugins := make(map[string]any, len(installs))
	for id, version := range installs {
		// installPath is what selection is established from, so a fixture that omitted it
		// was asserting against evidence the implementation no longer accepts. Derived from
		// the id so a test declares the tree once: the cache directory is
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
	writeTestFile(t, filepath.Join(home, ".claude", "plugins", "installed_plugins.json"),
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
	writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	base := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p")
	writeTestFile(t, filepath.Join(base, "1.0.0", ".mcp.json"),
		`{"mcpServers":{"old-only":{"command":"npx","args":["x"]}}}`)
	writeTestFile(t, filepath.Join(base, "2.0.0", ".mcp.json"),
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
	writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	dir := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	writeTestFile(t, filepath.Join(dir, ".mcp.json"),
		`{"mcpServers":{"srv":{"command":"npx","args":["x"]}}}`)
	writeTestFile(t, filepath.Join(dir, ".orphaned_at"), "2026-01-01T00:00:00.000Z")
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
	writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	writeTestFile(t, filepath.Join(home, ".claude", "plugins", "cache", "mp", "p",
		"1.0.0", ".mcp.json"), `{"mcpServers":{"srv":{"command":"npx","args":["x"]}}}`)
	writeTestFile(t, filepath.Join(home, ".claude", "plugins", "installed_plugins.json"),
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
		// The row says its selection could not be established; the *cause* is reported
		// once, at account level, by the records reader. The row used to name the cause
		// itself, which both duplicated that diagnostic and misattributed the other two
		// ways selection goes unknown -- an unreadable orphan marker and a record with no
		// installPath, neither of which is a records-read failure.
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
			writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
				`{"enabledPlugins":{"p@mp":true}}`)
			version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
			// Deliberately no .mcp.json at the plugin root: the manifest is the only
			// declaration, which is the case that produced nothing at all.
			writeTestFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
				tc.manifest)
			for rel, body := range tc.extra {
				writeTestFile(t, filepath.Join(version, filepath.FromSlash(rel)), body)
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
	writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	writeTestFile(t, filepath.Join(version, ".mcp.json"),
		`{"mcpServers":{"srv":{"command":"npx","args":["from-root"]}}}`)
	writeTestFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
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
			writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
				`{"enabledPlugins":{"p@mp":true}}`)
			version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
			writeTestFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
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
			writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
				`{"enabledPlugins":{"p@mp":true}}`)
			writeTestFile(t, filepath.Join(cache, ".mcp.json"),
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
			writeTestFile(t, filepath.Join(home, ".claude", "plugins",
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
	writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	writeTestFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
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
	writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	// Two names the grammar refuses, in separate inline maps, with identical launch
	// configurations so the published rows have nothing else to tell them apart.
	writeTestFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
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
	writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	// A healthy root config, so the plugin is not simply empty.
	writeTestFile(t, filepath.Join(version, ".mcp.json"),
		`{"mcpServers":{"srv":{"command":"npx","args":["x"]}}}`)
	writeTestFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
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
	writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	var declarations []string
	for index := 0; index < 500; index++ {
		rel := fmt.Sprintf("mcp/servers-%03d.json", index)
		declarations = append(declarations, fmt.Sprintf("%q", "./"+rel))
		writeTestFile(t, filepath.Join(version, filepath.FromSlash(rel)),
			fmt.Sprintf(`{"mcpServers":{"srv-%03d":{"command":"npx"}}}`, index))
	}
	writeTestFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
		`{"name":"p","mcpServers":[`+strings.Join(declarations, ",")+`]}`)
	writeInstalledPlugins(t, home, map[string]string{"p@mp": "1.0.0"})

	var servers, truncations int
	for _, row := range withoutStandingNotes(discoverForTest("alice", home)) {
		if row.rawName != "" {
			servers++
		}
		if row.Warning.Code == warnPluginManifestTruncated {
			truncations++
		}
	}
	if servers > maxManifestSourcesPerVersion {
		t.Errorf("%d servers from one manifest: the per-version cap of %d did not apply",
			servers, maxManifestSourcesPerVersion)
	}
	if truncations == 0 {
		t.Error("coverage was dropped by a cap with no diagnostic saying so")
	}
}

// A repeated declaration is read once but still decides precedence.
func TestRepeatedDeclarationIsMemoisedWithoutChangingPrecedence(t *testing.T) {
	home := t.TempDir()
	writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	writeTestFile(t, filepath.Join(version, ".mcp.json"),
		`{"mcpServers":{"srv":{"command":"npx","args":["from-root"]}}}`)
	writeTestFile(t, filepath.Join(version, "mcp", "servers.json"),
		`{"mcpServers":{"srv":{"command":"uvx","args":["from-file"]}}}`)
	// The same path twice, then an inline map, then the path again: the last declaration of
	// `srv` is the file, so the file's definition must win over the inline one.
	writeTestFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
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
			writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
				`{"enabledPlugins":{"p@mp":true}}`)
			version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
			writeTestFile(t, filepath.Join(version, ".mcp.json"),
				`{"mcpServers":{"srv":{"command":"npx","args":["old-package"]}}}`)
			writeTestFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
				tc.manifest)
			for rel, body := range tc.extra {
				writeTestFile(t, filepath.Join(version, filepath.FromSlash(rel)), body)
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
			writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
				`{"enabledPlugins":{"p@mp":true}}`)
			version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
			writeTestFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
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
			writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
				`{"enabledPlugins":{"p@mp":true}}`)
			version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
			writeTestFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
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

// A successful override must not inherit the stale-definition warning, and one stale plugin
// definition must not degrade the whole account.
//
// Two defects with one cause. Qualification ran *after* the merge, over the slice positions
// that existed before the source -- but a successful override replaces one of those positions
// in place, so the newly decoded authoritative definition picked up the warning meant for the
// row it had just replaced. And the code was home-scoped, so that misplaced warning set
// scan_complete = 0 on every row for the account, including configurations from unrelated
// clients. `WHERE scan_complete = 1` lost otherwise usable inventory for the whole host.
func TestHealthyOverrideBesideAMalformedSiblingStaysAuthoritative(t *testing.T) {
	home := t.TempDir()
	writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	// An unrelated client, healthy, for the same account.
	writeTestFile(t, filepath.Join(home, ".gemini", "settings.json"),
		`{"mcpServers":{"gem":{"command":"npx","args":["g"]}}}`)
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	writeTestFile(t, filepath.Join(version, ".mcp.json"),
		`{"mcpServers":{"srv":{"command":"npx","args":["old-package"]}}}`)
	// The manifest redefines srv successfully, and declares a malformed sibling.
	writeTestFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
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
	writeTestFile(t, filepath.Join(home, ".claude", "settings.json"),
		`{"enabledPlugins":{"p@mp":true}}`)
	version := filepath.Join(home, ".claude", "plugins", "cache", "mp", "p", "1.0.0")
	// Two servers in the root; the manifest fails while redefining only one of them.
	writeTestFile(t, filepath.Join(version, ".mcp.json"),
		`{"mcpServers":{"kept":{"command":"npx","args":["kept-pkg"]},`+
			`"replaced":{"command":"npx","args":["old-pkg"]}}}`)
	writeTestFile(t, filepath.Join(version, ".claude-plugin", "plugin.json"),
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
