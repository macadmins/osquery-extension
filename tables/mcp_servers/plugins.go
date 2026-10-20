package mcp_servers

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/macadmins/osquery-extension/pkg/devclients"
	"github.com/macadmins/osquery-extension/pkg/fsscan"
)

// Claude Code plugins declare their own MCP servers, and those servers are live. On the
// development machine ~/.claude.json declares four servers and a session had eight; the other
// four came from an enabled plugin's own .mcp.json under ~/.claude/plugins/cache/.
//
// Two different things live under ~/.claude/plugins:
//
//   - a marketplace *catalog* of plugins available to install, which is noise: on one
//     workstation 39 of 51 rows from one client were catalog entries;
//   - an *installed* plugin's own .mcp.json, which is configuration the client acts on.
//
// Only the installed tree is read here. ~/.claude/plugins/marketplaces/<name>/ is the
// marketplace's own checkout -- it holds the plugin source, so probing it would both
// reintroduce the catalog noise and double-count every installed plugin -- while
// ~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/ exists only for a plugin the user
// installed. That is what makes the noise impossible by construction rather than excluded by
// a list of path substrings maintained by noticing each new cache directory.
//
// Enablement is reported rather than filtered. An installed-but-not-enabled plugin's servers
// are declared and inert, which is exactly what approval_state exists to say -- the same
// distinction Claude Code's project .mcp.json approval makes. Filtering them out would hide a
// plugin someone installed and forgot, which is a thing a security inventory should show.

// Where the plugin tree and the settings that enable it live, relative to a home.
const (
	claudePluginCacheRel   = ".claude/plugins/cache"
	claudeInstalledRel     = ".claude/plugins/installed_plugins.json"
	pluginManifestRel      = ".claude-plugin/plugin.json"
	pluginOrphanMarkerName = ".orphaned_at"
	claudeSettingsRel      = ".claude/settings.json"
	claudePluginConfigName = ".mcp.json"
)

// Only the user settings file is read, and `.claude/settings.local.json` deliberately is not.
//
// Claude Code's documented precedence is managed settings, then the command line, then
// project-local `.claude/settings.local.json`, then shared project `.claude/settings.json`,
// then user `~/.claude/settings.json`. settings.local.json is a *project* file; there is no
// documented user-scope version of it.
//
// Reading ~/.claude/settings.local.json as a user-wide override would be wrong whenever a home
// directory has itself been opened as a project, which is common, because Claude Code then
// writes that file for the home-as-project, and its per-project overrides would apply to every
// plugin row for the account.
//
// Project-scoped plugin enablement is a documented omission in the table README rather than
// something approximated from a file that happens to sit in the home.

// The caps on the plugin enumeration.
//
// Three nested directory listings -- marketplace, plugin, version -- so the product is what
// needs bounding rather than any single level. maxPluginProbes is a budget across the whole
// enumeration, checked as it runs, which bounds the total work no matter how the tree is
// shaped. The per-level caps keep one pathological directory from consuming the whole budget
// before the others are reached.
//
// Measured against the development machine: 2 marketplaces, 4 installed plugins, 1 version
// each. These sit two orders of magnitude above that.
//
// Only directories count against the per-level caps; maxPluginDirEntries bounds the entries one
// listing reads to find them, so a .DS_Store or another file at any level is neither a plugin
// nor a version, and cannot use up a cap or the probe budget.
const (
	maxPluginMarketplaces = 20
	maxPluginsPerMarket   = 50
	maxPluginVersions     = 10
	maxPluginProbes       = 200
	maxPluginDirEntries   = 500

	// Manifest-declared sources are bounded separately, because the probe cap counts cached
	// version directories and a manifest adds reads underneath one of them. A 1 MiB manifest
	// may name thousands of independently capped 1 MiB files, so without these the accepted
	// byte total and row count were unbounded while every individual read looked compliant.
	// The deadline does not substitute: it bounds elapsed cooperative work, not bytes
	// accumulated before it expires.
	//
	// Eight per version is generous against the documented shape, which is a path, an object
	// or a short array of either; sixty-four across the pass bounds a host that has many
	// plugins each declaring a few. Exceeding either is reported, the first as
	// plugin_manifest_truncated and the second as plugin_manifest_reads_exhausted, so coverage
	// lost to a cap is visible rather than silent.
	maxManifestSourcesPerVersion = 8
	maxManifestSourcesPerPass    = 64
)

// pluginRef is one installed plugin's configuration file, with its enablement.
type pluginRef struct {
	// Rel is relative to the home, so the read goes through the same symlink-refusing
	// traversal every other source does.
	Rel string

	// Marketplace, Plugin and Version are directory names, kept for the enablement lookup
	// rather than for reporting. None of them reaches a column: source_path already names
	// the location and goes through the path redaction, so publishing them again in
	// source_context would add a second user-controlled string for no information.
	Marketplace string
	Plugin      string
	Version     string

	// Approval is the plugin's enablement, read from settings rather than inferred from
	// its presence on disk.
	Approval approvalState

	// Selection says whether this version is the one the client would load. A cache
	// directory is not evidence of that on its own; see pluginSelection.
	Selection pluginSelection
}

// pluginSelection is how much is known about a cached version being the one Claude loads.
//
// Enablement and installation are different facts and were conflated. enabledPlugins answers
// "is plugin p turned on", which is per plugin, and that answer was applied to every version
// directory found in the cache. Claude keeps old ones: on update it writes an `.orphaned_at`
// marker into the previous version's directory and deletes it in a background sweep fourteen
// days later, so that a session which already loaded that version keeps working. For two
// weeks after any plugin update, a server deleted in the new release was still reported as
// `enabled`.
type pluginSelection int

const (
	// selectionUnknown: the install records could not be read, so nothing is known about
	// which version is current.
	selectionUnknown pluginSelection = iota
	// versionSelected: installed_plugins.json records this version for this plugin.
	versionSelected
	// versionSuperseded: the records name a different version, or the directory carries the
	// orphan marker. A new session will not load it.
	versionSuperseded
)

// enabledPlugins reads the plugin enablement map from a home's Claude settings.
//
// The value is a bool rather than the list it looks like: settings.json holds
// {"data-plat@data-plat-marketplace": true}, so `false` is an explicit disable and absence is
// "never enabled". Those are three different states and approval_state has a value for each,
// which is why this returns the map rather than a set.
//
// Only `~/.claude/settings.json` is read. `~/.claude/settings.local.json` is a *project*-scope
// file, for the reason given at the top of this file.
//
// Absence and refusal are different answers. This file's absence is evidence that every
// installed plugin was never enabled, so only a genuinely missing file, or an object without
// enabledPlugins, reads as known and empty. A document that does not parse, or is null, is
// unknown. A refused one -- a `~/.claude/settings.json` that a dotfile manager such as chezmoi,
// stow or yadm symlinked into place, which this file does not follow -- is unknown, so the
// plugins' servers read `unknown` rather than `not_approved`, a positive claim about a decision
// nobody could read.
func enabledPlugins(home string) (enablement map[string]bool, known bool, warnings []warning) {
	out := make(map[string]bool)
	data, err := fsscan.ReadBoundedUnder(home, filepath.FromSlash(claudeSettingsRel),
		probeReadOpts(MaxFileSize))
	if err != nil {
		// Absence is the common case and is evidence in its own right: a user who has never
		// enabled a plugin has no enablement file, so an installed plugin genuinely is not
		// enabled. Anything else -- including a refused path, which is a file that exists --
		// means nothing is known about any plugin's state.
		if fsscan.ClassifyError(err) == fsscan.ClassAbsent {
			return out, true, nil
		}
		return out, false, []warning{{
			Code: warnPluginSettingsUnreadable, Class: fsscan.ClassifyError(err)}}
	}
	var doc struct {
		// The only field read. settings.json also carries permissions, allowedTools and
		// model configuration, none of which this table has any business in.
		EnabledPlugins map[string]bool `json:"enabledPlugins"`
	}
	data = devclients.StripBOM(data)
	if devclients.NullDocument(data) || json.Unmarshal(data, &doc) != nil {
		return out, false, []warning{{Code: warnPluginSettingsUnreadable}}
	}
	for name, enabled := range doc.EnabledPlugins {
		out[name] = enabled
	}
	return out, true, nil
}

// approvalForSelectedPlugin reports enablement only for the version the client would load.
//
// A superseded or unrecorded version resolves to unknown rather than to the plugin's
// enablement, and that is the honest answer rather than a conservative one. Claude keeps the
// previous version directory specifically so a session that already loaded it keeps running,
// so such a server may genuinely still be live in somebody's open session while no new
// session would load it. Neither `enabled` nor `not_approved` is true of that; `unknown` is.
func approvalForSelectedPlugin(enablement map[string]bool, known bool,
	marketplace, plugin string, selection pluginSelection) approvalState {
	if selection != versionSelected {
		return approvalUnknown
	}
	return approvalForPlugin(enablement, known, marketplace, plugin)
}

// approvalForPlugin maps a plugin's enablement onto the column's closed set.
//
// Three states from one map lookup, which is why enabledPlugins keeps the bool: a plugin
// turned off explicitly and one that was never turned on are different facts, and an
// inventory that reported both as "not enabled" would lose the distinction between a
// deliberate decision and an oversight.
func approvalForPlugin(enablement map[string]bool, known bool,
	marketplace, plugin string) approvalState {
	// Unreadable settings are not evidence of non-enablement. notApproved here would make a
	// malformed settings.json read as every installed plugin deliberately not enabled, in the
	// direction that invites ignoring a server that is running. A
	// warnPluginSettingsUnreadable row says the state is unknown, and the column agrees.
	if !known {
		return approvalUnknown
	}
	switch enabled, present := enablement[plugin+"@"+marketplace]; {
	case present && enabled:
		return approvalEnabled
	case present:
		return approvalDisabled
	default:
		return approvalNotApproved
	}
}

// claudePluginRefs enumerates every installed plugin that ships an MCP configuration.
//
// selectedVersions reads which installed version Claude would load for each plugin.
//
// installed_plugins.json is the record Claude Code itself loads from at session start, keyed
// by the plugin id `<entry-name>@<marketplace>` and holding one entry per install with its
// scope, installPath and version. Reading it is what separates "a directory exists in the
// cache" from "this is the configuration the client uses".
//
// Versions are collected as a set rather than compared. Sorting version strings would mean
// deciding whether `1.10.0` precedes `1.9.0`, and the resolved version is not required to be
// semver at all -- it can be a twelve-character commit SHA or the literal `unknown` -- so any
// ordering this package invented would be wrong for some real install. Set membership asks
// the only question that has an answer: did the client record this directory.
//
// A plugin may legitimately have more than one recorded install, because a plugin can be
// installed at user scope and again for a particular project, so the value is a set and not
// one string.
func selectedVersions(home string) (map[string]map[string]struct{}, bool, []warning) {
	data, err := fsscan.ReadBoundedUnder(home, filepath.FromSlash(claudeInstalledRel),
		probeReadOpts(MaxFileSize))
	if err != nil {
		if fsscan.ClassifyError(err) == fsscan.ClassAbsent {
			// No records file at all, which on a host with a populated cache is the same
			// ambiguity as a records file naming no plugins: it is evidence that something
			// is inconsistent, not evidence about any particular version. Silent, because
			// the per-row selection warning already says what is not known, and because a
			// host with no plugins installed has no cache directories and so never reaches
			// this.
			//
			// A *refused* records file falls through to the warning below rather than here.
			// It exists, so its contents are a thing this scan failed to read rather than a
			// thing that is not there.
			return nil, false, nil
		}
		return nil, false, []warning{{
			Code: warnPluginRecordsUnreadable, Class: fsscan.ClassifyError(err)}}
	}
	var doc struct {
		// Narrowly decoded, like every other reader here. The records also carry
		// projectPath, installedAt and gitCommitSha; projectPath in particular is a
		// filesystem path this table has no reason to hold.
		Plugins map[string][]struct {
			// installPath is the evidence, not version. A version names a *release* and
			// several directories can carry the same label -- a relative-path plugin loaded
			// in place, a relocated cache, a leftover directory -- so matching on it alone
			// treated any cached copy labelled `1.0.0` as the selected one even when the
			// record pointed somewhere else entirely. installPath names the filesystem copy
			// the client resolved, which is the question being asked.
			InstallPath string `json:"installPath"`
		} `json:"plugins"`
	}
	data = devclients.StripBOM(data)
	if devclients.NullDocument(data) || json.Unmarshal(data, &doc) != nil {
		return nil, false, []warning{{Code: warnPluginRecordsUnreadable}}
	}
	out := make(map[string]map[string]struct{}, len(doc.Plugins))
	for id, installs := range doc.Plugins {
		paths := make(map[string]struct{}, len(installs))
		for _, install := range installs {
			if install.InstallPath == "" {
				// A record with no path establishes nothing. Kept as an empty set rather
				// than skipped, so the plugin still counts as *recorded* and its versions
				// resolve to unknown instead of superseded -- the record exists, it just
				// does not say which copy.
				continue
			}
			paths[filepath.Clean(install.InstallPath)] = struct{}{}
		}
		out[id] = paths
	}
	if len(out) == 0 {
		// Readable but describing no plugins, while the cache has directories in it. That
		// is either a host where nothing is installed and the cache is a leftover, or a
		// records format this decoder does not understand -- the file carries a `version`
		// field, currently 2, so the format is expected to change. Those two cases call for
		// opposite answers and nothing here distinguishes them, so selection is reported as
		// unknown rather than treating every cached version as superseded. The narrow
		// reading matters: a schema change would otherwise turn every plugin row on every
		// host into a warning at once.
		return nil, false, nil
	}
	return out, true, nil
}

// versionSelection decides whether one cached version directory is the one Claude would load.
//
// The orphan marker is consulted as well as the records, and either is sufficient to call a
// version superseded. They fail differently: the records are a single file, so one unreadable
// or rewritten copy would otherwise leave every version looking current, while the marker
// sits in the directory it describes and survives that. Claude writes it on update and on
// uninstall, which is precisely the state this is trying to detect.
func versionSelection(home, versionRel, marketplace, plugin string,
	selected map[string]map[string]struct{}, selectionKnown bool) pluginSelection {
	markerRel := filepath.Join(versionRel, pluginOrphanMarkerName)
	if _, err := fsscan.ReadBoundedUnder(home, markerRel, probeReadOpts(maxOrphanMarker)); err == nil {
		return versionSuperseded
	} else if fsscan.ClassifyError(err) != fsscan.ClassAbsent {
		// The marker exists and could not be read, or the read was refused. Its presence is
		// the thing being tested, so an inconclusive answer is not "current". Tested against
		// ClassAbsent rather than IsExpectedAbsent, which is true for a refused path too, so a
		// marker this scan was not allowed to read does not count as a marker that is not
		// there, the one reading that makes a superseded version look current.
		return selectionUnknown
	}
	if !selectionKnown {
		return selectionUnknown
	}
	// The id Claude writes is the marketplace *entry* name joined to the marketplace, which
	// is also what names the cache directory, so the two agree by construction.
	paths, recorded := selected[plugin+"@"+marketplace]
	if !recorded {
		return versionSuperseded
	}
	if len(paths) == 0 {
		// Recorded, but no record carried a usable installPath. Absence of evidence, not
		// evidence of supersession.
		return selectionUnknown
	}
	if _, current := paths[filepath.Clean(filepath.Join(home, versionRel))]; current {
		return versionSelected
	}
	// Recorded with paths, none of which is this directory: the client resolved a different
	// copy. Compared as written rather than case-folded, so a record whose spelling differs
	// from the directory reads as superseded rather than as selected -- the safe direction,
	// since the cost is a qualified row and the alternative is a false `enabled`.
	return versionSuperseded
}

// maxOrphanMarker bounds the marker read. Claude writes a timestamp; anything larger is not
// the file this is looking for, and the read exists only to learn whether it is there.
const maxOrphanMarker = 4096

// Three bounded listings rather than a walk. Each level's names are chosen by the marketplace
// rather than by this package -- a marketplace name, a plugin name, a version -- so none can
// be a fixed path, and a listing is the only instrument that reaches them. The same one the
// VS Code profile directories and Codex named profiles use.
//
// The enablement settings and the installation records are read when the first installed version
// is found, not before: they describe plugins, so an account with none has no use for them, and a
// malformed copy would otherwise report plugin_settings_unreadable or plugin_records_unreadable
// about plugins that do not exist.
func claudePluginRefs(ctx context.Context, home string, deadline time.Time) ([]pluginRef, []warning, bool) {
	var (
		warnings                        []warning
		enablement                      map[string]bool
		selected                        map[string]map[string]struct{}
		enablementKnown, selectionKnown bool
		evidenceRead                    bool
	)

	cacheRel := filepath.FromSlash(claudePluginCacheRel)
	// No plugins installed is the overwhelmingly common case and is silent. A cache
	// directory that exists and cannot be listed means every plugin-declared server on this
	// account is unknown rather than absent.
	if !fsscan.BudgetRemains(ctx, deadline) {
		return nil, warnings, true
	}
	// A level reached through a symlink or junction is left out of its parent's listing, and is
	// reported as the refused listing it would have been: the directory exists, so the plugins
	// under it are missing rather than absent.
	reportLinks := func(links int) {
		if links > 0 {
			warnings = append(warnings, warning{
				Code: warnPluginListUnreadable, Class: fsscan.ClassRefusedPath})
		}
	}
	// Each limit reached is reported with its own count and limit, because each drops a
	// different part of the cache: a level's cap the names past it, the entry bound whatever
	// was not read of one directory. The limits differ, so limit= says which was reached, and
	// mergeWarnings folds repeats of one limit into a row. The entry bound is reported as soon
	// as a listing returns, because the entries past it were never read whatever happens next.
	// A level's cap is reported once its loop has taken every name it kept, and not when the
	// probe budget or the deadline stopped it first: then that level never reached it, and the
	// budget's row says why the rest was not listed.
	entriesTruncation := func(entriesTruncated bool) {
		if entriesTruncated {
			warnings = append(warnings, warning{Code: warnPluginListTruncated,
				Count: maxPluginDirEntries, Limit: maxPluginDirEntries})
		}
	}
	levelTruncation := func(listed, limit int) {
		if listed > limit {
			warnings = append(warnings, warning{Code: warnPluginListTruncated, Count: limit,
				Limit: int64(limit)})
		}
	}
	marketplaces, links, entriesTruncated, err := fsscan.ListSubdirNames(home, cacheRel,
		maxPluginDirEntries)
	reportLinks(links)
	if err != nil {
		warnings = append(warnings, warning{
			Code: warnPluginListUnreadable, Class: fsscan.ClassifyError(err)})
		return nil, warnings, false
	}
	entriesTruncation(entriesTruncated)
	marketsListed := len(marketplaces)
	marketplaces = marketplaces[:min(marketsListed, maxPluginMarketplaces)]

	var refs []pluginRef
	probes := 0
	stopped, budgetReached := false, false
	for _, marketplace := range marketplaces {
		if probes >= maxPluginProbes {
			budgetReached = true
			break
		}
		if !fsscan.BudgetRemains(ctx, deadline) {
			stopped = true
			break
		}
		marketRel := filepath.Join(cacheRel, marketplace)
		plugins, links, entriesTruncated, err := fsscan.ListSubdirNames(home, marketRel,
			maxPluginDirEntries)
		reportLinks(links)
		if err != nil {
			warnings = append(warnings, warning{
				Code: warnPluginListUnreadable, Class: fsscan.ClassifyError(err)})
			continue
		}
		entriesTruncation(entriesTruncated)
		pluginsListed := len(plugins)
		plugins = plugins[:min(pluginsListed, maxPluginsPerMarket)]
		for _, plugin := range plugins {
			if probes >= maxPluginProbes {
				budgetReached = true
				break
			}
			if !fsscan.BudgetRemains(ctx, deadline) {
				stopped = true
				break
			}
			pluginRelPath := filepath.Join(marketRel, plugin)
			versions, links, entriesTruncated, err := fsscan.ListSubdirNames(home, pluginRelPath,
				maxPluginDirEntries)
			reportLinks(links)
			if err != nil {
				warnings = append(warnings, warning{
					Code: warnPluginListUnreadable, Class: fsscan.ClassifyError(err)})
				continue
			}
			entriesTruncation(entriesTruncated)
			versionsListed := len(versions)
			versions = versions[:min(versionsListed, maxPluginVersions)]
			// Every installed version is probed, not just the newest. Comparing versions
			// means parsing them, and a plugin directory can hold a name this package has
			// no ordering for; reading all of them reports what is on disk, which is what
			// an inventory is for. Dedup at the probe keeps a shared config from doubling.
			for _, version := range versions {
				if probes >= maxPluginProbes {
					budgetReached = true
					break
				}
				probes++
				if !evidenceRead {
					var settingsWarnings, recordWarnings []warning
					enablement, enablementKnown, settingsWarnings = enabledPlugins(home)
					selected, selectionKnown, recordWarnings = selectedVersions(home)
					warnings = append(warnings, settingsWarnings...)
					warnings = append(warnings, recordWarnings...)
					evidenceRead = true
				}
				versionRel := filepath.Join(pluginRelPath, version)
				selection := versionSelection(home, versionRel, marketplace, plugin,
					selected, selectionKnown)
				refs = append(refs, pluginRef{
					Rel:         filepath.Join(versionRel, claudePluginConfigName),
					Marketplace: marketplace, Plugin: plugin, Version: version,
					Selection: selection,
					Approval: approvalForSelectedPlugin(enablement, enablementKnown,
						marketplace, plugin, selection),
				})
			}
			if !budgetReached && !stopped {
				levelTruncation(versionsListed, maxPluginVersions)
			}
		}
		if !budgetReached && !stopped {
			levelTruncation(pluginsListed, maxPluginsPerMarket)
		}
	}
	if !budgetReached && !stopped {
		levelTruncation(marketsListed, maxPluginMarketplaces)
	}
	if budgetReached {
		warnings = append(warnings, warning{
			Code: warnPluginListTruncated, Count: len(refs), Limit: maxPluginProbes})
	}
	// Sorted so the probe order, and therefore the row order, does not depend on readdir
	// order. ListDirNamesUnder already sorts each level; this makes the combination explicit
	// rather than relying on the nesting to preserve it.
	sort.Slice(refs, func(i, j int) bool { return refs[i].Rel < refs[j].Rel })
	return refs, warnings, stopped
}

// selectionWarning names the reason a cached version is not reported as enabled.
//
// Two codes, because the two are different for an operator: a superseded version is a fact
// about the host that will resolve itself when the orphan sweep runs, while an unestablished
// selection is a fact about this scan that will not.
//
// The second does not name a cause. selectionUnknown has three sources -- an orphan marker
// that could not be read, records that could not be read, and a record carrying no
// installPath -- and only the middle one is a records-read failure, which selectedVersions
// reports in its own right as a warning for the user.
func selectionWarning(selection pluginSelection) warning {
	if selection == versionSuperseded {
		return warning{Code: warnPluginSuperseded, Count: 1}
	}
	return warning{Code: warnPluginSelectionUnknown}
}

// manifestSource is one extra MCP configuration a plugin's manifest declares.
//
// Either a file to read, relative to the home like every other source here, or a document
// synthesized from an inline map so both forms reach the same extractor. Exactly one is set.
type manifestSource struct {
	Rel    string
	Inline []byte

	// Declared distinguishes a source the manifest named from the conventional
	// `.mcp.json` at the plugin root. The two need opposite absence policies: most plugins
	// ship no root config at all, so its absence is the common case and silent, while a
	// path the manifest named is documented to have to exist, so its absence is a broken
	// reference and a real loss of coverage.
	Declared bool
}

// pluginManifestSources returns the MCP configuration a plugin's manifest declares, beyond
// the `.mcp.json` at the plugin root.
//
// Only `.mcp.json` was probed, so a plugin that declares its servers in the manifest was
// omitted entirely -- no row, no diagnostic, and a sibling client's rows still reporting
// scan_complete = 1. The manifest's `mcpServers` key is documented to take a `.json` path, an
// inline map keyed by server name, or an array mixing them, and Claude loads `.mcp.json`
// first and then each declared shape in order, with a later server name replacing an earlier
// one. A manifest can therefore both add servers and rename them.
//
// Two of the documented shapes are deliberately not supported, and are reported rather than
// ignored. A `.mcpb` or `.dxt` bundle path would have to be unpacked, and a bundle URL
// downloaded, before either could say what servers it declares. Neither belongs in a
// scheduled query: one is an archive extraction driven by a file the user controls, the other
// is a network fetch to a host named in that file. An explicit incompleteness diagnostic says
// a declaration exists and was not read, which is the honest half of that trade.
func pluginManifestSources(home, versionRel string) ([]manifestSource, []warning) {
	manifestRel := filepath.Join(versionRel, filepath.FromSlash(pluginManifestRel))
	data, err := fsscan.ReadBoundedUnder(home, manifestRel, probeReadOpts(MaxFileSize))
	if err != nil {
		// The manifest is optional: a plugin laid out conventionally needs none, and most
		// have one with no MCP key. A genuinely missing one is silent; anything else,
		// a refused path included, is a manifest that exists and whose declarations are
		// therefore unlisted.
		if fsscan.ClassifyError(err) == fsscan.ClassAbsent {
			return nil, nil
		}
		return nil, []warning{{
			Code: warnPluginManifestUnreadable, Class: fsscan.ClassifyError(err)}}
	}
	var doc struct {
		// Raw, because the key is one of three shapes and the choice is made below. The
		// manifest also carries author, repository, userConfig and every other component
		// key, none of which this table reads.
		MCPServers json.RawMessage `json:"mcpServers"`
	}
	data = devclients.StripBOM(data)
	if devclients.NullDocument(data) || json.Unmarshal(data, &doc) != nil {
		return nil, []warning{{Code: warnPluginManifestUnreadable}}
	}
	if len(doc.MCPServers) == 0 {
		return nil, nil
	}
	// An array is flattened into its elements; anything else is one declaration. Decoding
	// the array first is what makes "array mixing both" work without a second pass.
	var elements []json.RawMessage
	if json.Unmarshal(doc.MCPServers, &elements) != nil {
		elements = []json.RawMessage{doc.MCPServers}
	}
	// Every element is classified before the cap is applied, so only usable declarations count
	// against it: a null, an invalid element and an unsupported one keep their own reporting and
	// do not use up the eight, and the truncation count is of the usable declarations.
	var sources []manifestSource
	var warnings []warning
	usable, unsupported, invalid, tooLong := 0, 0, 0, 0
	for _, element := range elements {
		source, kind := manifestDeclaration(home, versionRel, element)
		switch kind {
		case declNothing:
			continue
		case declInvalid:
			invalid++
		case declUnsupported:
			unsupported++
		case declTooLong:
			tooLong++
		case declUsable:
			usable++
			if len(sources) < maxManifestSourcesPerVersion {
				sources = append(sources, source)
			}
		}
	}
	if usable > maxManifestSourcesPerVersion {
		warnings = append(warnings, warning{Code: warnPluginManifestTruncated, Count: usable,
			Limit: maxManifestSourcesPerVersion})
	}
	if unsupported > 0 {
		warnings = append(warnings,
			warning{Code: warnPluginManifestUnsupported, Count: unsupported})
	}
	if invalid > 0 {
		warnings = append(warnings,
			warning{Code: warnPluginManifestInvalid, Count: invalid})
	}
	if tooLong > 0 {
		warnings = append(warnings, warning{Code: warnPluginManifestPathTooLong, Count: tooLong,
			Limit: devclients.MaxProjectPathLen})
	}
	return sources, warnings
}

// declKind is what one `mcpServers` element turned out to be.
//
// Four failure modes rather than one boolean, because they call for different reporting. An
// element of the wrong type -- `123` where a path or a map belongs -- is a malformed value in a
// field this table reads, which the client rejects at load, so `[{"healthy":{...}}, 123]` is
// reported rather than read as a complete listing of the healthy server.
type declKind int

const (
	// declNothing: the element declares no servers and nothing is missing. A JSON null, or
	// an inline map with no entries.
	declNothing declKind = iota
	// declInvalid: a value of a type or shape the field does not accept.
	declInvalid
	// declUnsupported: a valid declaration this table will not follow, because reading it
	// would mean unpacking an archive or fetching a URL.
	declUnsupported
	// declTooLong: a file whose absolute path is longer than devclients.MaxProjectPathLen. A
	// manifest may be 1 MiB, so without the bound one declaration could put most of a megabyte
	// into source_path, or into the component-wise open, which a recorded project's path is
	// refused for.
	declTooLong
	// declUsable: a declaration this table can read.
	declUsable
)

// manifestDeclaration interprets one `mcpServers` element.
func manifestDeclaration(home, versionRel string, element json.RawMessage) (manifestSource, declKind) {
	// Tested before the string decode, because `null` unmarshals into a string as "" and
	// would otherwise be indistinguishable from an empty path -- which is a broken reference
	// rather than an absent one.
	if string(element) == "null" {
		return manifestSource{}, declNothing
	}
	var path string
	if json.Unmarshal(element, &path) == nil {
		if path == "" {
			return manifestSource{}, declInvalid
		}
		// Paths are documented to start with `./` and to resolve inside the plugin root,
		// and the containment is re-established here rather than trusted: the manifest is a
		// file the marketplace controls. A backslash is refused outright because the
		// documentation makes such a path load on Windows only, so accepting it would make
		// this table's coverage differ from the client's by platform.
		if !strings.HasPrefix(path, "./") || strings.ContainsAny(path, `\:`) ||
			!strings.HasSuffix(strings.ToLower(path), ".json") {
			// Bundles and URLs land here too, and are the reason this is reported rather
			// than skipped: `./bundle.mcpb` and `https://host/server.mcpb` are both valid
			// declarations that this table will not follow.
			return manifestSource{}, declUnsupported
		}
		cleaned := filepath.Clean(filepath.FromSlash(strings.TrimPrefix(path, "./")))
		if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) ||
			filepath.IsAbs(cleaned) {
			return manifestSource{}, declUnsupported
		}
		rel := filepath.Join(versionRel, cleaned)
		if len(filepath.Join(home, rel)) > devclients.MaxProjectPathLen {
			return manifestSource{}, declTooLong
		}
		return manifestSource{Rel: rel, Declared: true}, declUsable
	}
	var inline map[string]json.RawMessage
	if json.Unmarshal(element, &inline) == nil {
		if len(inline) == 0 {
			return manifestSource{}, declNothing
		}
		// Wrapped in an envelope so the inline map reaches the same extractor the file forms
		// do, rather than growing a second path through materialize().
		document, err := json.Marshal(map[string]any{"mcpServers": inline})
		if err != nil {
			return manifestSource{}, declInvalid
		}
		return manifestSource{Inline: document, Declared: true}, declUsable
	}
	// Neither a string nor an object: a number, a boolean, or a nested array.
	return manifestSource{}, declInvalid
}

// pluginSourceContext names where a plugin-declared server came from.
//
// A fixed token. The marketplace, plugin and version are directory names the user's
// marketplaces control, and source_path already names the full location under the existing
// path redaction and containment assertion -- so putting them here as well would add a second
// user-controlled string to a column that is being narrowed, for information the row already
// carries.
const pluginSourceContext = "plugin.mcp_json"

// probePlugins reads each installed plugin's MCP configuration.
func probePlugins(ctx context.Context, home string, homeStorage fsscan.ErrClass, user string,
	deadline time.Time, seen map[string]struct{}, refs []pluginRef) ([]Server, bool) {
	var out []Server
	declaredReads := 0
	for _, ref := range refs {
		// Before each read, not only around the pass, so a cancelled query stops reading.
		if !fsscan.BudgetRemains(ctx, deadline) {
			return out, true
		}
		rootPath := filepath.Join(home, ref.Rel)
		if _, dup := seen[rootPath]; dup {
			continue
		}
		seen[rootPath] = struct{}{}
		versionRel := filepath.Dir(ref.Rel)
		manifestPath := filepath.Join(home, versionRel, filepath.FromSlash(pluginManifestRel))
		extra, manifestWarnings := pluginManifestSources(home, versionRel)
		var manifestRows []Server
		for _, manifestWarning := range manifestWarnings {
			manifestRows = append(manifestRows,
				diagnosticRow(user, manifestPath, "claude_code", manifestWarning))
		}
		// The root `.mcp.json` first and the manifest's declarations after, in the order
		// the manifest gives them, because that is the order Claude loads them in and the
		// order decides which definition of a repeated name survives.
		sources := append([]manifestSource{{Rel: ref.Rel}}, extra...)

		var rows []Server
		interrupted, exhausted := false, false
		latest := map[string]int{}
		// What each file read for this version returned, failures included, so a manifest that
		// names the same file twice pays for it once and is charged against
		// maxManifestSourcesPerPass once. Memoised rather than skipped, because a repeated
		// declaration is not a no-op: the last one still decides which definition of a name
		// survives, so dropping it would change precedence rather than just save a read. Keyed
		// by whether the source was declared as well as by path, because the root .mcp.json is
		// followed one hop when it is a link and a declared source is not: a manifest that
		// declares ./.mcp.json gets its own read under the declared rules, and is charged.
		type cachedRead struct {
			data []byte
			err  error
		}
		type readKey struct {
			rel      string
			declared bool
		}
		cache := map[readKey]cachedRead{}
		for _, source := range sources {
			if !fsscan.BudgetRemains(ctx, deadline) {
				// Breaks to the single finalization below rather than returning here, so an
				// interrupted version's rows still get file-wide placeholder ordinals: two
				// rejected names would otherwise both publish ordinal 1. One exit rather than
				// two, because a mid-manifest interruption cannot be provoked from a test:
				// the budget is read from the clock, so there is no seam to stop at a chosen
				// declaration.
				interrupted = true
				break
			}
			path := manifestPath
			data := source.Inline
			// A file this version already read. Its servers still take this position, which
			// decides precedence, but what it says about itself -- a missing file, a parse
			// failure, skipped entries -- was reported the first time, and repeating the row
			// for each declaration says nothing new.
			repeated := false
			if source.Inline == nil {
				path = filepath.Join(home, source.Rel)
				key := readKey{source.Rel, source.Declared}
				memo, cached := cache[key]
				repeated = cached
				read, readErr := memo.data, memo.err
				if !cached && source.Declared {
					if declaredReads >= maxManifestSourcesPerPass {
						// Its own code, because the manifest it sits on can be within its own
						// cap: the account's plugins together reached the per-pass bound.
						// Reported once for the version, and only this source is skipped: the
						// ones after it that need no read, inline declarations and files
						// already read, are still taken, in the manifest's order.
						if !exhausted {
							exhausted = true
							rows = append(rows, diagnosticRow(user, manifestPath, "claude_code",
								warning{Code: warnPluginManifestExhausted,
									Limit: maxManifestSourcesPerPass}))
						}
						continue
					}
					declaredReads++
				}
				if !cached {
					read, readErr = fsscan.ReadBoundedUnder(home, source.Rel,
						probeReadOpts(MaxFileSize))
					// The root .mcp.json is followed one hop when it is a link, as a home
					// config is. A declared source is not, and a refused one is reported as
					// plugin_manifest_missing_source.
					refused := fsscan.ClassifyError(readErr) == fsscan.ClassRefusedPath
					if !source.Declared && refused {
						dir, name := filepath.Split(source.Rel)
						read, readErr = fsscan.ReadLinkTarget(home, homeStorage, dir, name,
							probeReadOpts(MaxFileSize), linkChecks(fsscan.ReadBoundedUnder), readErr)
					}
					cache[key] = cachedRead{read, readErr}
				}
				if readErr != nil {
					// A plugin with no MCP configuration is the common case -- most ship
					// skills, agents or commands and no servers -- so the root file's
					// absence is silent, and any other failure is reported as a home
					// config's is: source_too_large or source_unreadable with the reason,
					// about this file. On this machine three of the four installed plugins
					// have no .mcp.json.
					//
					// A path the manifest named is the opposite case: it is documented to
					// exist, so its absence or refusal is a broken reference, reported with
					// its own code.
					switch {
					case repeated:
					case source.Declared:
						rows = append(rows, diagnosticRow(user, path, "claude_code",
							warning{Code: warnPluginManifestMissing,
								Class: fsscan.ClassifyError(readErr)}))
					default:
						rows = append(rows, finishProcessing(home, nil, readErr, path, user,
							"claude_code", true, MaxFileSize, extractEnvelopeSimple)...)
					}
					continue
				}
				data = read
			}
			// jsonc, because these are hand-written files and the shape permits comments.
			// The comment stripper is string-aware, which matters here: a plugin config is
			// mostly `"url": "https://..."` and a naive stripper would cut the URL at its
			// own slashes.
			produced := finishProcessing(home, data, nil, path, user, "claude_code", true,
				MaxFileSize, extractEnvelopeSimple)
			// Everything accumulated before this source is lower precedence than it, so if
			// this source could not be read, any of those definitions may be one the client
			// has replaced. The merger keys on names it decoded successfully, so a later
			// `"srv":{"command":123}` would otherwise leave the earlier `srv` standing as a
			// clean, enabled row.
			//
			// Qualified rather than dropped, and qualified rather than resolved: this table
			// cannot tell whether the client rejected the bad entry and kept the old one or
			// replaced it, so the honest row is the old definition marked as possibly stale.
			// Coarse by name but exact by precedence -- the extractor reports a failed
			// envelope without naming the entries in it, so which names were shadowed is not
			// recoverable, while which rows are lower precedence is.
			//
			// Before the merge, not after: a successful override replaces one of the earlier
			// positions in place, so marking first means the replacement overwrites the
			// qualified row and carries nothing from it, while a name this source failed to
			// redefine keeps the qualification.
			if hasScope(produced, scopeSource) {
				for i := range rows {
					if rows[i].rawName == "" {
						continue
					}
					rows[i].ScanComplete = false
					if rows[i].Warning.empty() {
						rows[i].Warning = warning{Code: warnPluginShadowedDecl}
					}
				}
			}
			for _, row := range produced {
				// The original name, which is the honest test for whether this row names a
				// server at all: a name that redacted to the marker is still a named
				// server.
				if row.rawName == "" {
					// A diagnostic from this source, which belongs to no name and so
					// cannot be superseded by one.
					if !repeated {
						rows = append(rows, row)
					}
					continue
				}
				// Enablement comes from settings rather than from the file, so it is
				// stamped here the same way project approval is: the extractor sees bytes
				// and has no idea which plugin they belong to.
				row.Approval = ref.Approval
				// Why the approval is unknown, when it is. Without this the row carried
				// `unknown` with an empty warning, which reads as a scan that could not be
				// bothered rather than as a version the client would not load. A warning
				// already on the row wins: a parse problem in the file is a worse fact
				// about this row than which release it came from.
				if ref.Selection != versionSelected && row.Warning.empty() {
					row.Warning = selectionWarning(ref.Selection)
				}
				row.rawContext = pluginSourceContext
				row.SourceContext = pluginSourceContext
				// Later replaces earlier, by original name. Keeping both would report one
				// server twice with two definitions, and the client runs only the last.
				if at, seenName := latest[row.rawName]; seenName {
					rows[at] = row
					continue
				}
				latest[row.rawName] = len(rows)
				rows = append(rows, row)
			}
		}
		rows = finalizeBySource(home, rows)
		// A plugin-scope finding, or a budget that ran out between this version's sources,
		// means the version's servers may not all be listed, so each of its server rows is
		// incomplete. Other plugin versions and other sources are unaffected.
		if interrupted || hasScope(manifestRows, scopePlugin) || hasScope(rows, scopePlugin) {
			for i := range rows {
				if rows[i].rawName != "" {
					rows[i].ScanComplete = false
				}
			}
		}
		out = append(out, manifestRows...)
		out = append(out, rows...)
		if interrupted {
			return out, true
		}
	}
	return out, false
}

// finalizeBySource settles the two properties that belong to a *file* rather than to a
// declaration, once every declaration from that file has been merged. finishProcessing runs
// once per declaration, because a manifest array is several declarations, so each call sees
// a fraction of the file:
//
// Completeness. An array holding one healthy inline server and one with `"command": 123` is
// one source, so the parse failure marks every row from it, the healthy one included.
//
// Placeholder ordinals. Two rejected names in two inline maps would each get ordinal 1 and
// publish the identical `[redacted:<manifest path>]`. They are numbered here, after
// last-declaration-wins has removed the rows that are not published, so the ordinals number
// what the table emits.
//
// Grouped by SourcePath, because one plugin version yields rows from several files -- the
// root `.mcp.json` and each declared `.json` -- and those are separate sources whose
// completeness and numbering are separate.
func finalizeBySource(home string, rows []Server) []Server {
	groups := map[string][]int{}
	order := []string{}
	for i := range rows {
		if _, seen := groups[rows[i].SourcePath]; !seen {
			order = append(order, rows[i].SourcePath)
		}
		groups[rows[i].SourcePath] = append(groups[rows[i].SourcePath], i)
	}
	for _, path := range order {
		indices := groups[path]
		// A copy per group, because assignNamePlaceholders numbers a contiguous slice and a
		// group's rows are not contiguous. Only the two placeholder fields are read back.
		group := make([]Server, 0, len(indices))
		for _, i := range indices {
			rows[i].PlaceholderSource, rows[i].PlaceholderIndex = "", 0
			group = append(group, rows[i])
		}
		if hasScope(group, scopeSource) {
			for _, i := range indices {
				rows[i].ScanComplete = false
			}
		}
		assignNamePlaceholders(home, path, group)
		for at, i := range indices {
			rows[i].PlaceholderSource = group[at].PlaceholderSource
			rows[i].PlaceholderIndex = group[at].PlaceholderIndex
		}
	}
	return rows
}
