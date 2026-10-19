package mcp_servers

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sort"
	"time"

	"github.com/macadmins/osquery-extension/pkg/devclients"
	"github.com/macadmins/osquery-extension/pkg/fsscan"
)

// Project discovery -- which projects each client recorded, containment, and the caps -- is
// shared with every table that reads project-local files, in pkg/devclients. This file adds
// what only this table needs: the approval and trust evidence that decides whether a project's
// servers are live, and the configuration files each client's list licenses opening.

// The shared discovery names, kept under this package's spellings so its call sites and tests
// are unchanged.
const (
	maxProjects      = devclients.MaxProjects
	maxWorkspaceDirs = devclients.MaxWorkspaceDirs
)

type originCode = devclients.Origin

const (
	originClaudeJSON        = devclients.OriginClaudeJSON
	originCodexTOML         = devclients.OriginCodexTOML
	originVSCodeWorkspace   = devclients.OriginVSCodeWorkspace
	originCursorWorkspace   = devclients.OriginCursorWorkspace
	originWindsurfWorkspace = devclients.OriginWindsurfWorkspace
)

// approvalState says whether a declared server is actually live.
//
// Claude Code treats a server declared in a project's .mcp.json as inert until the user
// approves it, recording the decision per project in ~/.claude.json. A security inventory
// that reported such a server as enabled is stating the opposite of the truth: the config
// declares it, and the client will not run it.
//
// Deliberately not folded into `disabled`. That column means "the configuration file said
// disabled", which is a fact about the file; approval is a fact about the client's state, and
// a user who has neither approved nor rejected a server is in neither of that column's two
// values. Overloading one column would make it mean different things per client, so the
// predicate `WHERE disabled = 0` would stop meaning anything a reader could state.
type approvalState string

const (
	// approvalEnabled: declared and approved, so the client will run it.
	approvalEnabled approvalState = "enabled"
	// approvalNotApproved: declared, never approved, so the client will not run it until
	// someone says yes. This is the value that was previously reported as enabled.
	approvalNotApproved approvalState = "not_approved"
	// approvalDisabled: declared and explicitly turned off.
	approvalDisabled approvalState = "disabled"
	// approvalNotApplicable: this client has no approval step, so the question does not
	// arise and the `disabled` column is the whole answer.
	approvalNotApplicable approvalState = "not_applicable"
	// approvalUnknown: this client has an approval step and the evidence for it could not
	// be read.
	//
	// Distinct from notApproved, which is a positive finding: the client recorded its
	// decisions and this server was not among them. Unknown means the record itself was
	// unreadable -- malformed settings, a malformed project entry -- so the server may well
	// be live. Collapsing the two reported "not approved" about a server nobody had
	// declined, which is a confident wrong answer in the direction an inventory must not
	// fail: it invites someone to ignore a server that is running.
	approvalUnknown approvalState = "unknown"
)

// projectRef is one recorded project, reduced to the only form that may be opened.
type projectRef struct {
	// Rel is relative to the home and has been through fsscan.ContainProjectPath. It is
	// the only field any read uses: the guarantee is not "this string starts with the
	// home" but "every component from the home down was opened with symlinks refused",
	// and that is a property of the relative form.
	Rel string

	// Abs is for reporting only, and is reported only where a path is already published.
	Abs string

	// Origins records every client list that named this project, and is what decides which
	// configuration files are probed inside it.
	//
	// A set rather than one value, because deduplication merges a project recorded by
	// several clients and the provenance of all of them matters. An earlier version kept a
	// single Origin and Client from whichever sighting happened to be first, never read
	// them, and applied every probe to every project -- so a directory known only to Codex
	// produced a vscode row because a dormant .vscode/mcp.json happened to sit in it. That
	// is a claim the evidence does not support: nothing established that VS Code had ever
	// opened the directory, let alone that it would load that file.
	Origins map[originCode]struct{}

	// Approval is every piece of evidence bearing on whether this project's .mcp.json
	// servers will run: the two name arrays from ~/.claude.json's project entry, plus the
	// three approval keys from each settings file that applies. Resolution is per server
	// name, because that is the shape of the data -- a project routinely has one approved
	// and one pending server -- and the precedence rule is per name too, so the resolver
	// lives with the evidence rather than at the call site. See approval.go.
	Approval claudeApproval

	// TrustDialogAccepted is Claude's workspace trust for this project.
	//
	// It gates whether a *committed* project settings file may approve servers: Claude
	// ignores repository-provided approvals in a folder whose trust dialog was never
	// accepted, which is what stops a repository approving its own MCP servers by shipping a
	// settings file. Absent or undecodable reads as not accepted, which is the fail-closed
	// direction and matches Claude's own default of asking.
	TrustDialogAccepted bool

	// Trusted reports Codex's project trust state, and TrustKnown whether it was readable.
	//
	// Codex skips every project-scoped `.codex/` layer for an untrusted project, so a
	// `.codex/config.toml` there declares servers Codex will not load. Reporting them as
	// configured is the same error as reporting an unapproved Claude server as enabled.
	Trusted    bool
	TrustKnown bool
}

// originProbes maps a client's project list to the configuration files that client actually
// loads from a project it has opened.
//
// This is what replaces applying every probe to every project. The maintainer's request was
// to map each client's list to its corresponding configuration, and the cross-product did
// the opposite: it used one client's evidence that a directory is a project to justify
// reporting a different client's configuration in it.
//
// VS Code's workspace list covers both `.vscode/mcp.json` and `.cursor/mcp.json` because the
// forks share the workspaceStorage layout and a Cursor workspace is recorded the same way,
// which is how the fork is identified in the first place.
var originProbes = map[originCode][]string{
	originClaudeJSON:      {".mcp.json"},
	originVSCodeWorkspace: {filepath.Join(".vscode", "mcp.json")},
	originCursorWorkspace: {filepath.Join(".cursor", "mcp.json")},
	originCodexTOML:       {filepath.Join(".codex", "config.toml")},
	// Windsurf records workspaces the same way and has no project-scoped MCP path this
	// table reads: its configuration is the user-scope .codeium/windsurf/mcp_config.json,
	// which a fixed probe already covers. Present as an origin so a Windsurf-only project
	// is still deduplicated and reported rather than silently absent, and mapped to nothing
	// rather than guessed at. Recorded as a known omission in the table README.
	originWindsurfWorkspace: nil,
}

// probesFor returns the relative paths worth probing inside this project, given which client
// lists named it. Sorted, so the probe order and therefore the row order is stable.
func (p projectRef) probesFor() []string {
	seen := make(map[string]struct{})
	var out []string
	for origin := range p.Origins {
		for _, rel := range originProbes[origin] {
			if _, dup := seen[rel]; dup {
				continue
			}
			seen[rel] = struct{}{}
			out = append(out, rel)
		}
	}
	sort.Strings(out)
	return out
}

// allowsCodexConfig reports whether this project's `.codex/config.toml` is configuration
// Codex would load.
//
// Untrusted projects are skipped entirely rather than reported with a state, because the file
// is not configuration for that project: Codex does not read it. Unknown trust fails closed
// for the same reason the rest of this table does -- an unverifiable claim is not published.
func (p projectRef) allowsCodexConfig() bool {
	return p.TrustKnown && p.Trusted
}

// approvalFor reports whether one server declared in this project is live.
//
// client is checked rather than assumed: the approval mechanism is Claude Code's, so a
// cursor or vscode config in the same directory has no approval state and must say so
// instead of borrowing Claude's.
func (p projectRef) approvalFor(client, serverName string) approvalState {
	if client != "claude_code" {
		return approvalNotApplicable
	}
	return p.Approval.stateFor(serverName)
}

// claudeProjectsRelPath and codexProjectsRelPath are both a source of servers and a source of
// the project list. That dual role is what makes the read cap on ~/.claude.json load-bearing:
// an oversized file costs the account its project inventory and its approval state, not only
// one client's global servers. See devclients.ClaudeListMaxSize.
const (
	claudeProjectsRelPath = devclients.ClaudeListPath
	codexProjectsRelPath  = devclients.CodexListPath
)

// claudeProjects lists the projects recorded in ~/.claude.json.
//
// Four things are read from a project entry: the key, which is the project path, the two
// server-name arrays, and the workspace trust flag. That is an enumerated allowlist rather
// than a minimisation -- the same object carries `lastSessionFirstPrompt`, which is the
// literal text of the last thing the user typed at the client, and `history`. A struct naming
// only these fields cannot reach them, which is why this decodes into a narrow struct instead
// of into a map; TestClaudeProjectsReadsOnlyDeclaredFields asserts it over a hostile entry.
//
// It was three fields until workspace trust was needed to decide whether a committed settings
// file may approve its own servers. The count is not the invariant; naming every field
// explicitly is.
func claudeProjects(home string, data []byte) ([]projectRef, []warning) {
	entries, err := devclients.ClaudeEntries(data)
	if err != nil {
		// The file is not JSON. The direct probe over the same bytes reports the parse
		// failure for the servers; this reports the separate and larger loss, which is that
		// no project-local configuration can be found for this account at all.
		return nil, []warning{{Code: warnProjectListUnreadable}}
	}

	userSettings, warnings := userApprovalSettings(home)
	collector := newProjectCollector(home, originClaudeJSON)
	for _, recorded := range entries {
		var entry struct {
			// The only fields read. Adding one here needs the same scrutiny as a new
			// column: the sibling keys in this object include the user's typed prompts.
			EnabledMcpjsonServers  []string `json:"enabledMcpjsonServers"`
			DisabledMcpjsonServers []string `json:"disabledMcpjsonServers"`
			HasTrustDialogAccepted bool     `json:"hasTrustDialogAccepted"`
		}
		// A project entry that will not decode costs its approval state, not its path: the
		// key is still a project worth probing, and treating an unreadable entry as an
		// absent project would lose a real configuration over a malformed sibling field.
		//
		// But the loss is recorded rather than swallowed. Without known, an undecodable
		// entry left both lists empty and every server in that project was reported
		// `not_approved` -- a positive claim resting on evidence that was never read.
		// The project entry's own arrays, which is where the interactive approval prompt
		// records its answer, merged with the account-wide settings keys. The settings are
		// read once per home rather than per project.
		// The project-history arrays, which is where the interactive approval prompt records
		// its answer. Certain: this is the user's own recorded decision, not a
		// repository-provided one, so no trust or tracking condition applies to it.
		history := claudeApproval{Known: json.Unmarshal(recorded.Raw, &entry) == nil}
		history.Certain = approvalEvidence{
			Enabled:  entry.EnabledMcpjsonServers,
			Disabled: entry.DisabledMcpjsonServers,
		}
		// The account-wide settings are the lower precedence of the two, and the project's
		// own files overlay both later, once containment has admitted the project.
		collector.addClaude(recorded.Recorded, userSettings.merge(history),
			entry.HasTrustDialogAccepted)
	}
	refs, collectorWarnings := collector.result()
	return refs, append(warnings, collectorWarnings...)
}

// codexProjects lists the projects recorded in ~/.codex/config.toml.
//
// The values are held as primitives and never decoded. Codex's [projects."<path>"] tables
// carry trust settings this table does not use, and decoding a value is how a format's
// unrelated fields start costing whole files -- twice already in this package, for
// tool_timeout_sec and for env_vars. Reading only the keys cannot fail that way.
func codexProjects(home string, data []byte) ([]projectRef, []warning) {
	entries, err := devclients.CodexEntries(data)
	if err != nil {
		return nil, []warning{{Code: warnProjectListUnreadable}}
	}

	collector := newProjectCollector(home, originCodexTOML)
	for _, recorded := range entries {
		// One field is decoded from the value, and it decides whether the project's config
		// is configuration at all.
		//
		// Codex skips every project-scoped `.codex/` layer for an untrusted project, so a
		// `.codex/config.toml` there declares servers Codex will not load. An earlier
		// version read the keys and never the values, and reported those servers as
		// configured -- the same error as reporting an unapproved Claude server as enabled.
		//
		// Decoded into a struct with exactly this field, for the reason the Claude lister
		// decodes into a narrow struct: the value carries other per-project state and a
		// map would put all of it one field access from a column.
		var entry struct {
			TrustLevel string `toml:"trust_level"`
		}
		known := recorded.Decode(&entry) == nil
		trusted := entry.TrustLevel == codexTrustedLevel
		// Missing or undecodable trust fails closed. An absent trust_level is not evidence
		// of trust, and Codex's own default is to ask rather than assume.
		collector.addTrusted(recorded.Recorded, known && entry.TrustLevel != "", trusted)
	}
	refs, warnings := collector.result()
	// Counted from the admitted refs rather than while iterating the file, so a project
	// containment refused does not also report a trust problem. An entry outside the home
	// produced both project_outside_home and project_trust_unknown, and the second is
	// home-scope, so a project explicitly beyond the discovery boundary flipped an unrelated
	// healthy row to scan_complete = 0.
	untrusted, unknownTrust := 0, 0
	for _, ref := range refs {
		switch {
		case !ref.TrustKnown:
			unknownTrust++
		case !ref.Trusted:
			untrusted++
		}
	}
	if untrusted > 0 {
		warnings = append(warnings, warning{Code: warnProjectUntrusted, Count: untrusted})
	}
	if unknownTrust > 0 {
		warnings = append(warnings, warning{Code: warnProjectTrustUnknown, Count: unknownTrust})
	}
	return refs, warnings
}

// codexTrustedLevel is the one trust_level value that admits project-scoped configuration.
//
// Matched positively rather than by excluding a known-untrusted spelling: a value this table
// does not recognise must not read as trusted, and Codex is free to add others.
const codexTrustedLevel = "trusted"

// vscodeWorkspaceProjects lists the folders recorded in each VS Code fork's workspaceStorage.
//
// The directory names under workspaceStorage are generated hashes, so this is the one place a
// fixed path cannot reach and fsscan.ListDirNamesUnder is used instead: one directory read per
// fork, no recursion, capped.
//
// Only the `folder` field is read. A multi-root workspace records `workspace` instead, naming
// a .code-workspace file whose own folder list would have to be parsed, and this machine has
// no workspaceStorage at all to verify that shape against -- so it is documented as a known
// omission rather than guessed at. See the table README.
func vscodeWorkspaceProjects(ctx context.Context, home, appDataRoot string,
	deadline time.Time) ([]projectRef, []warning, bool) {
	scan := devclients.WorkspaceFolders(ctx, home, appDataRoot, deadline,
		probeReadOpts(MaxFileSize))
	var warnings []warning
	for _, listing := range scan.Listings {
		if listing.Truncated {
			warnings = append(warnings, warning{
				Code: warnWorkspaceListTruncated, Count: listing.Count, Limit: maxWorkspaceDirs})
			continue
		}
		warnings = append(warnings, warning{Code: warnWorkspaceListUnreadable, Class: listing.Class})
	}
	collector := newProjectCollector(home, originVSCodeWorkspace)
	for _, folder := range scan.Folders {
		collector.addFileURL(folder.Recorded, folder.Origin)
	}
	// Counted across every fork rather than per fork, so one fact produces one row. A record
	// that exists and cannot be read is lost discovery evidence: a project whose configuration
	// is live could otherwise vanish while the remaining rows still claimed scan_complete = 1.
	if scan.UnreadableRecords > 0 {
		warnings = append(warnings, warning{
			Code: warnWorkspaceRecordUnreadable, Count: scan.UnreadableRecords})
	}
	if scan.MalformedRecords > 0 {
		warnings = append(warnings, warning{
			Code: warnWorkspaceRecordMalformed, Count: scan.MalformedRecords})
	}
	refs, collectorWarnings := collector.result()
	return refs, append(warnings, collectorWarnings...), scan.Stopped
}

// listCapped is fsscan.ListDirNamesCapped under this package's name.
var listCapped = fsscan.ListDirNamesCapped

// projectCollector pairs the shared containment collector with this table's evidence for each
// project: approval, Claude's workspace trust, and Codex's project trust.
//
// The diagnostics it produces carry counts and no path. A path inside a user's home is not
// publishable, so a diagnostic naming the offending project would reintroduce the disclosure
// these columns are narrowed to prevent.
type projectCollector struct {
	set    *devclients.Collector
	origin originCode

	// refs is index-aligned with set.Projects(). Rel, Abs and Origins are filled from the set
	// in result(); the other fields are merged here as each sighting arrives, because the
	// same project appears in Claude's list with its approvals and in Codex's without, and
	// keeping whichever was seen first would discard one of them.
	refs []projectRef
}

func newProjectCollector(home string, origin originCode) *projectCollector {
	return &projectCollector{set: devclients.NewCollector(home, maxProjects), origin: origin}
}

// add contains one recorded path and records it, or counts the refusal.
//
// approvalKnown says whether the project's entry decoded. It is threaded rather than inferred
// from the lists being empty, because "approved nothing" and "could not be read" are both
// empty lists and only one of them licenses reporting notApproved.
func (c *projectCollector) add(recorded string, approval claudeApproval) {
	c.contain(recorded, false, approval, true, true, false)
}

// addClaude is add for the one lister that also supplies Claude's workspace trust.
func (c *projectCollector) addClaude(recorded string, approval claudeApproval,
	trustDialogAccepted bool) {
	c.contain(recorded, false, approval, true, true, trustDialogAccepted)
}

// addTrusted is add for Codex, which supplies trust instead of approval.
func (c *projectCollector) addTrusted(recorded string, trustKnown, trusted bool) {
	c.contain(recorded, false, claudeApproval{Known: true}, trustKnown, trusted, false)
}

// addFileURL is add for the one recorded form that is a URL rather than a path. origin is
// supplied per call, because the workspace lister reads several forks and each contributes its
// own.
func (c *projectCollector) addFileURL(recorded string, origin originCode) {
	saved := c.origin
	c.origin = origin
	c.contain(recorded, true, claudeApproval{Known: true}, true, true, false)
	c.origin = saved
}

func (c *projectCollector) contain(recorded string, allowFileURL bool,
	approval claudeApproval, trustKnown, trusted, trustDialogAccepted bool) {
	index, admitted := c.set.Add(recorded, c.origin, allowFileURL)
	if !admitted {
		return
	}
	if index < len(c.refs) {
		// Every field that carries evidence merges. Certainty is conjunctive: one unreadable
		// sighting makes the approving answers unknown even if another sighting was clean,
		// because the unreadable one may have held a decision that contradicts it. A rejection
		// that was read survives regardless, which merge preserves.
		existing := &c.refs[index]
		existing.Approval = existing.Approval.merge(approval)
		// Accepted anywhere is accepted: only Claude's list reports it, so a sighting from
		// another lister has nothing to contribute and must not clear it.
		existing.TrustDialogAccepted = existing.TrustDialogAccepted || trustDialogAccepted
		if c.origin == originCodexTOML {
			existing.TrustKnown = trustKnown
			existing.Trusted = trusted
		}
		return
	}
	c.refs = append(c.refs, projectRef{
		Approval:            approval,
		TrustKnown:          trustKnown,
		Trusted:             trusted,
		TrustDialogAccepted: trustDialogAccepted,
	})
}

// result returns the contained projects and the aggregated refusals.
//
// A deleted project is silent. It is the common case by a wide margin -- three of the
// development machine's thirty recorded Claude projects no longer exist -- and absence is
// detected by the probe read returning ENOENT, which fsscan.IsExpectedAbsent already swallows.
func (c *projectCollector) result() ([]projectRef, []warning) {
	for index, project := range c.set.Projects() {
		c.refs[index].Rel = project.Rel
		c.refs[index].Abs = project.Abs
		c.refs[index].Origins = project.Origins
	}
	refusals := c.set.Refusals()
	var warnings []warning
	if refusals.Outside > 0 {
		warnings = append(warnings, warning{Code: warnProjectOutsideHome, Count: refusals.Outside})
	}
	if refusals.Remote > 0 {
		warnings = append(warnings, warning{Code: warnProjectRemoteOrigin, Count: refusals.Remote})
	}
	if refusals.Malformed > 0 {
		warnings = append(warnings, warning{Code: warnProjectMalformed, Count: refusals.Malformed})
	}
	if refusals.Truncated {
		warnings = append(warnings, warning{
			Code: warnProjectListTruncated, Count: len(c.refs), Limit: maxProjects})
	}
	return c.refs, warnings
}

// mergeProjects combines the three listers' results, probing a directory once however many
// clients recorded it.
//
// Ordered by Rel so the probe order, and therefore the row order, is a function of the
// filesystem rather than of map iteration. The cap is applied again across the union: three
// listers each under their own cap can still sum to three times it.
func mergeProjects(groups ...[]projectRef) ([]projectRef, []warning) {
	index := make(map[string]int)
	var out []projectRef
	truncated := 0
	for _, group := range groups {
		for _, ref := range group {
			if existing, seen := index[ref.Rel]; seen {
				for origin := range ref.Origins {
					out[existing].Origins[origin] = struct{}{}
				}
				out[existing].Approval = out[existing].Approval.merge(ref.Approval)
				out[existing].TrustDialogAccepted = out[existing].TrustDialogAccepted ||
					ref.TrustDialogAccepted
				// Trust comes only from Codex's list, so a sighting that carries it wins
				// over one that never had it to report.
				if _, fromCodex := ref.Origins[originCodexTOML]; fromCodex {
					out[existing].TrustKnown = ref.TrustKnown
					out[existing].Trusted = ref.Trusted
				}
				continue
			}
			if len(out) >= maxProjects {
				truncated++
				continue
			}
			index[ref.Rel] = len(out)
			out = append(out, ref)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	if truncated > 0 {
		return out, []warning{{
			Code: warnProjectListTruncated, Count: len(out), Limit: maxProjects}}
	}
	return out, nil
}

// projectRefusalWarning classifies a project-probe read failure, or reports that there is
// nothing to say.
//
// Three outcomes and they are deliberately not uniform. Absence is silent: a recorded project
// that was deleted, or one that simply has no MCP configuration, is the overwhelming majority
// and a row each would bury everything else. A cloud placeholder is counted, because it means
// a configuration exists and this scan declined to download it. A hard-link or owner refusal
// is never silent -- that one is a finding rather than an absence, and the whole reason those
// checks exist is to be told when they fire.
func projectRefusalWarning(err error, maxSize int64) (warning, bool) {
	switch class := fsscan.ClassifyError(err); class {
	case fsscan.ClassNone, fsscan.ClassAbsent, fsscan.ClassRefusedPath:
		return warning{}, false
	case fsscan.ClassCloudPlaceholder:
		return warning{Code: warnProjectCloudPlaceholder, Count: 1}, true
	case fsscan.ClassUserspaceFilesystem:
		return warning{Code: warnProjectUserspaceFS, Count: 1}, true
	case fsscan.ClassHardLink, fsscan.ClassForeignOwner:
		return warning{Code: warnProjectRefused, Class: class}, true
	case fsscan.ClassTooLarge:
		// Reported with the cap that actually applied rather than folded into the generic
		// unreadable class. An oversized file is the one read failure an operator can act
		// on, and the numbers are integers, so there is nothing here a column has to be
		// protected from. The project-rooted path reached this through the default branch
		// and lost the limit entirely.
		return warning{Code: warnSourceTooLarge, Limit: maxSize}, true
	default:
		return warning{Code: warnSourceUnreadable, Class: class}, true
	}
}

// claudeJSONMaxSize is the read cap for ~/.claude.json, and stripBOM removes a byte-order mark
// before a JSON decode; both live in pkg/devclients beside the readers that depend on them.
const claudeJSONMaxSize = devclients.ClaudeListMaxSize

var stripBOM = devclients.StripBOM

// mergeWarnings combines same-code findings from the three listers into one each.
//
// Each lister has its own collector and emits its own counts, so a machine with projects
// outside the home in two different clients' lists produced two rows saying the same thing
// with different numbers -- "count=3" and "count=1" where the fact is four. Observed on the
// development machine. Counts add; the other fields come from the first sighting, since a
// class with a Class or a Limit has exactly one producer.
//
// Sorted by code, because map iteration is random and these go straight to osquery.
func mergeWarnings(warnings []warning) []warning {
	if len(warnings) < 2 {
		return warnings
	}
	index := make(map[warnCode]int, len(warnings))
	var out []warning
	for _, w := range warnings {
		if at, seen := index[w.Code]; seen {
			out[at].Count += w.Count
			continue
		}
		index[w.Code] = len(out)
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}
