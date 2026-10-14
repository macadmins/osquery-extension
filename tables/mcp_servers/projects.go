package mcp_servers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
)

// Where project-local configuration comes from, now that nothing walks the filesystem.
//
// The walk it replaces was wrong in three ways the review named and one it did not. It was
// nondeterministic: ~22 roots per home to depth 6 under a budget shared across every home, so
// the first account's source tree could exhaust the allowance and the rows a second account
// got depended on how big the first account's checkout was. It downloaded files: ~/Documents
// and ~/Desktop are iCloud-backed under "Optimise Mac Storage", and reading a dehydrated file
// is a network fetch, so an inventory query pulled a user's documents down. And it blocked:
// one dead automount, offline network home or Windows oplock stalled the walk and everything
// osquery had scheduled behind it.
//
// The fourth problem is the one that makes the replacement better rather than merely safer. A
// walk finds files; it does not find *configuration*. It cannot tell a project the user works
// in from a vendored copy of someone else's repository, and on this machine 39 of 51 rows from
// one client came from a plugin marketplace cache -- installable catalog entries, not servers
// anybody had enabled. The exclusions that fixed that were substring matches on paths,
// maintained by noticing each new cache directory after it polluted the table.
//
// Every client already keeps a list of the projects its user actually opened. Reading that
// list and probing known filenames inside each entry is bounded by the number of projects
// rather than by the size of the disk, deterministic because the list is a file, and immune
// to the catalog problem because a marketplace cache is not a project anyone opened.
//
// What it costs is stated plainly in the table README: a project the user has never opened in
// a participating client is invisible, and so is one recorded by a client this file has no
// lister for.

// maxProjects bounds how many recorded projects one client's list may contribute.
//
// Measured against this machine, which records 30 projects for Claude Code and about 30 for
// Codex. An order of magnitude above that is unreachable by ordinary use and still bounds the
// work: each project costs one component-wise open per project-rooted probe, so the cap is
// what keeps a config file someone has scripted into thousands of entries from turning a
// bounded read into an unbounded one.
//
// Exceeding it is reported rather than silently truncating, because a project list cut short
// is the same shape of loss the walk's truncation was and the whole point of this change is
// that such a loss is visible.
const maxProjects = 200

// maxWorkspaceDirs bounds the generated-name directories under one fork's workspaceStorage.
//
// Separate from maxProjects because it bounds a different thing: this is a directory listing,
// one per VS Code fork, and each entry costs a read of a small JSON file. VS Code accumulates
// one of these per workspace ever opened and never prunes them, so the count is higher than
// the number of live projects by a wide margin.
const maxWorkspaceDirs = 500

// originCode names which client's list a project came from. Closed, and reported rather than
// inferred, because the answer is not recoverable from the path: the same directory can be
// recorded by all three.
type originCode string

const (
	originClaudeJSON originCode = "claude_json"
	originCodexTOML  originCode = "codex_toml"

	// One origin per editor, not one for the whole VS Code family.
	//
	// The forks share the workspaceStorage layout, and an earlier version took that to mean
	// one origin could stand for all of them -- so a project recorded only under
	// Code/User/workspaceStorage emitted a clean client=cursor row from a dormant
	// .cursor/mcp.json with no Cursor history anywhere on the host. Sharing a record format
	// establishes nothing about which editor opened the project or whose configuration it
	// would load, and the enumeration knows which fork's directory it is reading, so it
	// says so.
	originVSCodeWorkspace   originCode = "vscode_workspace"
	originCursorWorkspace   originCode = "cursor_workspace"
	originWindsurfWorkspace originCode = "windsurf_workspace"
)

// workspaceOriginFor maps a fork's client name to the provenance its workspace list carries.
//
// Keyed on the client rather than the directory, because Code, Code - Insiders and VSCodium
// all report as `vscode` and all read `.vscode/mcp.json`; they are the same editor and one
// origin is correct for them.
var workspaceOriginFor = map[string]originCode{
	"vscode":   originVSCodeWorkspace,
	"cursor":   originCursorWorkspace,
	"windsurf": originWindsurfWorkspace,
}

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

// claudeProjectsRelPath and codexProjectsRelPath name the two files that are both a source of
// servers and a source of the project list.
//
// Named rather than written inline because that dual role is what makes MaxFileSize
// load-bearing: an oversized ~/.claude.json used to cost one client's global servers, and now
// costs the entire project inventory for the account as well, because the list *is* that
// file. See claudeJSONMaxSize.
const (
	claudeProjectsRelPath = ".claude.json"
	codexProjectsRelPath  = ".codex/config.toml"
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
	var doc struct {
		Projects map[string]json.RawMessage `json:"projects"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		// The file is not JSON. The direct probe over the same bytes reports the parse
		// failure for the servers; this reports the separate and larger loss, which is that
		// no project-local configuration can be found for this account at all.
		return nil, []warning{{Code: warnProjectListUnreadable}}
	}
	// Sorted before anything is decided. Map iteration order is random, and the cap below
	// would otherwise admit a different 200 projects on every run -- which differential
	// logging reports as rows removed and re-added on an unchanged host.
	keys := make([]string, 0, len(doc.Projects))
	for key := range doc.Projects {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	userSettings, warnings := userApprovalSettings(home)
	collector := newProjectCollector(home, originClaudeJSON)
	for _, key := range keys {
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
		history := claudeApproval{Known: json.Unmarshal(doc.Projects[key], &entry) == nil}
		history.Certain = approvalEvidence{
			Enabled:  entry.EnabledMcpjsonServers,
			Disabled: entry.DisabledMcpjsonServers,
		}
		// The account-wide settings are the lower precedence of the two, and the project's
		// own files overlay both later, once containment has admitted the project.
		collector.addClaude(key, userSettings.merge(history), entry.HasTrustDialogAccepted)
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
	var doc struct {
		Projects map[string]toml.Primitive `toml:"projects"`
	}
	metadata, err := toml.Decode(string(data), &doc)
	if err != nil {
		return nil, []warning{{Code: warnProjectListUnreadable}}
	}
	keys := make([]string, 0, len(doc.Projects))
	for key := range doc.Projects {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	collector := newProjectCollector(home, originCodexTOML)
	for _, key := range keys {
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
		known := metadata.PrimitiveDecode(doc.Projects[key], &entry) == nil
		trusted := entry.TrustLevel == codexTrustedLevel
		// Missing or undecodable trust fails closed. An absent trust_level is not evidence
		// of trust, and Codex's own default is to ask rather than assume.
		collector.addTrusted(key, known && entry.TrustLevel != "", trusted)
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
	collector := newProjectCollector(home, originVSCodeWorkspace)
	var warnings []warning
	// Counted across every fork rather than per fork, so one fact produces one row.
	unreadable, malformed := 0, 0
	stopped := false
	for _, fork := range vscodeFamily {
		if !budgetRemains(ctx, deadline) {
			stopped = true
			break
		}
		for _, storageRel := range appSupportFork(fork.dir, "User", "workspaceStorage") {
			relPath, resolvable := resolveSnapPath(home, storageRel)
			if !resolvable {
				continue
			}
			if rewritten, usable := redirectAppSupport(relPath, appDataRoot, home); !usable {
				continue
			} else if rewritten != "" {
				relPath = rewritten
			}
			// An absent directory is the overwhelmingly common case -- most hosts have
			// none of the five forks installed -- so it is silent. A listing that is short
			// still yields its names; only a real failure yields none.
			names, truncated, err := listCapped(home, relPath, maxWorkspaceDirs)
			if err != nil {
				warnings = append(warnings, warning{
					Code:  warnWorkspaceListUnreadable,
					Class: fsscan.ClassifyError(err),
				})
				continue
			}
			if truncated {
				warnings = append(warnings, warning{
					Code: warnWorkspaceListTruncated, Count: len(names),
					Limit: maxWorkspaceDirs})
			}
			for _, name := range names {
				// Before each record. A fork accumulates one workspaceStorage directory per
				// workspace ever opened and never prunes them, so this loop is the one with
				// thousands of iterations and was the one that ignored cancellation.
				if !budgetRemains(ctx, deadline) {
					stopped = true
					break
				}
				var doc struct {
					Folder string `json:"folder"`
				}
				data, readErr := fsscan.ReadBoundedUnder(home,
					filepath.Join(relPath, name, "workspace.json"), probeReadOpts(MaxFileSize))
				if readErr != nil {
					// Absence is routine: a workspaceStorage directory outlives the
					// workspace it was created for, so most entries have no readable
					// record. Anything else is lost discovery evidence -- a permission
					// failure, the size cap, a refused hard link -- and an earlier version
					// of this loop treated all of it as absence with a bare `continue`. A
					// project whose configuration is live could vanish while the remaining
					// rows still claimed scan_complete = 1.
					if !fsscan.IsExpectedAbsent(readErr) {
						unreadable++
					}
					continue
				}
				if err := json.Unmarshal(stripBOM(data), &doc); err != nil {
					// The record exists and could not be parsed, so a project this fork
					// has open may be missing from the result. Counted separately from an
					// unreadable record because the remedies differ.
					malformed++
					continue
				}
				if doc.Folder == "" {
					// A multi-root workspace records `workspace` rather than `folder`, and
					// only `folder` is read. Documented as a known omission in the table
					// README rather than counted here, because it is a shape this table
					// declines to support rather than evidence it failed to read.
					continue
				}
				collector.addFileURL(doc.Folder, workspaceOriginFor[fork.client])
			}
		}
	}
	if unreadable > 0 {
		warnings = append(warnings, warning{
			Code: warnWorkspaceRecordUnreadable, Count: unreadable})
	}
	if malformed > 0 {
		warnings = append(warnings, warning{
			Code: warnWorkspaceRecordMalformed, Count: malformed})
	}
	refs, collectorWarnings := collector.result()
	return refs, append(warnings, collectorWarnings...), stopped
}

// listCapped applies ListDirNamesUnder's two-part contract in one place.
//
// That function deliberately returns the names it could fit *and* ErrTooLarge, so a caller
// can use the partial listing and report the shortfall. All three callers in this package got
// that wrong in the same way: they tested `err != nil` and skipped the level, so a directory
// holding more entries than the cap yielded *nothing* instead of the capped list -- turning a
// bounded answer into a silently empty one, which is the failure mode this table exists to
// prevent. Found by a test that put more plugins under one marketplace than the cap allows.
//
// truncated separates "the listing was short" from "the listing failed". Absence is neither,
// and is reported as a nil error with no names, because most of these directories do not
// exist on most hosts.
func listCapped(home, rel string, limit int) (names []string, truncated bool, err error) {
	names, err = fsscan.ListDirNamesUnder(home, rel, limit)
	switch {
	case err == nil:
		return names, false, nil
	case errors.Is(err, fsscan.ErrTooLarge):
		// The names are the capped prefix and are usable; the shortfall is the caller's to
		// report.
		return names, true, nil
	case fsscan.IsExpectedAbsent(err):
		return nil, false, nil
	default:
		return nil, false, err
	}
}

// projectCollector applies containment to each recorded path and aggregates the refusals.
//
// Aggregated rather than reported per entry, and with no path in the result: a path inside a
// user's home is not publishable, so a diagnostic naming the offending project would
// reintroduce exactly the disclosure these columns are narrowed to prevent. A count and a
// reason are what an operator can act on anyway -- "three recorded projects are outside this
// home" is actionable, and a fourth copy of the same sentence with a different path is not.
type projectCollector struct {
	home   string
	origin originCode

	// Keyed by Rel so a directory recorded by two clients is probed once. The map value is
	// an index into refs, so the approval arrays of a later sighting can be merged into the
	// first: the same project appears in Claude's list with its approvals and in Codex's
	// without, and keeping whichever was seen first would discard them.
	index map[string]int
	refs  []projectRef

	outside   int
	malformed int
	remote    int
	overCap   bool
}

func newProjectCollector(home string, origin originCode) *projectCollector {
	return &projectCollector{home: home, origin: origin, index: make(map[string]int)}
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

// addFileURL is add for the one recorded shape that is a URL rather than a path.
//
// origin is supplied per call rather than taken from the collector, because the workspace
// lister walks several forks and each contributes its own provenance.
func (c *projectCollector) addFileURL(recorded string, origin originCode) {
	saved := c.origin
	c.origin = origin
	c.contain(recorded, true, claudeApproval{Known: true}, true, true, false)
	c.origin = saved
}

func (c *projectCollector) contain(recorded string, allowFileURL bool,
	approval claudeApproval, trustKnown, trusted, trustDialogAccepted bool) {
	rel, err := fsscan.ContainProjectPath(c.home, recorded, allowFileURL)
	if err != nil {
		switch fsscan.ClassifyError(err) {
		case fsscan.ClassNotContained:
			c.outside++
		case fsscan.ClassUnsupportedOrigin:
			c.remote++
		default:
			c.malformed++
		}
		return
	}
	if existing, seen := c.index[rel]; seen {
		// Merged rather than replaced, and every field that carries evidence merges. Claude's
		// list is the only one bearing approvals and Codex's the only one bearing trust, so
		// keeping whichever sighting came first discarded one of them -- which is how the
		// provenance fields ended up unread and the probe list ended up a cross-product.
		c.refs[existing].Origins[c.origin] = struct{}{}
		// Unions, and certainty is conjunctive: one unreadable sighting makes the approving
		// answers unknown even if another sighting was clean, because the unreadable one
		// may have held a decision that contradicts it. A rejection that *was* read
		// survives regardless, which merge preserves.
		c.refs[existing].Approval = c.refs[existing].Approval.merge(approval)
		// Accepted anywhere is accepted: only Claude's list reports it, so a sighting from
		// another lister has nothing to contribute and must not clear it.
		c.refs[existing].TrustDialogAccepted = c.refs[existing].TrustDialogAccepted ||
			trustDialogAccepted
		if c.origin == originCodexTOML {
			c.refs[existing].TrustKnown = trustKnown
			c.refs[existing].Trusted = trusted
		}
		return
	}
	if len(c.refs) >= maxProjects {
		c.overCap = true
		return
	}
	c.index[rel] = len(c.refs)
	c.refs = append(c.refs, projectRef{
		Rel: rel, Abs: filepath.Join(c.home, rel),
		Origins:             map[originCode]struct{}{c.origin: {}},
		Approval:            approval,
		TrustKnown:          trustKnown,
		Trusted:             trusted,
		TrustDialogAccepted: trustDialogAccepted,
	})
}

// result returns the contained projects and the aggregated refusals.
//
// A deleted project is silent, and that is the maintainer's instruction rather than an
// oversight. It is also the common case by a wide margin: three of this machine's thirty
// recorded Claude projects no longer exist, because a project list is a history of what was
// opened and nobody prunes it. One row per deleted directory would be the majority of this
// table's output on any long-lived workstation. Absence is detected by the probe read
// returning ENOENT, which fsscan.IsExpectedAbsent already swallows, so no code is needed to
// make it silent -- only the decision not to add one.
func (c *projectCollector) result() ([]projectRef, []warning) {
	var warnings []warning
	if c.outside > 0 {
		warnings = append(warnings, warning{Code: warnProjectOutsideHome, Count: c.outside})
	}
	if c.remote > 0 {
		warnings = append(warnings, warning{Code: warnProjectRemoteOrigin, Count: c.remote})
	}
	if c.malformed > 0 {
		warnings = append(warnings, warning{Code: warnProjectMalformed, Count: c.malformed})
	}
	if c.overCap {
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

// claudeJSONMaxSize is the per-source cap for ~/.claude.json alone.
//
// MaxFileSize became load-bearing with this change, and raising it for one file is the
// narrowest available answer. Before, an oversized ~/.claude.json cost that account its
// claude_code rows. Now it also costs every project-local configuration for the account and
// the whole of the approval state, because the project list IS that file -- so one file's size
// decides whether an account has a project inventory at all.
//
// And the size is driven by something no operator can reason about. Measured on this machine:
// ~/.claude.json is 94,827 bytes, of which 43% is `cachedGrowthBookFeatures` -- the client's
// own feature-flag cache, which has nothing to do with configuration and grows on its own
// schedule.
//
// The cost of this number is real and worth stating: json.Unmarshal of a 4 MiB document
// allocates several times that, per account, per query, against the osquery watchdog. 4 MiB
// is roughly forty times the real file here, which leaves room for years of that cache
// without leaving room for an unbounded read.
//
// The structural fix is to stream the file with json.Decoder.Token(), skipping the values of
// every top-level key other than mcpServers and projects, and bounding on streamed bytes
// rather than on file size. Not done here, because it replaces the extractor rather than
// adjusting a constant.
const claudeJSONMaxSize = 4 << 20 // 4 MiB

// stripBOM removes a UTF-8 byte-order mark.
//
// Shared by the parse path and the project listers because both consume the same bytes and
// only one of them used to strip it: Go's encoding/json rejects a BOM outright, so a
// ~/.claude.json written by a Windows editor parsed for neither purpose, and the project
// list failed silently while the server list at least produced a warning row.
func stripBOM(data []byte) []byte {
	return bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
}

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
