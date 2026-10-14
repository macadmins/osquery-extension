package mcp_servers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/macadmins/osquery-extension/pkg/utils"
)

// MaxFileSize is the upper bound we'll read from any candidate JSON file. Anything larger is
// skipped with a diagnostic (fsscan reports "file exceeds N byte cap", which finishProcessing
// turns into a warning row), so an oversized config costs an account its inventory but never
// costs it silently.
//
// MCP configs proper are tiny. The one file that can outgrow this is ~/.claude.json, which is
// not only configuration: Claude Code keeps per-project state in it, and on a long-lived
// workstation that accumulates. Raising the cap trades a bounded read for a larger one on a
// path that runs per account per query, so the bound stays and the warning is the contract.
const MaxFileSize = 1 << 20 // 1 MiB

// Server is the normalized record emitted by the discovery pipeline.
type Server struct {
	User string
	// UserID is the identity the operating system records for the account, as opposed to
	// the label a person sees: the SID on Windows, the uid on POSIX.
	//
	// Carried because `user` is not a join key on Windows. A local `alice` and a domain
	// `alice` produce the same string, so a query correlating this table against osquery's
	// users table on name alone can match the wrong account. It is empty where the roster
	// could not supply one, which is itself information: it means the account could not be
	// identified, not that it has no identity.
	UserID         string
	SourcePath     string
	SourceContext  string // e.g., "mcpServers", "projects[/abs/path].mcpServers"
	Client         string
	ServerName     string
	Transport      string // stdio|http|sse|unknown
	Command        string
	Args           []string
	URL            string
	EnvKeys        []string
	PackageManager string
	PackageName    string
	RequestedSpec  string

	// PinnedVersion is the version this configuration pins, which is never the version
	// installed.
	//
	// Renamed from `version` because the old name invited exactly the wrong reading. A row
	// saying `version = 1.2.3` looks like a statement about what is running; what the file
	// said was `@1.2.3`, and `npx` will happily resolve that to something else, while
	// `@latest` or no version at all means the pin is absent rather than the version being
	// unknown. An operator correlating this against a vulnerability feed needs to know
	// which of the two they have.
	PinnedVersion string

	Confidence string // low|medium|high
	Disabled   bool

	// Approval says whether a declared server is actually live, for the clients that have
	// an approval step. See approvalState.
	Approval approvalState

	// ScanComplete records that every server declared in this row's source was listed, and
	// that the enumeration which found that source ran to completion.
	//
	// False by default, and set true only on the success path. That direction is
	// deliberate: a row whose completeness nobody established reads as incomplete, which is
	// the conservative answer. The opposite spelling -- an Incomplete flag defaulting to
	// "fine" -- makes every future code path complete until someone remembers to say
	// otherwise, and forgetting is how the gap this column closes was created.
	ScanComplete bool

	// Warning is a finding rather than a sentence. See warnings.go: the column it feeds
	// must be assembled only from bytes this package chose, and a string field is what let
	// error text carry a user's secret into it.
	Warning warning

	// Home is the account's home directory, carried so the row builder can validate the
	// columns that are only meaningful relative to it: source_path's containment assertion
	// and source_context's project path. Not emitted -- it is already the prefix of
	// source_path, and a column repeating it would be noise.
	Home string

	// rawName is the server name exactly as the configuration file spelled it.
	//
	// Unexported and never emitted: serverToRow publishes ServerName, which is the redacted
	// form. This exists because two things have to compare and order names *before* the
	// published form exists, and doing them on the redacted form was wrong in two ways that
	// a reader would not guess.
	//
	// Approval matching compares against the name arrays Claude records, which hold original
	// names -- so a legitimately-named server whose name happens to match a token shape
	// became "[REDACTED]", matched nothing in its own approval list, and was reported
	// not_approved though the user had approved it.
	//
	// Placeholder ordering sorts the unpublishable names to assign stable ordinals. Two
	// distinct token-shaped names both redact to exactly "[REDACTED]", so the sort compared
	// equal strings and inherited Go's randomised map order: across repeated parses of
	// identical bytes the same server alternated between `[redacted:...]` and
	// `[redacted:...]#2`, which differential logging reports as churn on a configuration
	// nobody touched. Redaction is many-to-one, so it can never be an identity key.
	rawName string

	// rawContext is the source_context exactly as discovery built it, before redaction.
	//
	// Kept for the same reason rawName is, and it is the same mistake one layer out: the
	// published SourceContext was used as the placeholder tie-break, and redaction is
	// many-to-one, so two ~/.claude.json project sections whose paths differ only in a
	// `--token=` value collapse to one string. The sort then compared equal keys and
	// sort.SliceStable preserved whatever map iteration had produced, so the two servers
	// swapped their ordinals between runs over unchanged bytes. Never published.
	rawContext string

	// PlaceholderSource and PlaceholderIndex name an unrepresentable server by position.
	//
	// Assigned during discovery rather than at row build, because the index requires seeing
	// the other names from the same file: a placeholder gets `#2` only when one file yields
	// more than one unrepresentable name, and the row builder sees one row at a time.
	// Ordered by raw name, so the assignment is stable across runs over an unchanged file.
	PlaceholderSource string
	PlaceholderIndex  int
}

// diagnosticRow builds a row that reports a problem rather than a server.
//
// Every diagnostic goes through here so none can be built by hand and miss the identity
// columns' contract. transport is documented as stdio|http|sse|unknown and confidence as
// low|medium|high, and these rows are created outside inferIdentity, so they were leaving both
// empty. An empty value is in neither documented set: `WHERE transport = 'unknown'` did not
// match them, and neither did `WHERE confidence IN ('high','medium','low')`, so the rows whose
// whole purpose is to be noticed were invisible to any query that constrained those columns.
func diagnosticRow(user, sourcePath, client string, w warning) Server {
	return Server{
		User:       user,
		SourcePath: sourcePath,
		Client:     client,
		Transport:  "unknown",
		Confidence: "low",
		// Never complete. A diagnostic row is the report that something was not listed, so
		// claiming it as a complete listing of anything would invert its purpose -- and
		// `WHERE scan_complete = 1` is meant to select the rows an operator can trust.
		ScanComplete: false,
		Approval:     approvalNotApplicable,
		Warning:      w,
	}
}

// probe describes a config file at a known path relative to some base.
//
// One struct for both pathways, with the base supplied at call time. A file is either named
// in one of the probe lists or it is not found, so there is no second table of recognised
// basenames to keep in agreement with this one. TestProjectSourcesCoverEveryClient asserts
// the project-rooted list covers every client that can own a project-local config.
type probe struct {
	// relPath is relative to whichever base the caller supplies: the home for the
	// home-rooted set, a contained project directory for the project-rooted one.
	relPath string
	client  string
	jsonc   bool

	// maxSize is this source's own cap, or 0 for MaxFileSize.
	//
	// Per source because one file needs a different answer from the rest, and a single
	// global constant made that file's cap decide things it should not. See
	// claudeJSONMaxSize. The largest real config of any other kind on this machine is
	// 14 KB, so the default is three orders of magnitude of headroom already.
	maxSize int64

	extract func(data []byte) ([]Server, error)
}

// readOpts is the cap and the refusals this probe reads under.
//
// RefuseHardLinks is on for every source here, which is affordable because these are a
// couple of dozen named configuration files per home. A second link to one is unexpected:
// macOS has no protected_hardlinks, so a user can link another account's config into their
// own home and have root read it and report it under theirs. The refusal is reported rather
// than silent, so a host where a dotfile manager legitimately hard-links configs says so
// rather than quietly returning fewer rows -- see warnProjectRefused and the table README.
func (p probe) readOpts() fsscan.ReadOpts {
	return probeReadOpts(p.cap())
}

// cap is this probe's effective size limit.
//
// Named so the probe and the oversize diagnostic read the same number. The diagnostic used to
// reconstruct it from the client name, which was wrong for every Claude source except
// ~/.claude.json: a 1.5 MiB project .mcp.json was reported as exceeding a 4 MiB limit, which
// is impossible and sends an administrator after the wrong remedy.
func (p probe) cap() int64 {
	if p.maxSize == 0 {
		return MaxFileSize
	}
	return p.maxSize
}

// probeReadOpts is the one place the read refusals are chosen, so a new read site cannot
// quietly opt out of them.
func probeReadOpts(maxSize int64) fsscan.ReadOpts {
	// OwnerUID is deliberately not set. It reads correctly on POSIX and cannot be
	// implemented on Windows without GetSecurityInfo and SID plumbing that no CI job would
	// ever execute -- and fsscan refuses rather than passes when asked for a check it
	// cannot perform, so setting it here would return zero rows on that platform. Enabling
	// it wants the Windows implementation, which wants a Windows CI job first.
	return fsscan.ReadOpts{MaxSize: maxSize, RefuseHardLinks: true}
}

// homeProbes lists every config found at a deterministic path relative to a user's home.
var homeProbes = buildHomeProbes()

// projectProbes lists every config found at a deterministic path inside a project directory.
//
// This replaces the walk entirely. Each is probed once per recorded project, which bounds the
// work at (projects x 4) component-wise opens instead of at the size of the user's disk --
// and makes the result a function of the project lists rather than of how far a shared budget
// happened to get.
//
// Four entries, one per client that keeps project-scoped MCP configuration.
// TestProjectSourcesCoverEveryClient pins that against the client set, because the previous
// design's characteristic failure was a file that one table knew about and the other did not.
// projectProbeFor indexes the project-rooted probes by their relative path, because the
// per-project probe list is now derived from which clients recorded the project rather than
// being the whole table.
var projectProbeFor = buildProjectProbeIndex()

func buildProjectProbeIndex() map[string]probe {
	out := make(map[string]probe, len(projectProbes))
	for _, src := range projectProbes {
		out[src.relPath] = src
	}
	return out
}

var projectProbes = []probe{
	// The project-local convention Claude Code popularised. Servers declared here are inert
	// until the user approves them, which is what approval_state reports.
	{relPath: ".mcp.json", client: "claude_code", jsonc: true, extract: extractEnvelopeSimple},
	{relPath: filepath.Join(".vscode", "mcp.json"), client: "vscode", jsonc: true,
		extract: extractEnvelopeSimple},
	{relPath: filepath.Join(".cursor", "mcp.json"), client: "cursor", jsonc: true,
		extract: extractEnvelopeSimple},
	// TOML, so jsonc is false and the extractor is the TOML one.
	{relPath: filepath.Join(".codex", "config.toml"), client: "codex", jsonc: false,
		extract: extractCodexTOML},
}

// buildHomeProbes concatenates the hand-written sources with the generated VS Code family
// ones.
//
// Written as an explicit copy rather than append(handWrittenHomeProbes, generated...).
// That form is correct only because a composite literal has len == cap so append must
// reallocate; if anyone ever gave handWrittenHomeProbes spare capacity, the append would
// write into its backing array and the two package variables would alias. Not a bug today
// and not worth leaving as one to discover later.
func buildHomeProbes() []probe {
	generated := vscodeFamilySources()
	out := make([]probe, 0, len(handWrittenHomeProbes)+len(generated))
	out = append(out, handWrittenHomeProbes...)
	out = append(out, generated...)
	return out
}

var handWrittenHomeProbes = []probe{
	{
		relPath: appSupport("Claude", "claude_desktop_config.json"),
		client:  "claude_desktop",
		jsonc:   true,
		extract: extractEnvelopeSimple,
	},
	{
		// The one source with a cap of its own, because it is also the project list for
		// this account. See claudeJSONMaxSize.
		relPath: claudeProjectsRelPath,
		client:  "claude_code",
		jsonc:   false,
		maxSize: claudeJSONMaxSize,
		extract: extractClaudeCode,
	},
	{
		relPath: ".cursor/mcp.json",
		client:  "cursor",
		jsonc:   true,
		extract: extractEnvelopeSimple,
	},
	{
		relPath: ".codeium/windsurf/mcp_config.json",
		client:  "windsurf",
		jsonc:   true,
		extract: extractEnvelopeSimple,
	},
	{
		relPath: ".gemini/settings.json",
		client:  "gemini",
		jsonc:   true,
		extract: extractGeminiSettings,
	},
	// VS Code's own user-scope MCP config, one per fork. Documented by Microsoft as the
	// user-profile counterpart to a workspace's .vscode/mcp.json, reached in the UI through
	// "MCP: Open User Configuration". It uses `servers` rather than `mcpServers`, which
	// extractEnvelope already accepts.
	// Copilot's portable config, which Microsoft documents as shared across the Agent Host
	// and other Copilot tools. Note the hyphen, which is why it needs its own entry.
	{relPath: ".copilot/mcp-config.json", client: "copilot", jsonc: true, extract: extractEnvelopeSimple},
	// Codex's actual configuration. TOML, not JSON, so jsonc is false and the extractor is a
	// TOML one: the probe abstraction only ever promised bytes in and Servers out, so a
	// second format needed no change to it.
	{relPath: codexProjectsRelPath, client: "codex", jsonc: false, extract: extractCodexTOML},
	// Codex's older JSON config, which current builds do not write but installs upgraded
	// from an older one still carry.
	//
	// This was reachable only through the walk, via a path-to-client classification case.
	// Dropping it with the walk would have lost the file silently, and there is no reason
	// to: it is a fixed path, so it costs one open per home and needs none of the
	// machinery the walk did. The same is true of ~/.codex/.mcp.json, which the deleted
	// classifier also recognised.
	{relPath: filepath.Join(".codex", "mcp.json"), client: "codex", jsonc: true,
		extract: extractEnvelopeSimple},
	{relPath: filepath.Join(".codex", ".mcp.json"), client: "codex", jsonc: true,
		extract: extractEnvelopeSimple},
}

// DiscoverAll iterates each user home under fsscan.UsersRoot and returns every normalized
// MCP server record found. userFilter, if non-empty, restricts the scan to those usernames.
//
// The walk budget is shared across every home rather than granted per home. fsscan.WalkTimeout
// is sized against osquery's watchdog on the assumption that one query costs one budget; giving
// each home its own turns that into homes x budget, and a shared Mac with a handful of accounts
// then walks for minutes and gets the whole extension killed, dropping every other table's rows
// along with ours.
//
// ctx is the context osquery handed Generate, so a cancelled query stops the walk. It is used
// for cancellation only: the budget is passed to each scan as a duration, because fsscan
// classifies a deadline it set itself as a truncation and a deadline on the caller's context as
// a cancellation, and exhausting our own budget is the former.
func DiscoverAll(ctx context.Context, clienter utils.OsqueryClienter, userFilter map[string]struct{}) []Server {
	if ctx == nil {
		ctx = context.Background()
	}
	// The account roster comes from osquery. There is no filesystem fallback: the socket is
	// how this extension returns rows at all, so if it cannot be reached osquery is not
	// receiving results either, and a guessed roster would only make that quieter.
	client, err := clienter.NewOsqueryClient()
	if err != nil {
		return rosterDiagnostic(userFilter, fsscan.UsersRoot,
			warning{Code: warnRosterUnreachable})
	}
	// KNOWN GAP: this Close is correct and currently
	// does nothing. The pinned osquery-go revision opens a transport in NewClient and never
	// assigns it to the struct, so Close finds a nil transport and returns. The socket is
	// left to the garbage collector, and this table opens one per query. Written anyway
	// because the call site is right and only the dependency is wrong; fixing it is an
	// osquery-go bump, which is a repository-wide change.
	defer client.Close()
	// Established before the roster is read, not after. The roster is now a query back to
	// osquery rather than a filesystem walk, so it is fast, but it is still work the budget
	// should cover: a deadline created afterwards excludes whatever the roster cost.
	deadline := time.Now().Add(fsscan.WalkTimeout())
	// The filter goes to the roster rather than being applied to its answer. Narrowing after
	// the fact still Lstat'd every home on the host, so one dead automount belonging to an
	// account nobody asked about could consume the budget of a query scoped to a single
	// local user.
	enumerated, err := fsscan.ListUserHomes(client, userFilter)
	if err != nil {
		// The roster itself is unreadable, so no account can be confirmed or ruled out.
		//
		// A single aggregate row with an empty user was dropped by `WHERE user = '<name>'`,
		// handing a constrained query a clean empty result for the one failure that can say
		// nothing about any account whatsoever -- the same confusion the per-account rows
		// below exist to prevent, on a wider blast radius. A narrowed query therefore gets
		// the diagnostic repeated under each name it asked about.
		//
		// An unconstrained query keeps the single aggregate row: there is no roster to
		// enumerate names from, so inventing them is not an option, and an empty user is
		// the honest answer to "which accounts" when that is precisely what failed.
		return rosterDiagnostic(userFilter, fsscan.UsersRoot,
			warning{Code: warnRosterQueryFailed})
	}
	var out []Server
	// The roster itself came back short, so there is no list of who is missing -- which is
	// exactly why this cannot be a single empty-user row. SQLite applies `WHERE user =
	// 'alice'` to whatever the generator returns, so an empty-user warning is discarded by
	// the one query most likely to be asked, and Alice being past the profile cap or served
	// only by LDAP produces the clean empty result the warning exists to prevent.
	// Whether anything was emitted that says the roster itself may be incomplete. The
	// missing-name diagnostic below points at such a row, and pointing at one that was
	// never emitted told an operator to go read a warning that does not exist.
	//
	// Only the nameless-account branch sets this now. The Linux local-accounts note used to
	// as well, on every single run, which made every Linux host permanently "uncertain" and
	// the flag meaningless there; that note is documentation rather than a row. See
	// fsscan/users.go.
	rosterUncertain := false
	scanned := make(map[string][]Server, len(enumerated.Homes))
	// Which of the requested names the roster could say something about, so the ones it
	// could not are answered explicitly below. Only built for a constrained query: an
	// unconstrained one asked about nobody in particular and has nothing to miss.
	var answered map[string]struct{}
	if userFilter != nil {
		answered = make(map[string]struct{}, len(userFilter))
	}
	// One row per skipped account, carrying that account's own name, identity and the path
	// the roster claimed for it.
	//
	// An aggregate row with an empty user was filtered out by `WHERE user = '<name>'`, so if
	// the account asked about was the skipped one the caller saw a clean empty result. The
	// userFilter is applied here too, so a narrowed query still gets the diagnostic that
	// concerns it and not the others.
	//
	// The path comes from the omission rather than being synthesised as <UsersRoot>/<name>.
	// A Windows profile can live on another volume or a redirected path, and reporting a
	// constructed path that does not exist sent an administrator looking in the wrong place.
	unusableHomes := 0
	for _, omission := range enumerated.Skipped {
		// An account whose home does not exist is worth a row only when someone asked
		// about it. Unconstrained, these are mostly service accounts that never had a home
		// created, and one row each buries the omissions that matter; they are counted and
		// reported together below instead.
		if omission.HomeUnusable && userFilter == nil {
			unusableHomes++
			continue
		}
		path := omission.Path
		if path == "" {
			path = fsscan.UsersRoot
		}
		// An omission with no resolvable name cannot be matched against a requested user,
		// and emitting it under an empty user hands a constrained query a row SQLite then
		// discards. It is not nothing, though: it means the roster cannot say whether the
		// account being asked about was covered, so it is reported as roster-level
		// uncertainty under each name the query named.
		if omission.Name == "" {
			out = append(out, rosterDiagnostic(userFilter, path,
				warning{Code: warnRosterAccountUnnamed})...)
			rosterUncertain = true
			continue
		}
		if userFilter != nil {
			if _, ok := userFilter[omission.Name]; !ok {
				continue
			}
		}
		row := diagnosticRow(omission.Name, path, "", omissionWarning(omission.Code))
		row.UserID = omission.ID
		out = append(out, row)
		if answered != nil {
			answered[omission.Name] = struct{}{}
		}
	}
	if unusableHomes > 0 {
		out = append(out, diagnosticRow("", fsscan.UsersRoot, "",
			warning{Code: warnAccountsHomeUnusable, Count: unusableHomes}))
	}
	for _, h := range enumerated.Homes {
		if userFilter != nil {
			if _, ok := userFilter[h.Name]; !ok {
				continue
			}
		}
		// Marked before the two branches below, not after. Both of them report on this
		// account -- cancelled, or out of budget -- so an account that reached either one
		// has been answered; counting it as unaccounted for would add a second row saying
		// no such account exists.
		if answered != nil {
			answered[h.Name] = struct{}{}
		}
		// Checked per home, before Pass 1 runs. Direct-path reads take no context, so without
		// this a cancelled query still performed ten opens per home for every home on the box.
		if ctx.Err() != nil {
			out = append(out, stampUserID([]Server{diagnosticRow(h.Name, h.Path, "",
				warning{Code: warnCancelledPreHome})}, h.ID)...)
			continue
		}
		// Scanned once per directory, reported once per account. Accounts legitimately
		// share a home, and the roster now keeps every one of them so a constrained query
		// cannot lose an account another had claimed -- which means the duplicate work has
		// to be avoided here instead, after the filter, rather than by discarding accounts
		// before it.
		//
		// Looked up before the budget is consulted, not after. The budget question is
		// whether there is time to do *new* filesystem work, and restamping a result
		// already in hand is none: two accounts sharing a home, where the first one's scan
		// spent the last of the allowance, had the second told "walk budget exhausted
		// before this user was scanned" about a home that had just been scanned in full.
		// The statement was false and it cost the account every row the cache was holding
		// for it.
		key := scanKey(h)
		rows, cached := scanned[key]
		if !cached {
			if time.Until(deadline) <= 0 {
				// Say so per user rather than stopping quietly. A user who was never
				// scanned and a user with no MCP configuration are otherwise the same
				// empty answer, which is the confusion the truncation contract exists to
				// prevent.
				out = append(out, stampUserID([]Server{diagnosticRow(h.Name, h.Path, "",
					warning{Code: warnBudgetExhaustedPreHome})}, h.ID)...)
				continue
			}
			rows = discoverForHome(ctx, h, deadline)
			scanned[key] = rows
		}
		out = append(out, stampUserID(copyRowsFor(rows, h.Name), h.ID)...)
	}
	// A rostered account that cannot log in. Skipped on purpose -- it keeps no editor or
	// agent configuration -- and silent unless someone asked for it by name, because a host
	// carries dozens of them and a row each would bury the omissions that matter. Asked for
	// by name it gets a real answer, which is the whole point of separating these from the
	// names the roster never mentioned: "daemon cannot log in" and "there is no daemon" are
	// different facts and only one of them is true.
	if userFilter != nil {
		for _, omission := range enumerated.NonLogin {
			if _, ok := userFilter[omission.Name]; !ok {
				continue
			}
			path := omission.Path
			if path == "" {
				path = fsscan.UsersRoot
			}
			row := diagnosticRow(omission.Name, path, "", omissionWarning(omission.Code))
			row.UserID = omission.ID
			out = append(out, row)
			if answered != nil {
				answered[omission.Name] = struct{}{}
			}
		}
	}
	// A name the roster never mentioned at all. Returning nothing for it is the one answer
	// this table refuses to give: `WHERE user = 'bob'` coming back empty reads as "bob has
	// no MCP servers", when what happened is that osquery's users table has no bob -- a
	// typo, a deleted account, or an account the roster does not enumerate. Every other
	// branch in this function exists to stop exactly that confusion; the requested name
	// nobody accounted for was the one path still taking it.
	for _, name := range unanswered(userFilter, answered) {
		// Whether the roster questioned itself is carried as a count rather than as a
		// second sentence. With no roster-level warning emitted the roster answered in
		// full and the name is genuinely absent; with one emitted, the name may simply be
		// behind it, and the companion row alongside this one says which. Reporting the
		// distinction as prose meant two near-identical paragraphs differing in a clause,
		// and the catalogue admits one sentence per code.
		row := diagnosticRow(name, fsscan.UsersRoot, "", warning{Code: warnAccountNotInRoster})
		if rosterUncertain {
			row.Warning.Count = 1
		}
		out = append(out, row)
	}
	return out
}

// omissionWarning maps the roster's reason for skipping an account onto this table's
// catalogue.
//
// A mapping rather than a passthrough of fsscan's own sentence, and the reason is the whole
// point of the catalogue: that sentence interpolates the account's shell, read out of the
// local account database. It is almost certainly harmless and it is not a byte this package
// chose, so it has no business in a column whose contract is that every byte is. fsscan
// carries a code alongside the sentence for exactly this.
func omissionWarning(code fsscan.OmissionReason) warning {
	switch code {
	case fsscan.OmittedNoUsername:
		return warning{Code: warnRosterAccountUnnamed}
	case fsscan.OmittedNonLoginShell:
		return warning{Code: warnAccountNonLogin}
	case fsscan.OmittedNoHomeDeclared:
		return warning{Code: warnAccountNoHome}
	case fsscan.OmittedHomeMissing:
		return warning{Code: warnAccountHomeMissing}
	case fsscan.OmittedHomeUnstattable:
		return warning{Code: warnAccountHomeUnstattable}
	case fsscan.OmittedHomeRedirected:
		return warning{Code: warnAccountHomeRedirected}
	case fsscan.OmittedHomeNotDirectory:
		return warning{Code: warnAccountHomeNotDirectory}
	default:
		// A reason this build has no code for. Reported as the generic inability to inspect
		// the home rather than dropped, because the account still went uninspected and
		// that is the fact the row exists to carry.
		return warning{Code: warnAccountHomeUnstattable}
	}
}

// unanswered returns the requested usernames no home and no omission accounted for, sorted
// because map iteration is random and these rows go straight to osquery.
func unanswered(userFilter, answered map[string]struct{}) []string {
	var names []string
	for name := range userFilter {
		if _, ok := answered[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// stampUserID attaches the account's stable identity to every row discovered for it,
// including the diagnostic rows, so a correlation query does not lose the identity precisely
// on the rows describing what went wrong.
func stampUserID(rows []Server, id string) []Server {
	if id == "" {
		return rows
	}
	for i := range rows {
		rows[i].UserID = id
	}
	return rows
}

// roamingRootFor reports the account's roaming application-data directory and, when the
// answer is not the conventional one, a diagnostic describing why.
//
// Three outcomes matter and only two of them are "fine". A confirmed default needs no
// comment. A confirmed redirection inside the profile is followed silently, because the
// configuration is still found. A redirection out of the profile, or an answer that could
// not be read at all, means this account's application-support configuration is not being
// inspected, and saying nothing there is the failure mode being fixed.
func roamingRootFor(account fsscan.UserHome) (root string, note warning) {
	if runtime.GOOS != "windows" {
		return "", warning{}
	}
	resolved, redirected, ok := fsscan.RoamingAppDataFor(account.ID, account.Path)
	if !ok {
		return "", warning{Code: warnAppDataUndetermined}
	}
	if !redirected {
		return "", warning{}
	}
	if !withinHome(resolved, account.Path) {
		// The redirected path is deliberately not reported. It was, through redact.Path,
		// and that is a path read out of another account's registry hive -- so it is a
		// value this package did not choose, in a column whose contract is that every byte
		// is one it did. The fact an operator needs is that the location is outside the
		// profile and was not inspected; the path itself is in the hive they would go and
		// read anyway.
		return resolved, warning{Code: warnAppDataRedirectedOut}
	}
	return resolved, warning{}
}

// withinHome reports whether an absolute path lies beneath home. Redirection inside the
// profile is still reachable by the ordinary bounded, symlink-refusing traversal; redirection
// outside it is not, because that traversal is anchored to the home on purpose.
func withinHome(path, home string) bool {
	rel, err := filepath.Rel(home, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// redirectAppSupport rewrites an application-support-relative path to sit under a redirected
// roaming root. It reports usable=false when the source cannot be reached at all, which is
// the out-of-profile case the caller has already warned about.
func redirectAppSupport(relPath, appDataRoot, home string) (rewritten string, usable bool) {
	if appDataRoot == "" {
		return "", true // conventional location; relPath already correct
	}
	prefix := appSupportDir() + string(os.PathSeparator)
	if !strings.HasPrefix(relPath, prefix) {
		return "", true // a dotfile source, unaffected by where AppData points
	}
	if !withinHome(appDataRoot, home) {
		return "", false
	}
	rel, err := filepath.Rel(home, appDataRoot)
	if err != nil {
		return "", false
	}
	return filepath.Join(rel, strings.TrimPrefix(relPath, prefix)), true
}

// scanKey names everything discovery depends on, so a cached result is only reused where it
// would genuinely have been identical.
//
// The home path alone is wrong on Windows. discoverForHome resolves Roaming AppData from the
// registry hive named by the account's SID, so two accounts reporting the same profile path
// can have different roaming roots, different warnings and different rows. Keyed on path
// alone, the first account scanned decided the answer for the rest and copyRowsFor merely
// relabelled it -- attributing one account's redirected AppData, or its "could not be
// determined" warning, to another.
//
// Elsewhere discovery is a pure function of the directory, so the path is the whole key and
// a shared home is scanned once.
func scanKey(account fsscan.UserHome) string {
	return scanKeyFor(runtime.GOOS, account)
}

// scanKeyFor takes the OS as a parameter so both branches are reachable from a test on any
// host. The Windows branch is the one that matters and the one no test here can otherwise
// execute, which is exactly how it went wrong in the first place.
func scanKeyFor(goos string, account fsscan.UserHome) string {
	if goos == "windows" {
		return account.ID + "\x00" + account.Path
	}
	return account.Path
}

// copyRowsFor re-stamps a cached scan for another account sharing the same home.
//
// Copied rather than returned directly: the cached slice is reused for every account naming
// that directory, and stamping the user onto the shared backing array would rewrite the
// rows already emitted for the previous one.
func copyRowsFor(rows []Server, user string) []Server {
	out := make([]Server, len(rows))
	copy(out, rows)
	for i := range out {
		out[i].User = user
	}
	return out
}

// rosterDiagnostic renders a finding that cannot be attributed to one named account.
//
// An unconstrained query gets a single row with an empty user, which is the honest answer.
// A constrained one gets the same warning repeated under every name it asked about, because
// osquery applies the WHERE clause to the rows this generator returns: an empty-user row is
// filtered out after the fact, so the query that asks about exactly the account the roster
// could not vouch for is the one guaranteed not to hear about it.
func rosterDiagnostic(userFilter map[string]struct{}, path string, w warning) []Server {
	if userFilter == nil {
		return []Server{diagnosticRow("", path, "", w)}
	}
	requested := make([]string, 0, len(userFilter))
	for name := range userFilter {
		requested = append(requested, name)
	}
	// Map iteration order is random and these rows go straight to osquery.
	sort.Strings(requested)
	rows := make([]Server, 0, len(requested))
	for _, name := range requested {
		rows = append(rows, diagnosticRow(name, path, "", w))
	}
	return rows
}

// deadline is absolute rather than a remaining duration. A duration is re-based on arrival,
// so everything this function does before re-basing it -- the home open below, which on a
// network-backed or automounted home can block for the mount timeout -- fell outside the
// budget and the home then received the whole of it again. One home overshooting the
// query-wide deadline by its own open time is small; every home doing it is not.
//
// Five passes, all of them bounded by a count rather than by a tree:
//
//  1. Home-rooted probes: a fixed list of paths relative to the home.
//  2. Profile enumeration: one directory read per VS Code fork, for the generated profile
//     names a fixed path cannot express, plus Codex's named-profile configs.
//  3. Installed Claude Code plugins, each of which may ship its own .mcp.json. Enablement
//     comes from settings and is reported rather than filtered on.
//  4. Project lists: read the projects each client records, and contain each recorded path.
//  5. Project-rooted probes: four known filenames inside each contained project.
//
// What this replaces was a filesystem walk of ~22 roots per home to depth 6. The passes
// above touch a number of paths that is a function of how many projects the user has opened,
// which is a number in a file, so two runs over an unchanged host do the same work and
// return the same rows. The walk's answer depended on how much of a shared budget earlier
// homes had left.
func discoverForHome(ctx context.Context, account fsscan.UserHome, deadline time.Time) []Server {
	user, home := account.Name, account.Path

	// One row when the home itself cannot be opened, rather than one per candidate inside
	// it. Every probe under an unreadable home fails identically, so without this an
	// ordinary unprivileged run produced sixteen rows all saying "permission denied" on the
	// same directory, plus a truncation summary -- seventeen ways of being told one thing.
	// The information an operator needs is that this account was not inspected.
	if handle, err := os.Open(home); err != nil {
		row := diagnosticRow(user, home, "", warning{
			Code: warnHomeUnreadable, Class: fsscan.ClassifyError(err)})
		row.Home = home
		return []Server{row}
	} else {
		_ = handle.Close()
	}

	// Charged against the same deadline the open just ran under. Opening a home on a dead
	// automount can consume most of a budget, and continuing afterwards spends time the
	// query no longer has.
	if time.Until(deadline) <= 0 {
		return []Server{diagnosticRow(user, home, "",
			warning{Code: warnBudgetExhaustedOpening})}
	}

	// Where this account actually keeps roaming application data. On Windows that is a
	// per-user known folder a policy can redirect; everywhere else it is a fixed subpath of
	// the home. An undetermined answer is reported rather than quietly assumed, because
	// assuming the default on a redirected host is how every VS Code, Claude Desktop and
	// Cline config for that account went missing with no warning.
	appData, appDataNote := roamingRootFor(account)
	var out []Server
	if !appDataNote.empty() {
		out = append(out, diagnosticRow(user, home, "", appDataNote))
	}
	seen := make(map[string]struct{})

	// Pass 1: known paths relative to the home.
	//
	// Each lookup goes through fsscan.ReadBoundedUnder, which walks the path
	// component-by-component with O_NOFOLLOW. This blocks the attack where a user replaces
	// an intermediate directory (e.g. ~/Library) with a symlink to harvest another user's
	// files when osqueryd runs as root.
	//
	// The bytes of the two files that are also project lists are kept, so pass 3 does not
	// read them a second time. That matters for ~/.claude.json in particular: it is the one
	// source with a raised cap, and decoding it twice would double the largest allocation
	// this table makes per account per query.
	rows, lists, stoppedEarly := probeHome(ctx, home, user, appData, deadline, seen, homeProbes)
	out = append(out, rows...)

	// One diagnostic covering both ways the budget can run out during a home, emitted here
	// rather than at the break so it cannot be missed on one path.
	//
	// Breaking out of pass 1 was handled; the loop *completing* while the deadline passed
	// during its last read was not. The range simply ended, no break fired, and the guard
	// below then skipped the remaining passes silently -- so a home whose final read was
	// slow, which is exactly the network-backed case this budget exists for, returned
	// partial rows that looked complete.
	if stoppedEarly || time.Until(deadline) <= 0 {
		return stampCompleteness(append(out,
			diagnosticRow(user, home, "", warning{Code: budgetCodeFor(ctx)})), false)
	}

	// Pass 2: the two places a generated name sits between a fixed path and a config file.
	profileRows, profileWarnings := probeGeneratedProfiles(ctx, home, user, appData, deadline, seen)
	out = append(out, profileRows...)
	for _, w := range profileWarnings {
		out = append(out, diagnosticRow(user, home, "", w))
	}

	if ctx.Err() != nil || time.Until(deadline) <= 0 {
		return stampCompleteness(append(out,
			diagnosticRow(user, home, "", warning{Code: budgetCodeFor(ctx)})), false)
	}

	// Pass 3: Claude Code plugins, which declare their own servers.
	//
	// Before the project lists, because a plugin is cheaper to enumerate than a project
	// list is to read and the budget is shared: three small directory listings against one
	// ~/.claude.json of up to 4 MiB. A budget that runs out should lose the expensive thing
	// rather than the cheap one.
	pluginRefs, pluginWarnings, pluginStopped := claudePluginRefs(ctx, home, deadline)
	pluginRows, probeStopped := probePlugins(ctx, home, user, deadline, seen, pluginRefs)
	out = append(out, pluginRows...)
	for _, w := range mergeWarnings(pluginWarnings) {
		out = append(out, diagnosticRow(user, home, "", w))
	}
	if pluginStopped || probeStopped {
		return stampCompleteness(append(out,
			diagnosticRow(user, home, "", warning{Code: budgetCodeFor(ctx)})), false)
	}

	if ctx.Err() != nil || time.Until(deadline) <= 0 {
		return stampCompleteness(append(out,
			diagnosticRow(user, home, "", warning{Code: budgetCodeFor(ctx)})), false)
	}

	// Pass 4: what the clients say the user's projects are.
	//
	// A lister whose file was never read is silent here rather than reporting an unreadable
	// list. Pass 1 already emitted the read failure for that file, and saying it twice --
	// once as "this config could not be read" and once as "this project list could not be
	// read" -- describes one failure as two.
	var projectGroups [][]projectRef
	var projectWarnings []warning
	if lists.claude != nil {
		refs, warnings := claudeProjects(home, lists.claude)
		projectGroups = append(projectGroups, refs)
		projectWarnings = append(projectWarnings, warnings...)
	}
	if lists.codex != nil {
		refs, warnings := codexProjects(home, lists.codex)
		projectGroups = append(projectGroups, refs)
		projectWarnings = append(projectWarnings, warnings...)
	}
	// A list file that exists and could not be read is a home-scope loss, and it is the
	// reason MaxFileSize became load-bearing with this change.
	//
	// Before, an oversized ~/.claude.json cost that account its claude_code rows: one
	// source-scope warning on one file. Now the same failure also costs every project-local
	// configuration for the account and the whole of the approval state, because the project
	// list IS that file. The oversize report on the file itself is still source-scope and
	// still emitted; this is the separate, larger fact, and without it the home would be
	// reported as completely enumerated on the strength of whatever the other probes found.
	//
	// Absence is silent, which is why this is keyed on a failed read rather than on empty
	// bytes: most homes have no Codex installed and most have no Claude Code, and a warning
	// for every account that simply does not use a client would be noise on every host.
	if lists.claudeFailed || lists.codexFailed {
		projectWarnings = append(projectWarnings, warning{Code: warnProjectListUnreadable})
	}
	workspaceRefs, workspaceWarnings, workspaceStopped := vscodeWorkspaceProjects(
		ctx, home, appData, deadline)
	projectGroups = append(projectGroups, workspaceRefs)
	projectWarnings = append(projectWarnings, workspaceWarnings...)

	if workspaceStopped {
		projectWarnings = append(projectWarnings, warning{Code: budgetCodeFor(ctx)})
	}
	projects, truncationWarnings := mergeProjects(projectGroups...)
	projectWarnings = append(projectWarnings, truncationWarnings...)
	// Aggregated across the three listers, so one fact produces one row. Each lister counts
	// its own refusals, and a home with projects outside it recorded by two clients was
	// emitting two rows with partial counts.
	for _, w := range mergeWarnings(projectWarnings) {
		out = append(out, diagnosticRow(user, home, "", w))
	}

	// Pass 5: four known filenames inside each contained project.
	projectRows, projectStopped := probeProjects(ctx, home, user, deadline, seen, projects)
	out = append(out, projectRows...)
	if projectStopped {
		out = append(out, diagnosticRow(user, home, "", warning{Code: budgetCodeFor(ctx)}))
	}

	// scan_complete, decided once for the whole home.
	//
	// Any home-scope finding means the enumeration that found these rows did not finish, so
	// every row for the account is marked incomplete -- including rows from files that were
	// read perfectly well. That is the point of the column: the question is not "was this
	// file parsed" but "is this list of servers the whole list", and a budget that ran out
	// before the project pass makes the answer no regardless of how clean the first pass was.
	return stampCompleteness(out, true)
}

// budgetCodeFor distinguishes the two ways a pass stops short, which mean different things
// to an operator: the query went away, or this host is too slow for the schedule it is on.
func budgetCodeFor(ctx context.Context) warnCode {
	if ctx.Err() != nil {
		return warnCancelledInHome
	}
	return warnBudgetExhaustedInHome
}

// stampCompleteness decides scan_complete for every row from one home.
//
// Called with enumerated=false on the early-return paths and with true at the end, where it
// scans what was emitted for a home-scope finding. Two spellings of the same rule, because
// the early returns know the answer without looking and the final one does not.
//
// Source-scope findings are deliberately not consulted here. Those were already applied by
// finishProcessing to the rows of the file they concern, and widening them to the home would
// mean one malformed project config marked every other server in the account as incomplete
// -- which makes the column useless by making it almost always zero.
func stampCompleteness(rows []Server, enumerated bool) []Server {
	complete := enumerated
	if complete {
		for _, row := range rows {
			if !row.Warning.empty() && row.Warning.Code.scope() == scopeHome {
				complete = false
				break
			}
		}
	}
	if complete {
		return rows
	}
	for i := range rows {
		rows[i].ScanComplete = false
	}
	return rows
}

// projectLists carries the bytes of the two sources that are also project lists, so the
// listers do not read them a second time.
//
// That matters for ~/.claude.json in particular: it is the one source with a raised cap, and
// decoding it twice would double the largest allocation this table makes per account per
// query. The failed flags are separate from nil bytes because the two mean different things
// to the caller -- a client that is not installed is silent, and a list file that exists and
// could not be read costs the home its whole project inventory.
type projectLists struct {
	claude, codex             []byte
	claudeFailed, codexFailed bool
}

// probeHome runs the home-rooted probe list, returning the rows, the captured project lists,
// and whether it stopped short.
func probeHome(ctx context.Context, home, user, appData string, deadline time.Time,
	seen map[string]struct{}, probes []probe) ([]Server, projectLists, bool) {
	var out []Server
	var lists projectLists
	for _, src := range probes {
		// Checked between sources, not just once per home. Each lookup is an open on a path
		// that may be network-backed, and a cancelled query used to keep working through all
		// of them.
		if ctx.Err() != nil || time.Now().After(deadline) {
			return out, lists, true
		}
		// snap keeps its configuration behind a `current` symlink, which the traversal
		// refuses. Resolved to the revision directory here so the read has a real path to
		// walk; a source that does not resolve is simply not installed for this user.
		relPath, resolvable := resolveSnapPath(home, src.relPath)
		if !resolvable {
			continue
		}
		if redirected, usable := redirectAppSupport(relPath, appData, home); !usable {
			continue
		} else if redirected != "" {
			relPath = redirected
		}
		path := filepath.Join(home, relPath)
		if _, dup := seen[path]; dup {
			continue
		}
		// The *resolved* path, not src.relPath. Passing the original meant the read walked
		// back through snap's `current` symlink, was refused, and had the refusal read as
		// expected absence -- so the resolution above changed only the dedup key and the
		// reported source_path while the file itself stayed undiscoverable.
		data, readErr := fsscan.ReadBoundedUnder(home, relPath, src.readOpts())
		// Captured before parsing and after the BOM strip, so the listers see the same bytes
		// the extractor does. Keyed on the original relPath rather than the resolved one:
		// the resolved spelling varies with the snap revision, and matching on it meant the
		// project list was silently never captured on a snap install.
		switch src.relPath {
		case claudeProjectsRelPath:
			lists.claude, lists.claudeFailed = capturedList(data, readErr)
		case codexProjectsRelPath:
			lists.codex, lists.codexFailed = capturedList(data, readErr)
		}
		rows := finishProcessing(home, data, readErr, path, user, src.client, src.jsonc,
			src.cap(), src.extract)
		if rows == nil {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, rows...)
	}
	return out, lists, false
}

// capturedList reports the bytes of a project list and whether reading it failed in a way
// that matters.
//
// Expected absence is neither: a host with no Claude Code installed has no ~/.claude.json,
// which is the common case and says nothing about completeness. Anything else -- oversized,
// permission denied, a refused hard link -- means the list exists and this scan could not
// read it, so the account's project inventory is missing rather than empty.
func capturedList(data []byte, readErr error) ([]byte, bool) {
	if readErr == nil {
		return stripBOM(data), false
	}
	return nil, !fsscan.IsExpectedAbsent(readErr)
}

// probeGeneratedProfiles reaches the two configuration locations whose directory name the
// application generates, so no fixed path can express them.
//
// Both are one bounded directory read, which is the shape the review sanctioned for
// workspaceStorage and is equally correct here: deterministic, no recursion, capped, and
// never inside a cloud-backed directory. Dropping them instead would have lost every
// per-profile VS Code config and every Codex named profile on the host, in silence -- the
// exact failure this table exists to prevent.
func probeGeneratedProfiles(ctx context.Context, home, user, appData string,
	deadline time.Time, seen map[string]struct{}) ([]Server, []warning) {
	var out []Server
	var warnings []warning

	// VS Code family: <appsupport>/<fork>/User/profiles/<generated-id>/mcp.json.
	for _, root := range vscodeProfileDirs() {
		if ctx.Err() != nil || time.Now().After(deadline) {
			return out, warnings
		}
		relPath, resolvable := resolveSnapPath(home, root.relPath)
		if !resolvable {
			continue
		}
		if redirected, usable := redirectAppSupport(relPath, appData, home); !usable {
			continue
		} else if redirected != "" {
			relPath = redirected
		}
		// An absent profiles directory is the common case: most hosts have none of the five
		// forks, and a fork with no secondary profile has no directory either. A listing
		// that is short still yields its names; only a real failure yields none.
		names, truncated, err := listCapped(home, relPath, maxProfileDirs)
		if err != nil {
			warnings = append(warnings, warning{
				Code: warnProfileListUnreadable, Class: fsscan.ClassifyError(err)})
			continue
		}
		if truncated {
			warnings = append(warnings, warning{
				Code: warnProfileListUnreadable, Count: len(names), Limit: maxProfileDirs})
		}
		for _, name := range names {
			// The client is carried from the directory being listed rather than inferred
			// from the path. Inferring it broke whenever Windows Roaming AppData was
			// redirected: the conventional root was no longer in the path, so a Cursor
			// profile config was reported as client=unknown and vanished from the query an
			// administrator would write.
			probes := []probe{{
				relPath: filepath.Join(relPath, name, "mcp.json"),
				client:  root.client, jsonc: true, extract: extractEnvelopeSimple,
			}}
			rows, _, stopped := probeHome(ctx, home, user, "", deadline, seen, probes)
			out = append(out, rows...)
			if stopped {
				return out, warnings
			}
		}
	}

	// Codex named profiles: ~/.codex/<profile>.config.toml, alongside the config.toml a
	// fixed path already covers. isCodexTOMLPath stays as the narrowing, for the reason it
	// was written: `config.toml` is one of the most common basenames on a developer machine,
	// so the `.codex` parent is what makes the match mean anything.
	codexNames, codexTruncated, err := listCapped(home, ".codex", maxProfileDirs)
	if err != nil {
		warnings = append(warnings, warning{
			Code: warnProfileListUnreadable, Class: fsscan.ClassifyError(err)})
		return out, warnings
	}
	if codexTruncated {
		warnings = append(warnings, warning{
			Code: warnProfileListUnreadable, Count: len(codexNames), Limit: maxProfileDirs})
	}
	for _, name := range codexNames {
		relPath := filepath.Join(".codex", name)
		if !isCodexTOMLPath(filepath.Join(home, relPath)) {
			continue
		}
		probes := []probe{{
			relPath: relPath, client: "codex", jsonc: false, extract: extractCodexTOML,
		}}
		rows, _, stopped := probeHome(ctx, home, user, "", deadline, seen, probes)
		out = append(out, rows...)
		if stopped {
			return out, warnings
		}
	}
	return out, warnings
}

// maxProfileDirs bounds one profile-directory listing.
//
// Smaller than maxWorkspaceDirs because these are live profiles a person created by hand,
// not storage directories an editor accumulates: a host with more than a few hundred VS Code
// profiles, or Codex named profiles, is not a host this cap is the problem on.
const maxProfileDirs = 200

// probeProjects runs the project-rooted probe list inside each contained project.
//
// Every read goes through fsscan.ReadProjectFile, which never opens the absolute path: the
// containment that produced projectRef.Rel is re-applied from the home down, component by
// component, with symlinks refused and the hard-link check from ReadOpts applied to the
// descriptor. That is what makes containment a guarantee about the bytes rather than a string
// comparison that happened earlier -- a project directory that was inside the home when it
// was checked and is a symlink by the time it is opened fails the open.
func probeProjects(ctx context.Context, home, user string, deadline time.Time,
	seen map[string]struct{}, projects []projectRef) ([]Server, bool) {
	var out []Server
	refusals := make(map[warnCode]*warning)
	for _, project := range projects {
		if ctx.Err() != nil || time.Now().After(deadline) {
			return append(out, aggregatedRefusals(user, home, refusals)...), true
		}
		// The project's own settings files, read once per project rather than per probe, and
		// only where they can bear on the answer.
		//
		// Gated on a Claude origin because approval is Claude's mechanism: for a project
		// recorded only by Codex or a VS Code fork there is nothing these files could
		// change, and reading them anyway touched files inside a project this pass has no
		// question about -- before the configuration probes, so it was the first thing to
		// reach a provider-backed file.
		if _, fromClaude := project.Origins[originClaudeJSON]; fromClaude {
			evidence, settingsWarnings := projectApprovalSettings(
				home, project.Rel, project.TrustDialogAccepted)
			project.Approval = project.Approval.overlay(evidence)
			for _, w := range settingsWarnings {
				out = append(out, diagnosticRow(user, project.Abs, "claude_code", w))
			}
		}
		// Only the probes the clients that recorded this project actually load, rather than
		// all four against every project. See projectRef.probesFor: using one client's
		// evidence that a directory is a project to justify reporting a different client's
		// configuration in it is a claim the evidence does not support.
		for _, relPath := range project.probesFor() {
			// Between individual probes as well as between projects. A project contributes
			// up to three reads, so checking only per project overruns by that much on the
			// last project rather than stopping where the budget ran out.
			if ctx.Err() != nil || time.Now().After(deadline) {
				return append(out, aggregatedRefusals(user, home, refusals)...), true
			}
			src, known := projectProbeFor[relPath]
			if !known {
				continue
			}
			// Codex does not read project-scoped configuration for an untrusted project, so
			// that file is not configuration there at all.
			if src.client == "codex" && !project.allowsCodexConfig() {
				continue
			}
			path := filepath.Join(project.Abs, relPath)
			if _, dup := seen[path]; dup {
				continue
			}
			data, readErr := fsscan.ReadProjectFile(home, project.Rel, relPath,
				src.readOpts())
			if readErr != nil {
				// Absence is silent and everything else is counted. A recorded project that
				// was deleted, or one with no MCP configuration, is the overwhelming
				// majority -- three of this machine's thirty recorded projects no longer
				// exist -- and a row each would be most of this table's output.
				if w, report := projectRefusalWarning(readErr, src.cap()); report {
					if existing, ok := refusals[w.Code]; ok {
						existing.Count += w.Count
					} else {
						copied := w
						refusals[w.Code] = &copied
					}
				}
				continue
			}
			rows := finishProcessing(home, data, nil, path, user, src.client, src.jsonc,
				src.cap(), src.extract)
			if rows == nil {
				continue
			}
			// Approval is per server and comes from the project, which is why it is stamped
			// here rather than inside the extractor: the extractor sees bytes and has no
			// idea which project directory they came from.
			for i := range rows {
				if rows[i].Warning.empty() || rows[i].ServerName != "" {
					// Matched on the original name. Claude's approval arrays hold the names
					// the file spelled, so comparing the redacted form reported a server
					// the user had approved as not_approved whenever its legitimate name
					// happened to match a token shape.
					rows[i].Approval = project.approvalFor(src.client, rows[i].rawName)
				}
				// Both forms, because the published one is redacted and the tie-break needs
				// the original: two project paths differing only in a credential-shaped
				// component collapse to one string once redacted.
				rows[i].rawContext = projectSourceContext(src.client, project)
				rows[i].SourceContext = rows[i].rawContext
			}
			seen[path] = struct{}{}
			out = append(out, rows...)
		}
	}
	return append(out, aggregatedRefusals(user, home, refusals)...), false
}

// aggregatedRefusals turns the counted project-probe refusals into one row each.
//
// Aggregated and with no path. A path inside a user's home is not publishable, so naming the
// offending project would reintroduce the disclosure these columns are narrowed to prevent --
// a project directory can be named after anything, including a secret. The home is reported
// instead, which is a path this table already publishes.
//
// Sorted by code, because map iteration is random and these rows go straight to osquery.
func aggregatedRefusals(user, home string, refusals map[warnCode]*warning) []Server {
	if len(refusals) == 0 {
		return nil
	}
	codes := make([]warnCode, 0, len(refusals))
	for code := range refusals {
		codes = append(codes, code)
	}
	sort.Slice(codes, func(i, j int) bool { return codes[i] < codes[j] })
	out := make([]Server, 0, len(codes))
	for _, code := range codes {
		out = append(out, diagnosticRow(user, home, "", *refusals[code]))
	}
	return out
}

// finishProcessing turns one file's bytes into rows, or into one diagnostic.
//
// Three of the four places user bytes used to reach the warning column are here. Each is now
// a code plus structured detail:
//
//   - a read failure was `"read: " + readErr.Error()`, which is the operating system's
//     message and carries the path. It is now fsscan.ClassifyError's closed enum.
//   - an unterminated JSONC comment was a fixed sentence already, and is now a shape.
//   - a parse failure was `"parse: " + err.Error()`, which is the worst of the four: both
//     encoding/json and BurntSushi/toml quote the input they failed on, so a malformed
//     `env = { TOKEN = abc123 }` put the token in the column verbatim. parseWarning reads
//     the position and nothing else.
//
// The fourth is parse.go's skipped-entry count, which was always just an integer.
func finishProcessing(home string, data []byte, readErr error, path, user, client string, jsonc bool, maxSize int64, extract func([]byte) ([]Server, error)) []Server {
	if readErr != nil {
		if fsscan.IsExpectedAbsent(readErr) {
			return nil
		}
		// Size is split out from the rest, because it is the one read failure an operator
		// can act on and the numbers are integers, so reporting them costs nothing. The
		// other classes are a closed enum.
		if errors.Is(readErr, fsscan.ErrTooLarge) {
			row := diagnosticRow(user, path, client, warning{
				Code: warnSourceTooLarge, Limit: maxSize})
			row.Home = home
			return []Server{row}
		}
		row := diagnosticRow(user, path, client, warning{
			Code: warnSourceUnreadable, Class: fsscan.ClassifyError(readErr)})
		row.Home = home
		return []Server{row}
	}
	// A UTF-8 byte-order mark is stripped before anything looks at the content.
	//
	// Go's encoding/json rejects one outright -- "invalid character '\ufeff' looking for
	// beginning of value" -- so a JSON or JSONC config carrying one was reported as
	// malformed rather than read. BurntSushi/toml happens to tolerate a leading BOM, so
	// Codex configs were never affected; the strip is applied here rather than on the JSON
	// path alone so that tolerance stays an implementation detail of the dependency rather
	// than something this table relies on. That is a Windows shape in particular:
	// Notepad has historically written UTF-8 with a BOM, and PowerShell's
	// `Set-Content -Encoding utf8` still does on Windows PowerShell 5.1. The file is
	// perfectly valid; only the marker is in the way.
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})

	if jsonc {
		stripped, terminated := stripJSONC(data)
		if !terminated {
			row := diagnosticRow(user, path, client, warning{
				Code: warnParseFailed, Shape: shapeUnterminatedComment})
			row.Home = home
			return []Server{row}
		}
		data = stripped
	}
	rows, err := extract(data)
	if err != nil {
		row := diagnosticRow(user, path, client, parseWarning(err))
		row.Home = home
		return []Server{row}
	}
	// Whether any row from this file reports a source-scope loss. If one does, every row
	// from the file is an incomplete listing of it: the question scan_complete answers is
	// "were all of this file's servers listed", and one undecodable sibling makes the answer
	// no for the whole file rather than for the entry nobody could read.
	complete := true
	for i := range rows {
		if !rows[i].Warning.empty() && rows[i].Warning.Code.scope() == scopeSource {
			complete = false
		}
	}
	for i := range rows {
		rows[i].User = user
		rows[i].SourcePath = path
		rows[i].Client = client
		rows[i].Home = home
		// Set here rather than at construction, because this is the first point at which
		// the answer is known: the extractor produced rows and nothing in the file was lost.
		// A diagnostic row never reaches this loop and keeps the zero value, which is what
		// makes "diagnostic rows are never complete" true by construction rather than by
		// remembering to set it.
		// Scope, not presence. This read `complete && rows[i].Warning.empty()`, which made
		// every warning degrade completeness -- including the ones classified descriptive,
		// where a single optional column was dropped and the warning exists to say why. A
		// dropped environment key or a literal TOML header left the row reporting
		// scan_complete = 0 while every server in the file was listed, which is the
		// opposite of what this column is documented to mean.
		rows[i].ScanComplete = complete && !rows[i].Warning.Code.degradesCompleteness()
		if rows[i].Approval == "" {
			rows[i].Approval = approvalNotApplicable
		}
		inferIdentity(&rows[i])
	}
	assignNamePlaceholders(home, path, rows)
	return rows
}

// assignNamePlaceholders numbers the servers in one file whose names cannot be published.
//
// Done here, over the whole file's rows at once, because the index is a property of the set:
// a placeholder gets no suffix when it is the only unrepresentable name in its file and `#2`
// onwards when it is not, and the row builder sees one row at a time.
//
// Ordered by the raw name rather than by the order the extractor produced them. Map iteration
// is random, so without this the same two unrepresentable names in an unchanged file would
// swap placeholders between runs -- which differential logging reports as two rows removed
// and two added, on a host where nothing happened.
func assignNamePlaceholders(home, path string, rows []Server) {
	var unrepresentable []int
	for i := range rows {
		if rows[i].rawName == "" {
			continue
		}
		if serverNameUnrepresentable(rows[i].ServerName) {
			unrepresentable = append(unrepresentable, i)
		}
	}
	if len(unrepresentable) == 0 {
		return
	}
	// A total order over the original name and the section it was declared in. Neither is
	// emitted; only the position each earns is.
	//
	// Sorting on the published name came first and compared "[REDACTED]" against
	// "[REDACTED]" for every token-shaped name in the file, so the order was whatever map
	// iteration produced. Sorting on the original name alone fixed that and left a narrower
	// tie: ~/.claude.json declares servers under many project sections, so the *same*
	// unpublishable name can appear more than once in one file, and those rows compared
	// equal and swapped their ordinals between runs over unchanged bytes. SourceContext
	// carries the section -- `projects[<path>].mcpServers` -- so the pair is unique within a
	// file. It has to be the *unredacted* section: two paths differing only in a `--token=`
	// value redact to the same string, which reinstated the tie that sort.SliceStable then
	// resolved by input order.
	sort.SliceStable(unrepresentable, func(a, b int) bool {
		left, right := rows[unrepresentable[a]], rows[unrepresentable[b]]
		if left.rawName != right.rawName {
			return left.rawName < right.rawName
		}
		return left.rawContext < right.rawContext
	})
	relative := path
	if home != "" {
		if rel, err := filepath.Rel(home, path); err == nil {
			relative = rel
		}
	}
	for ordinal, index := range unrepresentable {
		rows[index].PlaceholderSource = relative
		// 1-based, and 1 renders with no suffix: a file with one unrepresentable name gets
		// `[redacted:<path>]` rather than `[redacted:<path>]#1`.
		rows[index].PlaceholderIndex = ordinal + 1
	}
}

// projectSourceContext names where in a project a server was declared.
//
// A fixed token per probe plus the project path, where the path has already been through the
// same containment every read uses -- so this cannot publish a location a read would have
// refused. Which project declared a server is the thing an operator wants from this column
// and is not recoverable from anywhere else, so it is kept rather than dropped.
func projectSourceContext(client string, project projectRef) string {
	token := projectContextTokens[client]
	if token == "" {
		token = "project"
	}
	return token + "[" + project.Rel + "]"
}

// projectContextTokens is the closed set of section names a project-rooted probe may report.
var projectContextTokens = map[string]string{
	"claude_code": "project.mcp_json",
	"vscode":      "project.vscode_mcp_json",
	"cursor":      "project.cursor_mcp_json",
	"codex":       "project.codex_config_toml",
}

// extractEnvelopeSimple is the generic extractor used by the majority of clients.
// It tries the {mcpServers,servers} envelope; if that yields nothing it falls
// back to the flat shape.
func extractEnvelopeSimple(data []byte) ([]Server, error) {
	envelopes, skipped, err := extractEnvelope(data)
	if errors.Is(err, errNoDecodableEntries) {
		// The file has an envelope and it is broken. Reporting that is the whole answer;
		// re-reading it as a flat document would attribute an unrelated sibling object as a
		// server and lose the failure.
		return nil, err
	}
	if err != nil {
		// The envelope failed, which for a file that has an mcpServers or servers key means
		// one of its entries is malformed. Falling back to the flat shape finds nothing in
		// that case, because the only top-level value is the envelope object itself and it
		// does not look like a server entry. Returning that empty result would drop every
		// healthy server in the file and emit no warning either, so an empty fallback has to
		// surface the original error instead.
		flat, flatSkipped, fErr := extractFlat(data)
		if fErr != nil || len(flat) == 0 {
			return nil, err
		}
		rows, mErr := materialize(flat, "")
		if mErr != nil {
			return nil, mErr
		}
		return append(rows, skippedEntryWarning(flatSkipped)...), nil
	}
	if !envelopes.Present {
		flat, flatSkipped, fErr := extractFlat(data)
		if fErr != nil {
			// Neither the envelope nor the flat shape matched, and the envelope parse itself
			// did not error: so this is valid JSON that simply is not MCP configuration.
			// No servers and no error is the correct answer; a warning row here would fire on
			// every unrelated JSON file the walk happens to reach.
			//nolint:nilerr // deliberate: a non-match is not an error
			return nil, nil
		}
		rows, mErr := materialize(flat, "")
		if mErr != nil {
			return nil, mErr
		}
		return append(rows, skippedEntryWarning(flatSkipped)...), nil
	}
	// Each envelope keeps its own name, so source_context describes the real location.
	rows, err := materialize(envelopes.MCPServers, "mcpServers")
	if err != nil {
		return nil, err
	}
	serverRows, err := materialize(envelopes.Servers, "servers")
	if err != nil {
		return nil, err
	}
	rows = append(rows, serverRows...)
	return append(rows, skippedEntryWarning(skipped)...), nil
}

// decodeContainer decodes one top-level object of a larger config file. It reports whether
// the value was usable, so a caller holding several independent containers can lose one
// without losing the rest. An absent container is not a failure: ok is true with a nil map.
func decodeContainer(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	if len(raw) == 0 {
		return nil, true
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, false
	}
	return out, true
}

// extractClaudeCode reads ~/.claude.json. The file is a big per-user blob with
// `mcpServers` at the top and a `projects` map keyed by project path whose
// values each carry their own `mcpServers`.
func extractClaudeCode(data []byte) ([]Server, error) {
	// Both containers are held raw and decoded independently below. Binding either one to a
	// map directly made its *type* part of the whole-document Unmarshal: a global
	// `"mcpServers": "broken"` returned an error from the outer Unmarshal, and the early
	// return discarded every healthy project-scoped server with it -- on the file that holds
	// the most servers on a real machine, and in exactly the way the per-project loop below
	// already took care to avoid. The two sections fail independently because they are
	// independent sources of servers.
	var doc struct {
		MCPServers json.RawMessage `json:"mcpServers"`
		Projects   json.RawMessage `json:"projects"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		// The document itself is not JSON. There is nothing to recover and the caller turns
		// this into a parse warning row.
		return nil, err
	}
	var out []Server
	skipped := 0
	// A malformed container counts as one skipped item even though it may have held many
	// servers. That understates the loss, but it matches the envelope extractor and keeps a
	// single warning shape; either way the row set is marked incomplete, which is what the
	// warning column exists to say.
	globalScope, ok := decodeContainer(doc.MCPServers)
	if !ok {
		skipped++
	}
	userScope := make(map[string]rawServerEntry, len(globalScope))
	skipped += decodeInto(userScope, globalScope)
	if rows, err := materialize(userScope, "mcpServers"); err == nil {
		out = append(out, rows...)
	}
	projects, ok := decodeContainer(doc.Projects)
	if !ok {
		skipped++
	}
	for projPath, raw := range projects {
		var project struct {
			MCPServers map[string]json.RawMessage `json:"mcpServers"`
		}
		if err := json.Unmarshal(raw, &project); err != nil {
			// This one project is unreadable; its siblings are not.
			skipped++
			continue
		}
		if len(project.MCPServers) == 0 {
			continue
		}
		scoped := make(map[string]rawServerEntry, len(project.MCPServers))
		skipped += decodeInto(scoped, project.MCPServers)
		rows, _ := materialize(scoped, "projects["+projPath+"].mcpServers")
		out = append(out, rows...)
	}
	return append(out, skippedEntryWarning(skipped)...), nil
}

// extractGeminiSettings reads ~/.gemini/settings.json which carries many keys
// alongside `mcpServers`.
func extractGeminiSettings(data []byte) ([]Server, error) {
	var doc struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	entries := make(map[string]rawServerEntry, len(doc.MCPServers))
	skipped := decodeInto(entries, doc.MCPServers)
	rows, err := materialize(entries, "mcpServers")
	if err != nil {
		return nil, err
	}
	return append(rows, skippedEntryWarning(skipped)...), nil
}

// materialize converts the parsed raw entries into normalized Server records.
// All credential-bearing fields are sanitized here so downstream consumers
// (identity inference, the table plugin) never see raw secrets:
//   - URL: reduced to scheme://host (path/query/fragment/userinfo dropped)
//   - args / command: known token shapes and secret-flag values replaced with
//     [REDACTED]
//   - env values: never extracted (rawServerEntry.Env is parsed but discarded);
//     env *keys* are retained as a security signal
//
// inferIdentity is not called here, that's done by the caller after stamping
// User / SourcePath / Client, so the identity step sees a complete record.
func materialize(in map[string]rawServerEntry, ctx string) ([]Server, error) {
	out := make([]Server, 0, len(in))
	for name, e := range in {
		dropped := 0
		rawURL := firstNonEmpty(e.URL, e.ServerURL, e.HTTPURL)
		s := Server{
			// SourceContext can include a project path the user controls
			// (e.g., projects[/abs/path].mcpServers from ~/.claude.json).
			// Apply redactSecret to catch token-shaped substrings in case a
			// project lives in a directory whose name contains a secret.
			SourceContext: redactSecret(ctx),
			// JSON map keys are attacker-controlled. A user could (deliberately
			// or accidentally) place a token-shaped string as a server name
			// in their MCP config. Redact before emit.
			rawName:    name,
			rawContext: ctx,
			ServerName: redactSecret(name),
			Command:    redactSecret(e.Command),
			Args:       redactArgs(e.Args),
			URL:        sanitizeRemoteURL(rawURL),
			// Inferred here, from the unsanitized URL, because sanitizeRemoteURL drops the
			// path and the /sse convention lives in it. Doing this later in inferIdentity
			// meant https://example.test/sse was always reported as http.
			Transport: firstNonEmpty(normalizeTransport(e.Type, e.Transport),
				transportFromRawURL(rawURL, e.Args)),
		}
		if e.Disabled != nil {
			s.Disabled = *e.Disabled
		}
		if len(e.Env) > 0 {
			// Collected in map order and sorted at the emit boundary, not here:
			// redactedJSONStringArray sorts after redacting, which is the only place that
			// can guarantee the column is stable for every JSON-array column at once.
			// Sorting here as well would be redundant, and sorting *instead* of there would
			// leave env_keys stable while the other array columns were not.
			//
			// The ordering matters because env_keys is part of the row value: an unsorted
			// column would make a scheduled query with differential logging report the same
			// unchanged server as removed and re-added on every run.
			s.EnvKeys = make([]string, 0, len(e.Env))
			for k := range e.Env {
				// Gated here as well as at the row boundary, so the drop can be attributed
				// to this source rather than reported as a bare count at the end. An env
				// key is a C identifier in every shell and runtime, so a name that fails
				// could not have been doing the job this column describes.
				if !envKeyAllowed(k) {
					dropped++
					continue
				}
				s.EnvKeys = append(s.EnvKeys, k)
			}
		}
		if dropped > 0 {
			s.Warning = warning{Code: warnEnvKeyDropped, Count: dropped}
		}
		out = append(out, s)
	}
	return out, nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// transportFromRawURL distinguishes sse from http using the endpoint path, which only exists
// before sanitizeRemoteURL runs. Returns "" when there is no URL at all, so a stdio server is
// not given a remote transport by accident.
func transportFromRawURL(rawURL string, args []string) string {
	if rawURL == "" {
		return ""
	}
	return guessRemoteTransport(rawURL, args)
}

// normalizeTransport maps a declared transport onto the documented set, and distinguishes a
// field that was not supplied from one that was supplied and is not recognised.
//
// The difference decides whether the caller may guess. An absent transport is an invitation
// to infer one from the URL or the command; a present but unfamiliar one is a statement
// about the file, and overwriting it reports something the file does not say. A config
// declaring `"type": "websocket"` beside an `https://` URL was reported as `transport=http`,
// so a transport this table does not support was indistinguishable from one it does -- and
// the next transport MCP adds would arrive disguised as an existing protocol rather than
// showing up as something to look at.
//
// "unknown" is already one of the four documented values of this column, so reporting it
// costs no schema change and is what a reader filtering for the supported set already
// excludes.
func normalizeTransport(t1, t2 string) string {
	declared := false
	for _, t := range [2]string{t1, t2} {
		if strings.TrimSpace(t) != "" {
			declared = true
		}
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "stdio":
			return "stdio"
		case "sse":
			return "sse"
		case "http", "streamable-http", "streamablehttp":
			return "http"
		}
	}
	if declared {
		return "unknown"
	}
	return ""
}
