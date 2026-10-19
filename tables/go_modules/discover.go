package go_modules

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/macadmins/osquery-extension/pkg/devclients"
	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/macadmins/osquery-extension/pkg/utils"
)

// Discovery reads the projects each client recorded for an account, then two known files in
// each: go.mod and go.sum at the project root. It never walks a directory tree. See
// pkg/devclients for why the project lists replace a walk, and the table README for what that
// costs.
//
// Only the project root is read. A repository whose module lives in a subdirectory, or a
// go.work that names several modules, contributes only what sits at the root.

// Source files read in each project, in the order they are read.
const (
	goModFile = "go.mod"
	goSumFile = "go.sum"
	// goWorkFile is checked for presence only: workspace discovery is not supported.
	goWorkFile = "go.work"
)

// maxGoFileSize bounds the read of one go.mod or go.sum. The largest measured on the development
// machine, Fleet's go.sum, is 115 KB; 2 MiB is about eighteen times that. The size cap bounds
// the bytes read, and maxEntriesPerFile bounds the rows a file can produce from them.
const maxGoFileSize = 2 << 20

// maxRows bounds the module rows one query returns across every account, so a host where users
// control many large manifests cannot grow the extension's memory without limit. A project the
// size of Fleet produces about 1,000 rows, so the cap holds about fifty of them. Reaching it is
// reported, and the module rows kept from the project it stops in are marked incomplete.
const maxRows = 50000

// maxListSize bounds the read of ~/.codex/config.toml and each workspace.json, matching the
// cap mcp_servers applies to the same files.
const maxListSize = 1 << 20

// maxProjects bounds the distinct project directories one account contributes, across every
// client's list. A directory several clients record counts once, but a repository opened at
// its root in one client and at a subdirectory in another counts twice, and a developer who
// uses several editors accumulates entries in each. The lists fill in a fixed order -- the VS
// Code family, JetBrains, Claude Code, Codex -- so a cap reached early drops whole clients.
// Each project costs two component-wise opens, most of which fail at once because most recorded
// projects are not Go projects, so 1,000 is cheap; the query budget and maxRows still bound the
// work. mcp_servers keeps devclients.MaxProjects.
const maxProjects = 1000

// readOpts is the one place the read refusals are chosen, so a read site cannot opt out.
// Hard links are refused because a hard link to another user's file passes every path check.
// Owner checks are not set: fsscan refuses rather than passes an owner check on Windows, where
// it is not implemented, so setting one here would return no rows on that platform.
func readOpts(maxSize int64) fsscan.ReadOpts {
	return fsscan.ReadOpts{MaxSize: maxSize, RefuseHardLinks: true, CloudPlaceholder: cloudPlaceholder}
}

// Where a project's content is stored decides whether this table reads it. A project stored
// with a cloud storage provider, or on a network filesystem, is inventoried where it is stored,
// so it is counted and not read. These are the checks, as variables so tests can substitute
// them: a network mount and a cloud placeholder cannot be created in a test.
var (
	underCloudStorage = fsscan.UnderCloudStorage
	probeProject      = fsscan.ProbeProjectDir
	// roamingAppDataFor reads an account's registry hive on Windows. Tests use temporary homes
	// with no hive, so they substitute it.
	roamingAppDataFor = fsscan.RoamingAppDataFor
	// cloudPlaceholder is nil in production, which selects fsscan.IsCloudPlaceholder.
	cloudPlaceholder func(*os.File) (bool, error)
)

// row is one module version, or one diagnostic, before publication. SourceFile is set only on a
// diagnostic row about one module file, and is published as a prefix of its warning.
type row struct {
	User          string
	UID           string
	UserID        string
	Home          string
	ProjectPath   string
	ProjectModule string
	SourceFile    string
	Entry         moduleEntry
	ScanComplete  bool
	Warning       warning
}

// diagnosticRow builds a row that reports a finding instead of a module. It is never marked
// complete: it reports that something was not listed, and `WHERE scan_complete = 1` selects
// the rows an operator can rely on.
func diagnosticRow(user, userID string, w warning) row {
	return row{User: user, UserID: userID, Warning: w}
}

// discoverAll lists the modules for every account the query asks about.
//
// The account roster comes from osquery's users table, through the extension socket. There is
// no filesystem fallback: if the socket cannot be reached osquery is not receiving rows
// either, and a guessed roster would only make that failure harder to see.
func discoverAll(ctx context.Context, clienter utils.OsqueryClienter,
	userFilter map[string]struct{}) []row {
	return discoverWithin(ctx, clienter, userFilter, maxRows)
}

// discoverWithin is discoverAll with the row limit supplied, so a test can reach it without
// writing tens of thousands of rows.
func discoverWithin(ctx context.Context, clienter utils.OsqueryClienter,
	userFilter map[string]struct{}, rowLimit int) []row {
	client, err := clienter.NewOsqueryClient()
	if err != nil {
		return rosterRows(userFilter, warning{Code: warnRosterUnreachable})
	}
	defer client.Close()
	// Set before the roster is read, so the roster query is inside the budget.
	deadline := time.Now().Add(fsscan.WalkTimeout())
	enumerated, err := fsscan.ListUserHomes(client, userFilter)
	if err != nil {
		return rosterRows(userFilter, warning{Code: warnRosterQueryFailed})
	}

	var out []row
	answered := make(map[string]struct{})
	unusableHomes := 0
	for _, omission := range enumerated.Skipped {
		// Unconstrained, an account with no usable home is usually a service account that
		// never had one created, and a row each would bury the omissions that matter.
		if omission.HomeUnusable && userFilter == nil {
			unusableHomes++
			continue
		}
		w := warning{Code: warnAccountNotInspected, Reason: omission.Code}
		// An omission with no name cannot be matched to a requested user, so it is reported
		// under each name the query asked about.
		if omission.Name == "" {
			out = append(out, rosterRows(userFilter, w)...)
			continue
		}
		if !requested(userFilter, omission.Name) {
			continue
		}
		out = append(out, diagnosticRow(omission.Name, omission.ID, w))
		answered[omission.Name] = struct{}{}
	}
	if unusableHomes > 0 {
		out = append(out, diagnosticRow("", "",
			warning{Code: warnAccountsHomeUnusable, Count: unusableHomes}))
	}
	// An account that cannot log in keeps no projects. It is silent unless asked for by name,
	// and then it gets a real answer: "cannot log in" and "does not exist" are different facts.
	if userFilter != nil {
		for _, omission := range enumerated.NonLogin {
			if requested(userFilter, omission.Name) {
				out = append(out, diagnosticRow(omission.Name, omission.ID,
					warning{Code: warnAccountNotInspected, Reason: omission.Code}))
				answered[omission.Name] = struct{}{}
			}
		}
	}

	// Accounts that share a home are scanned once and reported once each.
	scanned := make(map[string][]row, len(enumerated.Homes))
	remaining := rowLimit
	for _, home := range enumerated.Homes {
		if !requested(userFilter, home.Name) {
			continue
		}
		answered[home.Name] = struct{}{}
		rows := rowsForHome(ctx, home, deadline, remaining, rowLimit, scanned)
		remaining -= moduleRows(rows)
		out = append(out, rows...)
	}

	// A requested name the roster never mentioned. An empty result would read as "this user
	// has no Go modules" when the users table has no such account.
	if userFilter != nil {
		missing := make([]string, 0, len(userFilter))
		for name := range userFilter {
			if _, ok := answered[name]; !ok {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		for _, name := range missing {
			out = append(out, diagnosticRow(name, "", warning{Code: warnAccountNotInRoster}))
		}
	}
	return out
}

// rowsForHome returns one rostered account's rows, labeled with its name and identity.
//
// A home already scanned for another account is reused before the time budget is consulted,
// because the budget bounds filesystem work and a cached result needs none: when two accounts
// share a home and the first scan finishes as the deadline passes, the second account still
// gets the rows. Cancellation is checked first, because a cancelled query wants nothing back.
// The row limit applies to cached rows too, since they count again for each account they are
// reported under.
//
// The home path alone is not the whole cache key on Windows, where discovery also reads the
// account's own registry hive; see devclients.ScanKey.
func rowsForHome(ctx context.Context, home fsscan.UserHome, deadline time.Time,
	remaining, rowLimit int, scanned map[string][]row) []row {
	if ctx.Err() != nil {
		return []row{diagnosticRow(home.Name, home.ID, warning{Code: warnCancelledPreHome})}
	}
	limitReached := []row{diagnosticRow(home.Name, home.ID,
		warning{Code: warnRowLimitPreHome, Limit: int64(rowLimit)})}
	key := devclients.ScanKey(home)
	rows, cached := scanned[key]
	if !cached {
		if remaining <= 0 {
			return limitReached
		}
		if !time.Now().Before(deadline) {
			return []row{diagnosticRow(home.Name, home.ID, warning{Code: warnBudgetExhaustedPreHome})}
		}
		rows = discoverHome(ctx, home, deadline, remaining, rowLimit)
		scanned[key] = rows
	} else if moduleRows(rows) > remaining {
		return limitReached
	}
	labeled := make([]row, 0, len(rows))
	for _, r := range rows {
		r.User, r.UID, r.UserID = home.Name, home.UID, home.ID
		labeled = append(labeled, r)
	}
	return labeled
}

// requested reports whether a query constrained to userFilter asked about name. A nil filter
// asks about every account.
func requested(userFilter map[string]struct{}, name string) bool {
	if userFilter == nil {
		return true
	}
	_, ok := userFilter[name]
	return ok
}

// rosterRows reports a roster-level finding. A constrained query gets the row under each name
// it asked about, because SQLite applies `WHERE user = 'alice'` to whatever the generator
// returns and would discard a row with an empty user. An unconstrained query gets one row.
func rosterRows(userFilter map[string]struct{}, w warning) []row {
	if userFilter == nil {
		return []row{diagnosticRow("", "", w)}
	}
	names := make([]string, 0, len(userFilter))
	for name := range userFilter {
		names = append(names, name)
	}
	sort.Strings(names)
	rows := make([]row, 0, len(names))
	for _, name := range names {
		rows = append(rows, diagnosticRow(name, "", w))
	}
	return rows
}

// discoverHome lists the modules in every recorded project for one account. Each project's
// rows carry their own scan_complete, and a problem finding the projects is a warning row for
// the account. allowance is how many module rows the query can still return.
func discoverHome(ctx context.Context, account fsscan.UserHome, deadline time.Time,
	allowance, rowLimit int) []row {
	home := account.Path
	var out []row
	note := func(w warning) { out = append(out, row{Home: home, Warning: w}) }

	// A home this process cannot open, such as root's when osqueryi runs as a user, would
	// otherwise produce one row per client list, each saying the list could not be read. One row
	// says what an operator needs: the account was not inspected. mcp_servers makes the same check.
	handle, err := os.Open(home)
	if err != nil {
		note(warning{Code: warnHomeUnreadable, Class: fsscan.ClassifyError(err)})
		return out
	}
	_ = handle.Close()

	appData, appDataNote := roamingRoot(account)
	if !appDataNote.empty() {
		note(appDataNote)
	}

	// The lists fill the collector in the order Go developers use the clients, so a project cap
	// reached early drops the least-used ones: the VS Code family, then JetBrains IDEs, then the
	// coding agents. The 2025 Go Developer Survey puts VS Code at 37% and GoLand at 28%.
	collector := devclients.NewCollector(home, maxProjects)

	workspaces := devclients.WorkspaceFolders(ctx, home, appData, deadline, readOpts(maxListSize))
	for _, listing := range workspaces.Listings {
		if listing.Truncated {
			note(warning{Code: warnWorkspaceListTruncated, Count: listing.Count,
				Limit: devclients.MaxWorkspaceDirs})
			continue
		}
		note(warning{Code: warnWorkspaceListUnreadable, Class: listing.Class})
	}
	if workspaces.UnreadableRecords > 0 {
		note(warning{Code: warnWorkspaceRecordUnreadable, Count: workspaces.UnreadableRecords})
	}
	if workspaces.MalformedRecords > 0 {
		note(warning{Code: warnWorkspaceRecordMalformed, Count: workspaces.MalformedRecords})
	}
	for _, folder := range workspaces.Folders {
		collector.Add(folder.Recorded, folder.Origin, folder.FileURL)
	}
	if workspaces.Stopped {
		note(warning{Code: budgetCode(ctx)})
		return out
	}

	// JetBrains IDEs keep one recent-projects list per product and version. A list that exists
	// and cannot be read or parsed is a lost list of projects, so it is reported the way an
	// unreadable ~/.claude.json is.
	jetbrains := devclients.JetBrainsProjects(ctx, home, appData, deadline, readOpts(maxListSize))
	for _, listing := range jetbrains.Listings {
		if listing.Truncated {
			note(warning{Code: warnProjectListTruncated, Count: listing.Count,
				Limit: devclients.MaxJetBrainsDirs})
			continue
		}
		note(warning{Code: warnProjectListUnreadable, Class: listing.Class})
	}
	if lost := jetbrains.UnreadableRecords + jetbrains.MalformedRecords; lost > 0 {
		note(warning{Code: warnProjectListUnreadable, Count: lost})
	}
	for _, folder := range jetbrains.Folders {
		collector.Add(folder.Recorded, folder.Origin, folder.FileURL)
	}
	if jetbrains.Stopped {
		note(warning{Code: budgetCode(ctx)})
		return out
	}

	if !addAgentLists(ctx, home, deadline, collector, note) {
		return out
	}

	refusals := collector.Refusals()
	if refusals.Outside > 0 {
		note(warning{Code: warnProjectOutsideHome, Count: refusals.Outside})
	}
	if refusals.Remote > 0 {
		note(warning{Code: warnProjectRemoteOrigin, Count: refusals.Remote})
	}
	if refusals.Malformed > 0 {
		note(warning{Code: warnProjectMalformed, Count: refusals.Malformed})
	}
	if refusals.Truncated {
		note(warning{Code: warnProjectListTruncated, Count: len(collector.Projects()),
			Limit: maxProjects})
	}

	// Sorted by path, so the row order depends on the filesystem rather than on which client
	// recorded a project first.
	projects := append([]devclients.Project(nil), collector.Projects()...)
	sort.Slice(projects, func(i, j int) bool { return projects[i].Rel < projects[j].Rel })
	used, cloudStored, onNetwork, goWorkspaces := 0, 0, 0, 0
	for _, project := range projects {
		// The checks run in order of cost, each at the first point it can be answered. The
		// cloud-folder rule is a string comparison on the recorded path.
		if underCloudStorage(project.Rel) {
			cloudStored++
			continue
		}
		if !budgetRemains(ctx, deadline) {
			note(warning{Code: budgetCode(ctx)})
			break
		}
		// One directory open per project. A network mount is decided here, before any file in
		// it is opened. A missing or symlinked directory is skipped too, with the same silence
		// the file reads would give it, and any other failure is left for the reads to report.
		switch probeErr := probeProject(home, project.Rel); fsscan.ClassifyError(probeErr) {
		case fsscan.ClassNetworkFilesystem:
			onNetwork++
			continue
		case fsscan.ClassAbsent, fsscan.ClassRefusedPath:
			continue
		}
		var files [2]projectFile
		stopped, partial := false, false
		for index, file := range []string{goModFile, goSumFile} {
			// Checked before each file rather than each project, so one project's second file
			// is not read after the budget has run out. What the first file yielded is still
			// listed, marked incomplete, because the project's other file was not read.
			if !budgetRemains(ctx, deadline) {
				note(warning{Code: budgetCode(ctx)})
				stopped, partial = true, index > 0
				break
			}
			files[index] = readModuleFile(home, project, file)
			if files[index].cloudStored {
				break
			}
		}
		if files[0].cloudStored || files[1].cloudStored {
			// A module file whose content is not on this disk: the project is stored with its
			// provider, and a partial listing from the other file would misdescribe it.
			cloudStored++
			if stopped {
				break
			}
			continue
		}
		// One file refused as a symbolic link beside a readable other file: the readable file's
		// rows are published, marked incomplete, with a finding naming the refused file. Without
		// it, go.sum rows beside a refused go.mod would read as versions go.mod does not require.
		for index, file := range []string{goModFile, goSumFile} {
			other := files[1-index]
			if files[index].linkRefused && (len(other.result.Entries) > 0 || len(other.findings) > 0) {
				files[index].findings = append(files[index].findings, row{Home: home,
					ProjectPath: project.Abs, SourceFile: file, Warning: warning{Code: warnSourceLinkRefused}})
			}
		}
		// A go.work at the root names other modules, which this version does not read. It is
		// counted whether or not the root has a go.mod: without one, the project would look as
		// if it had no Go dependencies; with one, only the root module is listed.
		if !stopped {
			if !budgetRemains(ctx, deadline) {
				note(warning{Code: budgetCode(ctx)})
				stopped = true
			} else if workspaceAt(home, project.Rel) {
				goWorkspaces++
			}
		}
		rows := projectRows(home, project, files[0], files[1])
		if partial {
			for index := range rows {
				rows[index].ScanComplete = false
			}
		}
		if used+moduleRows(rows) > allowance {
			// Keep what fits, report the limit, and stop. The kept rows of this project are marked
			// incomplete; the rows of projects before it are unchanged.
			out = append(out, keepModuleRows(rows, allowance-used)...)
			note(warning{Code: warnRowLimitInHome, Limit: int64(rowLimit)})
			break
		}
		used += moduleRows(rows)
		out = append(out, rows...)
		if stopped {
			break
		}
	}
	// Counted rather than listed, like projects outside the home: where a project is stored
	// defines what this table reads, so these leave scan_complete alone.
	if cloudStored > 0 {
		note(warning{Code: warnProjectInCloudStorage, Count: cloudStored})
	}
	if onNetwork > 0 {
		note(warning{Code: warnProjectOnNetworkFS, Count: onNetwork})
	}
	if goWorkspaces > 0 {
		note(warning{Code: warnWorkspaceUnsupported, Count: goWorkspaces})
	}
	return out
}

// workspaceAt reports whether a project has a go.work at its root. It opens the file with the
// symlink refusal every read applies and reads nothing, because only its presence is reported.
func workspaceAt(home, projRel string) bool {
	file, err := fsscan.OpenBeneath(home, filepath.Join(projRel, goWorkFile))
	if err != nil {
		return false
	}
	_ = file.Close()
	return true
}

// moduleRows counts the rows that report a module rather than a finding.
func moduleRows(rows []row) int {
	count := 0
	for _, r := range rows {
		if r.Entry.Path != "" {
			count++
		}
	}
	return count
}

// keepModuleRows returns rows with every finding and at most limit module rows, in order. The
// project's listing is cut short, so the module rows it keeps are marked incomplete.
func keepModuleRows(rows []row, limit int) []row {
	kept := make([]row, 0, len(rows))
	for _, r := range rows {
		if r.Entry.Path != "" {
			if limit <= 0 {
				continue
			}
			limit--
			r.ScanComplete = false
		}
		kept = append(kept, r)
	}
	return kept
}

// projectFile is what one module file in a project yielded: its parse result, and a diagnostic
// row for each finding about it.
type projectFile struct {
	result   parseResult
	findings []row
	// cloudStored is set when the file's content is held by a cloud storage provider rather
	// than on this disk. The project is then counted and not listed.
	cloudStored bool
	// linkRefused is set when the file is a symbolic link, which is not followed. On its own
	// that is silent, like a project behind a symlink; beside a readable other file it is a
	// finding, because that file's rows would otherwise read as complete.
	linkRefused bool
}

// projectRows merges a project's go.mod and go.sum into one row per module version, followed by
// the findings about either file. A finding about either file marks every module row for the
// project incomplete, because each row's columns can come from both files. A file that is
// absent is not a finding: a project with no go.sum has rows with empty go.sum columns, and they
// are complete.
func projectRows(home string, project devclients.Project, goMod, goSum projectFile) []row {
	base := row{Home: home, ProjectPath: project.Abs, ProjectModule: goMod.result.ProjectModule}
	complete := len(goMod.findings) == 0 && len(goSum.findings) == 0
	entries := mergeEntries(goMod.result.Entries, goSum.result.Entries)
	rows := make([]row, 0, len(entries)+len(goMod.findings)+len(goSum.findings))
	for _, entry := range entries {
		r := base
		r.Entry = entry
		r.ScanComplete = complete
		rows = append(rows, r)
	}
	rows = append(rows, goMod.findings...)
	return append(rows, goSum.findings...)
}

// readModuleFile reads one go.mod or go.sum in a project.
//
// A file that is absent yields nothing. That is the common case -- most recorded projects are
// not Go projects, and a project list records directories that have since been deleted -- and a
// row for each would bury everything else.
func readModuleFile(home string, project devclients.Project, file string) projectFile {
	finding := row{Home: home, ProjectPath: project.Abs, SourceFile: file}
	data, err := fsscan.ReadProjectFile(home, project.Rel, file, readOpts(maxGoFileSize))
	if err != nil {
		switch fsscan.ClassifyError(err) {
		case fsscan.ClassCloudPlaceholder:
			return projectFile{cloudStored: true}
		case fsscan.ClassRefusedPath:
			return projectFile{linkRefused: true}
		}
		w, report := readFailure(err)
		if !report {
			return projectFile{}
		}
		finding.Warning = w
		return projectFile{findings: []row{finding}}
	}

	var result parseResult
	if file == goModFile {
		var parseErr error
		if result, parseErr = parseGoMod(data); parseErr != nil {
			finding.Warning = warning{Code: warnGoModMalformed}
			return projectFile{findings: []row{finding}}
		}
	} else {
		result = parseGoSum(data)
	}

	// Each reason the file's listing is short is one diagnostic row.
	var findings []warning
	if result.PartialLine > 0 {
		findings = append(findings, warning{Code: warnGoModPartial, Line: result.PartialLine})
	}
	if result.ConflictingReplaces > 0 {
		findings = append(findings, warning{Code: warnReplaceConflict, Count: result.ConflictingReplaces})
	}
	if result.ChecksumConflicts > 0 {
		findings = append(findings, warning{Code: warnChecksumConflict, Count: result.ChecksumConflicts})
	}
	if result.Truncated {
		findings = append(findings, warning{Code: warnEntriesTruncated, Limit: maxEntriesPerFile})
	}
	if result.MalformedLines > 0 {
		findings = append(findings, warning{Code: warnGoSumMalformed, Count: result.MalformedLines})
	}
	if result.Dropped > 0 {
		findings = append(findings, warning{Code: warnEntriesDropped, Count: result.Dropped})
	}
	found := projectFile{result: result}
	for _, w := range findings {
		r := finding
		r.Warning = w
		found.findings = append(found.findings, r)
	}
	return found
}

// readFailure classifies a failed read of a module file, or reports that there is nothing to
// say. Absence is silent; readModuleFile handles a cloud placeholder and a refused symlink
// before this. A userspace filesystem and a refused hard link are each a file that exists and
// was deliberately not read, which leaves the project's listing short. Anything else is a
// failure to read one file.
func readFailure(err error) (warning, bool) {
	switch class := fsscan.ClassifyError(err); class {
	case fsscan.ClassNone, fsscan.ClassAbsent, fsscan.ClassRefusedPath:
		return warning{}, false
	case fsscan.ClassUserspaceFilesystem:
		return warning{Code: warnProjectUserspaceFS, Count: 1}, true
	case fsscan.ClassHardLink, fsscan.ClassForeignOwner:
		return warning{Code: warnProjectRefused, Class: class}, true
	case fsscan.ClassTooLarge:
		return warning{Code: warnSourceTooLarge, Limit: maxGoFileSize}, true
	default:
		return warning{Code: warnSourceUnreadable, Class: class}, true
	}
}

// addAgentLists adds the projects Claude Code and Codex record, one fixed file each. The budget
// is checked before each read: the JetBrains reads before these can end after the deadline
// without reporting a stop, and a read under the home can block. It returns false, after noting
// why, when the budget ran out before a read.
func addAgentLists(ctx context.Context, home string, deadline time.Time,
	collector *devclients.Collector, note func(warning)) bool {
	if !budgetRemains(ctx, deadline) {
		note(warning{Code: budgetCode(ctx)})
		return false
	}
	if entries, w := readClaudeList(home); !w.empty() {
		note(w)
	} else {
		for _, entry := range entries {
			collector.Add(entry.Recorded, devclients.OriginClaudeJSON, false)
		}
	}
	if !budgetRemains(ctx, deadline) {
		note(warning{Code: budgetCode(ctx)})
		return false
	}
	if entries, w := readCodexList(home); !w.empty() {
		note(w)
	} else {
		for _, entry := range entries {
			collector.Add(entry.Recorded, devclients.OriginCodexTOML, false)
		}
	}
	return true
}

// readClaudeList reads the project paths from ~/.claude.json. Only the recorded paths are used;
// the entries' values are never decoded here, because they include the text the user last
// typed at the client.
func readClaudeList(home string) ([]devclients.ClaudeEntry, warning) {
	data, err := fsscan.ReadBoundedUnder(home, devclients.ClaudeListPath,
		readOpts(devclients.ClaudeListMaxSize))
	if err != nil {
		return nil, listReadFailure(err)
	}
	entries, err := devclients.ClaudeEntries(data)
	if err != nil {
		return nil, warning{Code: warnProjectListUnreadable}
	}
	return entries, warning{}
}

// readCodexList reads the project paths from ~/.codex/config.toml.
func readCodexList(home string) ([]devclients.CodexEntry, warning) {
	data, err := fsscan.ReadBoundedUnder(home, devclients.CodexListPath, readOpts(maxListSize))
	if err != nil {
		return nil, listReadFailure(err)
	}
	entries, err := devclients.CodexEntries(data)
	if err != nil {
		return nil, warning{Code: warnProjectListUnreadable}
	}
	return entries, warning{}
}

// listReadFailure classifies a failed read of a project-list file. Only absence is silent: most
// accounts do not use every client.
//
// A refused symlink is reported, unlike a module-file probe, where a refusal is silent. A
// refused list is not a missing project but a missing list of projects: every project it
// records disappears from the account, and without a row saying so the rows found through the
// other lists would read as a complete inventory. The refusal itself stays in force; the file
// is still not followed.
func listReadFailure(err error) warning {
	class := fsscan.ClassifyError(err)
	if class == fsscan.ClassAbsent {
		return warning{}
	}
	return warning{Code: warnProjectListUnreadable, Class: class}
}

// roamingRoot reports the account's redirected roaming application-data directory on
// Windows, where editors keep their workspace lists, or "" for the conventional location.
// The redirected path is never reported: it is read from the account's registry hive, so it
// is a value this table did not choose.
func roamingRoot(account fsscan.UserHome) (string, warning) {
	if runtime.GOOS != "windows" {
		return "", warning{}
	}
	resolved, redirected, ok := roamingAppDataFor(account.ID, account.Path)
	if !ok {
		return "", warning{Code: warnAppDataUndetermined}
	}
	if !redirected {
		return "", warning{}
	}
	if !devclients.WithinHome(resolved, account.Path) {
		return resolved, warning{Code: warnAppDataRedirectedOut}
	}
	return resolved, warning{}
}

// budgetCode distinguishes the two ways a scan stops short: the query went away, or the host
// is too slow for the schedule it is on.
func budgetCode(ctx context.Context) warnCode {
	if ctx.Err() != nil {
		return warnCancelledInHome
	}
	return warnBudgetExhaustedInHome
}

func budgetRemains(ctx context.Context, deadline time.Time) bool {
	return ctx.Err() == nil && time.Now().Before(deadline)
}
