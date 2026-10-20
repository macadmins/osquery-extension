package go_modules

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"
	"unicode/utf8"

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

// maxOutputBytes bounds the bytes of module rows one query returns across every account, as
// maxRows bounds their number. A row's size is bounded by rowBytes. 32 MiB is above the
// realistic output at the row cap, about 22 MiB, so it binds only when rows are unusually long,
// as a crafted manifest can make them: three 512-byte module paths and a long project path on
// each of 50,000 rows would otherwise be well over 100 MiB.
const maxOutputBytes = 32 << 20

// outputLimits is a number of module rows and a number of bytes, either as the caps on one
// query or as what remains of them.
type outputLimits struct {
	rows  int
	bytes int
}

// maxListSize bounds the read of ~/.codex/config.toml, each workspace.json and each
// recentProjects.xml, matching the
// cap mcp_servers applies to the same files.
const maxListSize = 1 << 20

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
	// openGoWork opens a project's go.work. Tests substitute it to return the refusal Windows
	// gives a storage provider's reparse point.
	openGoWork = fsscan.OpenBeneath
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
	GoDirective   string
	Toolchain     string
	SourceFile    string
	// NamedPath marks a row whose ProjectPath is a path a project_path constraint named, which
	// is published as the query wrote it.
	NamedPath    bool
	Entry        moduleEntry
	ScanComplete bool
	Warning      warning
}

// diagnosticRow builds a row that reports a finding instead of a module. It is never marked
// complete: it reports that something was not listed, and `WHERE scan_complete = 1` selects
// the rows an operator can rely on. A row about one account carries its uid and user_id, so
// `WHERE uid = ...` and `JOIN users USING (uid)` keep the rows explaining what is missing.
func diagnosticRow(user, uid, userID string, w warning) row {
	return row{User: user, UID: uid, UserID: userID, Warning: w}
}

// discoverAll lists the modules for every account the query asks about.
//
// The account roster comes from osquery's users table, through the extension socket. There is
// no filesystem fallback: if the socket cannot be reached osquery is not receiving rows
// either, and a guessed roster would only make that failure harder to see.
func discoverAll(ctx context.Context, clienter utils.OsqueryClienter,
	userFilter, pathFilter map[string]struct{}) []row {
	return discoverWithin(ctx, clienter, userFilter, pathFilter,
		outputLimits{rows: maxRows, bytes: maxOutputBytes})
}

// discoverWithin is discoverAll with the output limits supplied, so a test can reach them
// without writing tens of thousands of rows.
func discoverWithin(ctx context.Context, clienter utils.OsqueryClienter,
	userFilter, pathFilter map[string]struct{}, limits outputLimits) []row {
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
		// An omission with no name cannot be matched to a requested user, so it is reported
		// under each name the query asked about, as uncertainty about the roster rather than
		// as a statement that the requested account was not inspected.
		if omission.Name == "" {
			out = append(out, rosterRows(userFilter, warning{Code: warnRosterAccountUnnamed})...)
			continue
		}
		if !requested(userFilter, omission.Name) {
			continue
		}
		out = append(out, diagnosticRow(omission.Name, omission.UID, omission.ID,
			warning{Code: warnAccountNotInspected, Reason: omission.Code}))
		answered[omission.Name] = struct{}{}
	}
	if unusableHomes > 0 {
		out = append(out, diagnosticRow("", "", "",
			warning{Code: warnAccountsHomeUnusable, Count: unusableHomes}))
	}
	// An account that cannot log in keeps no projects. It is silent unless asked for by name,
	// and then it gets a real answer: "cannot log in" and "does not exist" are different facts.
	if userFilter != nil {
		for _, omission := range enumerated.NonLogin {
			if requested(userFilter, omission.Name) {
				out = append(out, diagnosticRow(omission.Name, omission.UID, omission.ID,
					warning{Code: warnAccountNotInspected, Reason: omission.Code}))
				answered[omission.Name] = struct{}{}
			}
		}
	}

	// A named path no published project_path can equal is not read for: one not written as
	// project_path publishes it, one redaction would change, or one longer than the collector
	// admits. namedPathRows reports the first kind. A set left empty reads nothing, which is
	// different from no constraint.
	scanFilter := pathFilter
	if pathFilter != nil {
		scanFilter = make(map[string]struct{}, len(pathFilter))
		for path := range pathFilter {
			publishedForm, redacted := namedPathForm(path)
			if publishedForm && !redacted && len(path) <= devclients.MaxProjectPathLen {
				scanFilter[path] = struct{}{}
			}
		}
	}

	// Accounts that share a home are scanned once and reported once each.
	scanned := make(map[string][]row, len(enumerated.Homes))
	remaining := limits
	for _, home := range enumerated.Homes {
		if !requested(userFilter, home.Name) {
			continue
		}
		answered[home.Name] = struct{}{}
		rows := rowsForHome(ctx, home, deadline, remaining, limits, scanFilter, scanned)
		remaining.rows -= moduleRows(rows)
		remaining.bytes -= outputBytes(rows, home)
		// A cap reached part way through this home leaves nothing for the next one, even when the
		// rows kept did not use the whole remainder, as they do not when the next row was too long
		// for the bytes left.
		byRows, byBytes := capReached(rows)
		if byRows {
			remaining.rows = 0
		}
		if byBytes {
			remaining.bytes = 0
		}
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
			out = append(out, diagnosticRow(name, "", "", warning{Code: warnAccountNotInRoster}))
		}
	}
	return append(out, namedPathRows(pathFilter, userFilter, enumerated.Homes, out)...)
}

// rowsForHome returns one rostered account's rows, labeled with its name and identity.
//
// A home already scanned for another account is reused before the time budget is consulted,
// because the budget bounds filesystem work and a cached result needs none: when two accounts
// share a home and the first scan finishes as the deadline passes, the second account still
// gets the rows. Cancellation is checked first, because a cancelled query wants nothing back.
// The output limits apply to cached rows too, since they count again for each account they are
// reported under.
//
// The home path alone is not the whole cache key on Windows, where discovery also reads the
// account's own registry hive; see devclients.ScanKey. pathFilter is the same for every account
// in one query, so a cached scan is the same scan another account sharing the home would make.
func rowsForHome(ctx context.Context, home fsscan.UserHome, deadline time.Time,
	remaining, limits outputLimits, pathFilter map[string]struct{},
	scanned map[string][]row) []row {
	if ctx.Err() != nil {
		return []row{diagnosticRow(home.Name, home.UID, home.ID, warning{Code: warnCancelledPreHome})}
	}
	key := devclients.ScanKey(home)
	rows, cached := scanned[key]
	// Each cap the account cannot fit within is reported, both when both are spent.
	var limitRows []row
	if (!cached && remaining.rows <= 0) || (cached && moduleRows(rows) > remaining.rows) {
		limitRows = append(limitRows, diagnosticRow(home.Name, home.UID, home.ID,
			warning{Code: warnRowLimitPreHome, Limit: int64(limits.rows)}))
	}
	if (!cached && remaining.bytes <= 0) || (cached && outputBytes(rows, home) > remaining.bytes) {
		limitRows = append(limitRows, diagnosticRow(home.Name, home.UID, home.ID,
			warning{Code: warnOutputSizePreHome, Limit: int64(limits.bytes)}))
	}
	if len(limitRows) > 0 {
		return limitRows
	}
	switch {
	case !cached:
		if !time.Now().Before(deadline) {
			return []row{diagnosticRow(home.Name, home.UID, home.ID, warning{Code: warnBudgetExhaustedPreHome})}
		}
		rows = discoverHome(ctx, home, deadline, remaining, limits, pathFilter)
		// A scan a cap stopped is this account's share of the output, not the home's inventory,
		// so it is not reused for another account sharing the home, which then meets the cap
		// before its own scan.
		if byRows, byBytes := capReached(rows); !byRows && !byBytes {
			scanned[key] = rows
		}
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
		return []row{diagnosticRow("", "", "", w)}
	}
	names := make([]string, 0, len(userFilter))
	for name := range userFilter {
		names = append(names, name)
	}
	sort.Strings(names)
	rows := make([]row, 0, len(names))
	for _, name := range names {
		rows = append(rows, diagnosticRow(name, "", "", w))
	}
	return rows
}

// namedPathRows reports each path a project_path constraint names that no row matches as
// published, so a query for one project that finds nothing says why instead of returning
// nothing. Each row carries the named path as the query wrote it, which SQLite's filter keeps.
// A path not written as project_path publishes it was not read, and is reported as such. A path
// inside the home of an account the query scanned gets one row for each such account with no row
// at that path, so two accounts that share a home are answered separately: a cap that stops the
// second one's scan leaves it this row, which the filter keeps, while its cap row has an empty
// project_path. Any other path is reported as a roster-level finding is, by rosterRows. A path redaction would change, and one
// longer than any published project_path, gets no row: carrying it would publish what redaction
// exists to remove, and a row carrying anything else is one SQLite's filter drops.
func namedPathRows(pathFilter, userFilter map[string]struct{}, homes []fsscan.UserHome,
	found []row) []row {
	if pathFilter == nil {
		return nil
	}
	type account struct{ user, path string }
	matched := make(map[account]struct{}, len(found))
	for _, r := range found {
		if r.ProjectPath != "" {
			matched[account{r.User, publishedPath(r.ProjectPath, r.Home)}] = struct{}{}
		}
	}
	paths := make([]string, 0, len(pathFilter))
	for path := range pathFilter {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var out []row
	for _, path := range paths {
		publishedForm, redacted := namedPathForm(path)
		if redacted || len(path) > devclients.MaxProjectPathLen {
			continue
		}
		if !publishedForm {
			for _, r := range rosterRows(userFilter, warning{Code: warnNamedPathNotPublished}) {
				r.ProjectPath, r.NamedPath = path, true
				out = append(out, r)
			}
			continue
		}
		owners := 0
		for _, home := range homes {
			if !requested(userFilter, home.Name) {
				continue
			}
			if !namedPathIn(home.Path, path) {
				continue
			}
			owners++
			if _, ok := matched[account{home.Name, path}]; ok {
				continue
			}
			r := diagnosticRow(home.Name, home.UID, home.ID, warning{Code: warnNamedPathNoRows})
			r.ProjectPath, r.Home, r.NamedPath = path, home.Path, true
			out = append(out, r)
		}
		if owners > 0 {
			continue
		}
		for _, r := range rosterRows(userFilter, warning{Code: warnNamedPathOutsideHomes}) {
			r.ProjectPath, r.NamedPath = path, true
			out = append(out, r)
		}
	}
	return out
}

// namedPathIn reports whether a path a project_path constraint names is inside home in the form
// project_path publishes for a project there: the home spelled as the roster spells it, byte for
// byte. Containment folds case on macOS and Windows, so `/users/alice/code` is contained in the
// home `/Users/Alice`, but the rows read for it publish `/Users/Alice/code`, which SQLite's filter
// drops, and the path would then be reported as yielding no rows although it was read.
func namedPathIn(home, path string) bool {
	rel, err := fsscan.ContainProjectPath(home, path, false)
	return err == nil && filepath.Join(home, rel) == path
}

// discoverHome lists the modules in every recorded project for one account. Each project's
// rows carry their own scan_complete, and a problem finding the projects is a warning row for
// the account. remaining is what the query can still return.
//
// pathFilter is the set of paths a `project_path =` constraint names, or nil. With one, the
// named paths inside this home are the projects, and no list is read; a home that contains none
// of them is not opened at all.
func discoverHome(ctx context.Context, account fsscan.UserHome, deadline time.Time,
	remaining, limits outputLimits, pathFilter map[string]struct{}) []row {
	home := account.Path
	var out []row
	note := func(w warning) { out = append(out, row{Home: home, Warning: w}) }

	// A string comparison, before anything is opened.
	var named []string
	if pathFilter != nil {
		for path := range pathFilter {
			if namedPathIn(home, path) {
				named = append(named, path)
			}
		}
		if len(named) == 0 {
			return nil
		}
		sort.Strings(named)
	}

	// The home is opened once, by the same probe as a project, with symlinks refused. A home this
	// process cannot open, such as root's when osqueryi runs as a user, would otherwise produce
	// one row per client list, each saying the list could not be read; one row says what an
	// operator needs, that the account was not inspected. mcp_servers makes the same check.
	//
	// Where the home is stored also decides which projects count as stored elsewhere. A home on a
	// network filesystem, as in many managed fleets, is where its user works, and its client lists
	// are read there anyway, so its projects on that kind of filesystem are read too.
	homeStorage := fsscan.ClassifyError(probeProject(home, "."))
	switch homeStorage {
	case fsscan.ClassNone, fsscan.ClassNetworkFilesystem, fsscan.ClassUserspaceFilesystem:
	default:
		note(warning{Code: warnHomeUnreadable, Class: homeStorage})
		return out
	}

	collector := devclients.NewCollector(home, devclients.MaxProjects)
	// Projects, and .code-workspace files, stored somewhere other than this machine's disk,
	// counted by the class that said so: a cloud provider's folder or content, a network
	// filesystem or a userspace one.
	storedElsewhere := map[fsscan.ErrClass]int{}
	if pathFilter != nil {
		// A named path goes through the same containment and caps a recorded one does.
		for _, path := range named {
			collector.Add(path, devclients.OriginQuery, false)
		}
	} else if !addRecordedProjects(ctx, account, homeStorage, deadline, collector, storedElsewhere,
		note) {
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
			Limit: devclients.MaxProjects})
	}

	// Sorted by path, so the row order depends on the filesystem rather than on which client
	// recorded a project first.
	projects := append([]devclients.Project(nil), collector.Projects()...)
	sort.Slice(projects, func(i, j int) bool { return projects[i].Rel < projects[j].Rel })
	var used outputLimits
	goWorkspaces := 0
	// Project directories that exist and could not be opened, counted by why, so a directory
	// macOS denies without Full Disk Access is one count rather than a row for each module file
	// that was never reached.
	dirUnreadable := map[fsscan.ErrClass]int{}
	for _, project := range projects {
		// The checks run in order of cost, each at the first point it can be answered. The
		// cloud-folder rule is a string comparison on the recorded path.
		if underCloudStorage(project.Rel) {
			storedElsewhere[fsscan.ClassCloudPlaceholder]++
			continue
		}
		if !fsscan.BudgetRemains(ctx, deadline) {
			note(warning{Code: budgetCode(ctx)})
			break
		}
		// One directory open per project. A network mount is decided here, before any file in
		// it is opened. A missing or symlinked directory is skipped too, with the same silence
		// the file reads would give it, and any other failure to open it is counted once by
		// class rather than left for each read.
		switch storage := fsscan.ClassifyError(probeProject(home, project.Rel)); {
		// A directory a provider holds, which on Windows the probe reports from its reparse
		// point, is counted with the cloud folders rather than as unreadable.
		case storage == fsscan.ClassCloudPlaceholder:
			storedElsewhere[storage]++
			continue
		case storage == fsscan.ClassNetworkFilesystem && homeStorage != storage:
			storedElsewhere[storage]++
			continue
		case storage == fsscan.ClassUserspaceFilesystem && homeStorage != storage:
			storedElsewhere[storage]++
			continue
		case storage == fsscan.ClassAbsent, storage == fsscan.ClassRefusedPath:
			continue
		case storage != fsscan.ClassNone && storage != fsscan.ClassNetworkFilesystem &&
			storage != fsscan.ClassUserspaceFilesystem:
			dirUnreadable[storage]++
			continue
		}
		var files [2]projectFile
		stopped, partial := false, false
		for index, file := range []string{goModFile, goSumFile} {
			// Checked before each file rather than each project, so one project's second file
			// is not read after the budget has run out. What the first file yielded is still
			// listed, marked incomplete, because the project's other file was not read.
			if !fsscan.BudgetRemains(ctx, deadline) {
				note(warning{Code: budgetCode(ctx)})
				stopped, partial = true, index > 0
				break
			}
			files[index] = readModuleFile(home, homeStorage, project, file)
			if files[index].cloudStored {
				break
			}
		}
		if files[0].cloudStored || files[1].cloudStored {
			// A module file whose content is not on this disk: the project is stored with its
			// provider, and a partial listing from the other file would misdescribe it.
			storedElsewhere[fsscan.ClassCloudPlaceholder]++
			continue
		}
		// One file refused as a symbolic link beside a readable other file: the readable file's
		// rows are published, marked incomplete, with a finding naming the refused file. Without
		// it, go.sum rows beside a refused go.mod would read as versions go.mod does not require.
		for index, file := range []string{goModFile, goSumFile} {
			other := files[1-index]
			if files[index].linkRefused && (other.present || len(other.findings) > 0) {
				files[index].findings = append(files[index].findings, row{Home: home,
					ProjectPath: project.Abs, SourceFile: file, Warning: warning{Code: warnSourceLinkRefused}})
			}
		}
		// A go.work at the root names other modules, which this version does not read. It is
		// counted whether or not the root has a go.mod: without one, the project would look as
		// if it had no Go dependencies; with one, only the root module is listed.
		if !stopped {
			if !fsscan.BudgetRemains(ctx, deadline) {
				note(warning{Code: budgetCode(ctx)})
				stopped = true
			} else if workspaceAt(home, homeStorage, project.Rel) {
				goWorkspaces++
			}
		}
		rows := projectRows(home, project, files[0], files[1])
		if partial {
			for index := range rows {
				rows[index].ScanComplete = false
			}
		}
		size := outputBytes(rows, account)
		if used.rows+moduleRows(rows) > remaining.rows || used.bytes+size > remaining.bytes {
			// Keep what fits, report the limit that was reached, and stop. The kept rows of this
			// project are marked incomplete; the rows of projects before it are unchanged.
			room := outputLimits{rows: remaining.rows - used.rows, bytes: remaining.bytes - used.bytes}
			kept, byRows, byBytes := keepModuleRows(rows, room, account)
			out = append(out, kept...)
			if byRows {
				note(warning{Code: warnRowLimitInHome, Limit: int64(limits.rows)})
			}
			if byBytes {
				note(warning{Code: warnOutputSizeInHome, Limit: int64(limits.bytes)})
			}
			break
		}
		used.rows += moduleRows(rows)
		used.bytes += size
		out = append(out, rows...)
		if stopped {
			break
		}
	}
	// Counted rather than listed, like projects outside the home: where a project is stored
	// defines what this table reads, so these leave scan_complete alone.
	for _, stored := range []struct {
		class fsscan.ErrClass
		code  warnCode
	}{
		{fsscan.ClassCloudPlaceholder, warnProjectInCloudStorage},
		{fsscan.ClassNetworkFilesystem, warnProjectOnNetworkFS},
		{fsscan.ClassUserspaceFilesystem, warnProjectOnUserspaceFS},
	} {
		if count := storedElsewhere[stored.class]; count > 0 {
			note(warning{Code: stored.code, Count: count})
		}
	}
	if goWorkspaces > 0 {
		note(warning{Code: warnWorkspaceUnsupported, Count: goWorkspaces})
	}
	classes := make([]fsscan.ErrClass, 0, len(dirUnreadable))
	for class := range dirUnreadable {
		classes = append(classes, class)
	}
	sort.Slice(classes, func(i, j int) bool { return classes[i] < classes[j] })
	for _, class := range classes {
		note(warning{Code: warnProjectDirUnreadable, Count: dirUnreadable[class], Class: class})
	}
	return out
}

// addRecordedProjects adds the projects every client records for one account to collector, and
// counts in storedElsewhere the .code-workspace files stored somewhere other than this
// machine's disk. It returns false, after noting why, when the budget ran out partway.
func addRecordedProjects(ctx context.Context, account fsscan.UserHome, homeStorage fsscan.ErrClass,
	deadline time.Time, collector *devclients.Collector, storedElsewhere map[fsscan.ErrClass]int,
	note func(warning)) bool {
	home := account.Path
	appData, appDataNote := roamingRoot(account)
	if !appDataNote.empty() {
		note(appDataNote)
	}

	// The lists fill the collector in the order Go developers use the clients, so a project cap
	// reached early drops the least-used ones: the VS Code family, then JetBrains IDEs, then the
	// coding agents. The 2025 Go Developer Survey puts VS Code at 37% and GoLand at 28%.
	workspaces := devclients.WorkspaceFolders(ctx, home, appData, homeStorage, deadline,
		readOpts(maxListSize))
	for class, count := range workspaces.StoredElsewhere {
		storedElsewhere[class] += count
	}
	for _, listing := range workspaces.Listings {
		if listing.Class != fsscan.ClassNone {
			note(warning{Code: warnWorkspaceListUnreadable, Class: listing.Class,
				Source: listing.Origin})
			continue
		}
		if listing.Truncated {
			note(warning{Code: warnWorkspaceListTruncated, Count: listing.Count,
				Limit: int64(listing.Limit), Source: listing.Origin})
		}
		// Records past the most recent MaxWorkspaceDirs describe what the table reads.
		if listing.Older > 0 {
			note(warning{Code: warnWorkspaceRecordsOlder, Count: listing.Older,
				Limit: devclients.MaxWorkspaceDirs, Source: listing.Origin})
		}
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
		return false
	}

	// JetBrains IDEs keep one recent-projects list per product and version. A list that exists
	// and cannot be read or parsed is a lost list of projects, so it is reported the way an
	// unreadable ~/.claude.json is.
	jetbrains := devclients.JetBrainsProjects(ctx, home, appData, deadline, readOpts(maxListSize))
	for _, listing := range jetbrains.Listings {
		if listing.Truncated {
			note(warning{Code: warnProjectListTruncated, Count: listing.Count,
				Limit: int64(listing.Limit), Source: listing.Origin})
			continue
		}
		note(warning{Code: warnProjectListUnreadable, Class: listing.Class, Source: listing.Origin})
	}
	if lost := jetbrains.UnreadableRecords + jetbrains.MalformedRecords; lost > 0 {
		note(warning{Code: warnProjectListUnreadable, Count: lost,
			Source: devclients.OriginJetBrainsRecent})
	}
	for _, folder := range jetbrains.Folders {
		collector.Add(folder.Recorded, folder.Origin, folder.FileURL)
	}
	if jetbrains.Stopped {
		note(warning{Code: budgetCode(ctx)})
		return false
	}

	return addAgentLists(ctx, home, homeStorage, deadline, collector, note)
}

// workspaceAt reports whether a project has a go.work at its root. Only its presence is
// reported, so nothing is read. A regular file counts, and a directory or a device named go.work
// does not. A symbolic link named go.work, a common way to share one workspace file, counts when
// linkTarget follows it to a regular file, and counts unopened when linkTarget declines or the
// target is itself a link, because the link still shows the project is a workspace. A link whose
// target cannot exist, or whose target is a directory or a device, does not count. A go.work,
// or a followed link's target, that is a storage provider's reparse point, which Windows refuses
// before opening it, counts unopened for the same reason, whatever the provider holds there.
func workspaceAt(home string, homeStorage fsscan.ErrClass, projRel string) bool {
	file, err := openGoWork(home, filepath.Join(projRel, goWorkFile))
	if fsscan.ClassifyError(err) == fsscan.ClassRefusedPath {
		target, link := linkTarget(home, homeStorage, projRel, goWorkFile)
		switch link {
		case fsscan.LinkDeclined:
			return true
		case fsscan.LinkAbsent:
			return false
		}
		file, err = openGoWork(home, target)
		if fsscan.ClassifyError(err) == fsscan.ClassRefusedPath {
			return true // a link to another link, which is not walked
		}
	}
	if fsscan.ClassifyError(err) == fsscan.ClassCloudPlaceholder {
		return true
	}
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	return err == nil && info.Mode().IsRegular()
}

// linkTarget resolves a project's symlinked module file, or go.work, by one hop, under
// fsscan.FollowLink's rules, with this package's storage checks so tests can substitute them.
func linkTarget(home string, homeStorage fsscan.ErrClass, projRel, file string) (string,
	fsscan.LinkResult) {
	return fsscan.FollowLink(home, homeStorage, projRel, file, linkChecks())
}

// linkChecks hands fsscan the storage checks a link target's directory passes: the same ones,
// and the same test seams, a recorded project's directory passes.
func linkChecks() fsscan.LinkChecks {
	return fsscan.LinkChecks{UnderCloudStorage: underCloudStorage, ProbeDir: probeProject}
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

// capReached reports which output cap stopped a home's scan part way through, if either did.
func capReached(rows []row) (byRows, byBytes bool) {
	for _, r := range rows {
		switch r.Warning.Code {
		case warnRowLimitInHome:
			byRows = true
		case warnOutputSizeInHome:
			byBytes = true
		}
	}
	return byRows, byBytes
}

// rowBytes is the most one module row can take in the output: the row as publish renders it for
// account, as a JSON object of column names and string values, each at its jsonWidth. Measured
// from the published row rather than the stored values, so a publication rule that lengthens a
// value, as redaction can lengthen a project path, and a column added later are both counted.
func rowBytes(r row, account fsscan.UserHome) int {
	r.User, r.UID, r.UserID = account.Name, account.UID, account.ID
	published := publish(r)
	// Two braces and a comma between each pair of columns.
	total := 2 + len(published) - 1
	for column, value := range published {
		// The quotes around the name and the value, and the colon between them.
		total += jsonWidth(column) + jsonWidth(value) + 5
	}
	return total
}

// jsonWidth is the most bytes s can take as a JSON string value: a quote, a backslash and the
// control characters with a short escape (\b, \f, \n, \r, \t) are two bytes; <, > and & are six
// as Go's encoder escapes them, and so is every other control character, each byte of invalid
// UTF-8, and U+2028 or U+2029. The module values are grammar-checked ASCII, and
// fsscan.ContainProjectPath refuses a recorded project path with a control character anywhere,
// its home prefix included, but the account name, uid and user_id come from the roster
// unfiltered.
func jsonWidth(s string) int {
	width := 0
	for index := 0; index < len(s); {
		char, size := utf8.DecodeRuneInString(s[index:])
		switch {
		case char == utf8.RuneError && size == 1, char == '\u2028', char == '\u2029':
			width += 6
		case char == '"', char == '\\', char == '\b', char == '\f', char == '\n', char == '\r', char == '\t':
			width += 2
		case char < 0x20:
			width += 6
		case char == '<', char == '>', char == '&':
			width += 6
		default:
			width += size
		}
		index += size
	}
	return width
}

// outputBytes sums rowBytes over the module rows. Findings are not counted, as they are not
// counted against maxRows: a diagnostic row is kept whatever the limits.
func outputBytes(rows []row, account fsscan.UserHome) int {
	total := 0
	for _, r := range rows {
		if r.Entry.Path != "" {
			total += rowBytes(r, account)
		}
	}
	return total
}

// keepModuleRows returns rows with every finding and the module rows that fit room, in order,
// stopping at the first that does not, and reports which limits that row met: the row count,
// the bytes, or both. The project's listing is cut short, so the module rows it keeps are
// marked incomplete.
func keepModuleRows(rows []row, room outputLimits, account fsscan.UserHome) ([]row, bool, bool) {
	kept := make([]row, 0, len(rows))
	stopped, byRows, byBytes := false, false, false
	for _, r := range rows {
		if r.Entry.Path != "" {
			if stopped {
				continue
			}
			size := rowBytes(r, account)
			if room.rows <= 0 || size > room.bytes {
				stopped, byRows, byBytes = true, room.rows <= 0, size > room.bytes
				continue
			}
			room.rows--
			room.bytes -= size
			r.ScanComplete = false
		}
		kept = append(kept, r)
	}
	return kept, byRows, byBytes
}

// projectFile is what one module file in a project yielded: its parse result, and a diagnostic
// row for each finding about it.
type projectFile struct {
	result   parseResult
	findings []row
	// cloudStored is set when the file's content is held by a cloud storage provider rather
	// than on this disk. The project is then counted and not listed.
	cloudStored bool
	// linkRefused is set when the file is a symbolic link that linkTarget did not follow, or
	// that names another link. On its own that is silent, like a project behind a symlink;
	// beside a readable other file it is a finding, because that file's rows would otherwise
	// read as complete.
	linkRefused bool
	// present is set when the file was read, whether or not it held an entry, so a refused
	// sibling is reported beside an empty go.sum or a go.mod with no requirements too.
	present bool
}

// projectRows merges a project's go.mod and go.sum into one row per module version, followed by
// the findings about either file. A finding about either file marks every module row for the
// project incomplete, because each row's columns can come from both files. A file that is
// absent is not a finding: a project with no go.sum has rows with empty go.sum columns, and they
// are complete.
func projectRows(home string, project devclients.Project, goMod, goSum projectFile) []row {
	base := row{Home: home, ProjectPath: project.Abs, ProjectModule: goMod.result.ProjectModule,
		GoDirective: goMod.result.GoDirective, Toolchain: goMod.result.ToolchainDirective}
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
// row for each would bury everything else. A symbolic link is followed one hop when
// fsscan.ReadLinkTarget accepts its target, which is then read with every check a module file
// gets, so a dangling link is absent, a hard-linked target is refused, and an oversized target
// is too large. A link it does not follow keeps the refusal, whatever the target is, and the
// project itself is local, so its other file is still listed.
func readModuleFile(home string, homeStorage fsscan.ErrClass, project devclients.Project,
	file string) projectFile {
	finding := row{Home: home, ProjectPath: project.Abs, SourceFile: file}
	data, err := fsscan.ReadProjectFile(home, project.Rel, file, readOpts(maxGoFileSize))
	if fsscan.ClassifyError(err) == fsscan.ClassRefusedPath {
		data, err = fsscan.ReadLinkTarget(home, homeStorage, project.Rel, file,
			readOpts(maxGoFileSize), linkChecks(), err)
	}
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
	if result.DroppedValues > 0 {
		findings = append(findings, warning{Code: warnValuesDropped, Count: result.DroppedValues})
	}
	found := projectFile{result: result, present: true}
	for _, w := range findings {
		r := finding
		r.Warning = w
		found.findings = append(found.findings, r)
	}
	return found
}

// readFailure classifies a failed read of a module file, or reports that there is nothing to
// say. Absence is silent; readModuleFile handles a cloud placeholder and a symlink it did not
// follow before this. A userspace filesystem and a refused hard link are each a file that exists and
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
func addAgentLists(ctx context.Context, home string, homeStorage fsscan.ErrClass,
	deadline time.Time, collector *devclients.Collector, note func(warning)) bool {
	if !fsscan.BudgetRemains(ctx, deadline) {
		note(warning{Code: budgetCode(ctx)})
		return false
	}
	if entries, w := readClaudeList(home, homeStorage); !w.empty() {
		w.Source = devclients.OriginClaudeJSON
		note(w)
	} else {
		for _, entry := range entries {
			collector.Add(entry.Recorded, devclients.OriginClaudeJSON, false)
		}
	}
	if !fsscan.BudgetRemains(ctx, deadline) {
		note(warning{Code: budgetCode(ctx)})
		return false
	}
	if entries, w := readCodexList(home, homeStorage); !w.empty() {
		w.Source = devclients.OriginCodexTOML
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
func readClaudeList(home string, homeStorage fsscan.ErrClass) ([]devclients.ClaudeEntry, warning) {
	data, err := readListFile(home, homeStorage, devclients.ClaudeListPath,
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
func readCodexList(home string, homeStorage fsscan.ErrClass) ([]devclients.CodexEntry, warning) {
	data, err := readListFile(home, homeStorage, devclients.CodexListPath, readOpts(maxListSize))
	if err != nil {
		return nil, listReadFailure(err)
	}
	entries, err := devclients.CodexEntries(data)
	if err != nil {
		return nil, warning{Code: warnProjectListUnreadable}
	}
	return entries, warning{}
}

// readListFile reads a project-list file, relative to the home. A list file that is a symbolic
// link is followed one hop under fsscan.ReadLinkTarget's rules, as a dotfile manager links one
// into place, and its target is read as the list itself is; a link it declines keeps the
// refusal.
func readListFile(home string, homeStorage fsscan.ErrClass, rel string,
	opts fsscan.ReadOpts) ([]byte, error) {
	data, err := fsscan.ReadBoundedUnder(home, rel, opts)
	if fsscan.ClassifyError(err) == fsscan.ClassRefusedPath {
		dir, name := filepath.Split(filepath.FromSlash(rel))
		checks := linkChecks()
		checks.Read = fsscan.ReadBoundedUnder
		data, err = fsscan.ReadLinkTarget(home, homeStorage, dir, name, opts, checks, err)
	}
	return data, err
}

// listReadFailure classifies a failed read of a project-list file. Only absence is silent: most
// accounts do not use every client.
//
// A refused symlink, one readListFile did not follow, is reported, unlike a module-file probe,
// where a refusal is silent. A refused list is not a missing project but a missing list of
// projects: every project it records disappears from the account, and without a row saying so
// the rows found through the other lists would read as a complete inventory.
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
