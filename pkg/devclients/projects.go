package devclients

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

// Project-local files are found through the projects each client records, never by walking
// the filesystem.
//
// A walk is wrong in three ways on a shared host. It is nondeterministic: many roots per home
// under a budget shared across every home, so the first account's source tree can exhaust the
// allowance and the rows a second account gets depend on how big the first account's checkout
// is. It downloads files: ~/Documents and ~/Desktop are iCloud-backed under "Optimize Mac
// Storage", and reading a dehydrated file is a network fetch. And it blocks: one dead
// automount, offline network home or Windows oplock stalls the walk and everything osquery has
// scheduled behind it.
//
// A walk also finds files rather than projects. It cannot tell a project the user works in
// from a vendored copy of someone else's repository or a plugin marketplace cache.
//
// Every client keeps a list of the projects its user opened. Reading that list and opening
// known filenames inside each entry is bounded by the number of projects rather than by the
// size of the disk, deterministic because the list is a file, and limited to directories a
// person opened.
//
// The cost, which each table using this package states in its README: a project the user has
// never opened in a participating client is invisible, and so is one recorded only by a client
// this package has no reader for.

// MaxProjects bounds the distinct project directories one home contributes, across every
// client's list. A directory several clients record counts once, but a repository opened at its
// root in one client and at a subdirectory in another counts twice, and a developer who uses
// several editors accumulates entries in each, so a cap reached early drops whole clients. Each
// project costs one to three component-wise opens, most of which fail at once because most
// recorded projects hold none of the files a table looks for, so 1,000 is cheap; the query
// budget still bounds the work, and a caller reports exceeding the cap rather than truncating
// silently. The development machine records about 30 projects each for Claude Code and Codex.
const MaxProjects = 1000

// MaxProjectPathLen bounds the absolute path of a recorded project. macOS's PATH_MAX is 1,024
// bytes, so no usable path there is longer, and on Linux, where it is 4,096, a project directory
// deeper than 1,024 bytes is implausible. Every row about a project carries its path, and a
// table keeps its diagnostic rows whatever its output caps, so without this bound a path of any
// length recorded in a list the user writes would be published once per finding. A longer
// path is counted as malformed, like any other unusable recorded path.
const MaxProjectPathLen = 1024

// MaxRecordedPathLen bounds a recorded value before it is contained: percent-encoding at most
// triples a path, and "file://localhost/" is the longest prefix the reader accepts, so a longer
// value cannot contain to a path within MaxProjectPathLen. The list readers blank a longer value
// as soon as they decode it, so a list of large records is not held in memory, and Collector.Add
// then counts it as malformed.
const MaxRecordedPathLen = 3*MaxProjectPathLen + len("file://localhost/")

// MaxWorkspaceDirs bounds the records read from one fork's workspaceStorage: the 500 most
// recently modified of its generated-name directories, each costing a read of a small JSON
// file.
//
// Separate from MaxProjects because it bounds a different thing: one directory listing per
// VS Code fork. VS Code creates one of these directories per workspace ever opened and never
// prunes them, so on a long-lived machine most are projects nobody has opened in years. The
// editor writes the directory's state.vscdb while the workspace is open, which updates the
// directory's modification time, so the most recently modified are the projects in use.
const MaxWorkspaceDirs = 500

// MaxWorkspaceEntries bounds the entries listed in one fork's workspaceStorage before the most
// recent MaxWorkspaceDirs are chosen. Each costs one fstatat, so a directory of tens of
// thousands of records costs a bounded amount of work; a directory with more is reported as
// truncated, and only the entries read are ordered.
const MaxWorkspaceEntries = 5000

// Origin names which client's list recorded a project. Closed, and reported rather than
// inferred, because the answer is not recoverable from the path: the same directory can be
// recorded by several clients.
type Origin string

const (
	OriginClaudeJSON Origin = "claude_json"
	OriginCodexTOML  Origin = "codex_toml"

	// One origin per editor, not one for the whole VS Code family. The forks share the
	// workspaceStorage layout, but sharing a record format establishes nothing about which
	// editor opened a project or whose configuration it would load, and the enumeration knows
	// which fork's directory it is reading.
	OriginVSCodeWorkspace   Origin = "vscode_workspace"
	OriginCursorWorkspace   Origin = "cursor_workspace"
	OriginWindsurfWorkspace Origin = "windsurf_workspace"

	// OriginJetBrainsRecent covers every JetBrains IDE -- GoLand, IntelliJ IDEA, PyCharm and
	// the rest -- because they share one recent-projects format and none of them has a
	// project-scoped file another reader here depends on.
	OriginJetBrainsRecent Origin = "jetbrains_recent"

	// OriginQuery is a project the query named, in a constraint on the column that publishes a
	// project's path, rather than one a client recorded.
	OriginQuery Origin = "query"
)

// workspaceOriginFor maps a fork's client name to the origin its workspace list carries.
// Keyed on the client rather than the directory, because Code, Code - Insiders and VSCodium
// all report as `vscode`: they are the same editor and one origin is correct for them.
var workspaceOriginFor = map[string]Origin{
	"vscode":   OriginVSCodeWorkspace,
	"cursor":   OriginCursorWorkspace,
	"windsurf": OriginWindsurfWorkspace,
}

// ClaudeListPath and CodexListPath name the two files, relative to a home, that hold Claude
// Code's and Codex's project lists.
const (
	ClaudeListPath = ".claude.json"
	CodexListPath  = ".codex/config.toml"
)

// ClaudeListMaxSize is the read cap for ~/.claude.json.
//
// Larger than a typical configuration cap because the project list is that file, so its size
// decides whether an account has a project inventory at all. The size is driven by something
// no operator can reason about: on the development machine ~/.claude.json is 94,827 bytes, of
// which 43% is `cachedGrowthBookFeatures`, the client's own feature-flag cache, which grows on
// its own schedule.
//
// The cost is real: json.Unmarshal of a 4 MiB document allocates several times that, per
// account, per query. 4 MiB is roughly forty times the real file, which leaves room for years
// of that cache without allowing an unbounded read. Streaming the file with
// json.Decoder.Token() and skipping every top-level key but the ones a table reads would remove
// the cost; that replaces the decoder rather than adjusting a constant.
const ClaudeListMaxSize = 4 << 20 // 4 MiB

// StripBOM removes a UTF-8 byte-order mark. Go's encoding/json rejects a BOM, and a file
// written by a Windows editor can start with one.
func StripBOM(data []byte) []byte {
	return bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
}

// ErrNullDocument reports a JSON document that is the literal null where an object is required.
var ErrNullDocument = errors.New("devclients: the document is null, not an object")

// NullDocument reports whether a JSON document is the literal null. encoding/json decodes null
// into a struct or a map without an error and leaves it zero, so a reader that relies on the
// error alone takes a null document for an empty one. Every other value that is not an object
// fails the decode.
func NullDocument(data []byte) bool {
	return string(bytes.Trim(data, " \t\r\n")) == "null"
}

// Project is one recorded project that passed containment.
type Project struct {
	// Rel is relative to the home and has been through fsscan.ContainProjectPath. It is the
	// only field a read may use: the guarantee is not "this string starts with the home" but
	// "every component from the home down was opened with symlinks refused", and that is a
	// property of the relative form.
	Rel string

	// Abs is for reporting only.
	Abs string

	// Origins records every client list that named this project. A set, because the same
	// directory is often recorded by several clients and a table may need to know each one.
	Origins map[Origin]struct{}
}

// Refusals counts recorded projects that were not admitted, by reason. Counts rather than
// paths: a path inside a user's home is not publishable, and a count and a reason are what an
// operator can act on anyway. A deleted project is not a refusal and is not counted -- it is
// the common case on any long-lived workstation, because nobody prunes a project history.
type Refusals struct {
	Outside   int  // the recorded path is not inside the home
	Remote    int  // a URL for a remote workspace, such as vscode-remote://
	Malformed int  // not a usable absolute path or file:// URL
	Truncated bool // MaxProjects, or the caller's limit, was reached
}

// Collector applies containment to each recorded path, merges a directory recorded by several
// clients into one project, and counts the refusals.
type Collector struct {
	home     string
	limit    int
	index    map[string]int
	projects []Project
	refusals Refusals
}

// NewCollector returns a Collector for one home that admits at most limit projects.
func NewCollector(home string, limit int) *Collector {
	return &Collector{home: home, limit: limit, index: make(map[string]int)}
}

// Add contains one recorded path and records it under origin.
//
// It returns the project's index in Projects and whether the path was admitted. A path already
// admitted from another list returns its existing index with origin added, so a caller that
// keeps per-project evidence beside the Collector can merge it: the index is equal to the
// caller's count of projects for a new one and below it for a repeat. allowFileURL admits a
// file:// URL, which is how VS Code records a workspace folder.
//
// The order matters and is fixed: containment first, then the repeat check, then the limit.
// A repeat is merged even when the limit has been reached, because it adds no project.
func (c *Collector) Add(recorded string, origin Origin, allowFileURL bool) (int, bool) {
	// A recorded value longer than MaxRecordedPathLen cannot contain to a usable path, so it is
	// refused before it is parsed.
	if len(recorded) > MaxRecordedPathLen {
		c.refusals.Malformed++
		return -1, false
	}
	rel, err := fsscan.ContainProjectPath(c.home, recorded, allowFileURL)
	if err == nil && len(filepath.Join(c.home, rel)) > MaxProjectPathLen {
		c.refusals.Malformed++
		return -1, false
	}
	if err != nil {
		switch fsscan.ClassifyError(err) {
		case fsscan.ClassNotContained:
			c.refusals.Outside++
		case fsscan.ClassUnsupportedOrigin:
			c.refusals.Remote++
		default:
			c.refusals.Malformed++
		}
		return -1, false
	}
	key := fsscan.SamePathKey(rel)
	if existing, seen := c.index[key]; seen {
		c.projects[existing].Origins[origin] = struct{}{}
		return existing, true
	}
	if len(c.projects) >= c.limit {
		c.refusals.Truncated = true
		return -1, false
	}
	c.index[key] = len(c.projects)
	c.projects = append(c.projects, Project{
		Rel:     rel,
		Abs:     filepath.Join(c.home, rel),
		Origins: map[Origin]struct{}{origin: {}},
	})
	return len(c.projects) - 1, true
}

// boundedRecorded returns recorded, or "" when it is longer than MaxRecordedPathLen. A list
// reader keeps every folder it decodes until the collector sees them, and a record can be as
// large as its file cap, so a long value is blanked at once; Collector.Add counts the empty
// value as malformed, as it would have counted the long one.
func boundedRecorded(recorded string) string {
	if len(recorded) > MaxRecordedPathLen {
		return ""
	}
	return recorded
}

// Projects returns the admitted projects in the order they were first admitted.
func (c *Collector) Projects() []Project { return c.projects }

// Refusals returns the counts of recorded paths that were not admitted.
func (c *Collector) Refusals() Refusals { return c.refusals }

// ClaudeEntry is one project recorded in ~/.claude.json: the key, which is the project path as
// Claude recorded it, and the entry's value, undecoded.
//
// The value is handed back raw on purpose. The same object carries `lastSessionFirstPrompt`,
// which is the literal text of the last thing the user typed at the client, and `history`. A
// caller that needs fields from it decodes them into a struct that names only those fields, so
// nothing else in the object is one field access from a column. A caller that needs only the
// path ignores Raw.
type ClaudeEntry struct {
	Recorded string
	Raw      json.RawMessage
}

// ClaudeEntries lists the projects recorded in ~/.claude.json, sorted by path. A document that is
// not JSON, or is null, is an error.
//
// Sorted before anything is decided: map iteration order is random, and a cap applied later
// would otherwise admit a different set of projects on every run, which differential logging
// reports as rows removed and re-added on an unchanged host.
func ClaudeEntries(data []byte) ([]ClaudeEntry, error) {
	var doc struct {
		Projects map[string]json.RawMessage `json:"projects"`
	}
	data = StripBOM(data)
	if NullDocument(data) {
		return nil, ErrNullDocument
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	out := make([]ClaudeEntry, 0, len(doc.Projects))
	for key, raw := range doc.Projects {
		out = append(out, ClaudeEntry{Recorded: boundedRecorded(key), Raw: raw})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Recorded < out[j].Recorded })
	return out, nil
}

// CodexEntry is one project recorded in ~/.codex/config.toml as a [projects."<path>"] table.
type CodexEntry struct {
	Recorded string
	value    toml.Primitive
	metadata toml.MetaData
}

// Decode decodes the entry's table into target.
//
// The value is held as a primitive until a caller asks. Codex's per-project tables carry
// settings a caller may not use, and decoding a value is how a format's unrelated fields start
// costing whole files: a field with an unexpected type fails the decode. A caller that needs
// only the path never decodes, and so cannot fail that way.
func (e CodexEntry) Decode(target any) error {
	return e.metadata.PrimitiveDecode(e.value, target)
}

// CodexEntries lists the projects recorded in ~/.codex/config.toml, sorted by path.
func CodexEntries(data []byte) ([]CodexEntry, error) {
	var doc struct {
		Projects map[string]toml.Primitive `toml:"projects"`
	}
	metadata, err := toml.Decode(string(data), &doc)
	if err != nil {
		return nil, err
	}
	out := make([]CodexEntry, 0, len(doc.Projects))
	for key, value := range doc.Projects {
		out = append(out, CodexEntry{Recorded: boundedRecorded(key), value: value, metadata: metadata})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Recorded < out[j].Recorded })
	return out, nil
}

// ListedFolder is one project an editor recorded, exactly as it wrote it, with the origin
// of the editor that recorded it. FileURL is true when Recorded is a file:// URL, as VS Code
// writes it, and false when it is a path, as JetBrains writes it after placeholder expansion.
type ListedFolder struct {
	Recorded string
	Origin   Origin
	FileURL  bool
}

// DirListing is one editor directory whose records were not all read: a VS Code fork's
// workspaceStorage, or the JetBrains configuration directory.
type DirListing struct {
	// Class says why the listing failed; ClassNone when it did not.
	Class fsscan.ErrClass
	// Truncated is true when the directory, or a .code-workspace file's folders, held more than
	// Limit entries and Count were read.
	Truncated bool
	Count     int
	Limit     int
	// Older counts the workspaceStorage records read and not inspected, because
	// MaxWorkspaceDirs more recently modified ones were kept. Every directory of one origin
	// is summed into one listing.
	Older int
	// Origin names the client whose list this is, so a warning about it can say which.
	Origin Origin
}

// ProjectListScan is what one editor family's project lists yielded for one home: the
// VS Code family's workspaceStorage records, from WorkspaceFolders, or the JetBrains IDEs'
// recentProjects.xml files, from JetBrainsProjects.
type ProjectListScan struct {
	Folders []ListedFolder

	// Listings holds each directory that failed, was cut short or had older records left
	// unread, in the order met.
	Listings []DirListing

	// UnreadableRecords counts record files, workspace.json or recentProjects.xml, that exist
	// and could not be read: a permission failure, the size cap, a refused hard link, content a
	// cloud provider holds. Absence is not counted, because a workspaceStorage directory outlives
	// the workspace it was created for and most entries have no readable record.
	UnreadableRecords int

	// MalformedRecords counts record files that were read and did not parse. Counted apart
	// from unreadable ones because the remedies differ.
	MalformedRecords int

	// StoredElsewhere counts the .code-workspace files not read because they are stored
	// somewhere other than this machine's disk, by the class that said so:
	// fsscan.ClassCloudPlaceholder, ClassNetworkFilesystem or ClassUserspaceFilesystem.
	StoredElsewhere map[fsscan.ErrClass]int

	// Stopped is true when ctx was cancelled or deadline passed before the enumeration ended.
	Stopped bool
}

// storedElsewhere counts one workspace file stored somewhere other than this machine's disk.
func (scan *ProjectListScan) storedElsewhere(class fsscan.ErrClass) {
	if scan.StoredElsewhere == nil {
		scan.StoredElsewhere = map[fsscan.ErrClass]int{}
	}
	scan.StoredElsewhere[class]++
}

// addListing records a listing. A failed one is kept per directory, with its own class; the
// others are merged per origin and limit, so the directories one origin covers -- Code,
// Code - Insiders and VSCodium, and the snap and flatpak roots -- report once, with their older
// records summed.
func (scan *ProjectListScan) addListing(listing DirListing) {
	if listing.Class == fsscan.ClassNone {
		for index := range scan.Listings {
			existing := &scan.Listings[index]
			if existing.Class == fsscan.ClassNone && existing.Origin == listing.Origin &&
				existing.Limit == listing.Limit {
				existing.Truncated = existing.Truncated || listing.Truncated
				existing.Count = max(existing.Count, listing.Count)
				existing.Older += listing.Older
				return
			}
		}
	}
	scan.Listings = append(scan.Listings, listing)
}

// WorkspaceFolders lists the folders recorded in each VS Code fork's workspaceStorage.
//
// The directory names under workspaceStorage are generated hashes, so this is the one list a
// fixed path cannot reach: one directory read per fork and storage root, no recursion, at most
// MaxWorkspaceEntries entries, of which the MaxWorkspaceDirs most recently modified directories
// are read, newest first, so a project cap reached later drops the least recently used
// projects. Files beside them are not records and are skipped before the cap, so they cannot
// displace one. A record directory that is a symlink, or on Windows a junction, cannot be read
// through and is counted as unreadable.
//
// A record names one folder, or, for a multi-root workspace, a .code-workspace file whose
// folders are read too; see addWorkspaceFile.
//
// appDataRoot is the account's redirected roaming root on Windows, or "" for the conventional
// location; see RedirectAppSupport. homeStorage is how the home is stored, as
// fsscan.ProbeProjectDir classified it, which a workspace file's directory may share. opts
// governs every read.
func WorkspaceFolders(ctx context.Context, home, appDataRoot string, homeStorage fsscan.ErrClass,
	deadline time.Time, opts fsscan.ReadOpts) ProjectListScan {
	var scan ProjectListScan
	files := &workspaceFiles{ctx: ctx, home: home, homeStorage: homeStorage, deadline: deadline,
		opts: opts, read: map[string]workspaceFile{}, emitted: map[workspaceEmission]struct{}{}}
	// The budget is checked before each listing and before each record, and a failed check
	// ends the whole enumeration. Ending only the record loop let the next storage root of the
	// same fork be listed after the budget had run out, which is filesystem work the deadline
	// exists to prevent.
forks:
	for _, fork := range VSCodeFamily {
		for _, storageRel := range AppSupportFork(fork.Dir, "User", "workspaceStorage") {
			if !fsscan.BudgetRemains(ctx, deadline) {
				scan.Stopped = true
				break forks
			}
			relPath, resolvable := ResolveSnapPath(home, storageRel)
			if !resolvable {
				continue
			}
			if rewritten, usable := RedirectAppSupport(relPath, appDataRoot, home); !usable {
				continue
			} else if rewritten != "" {
				relPath = rewritten
			}
			// An absent directory is the common case -- most hosts have none of the five forks
			// installed -- so it is silent. A listing that is short still yields its names.
			origin := workspaceOriginFor[fork.Client]
			names, older, links, truncated, err := fsscan.ListRecentDirNames(home, relPath,
				MaxWorkspaceDirs, MaxWorkspaceEntries)
			if err != nil {
				scan.addListing(DirListing{Class: fsscan.ClassifyError(err), Origin: origin})
				continue
			}
			scan.UnreadableRecords += links
			if truncated || older > 0 {
				listing := DirListing{Truncated: truncated, Limit: MaxWorkspaceEntries,
					Older: older, Origin: origin}
				if truncated {
					listing.Count = MaxWorkspaceEntries
				}
				scan.addListing(listing)
			}
			for _, name := range names {
				// This loop is the one with thousands of iterations on a long-lived workstation.
				if !fsscan.BudgetRemains(ctx, deadline) {
					scan.Stopped = true
					break forks
				}
				data, readErr := fsscan.ReadBoundedUnder(home,
					filepath.Join(relPath, name, "workspace.json"), opts)
				// Absence is silent, because a workspaceStorage directory outlives its record, and
				// so is a regular file partway down the path. A record that exists and was not
				// read, a refused symlink included, is counted. So is one whose content a cloud
				// provider holds: the record is in the editor's settings, not with its project, so
				// the project may be on this disk and is missing.
				if readErr != nil {
					if fsscan.ClassifyError(readErr) != fsscan.ClassAbsent && !fsscan.IsNotDirectory(readErr) {
						scan.UnreadableRecords++
					}
					continue
				}
				// Kept raw, so a multi-root workspace, which has no folder and names a workspace
				// file, is told apart from a record whose folder is null or not a string, and from
				// a top-level null or an object with neither field, which are malformed.
				var record struct {
					Folder    json.RawMessage `json:"folder"`
					Workspace json.RawMessage `json:"workspace"`
				}
				if err := json.Unmarshal(StripBOM(data), &record); err != nil {
					scan.MalformedRecords++
					continue
				}
				if record.Folder == nil {
					var workspace string
					if json.Unmarshal(record.Workspace, &workspace) != nil || workspace == "" {
						scan.MalformedRecords++
						continue
					}
					if !files.add(workspace, origin, &scan) {
						scan.Stopped = true
						break forks
					}
					continue
				}
				var folder string
				if err := json.Unmarshal(record.Folder, &folder); err != nil || folder == "" ||
					string(record.Folder) == "null" {
					scan.MalformedRecords++
					continue
				}
				scan.Folders = append(scan.Folders, ListedFolder{
					Recorded: boundedRecorded(folder), Origin: origin, FileURL: true})
			}
		}
	}
	return scan
}
