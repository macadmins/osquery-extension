package devclients

import (
	"bytes"
	"context"
	"encoding/json"
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

// MaxProjects bounds how many recorded projects one home may contribute.
//
// Measured against the development machine, which records 30 projects for Claude Code and
// about 30 for Codex. An order of magnitude above that is unreachable by ordinary use and still
// bounds the work: each project costs one component-wise open per file read inside it, so the
// cap is what keeps a list someone has scripted into thousands of entries from turning a
// bounded read into an unbounded one. A caller reports exceeding it rather than truncating
// silently.
const MaxProjects = 200

// MaxWorkspaceDirs bounds the generated-name directories under one fork's workspaceStorage.
//
// Separate from MaxProjects because it bounds a different thing: a directory listing, one per
// VS Code fork, where each entry costs a read of a small JSON file. VS Code creates one of
// these per workspace ever opened and never prunes them, so the count is higher than the
// number of live projects by a wide margin.
const MaxWorkspaceDirs = 500

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
	rel, err := fsscan.ContainProjectPath(c.home, recorded, allowFileURL)
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
	if existing, seen := c.index[rel]; seen {
		c.projects[existing].Origins[origin] = struct{}{}
		return existing, true
	}
	if len(c.projects) >= c.limit {
		c.refusals.Truncated = true
		return -1, false
	}
	c.index[rel] = len(c.projects)
	c.projects = append(c.projects, Project{
		Rel:     rel,
		Abs:     filepath.Join(c.home, rel),
		Origins: map[Origin]struct{}{origin: {}},
	})
	return len(c.projects) - 1, true
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

// ClaudeEntries lists the projects recorded in ~/.claude.json, sorted by path.
//
// Sorted before anything is decided: map iteration order is random, and a cap applied later
// would otherwise admit a different set of projects on every run, which differential logging
// reports as rows removed and re-added on an unchanged host.
func ClaudeEntries(data []byte) ([]ClaudeEntry, error) {
	var doc struct {
		Projects map[string]json.RawMessage `json:"projects"`
	}
	if err := json.Unmarshal(StripBOM(data), &doc); err != nil {
		return nil, err
	}
	out := make([]ClaudeEntry, 0, len(doc.Projects))
	for key, raw := range doc.Projects {
		out = append(out, ClaudeEntry{Recorded: key, Raw: raw})
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
		out = append(out, CodexEntry{Recorded: key, value: value, metadata: metadata})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Recorded < out[j].Recorded })
	return out, nil
}

// WorkspaceFolder is one project an editor recorded, exactly as it wrote it, with the origin
// of the editor that recorded it. FileURL is true when Recorded is a file:// URL, as VS Code
// writes it, and false when it is a path, as JetBrains writes it after placeholder expansion.
type WorkspaceFolder struct {
	Recorded string
	Origin   Origin
	FileURL  bool
}

// WorkspaceListing is one workspaceStorage directory that could not be listed in full.
type WorkspaceListing struct {
	// Truncated is true when the listing filled MaxWorkspaceDirs and Count names were used.
	// Otherwise the listing failed and Class says why.
	Truncated bool
	Count     int
	Class     fsscan.ErrClass
}

// WorkspaceScan is what the workspace enumeration found for one home.
type WorkspaceScan struct {
	Folders []WorkspaceFolder

	// Listings holds each storage directory that failed or was cut short, in the order met.
	Listings []WorkspaceListing

	// UnreadableRecords counts workspace.json files that exist and could not be read: a
	// permission failure, the size cap, a refused hard link. Absence is not counted, because a
	// workspaceStorage directory outlives the workspace it was created for and most entries
	// have no readable record.
	UnreadableRecords int

	// MalformedRecords counts workspace.json files that were read and did not parse. Counted
	// apart from unreadable ones because the remedies differ.
	MalformedRecords int

	// Stopped is true when ctx was cancelled or deadline passed before the enumeration ended.
	Stopped bool
}

// WorkspaceFolders lists the folders recorded in each VS Code fork's workspaceStorage.
//
// The directory names under workspaceStorage are generated hashes, so this is the one list a
// fixed path cannot reach: one directory read per fork and storage root, no recursion, capped
// at MaxWorkspaceDirs.
//
// Only the `folder` field is read. A multi-root workspace records `workspace` instead, naming
// a .code-workspace file whose own folder list would have to be parsed. No development machine
// has had one to verify that format against, so it is skipped rather than guessed at.
//
// appDataRoot is the account's redirected roaming root on Windows, or "" for the conventional
// location; see RedirectAppSupport. opts governs every workspace.json read.
func WorkspaceFolders(ctx context.Context, home, appDataRoot string, deadline time.Time,
	opts fsscan.ReadOpts) WorkspaceScan {
	var scan WorkspaceScan
	// The budget is checked before each listing and before each record, and a failed check
	// ends the whole enumeration. Ending only the record loop let the next storage root of the
	// same fork be listed after the budget had run out, which is filesystem work the deadline
	// exists to prevent.
forks:
	for _, fork := range VSCodeFamily {
		for _, storageRel := range AppSupportFork(fork.Dir, "User", "workspaceStorage") {
			if !budgetRemains(ctx, deadline) {
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
			names, truncated, err := fsscan.ListDirNamesCapped(home, relPath, MaxWorkspaceDirs)
			if err != nil {
				scan.Listings = append(scan.Listings, WorkspaceListing{Class: fsscan.ClassifyError(err)})
				continue
			}
			if truncated {
				scan.Listings = append(scan.Listings, WorkspaceListing{Truncated: true, Count: len(names)})
			}
			for _, name := range names {
				// This loop is the one with thousands of iterations on a long-lived workstation.
				if !budgetRemains(ctx, deadline) {
					scan.Stopped = true
					break forks
				}
				data, readErr := fsscan.ReadBoundedUnder(home,
					filepath.Join(relPath, name, "workspace.json"), opts)
				if readErr != nil {
					if !fsscan.IsExpectedAbsent(readErr) {
						scan.UnreadableRecords++
					}
					continue
				}
				var record struct {
					Folder string `json:"folder"`
				}
				if err := json.Unmarshal(StripBOM(data), &record); err != nil {
					scan.MalformedRecords++
					continue
				}
				if record.Folder == "" {
					continue // a multi-root workspace; see the function comment
				}
				scan.Folders = append(scan.Folders, WorkspaceFolder{
					Recorded: record.Folder, Origin: workspaceOriginFor[fork.Client], FileURL: true})
			}
		}
	}
	return scan
}

// budgetRemains reports whether a loop may take its next step: the query is still wanted and
// the time allowance has not run out.
func budgetRemains(ctx context.Context, deadline time.Time) bool {
	return ctx.Err() == nil && time.Now().Before(deadline)
}
