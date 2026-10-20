package devclients

import (
	"context"
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
)

// A multi-root VS Code workspace records `workspace` in its workspace.json instead of
// `folder`: a file:// URI naming a .code-workspace file, which lists the workspace's folders.
// VS Code documents the format as JSON with comments, with a `folders` array whose entries
// carry either a `path`, absolute or relative to the .code-workspace file's directory, or a
// `uri`, which may name another filesystem. An untitled workspace is the same file, kept under
// the editor's application-support directory.

// MaxWorkspaceFileFolders bounds the folders read from one .code-workspace file. A file listing
// more is reported as truncated, and the folders past the cap are not inspected.
const MaxWorkspaceFileFolders = 100

// MaxWorkspaceFileFoldersTotal bounds the folders taken from every .code-workspace file one
// scan reads. Each folder is held until the collector sees it, and the records can name
// thousands of distinct files, so without it a crafted set of files could hold hundreds of
// megabytes. The collector admits at most MaxProjects projects, so folders past this could only
// repeat or be refused.
const MaxWorkspaceFileFoldersTotal = 1000

// Where a workspace file is stored decides whether it is read, by the checks a recorded project
// and a followed link's target get. Variables so tests can substitute them: a cloud folder and
// a network mount cannot be created in a test.
var (
	underCloudStorage = fsscan.UnderCloudStorage
	probeDir          = fsscan.ProbeProjectDir
)

// samePathKey keys the files read and passed on, a variable so a test on any host can give it
// the case rule it has on Windows.
var samePathKey = fsscan.SamePathKey

// workspaceFiles reads the .code-workspace files that one WorkspaceFolders call's records name,
// each once, within MaxWorkspaceFileFoldersTotal.
type workspaceFiles struct {
	ctx         context.Context
	home        string
	homeStorage fsscan.ErrClass
	deadline    time.Time
	opts        fsscan.ReadOpts
	// read holds what each file contributed, by its home-relative path. A file that was
	// opened and gave no folders, or was not read, is present with no folders.
	read map[string]workspaceFile
	// emitted records each file and origin whose folders were passed on.
	emitted map[workspaceEmission]struct{}
	taken   int
}

// workspaceFile is what one .code-workspace file contributed: up to MaxWorkspaceFileFolders of its
// folders, without an origin, and whether it listed more.
type workspaceFile struct {
	folders   []ListedFolder
	truncated bool
}

type workspaceEmission struct {
	rel    string
	origin Origin
}

// add reads the folders of the .code-workspace file a multi-root record names into scan. It
// returns false when the budget ran out before the file was read.
//
// A file is read once per scan, and its folders are passed on once for each editor whose
// records name it, because the editor that recorded a project decides which of its files a
// caller reads there. Once MaxWorkspaceFileFoldersTotal folders are taken, no new file is
// opened, and the record is reported as a truncated listing for its editor.
//
// A workspace file outside the home, on another host or at an unusable location is passed on as
// a folder, so the collector counts it with the other recorded locations it does not read. One
// stored somewhere other than this machine's disk -- in a cloud provider's folder or held by the
// provider, or in a directory on a network or userspace filesystem the home is not on -- is
// counted in StoredElsewhere and not read. One that is absent is silent, like an absent
// workspace.json; one that exists and cannot be read, or does not parse, is counted with the
// workspace records.
func (w *workspaceFiles) add(workspace string, origin Origin, scan *ProjectListScan) bool {
	var rel string
	var err error
	if len(workspace) <= MaxRecordedPathLen {
		rel, err = fsscan.ContainProjectPath(w.home, workspace, true)
	}
	if rel == "" || err != nil {
		scan.Folders = append(scan.Folders, ListedFolder{
			Recorded: boundedRecorded(workspace), Origin: origin, FileURL: true})
		return true
	}
	// Keyed so that on Windows a file two records name in different case is read once.
	key := samePathKey(rel)
	if file, done := w.read[key]; done {
		w.emit(rel, file, origin, scan)
		return true
	}
	if w.taken >= MaxWorkspaceFileFoldersTotal {
		w.totalReached(origin, scan)
		return true
	}
	w.read[key] = workspaceFile{}
	if underCloudStorage(rel) {
		scan.storedElsewhere(fsscan.ClassCloudPlaceholder)
		return true
	}
	if !fsscan.BudgetRemains(w.ctx, w.deadline) {
		return false
	}
	dir := filepath.Dir(rel)
	probeErr := probeDir(w.home, dir)
	switch storage := fsscan.ClassifyError(probeErr); {
	case storage == fsscan.ClassNone, storage == w.homeStorage:
	// A directory a provider holds, which on Windows the probe reports from its reparse point, is
	// stored elsewhere like a network or userspace one, not an unreadable record.
	case storage == fsscan.ClassCloudPlaceholder, storage == fsscan.ClassNetworkFilesystem,
		storage == fsscan.ClassUserspaceFilesystem:
		scan.storedElsewhere(storage)
		return true
	case storage == fsscan.ClassAbsent, fsscan.IsNotDirectory(probeErr):
		return true
	default:
		scan.UnreadableRecords++
		return true
	}
	data, err := fsscan.ReadProjectFile(w.home, dir, filepath.Base(rel), w.opts)
	switch class := fsscan.ClassifyError(err); {
	case class == fsscan.ClassNone:
	case class == fsscan.ClassAbsent, fsscan.IsNotDirectory(err):
		return true
	case class == fsscan.ClassCloudPlaceholder, class == fsscan.ClassUserspaceFilesystem:
		scan.storedElsewhere(class)
		return true
	default:
		scan.UnreadableRecords++
		return true
	}
	stripped, terminated := StripJSONC(StripBOM(data))
	// Only the folders are decoded. The file also carries the workspace's settings, which can
	// hold anything a user configures, none of which this reader has a use for. A pointer, so
	// a file with no folders array, or a null one, is told apart from an empty array.
	var file struct {
		Folders *[]struct {
			Path string `json:"path"`
			URI  string `json:"uri"`
		} `json:"folders"`
	}
	if !terminated || json.Unmarshal(stripped, &file) != nil || file.Folders == nil {
		scan.MalformedRecords++
		return true
	}
	entries := *file.Folders
	var read workspaceFile
	if len(entries) > MaxWorkspaceFileFolders {
		entries, read.truncated = entries[:MaxWorkspaceFileFolders], true
	}
	// Held whole, up to the per-file cap, so another editor naming the file gets all of them; a
	// file is opened only while the total has room, so what is held stays within the total plus
	// one file's cap.
	for _, entry := range entries {
		read.folders = append(read.folders, workspaceFileFolder(w.home, dir, entry.Path,
			entry.URI, ""))
	}
	w.read[key] = read
	w.emit(rel, read, origin, scan)
	return true
}

// emit passes a read file's folders on under origin, once per file and origin, each counted
// against MaxWorkspaceFileFoldersTotal. The file's own truncation is reported only when every
// folder it kept was taken: a file the total cut short is reported by the total's listing, and
// a per-file row would claim MaxWorkspaceFileFolders folders were taken from it.
func (w *workspaceFiles) emit(rel string, file workspaceFile, origin Origin,
	scan *ProjectListScan) {
	key := workspaceEmission{samePathKey(rel), origin}
	if _, done := w.emitted[key]; done {
		return
	}
	w.emitted[key] = struct{}{}
	for _, folder := range file.folders {
		if w.taken >= MaxWorkspaceFileFoldersTotal {
			w.totalReached(origin, scan)
			return
		}
		w.taken++
		folder.Origin = origin
		scan.Folders = append(scan.Folders, folder)
	}
	if file.truncated {
		scan.addListing(DirListing{Truncated: true, Count: MaxWorkspaceFileFolders,
			Limit: MaxWorkspaceFileFolders, Origin: origin})
	}
}

// totalReached reports that MaxWorkspaceFileFoldersTotal left folders a record names untaken.
func (w *workspaceFiles) totalReached(origin Origin, scan *ProjectListScan) {
	scan.addListing(DirListing{Truncated: true, Count: MaxWorkspaceFileFoldersTotal,
		Limit: MaxWorkspaceFileFoldersTotal, Origin: origin})
}

// workspaceFileFolder turns one `folders` entry into a recorded folder. A `uri` goes to the
// collector as a URL, so one naming another filesystem is counted as remote. An absolute `path`
// is passed as recorded. A relative `path` is resolved from the workspace file's directory,
// dirRel, under fsscan.ResolveBeneath's rules: a leading ".." may climb only as far as the home,
// and a ".." after a named directory could name a different directory than the text does. An
// entry the rules refuse, one longer than MaxRecordedPathLen, and one with neither field, is
// passed empty, which the collector counts as an unusable path.
func workspaceFileFolder(home, dirRel, path, uri string, origin Origin) ListedFolder {
	switch {
	case uri != "":
		return ListedFolder{Recorded: boundedRecorded(uri), Origin: origin, FileURL: true}
	case path == "", len(path) > MaxRecordedPathLen:
		return ListedFolder{Origin: origin}
	case filepath.IsAbs(path):
		return ListedFolder{Recorded: path, Origin: origin}
	}
	rel, err := fsscan.ResolveBeneath(home, dirRel, path)
	if err != nil {
		return ListedFolder{Origin: origin}
	}
	return ListedFolder{Recorded: boundedRecorded(filepath.Join(home, rel)), Origin: origin}
}
