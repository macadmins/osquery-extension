package devclients

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/macadmins/osquery-extension/pkg/testutil"
)

// multiRootRecord writes a workspaceStorage record naming the .code-workspace file at path, and
// that file with body, under home's VS Code storage.
func multiRootRecord(t *testing.T, home, hash, path, body string) {
	t.Helper()
	storage := filepath.Join(home, AppSupportFork("Code", "User", "workspaceStorage")[0])
	testutil.WriteFile(t, filepath.Join(storage, hash, "workspace.json"),
		`{"workspace":"`+testutil.FileURL(path)+`"}`)
	if body != "" {
		testutil.WriteFile(t, path, body)
	}
}

func scanWorkspaces(home string) ProjectListScan {
	return WorkspaceFolders(context.Background(), home, "", fsscan.ClassNone, time.Now().Add(time.Minute),
		fsscan.ReadOpts{MaxSize: 1 << 20})
}

// TestWorkspaceFoldersReadsAMultiRootWorkspace: a hand-edited multi-root workspace, with paths
// relative to the .code-workspace file, a comment and a trailing comma, which the format allows,
// yields each folder as an absolute path, which the collector then contains.
func TestWorkspaceFoldersReadsAMultiRootWorkspace(t *testing.T) {
	home := t.TempDir()
	workspace := filepath.Join(home, "mr-sample", "sample.code-workspace")
	multiRootRecord(t, home, "aa", workspace, `{
	// written by the editor
	"folders": [
		{
			"path": "alpha"
		},
		{
			"path": "beta"
		},
	],
	"settings": {"secret.setting": "never decoded"}
}`)
	scan := scanWorkspaces(home)
	want := []ListedFolder{
		{Recorded: filepath.Join(home, "mr-sample", "alpha"), Origin: OriginVSCodeWorkspace},
		{Recorded: filepath.Join(home, "mr-sample", "beta"), Origin: OriginVSCodeWorkspace},
	}
	if !reflect.DeepEqual(scan.Folders, want) || scan.MalformedRecords != 0 || scan.UnreadableRecords != 0 {
		t.Errorf("scan = %+v, want folders %+v", scan, want)
	}
	collector := NewCollector(home, MaxProjects)
	for _, folder := range scan.Folders {
		collector.Add(folder.Recorded, folder.Origin, folder.FileURL)
	}
	if projects := collector.Projects(); len(projects) != 2 ||
		projects[0].Rel != filepath.Join("mr-sample", "alpha") {
		t.Errorf("projects = %+v, want alpha and beta contained", projects)
	}
}

// TestWorkspaceFileFoldersFollowTheContainmentRules: a uri goes to the collector as a URL, an
// absolute path as recorded, and a relative path is resolved from the file's directory, with a
// leading ".." allowed only within the home and a ".." after a named directory refused. A refused
// entry, and one with neither field, is passed empty, which the collector counts as unusable.
// TestRootedAndDriveRelativeFoldersAreRefusedOnWindows: `\repo` and `C:repo` are relative to a
// current drive or directory the scan does not have, so they are passed empty rather than
// resolved under the workspace file's directory.
func TestRootedAndDriveRelativeFoldersAreRefusedOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("a rooted or drive-relative path is Windows syntax")
	}
	for _, path := range []string{`\Users\alice\repo`, `/Users/alice/repo`, `C:repo`} {
		got := workspaceFileFolder(`C:\Users\alice`, "ws", path, "", OriginVSCodeWorkspace)
		if !reflect.DeepEqual(got, ListedFolder{Origin: OriginVSCodeWorkspace}) {
			t.Errorf("%q: %+v, want an empty Recorded", path, got)
		}
	}
}

func TestWorkspaceFileFoldersFollowTheContainmentRules(t *testing.T) {
	home := t.TempDir()
	other := testutil.FileURL(filepath.Join(home, "other"))
	absolute := filepath.Join(home, "abs")
	workspace := filepath.Join(home, "ws", "multi.code-workspace")
	multiRootRecord(t, home, "aa", workspace, fmt.Sprintf(`{"folders":[
		{"uri":%q},
		{"uri":"vscode-remote://ssh-remote%%2Bbox/home/alice/p"},
		{"path":%q},
		{"path":"../shared"},
		{"path":"."},
		{"path":"alpha/../beta"},
		{"path":"../../outside"},
		{"name":"no location"}
	]}`, other, absolute))
	scan := scanWorkspaces(home)
	want := []ListedFolder{
		{Recorded: other, Origin: OriginVSCodeWorkspace, FileURL: true},
		{Recorded: "vscode-remote://ssh-remote%2Bbox/home/alice/p", Origin: OriginVSCodeWorkspace, FileURL: true},
		{Recorded: absolute, Origin: OriginVSCodeWorkspace},
		{Recorded: filepath.Join(home, "shared"), Origin: OriginVSCodeWorkspace},
		{Recorded: filepath.Join(home, "ws"), Origin: OriginVSCodeWorkspace},
		{Origin: OriginVSCodeWorkspace},
		{Origin: OriginVSCodeWorkspace},
		{Origin: OriginVSCodeWorkspace},
	}
	if !reflect.DeepEqual(scan.Folders, want) {
		t.Errorf("folders =\n%+v\nwant\n%+v", scan.Folders, want)
	}
}

// TestWorkspaceFileFailuresAreCounted: a workspace file outside the home is passed on for the
// collector to count, one that does not parse or cannot be read is counted with the records, and
// one listing more than MaxWorkspaceFileFolders is read up to the cap and reported as truncated.
func TestWorkspaceFileFailuresAreCounted(t *testing.T) {
	home := t.TempDir()
	outside := filepath.Join(t.TempDir(), "elsewhere.code-workspace")
	multiRootRecord(t, home, "aa", outside, "")
	multiRootRecord(t, home, "bb", filepath.Join(home, "bad.code-workspace"), `{"folders": /* never closed`)
	unreadable := filepath.Join(home, "dir.code-workspace")
	multiRootRecord(t, home, "cc", unreadable, "")
	if err := os.MkdirAll(unreadable, 0o755); err != nil {
		t.Fatal(err)
	}
	var many []string
	for index := 0; index <= MaxWorkspaceFileFolders; index++ {
		many = append(many, fmt.Sprintf(`{"path":"p%d"}`, index))
	}
	multiRootRecord(t, home, "dd", filepath.Join(home, "many.code-workspace"),
		`{"folders":[`+strings.Join(many, ",")+`]}`)

	scan := scanWorkspaces(home)
	if scan.MalformedRecords != 1 || scan.UnreadableRecords != 1 {
		t.Errorf("malformed %d, unreadable %d; want one each", scan.MalformedRecords, scan.UnreadableRecords)
	}
	collector := NewCollector(home, MaxProjects)
	for _, folder := range scan.Folders {
		collector.Add(folder.Recorded, folder.Origin, folder.FileURL)
	}
	if refusals := collector.Refusals(); refusals.Outside != 1 || len(collector.Projects()) != MaxWorkspaceFileFolders {
		t.Errorf("outside %d, projects %d; want the outside file counted and %d folders read",
			refusals.Outside, len(collector.Projects()), MaxWorkspaceFileFolders)
	}
	want := DirListing{Truncated: true, Count: MaxWorkspaceFileFolders, Limit: MaxWorkspaceFileFolders,
		Origin: OriginVSCodeWorkspace}
	if len(scan.Listings) != 1 || scan.Listings[0] != want {
		t.Errorf("listings = %+v, want %+v", scan.Listings, want)
	}
}

// The records and the workspace file Cursor wrote on the development machine on 2026-10-20,
// for a folder alpha opened alone, a folder beta opened alone, and then a workspace with both,
// saved as sample.code-workspace: File > Open Folder, File > Add Folder to Workspace, File > Save
// Workspace As. Byte for byte, except that each file:// URL is rebuilt under the test's home.
const (
	cursorFolderRecord    = "{\n  \"folder\": \"%s\"\n}"
	cursorWorkspaceRecord = "{\n  \"workspace\": \"%s\"\n}"
	cursorWorkspaceFile   = "{\n\t\"folders\": [\n\t\t{\n\t\t\t\"path\": \"beta\"\n\t\t},\n\t\t{\n\t\t\t\"path\": \"alpha\"\n\t\t}\n\t],\n\t\"settings\": {}\n}"
)

// TestWorkspaceFoldersReadsTheCursorMultiRootSample: the multi-root record Cursor wrote names its
// .code-workspace file by URL, and the file's relative paths are read in the order the file
// lists them. With the two single-folder records beside it, the collector holds each folder once.
func TestWorkspaceFoldersReadsTheCursorMultiRootSample(t *testing.T) {
	home := t.TempDir()
	sample := filepath.Join(home, "mr-sample")
	storage := filepath.Join(home, AppSupportFork("Cursor", "User", "workspaceStorage")[0])
	testutil.WriteFile(t, filepath.Join(sample, "sample.code-workspace"), cursorWorkspaceFile)
	testutil.WriteFile(t, filepath.Join(storage, "ddd4451d44330b535d405413b5565dd2", "workspace.json"),
		fmt.Sprintf(cursorWorkspaceRecord, testutil.FileURL(filepath.Join(sample, "sample.code-workspace"))))

	scan := scanWorkspaces(home)
	want := []ListedFolder{
		{Recorded: filepath.Join(sample, "beta"), Origin: OriginCursorWorkspace},
		{Recorded: filepath.Join(sample, "alpha"), Origin: OriginCursorWorkspace},
	}
	if !reflect.DeepEqual(scan.Folders, want) || scan.MalformedRecords != 0 || scan.UnreadableRecords != 0 ||
		len(scan.Listings) != 0 {
		t.Fatalf("scan = %+v, want folders %+v", scan, want)
	}

	for hash, folder := range map[string]string{
		"216f6ce2aa60bc4dcfd9b4d36afcea17": "alpha", "39037cc39572e37eff7865bbb5445943": "beta",
	} {
		testutil.WriteFile(t, filepath.Join(storage, hash, "workspace.json"),
			fmt.Sprintf(cursorFolderRecord, testutil.FileURL(filepath.Join(sample, folder))))
	}
	collector := NewCollector(home, MaxProjects)
	for _, folder := range scanWorkspaces(home).Folders {
		collector.Add(folder.Recorded, folder.Origin, folder.FileURL)
	}
	var rels []string
	for _, project := range collector.Projects() {
		rels = append(rels, project.Rel)
	}
	sort.Strings(rels)
	wantRels := []string{filepath.Join("mr-sample", "alpha"), filepath.Join("mr-sample", "beta")}
	if !reflect.DeepEqual(rels, wantRels) {
		t.Errorf("projects = %v, want %v", rels, wantRels)
	}
}

// TestAWorkspaceFileIsReadOnceAndBounded: a .code-workspace file many records name is read once,
// a relative path longer than any usable one is dropped before it is resolved, and the folders
// taken from every workspace file in one scan stop at MaxWorkspaceFileFoldersTotal.
func TestAWorkspaceFileIsReadOnceAndBounded(t *testing.T) {
	home := t.TempDir()
	shared := filepath.Join(home, "ws", "shared.code-workspace")
	long := strings.Repeat("d", MaxRecordedPathLen+1)
	for index := 0; index < 50; index++ {
		body := ""
		if index == 0 {
			body = `{"folders":[{"path":"` + long + `"},{"path":"alpha"}]}`
		}
		multiRootRecord(t, home, fmt.Sprintf("r%02d", index), shared, body)
	}
	scan := scanWorkspaces(home)
	want := []ListedFolder{{Origin: OriginVSCodeWorkspace},
		{Recorded: filepath.Join(home, "ws", "alpha"), Origin: OriginVSCodeWorkspace}}
	if !reflect.DeepEqual(scan.Folders, want) {
		t.Errorf("folders = %d entries, want the file's two folders once, the long one emptied: %.200v",
			len(scan.Folders), scan.Folders)
	}

	home = t.TempDir()
	var hundred []string
	for index := 0; index < MaxWorkspaceFileFolders; index++ {
		hundred = append(hundred, fmt.Sprintf(`{"path":"p%d"}`, index))
	}
	files := MaxWorkspaceFileFoldersTotal/MaxWorkspaceFileFolders + 1
	for index := 0; index < files; index++ {
		multiRootRecord(t, home, fmt.Sprintf("f%02d", index),
			filepath.Join(home, fmt.Sprintf("w%02d", index), "x.code-workspace"),
			`{"folders":[`+strings.Join(hundred, ",")+`]}`)
	}
	scan = scanWorkspaces(home)
	wantListing := DirListing{Truncated: true, Count: MaxWorkspaceFileFoldersTotal,
		Limit: MaxWorkspaceFileFoldersTotal, Origin: OriginVSCodeWorkspace}
	if len(scan.Folders) != MaxWorkspaceFileFoldersTotal || len(scan.Listings) != 1 ||
		scan.Listings[0] != wantListing {
		t.Errorf("folders %d, listings %+v; want %d and %+v", len(scan.Folders), scan.Listings,
			MaxWorkspaceFileFoldersTotal, wantListing)
	}
}

// TestAWorkspaceFileNamedInTwoCases: on Windows a .code-workspace file two records name in
// different case is one file, probed and read once and its folders passed on once. Elsewhere the
// spellings are two files: a case-insensitive volume reads the one file twice, and on a
// case-sensitive one the second spelling names nothing. The same scan with samePathKey given
// Windows's case rule probes once on every host, so the read cache, not only the emission one,
// is keyed.
func TestAWorkspaceFileNamedInTwoCases(t *testing.T) {
	home := t.TempDir()
	named, respelled := filepath.Join(home, "ws", "Shared.code-workspace"), filepath.Join(home, "ws", "shared.code-workspace")
	multiRootRecord(t, home, "aa", named, `{"folders":[{"path":"alpha"}]}`)
	multiRootRecord(t, home, "bb", respelled, "")
	// Records are read newest first, so the one naming the file that exists is made the newest. On
	// a case-sensitive volume the other spelling names nothing, and under Windows's case rule that
	// absence, read first, would be cached for both.
	later := time.Now().Add(time.Hour)
	storage := filepath.Join(home, AppSupportFork("Code", "User", "workspaceStorage")[0])
	if err := os.Chtimes(filepath.Join(storage, "aa"), later, later); err != nil {
		t.Fatal(err)
	}
	savedProbe, savedKey := probeDir, samePathKey
	t.Cleanup(func() { probeDir, samePathKey = savedProbe, savedKey })
	probes := 0
	probeDir = func(base, rel string) error {
		probes++
		return savedProbe(base, rel)
	}
	scanCounts := func() (int, int) {
		probes = 0
		taken := 0
		for _, folder := range scanWorkspaces(home).Folders {
			if folder.Recorded == filepath.Join(home, "ws", "alpha") {
				taken++
			}
		}
		return probes, taken
	}

	wantProbes, wantTaken := 2, 1
	if runtime.GOOS == "windows" {
		wantProbes = 1
	} else if testutil.SameFile(t, named, respelled) {
		wantTaken = 2
	}
	if gotProbes, gotTaken := scanCounts(); gotProbes != wantProbes || gotTaken != wantTaken {
		t.Errorf("probes %d, alpha passed on %d times; want %d and %d on this %s volume",
			gotProbes, gotTaken, wantProbes, wantTaken, runtime.GOOS)
	}

	samePathKey = strings.ToLower
	if gotProbes, gotTaken := scanCounts(); gotProbes != 1 || gotTaken != 1 {
		t.Errorf("with Windows's case rule: probes %d, alpha passed on %d times; want 1 and 1", gotProbes, gotTaken)
	}
}

// TestAWorkspaceFileStoredElsewhereIsCountedNotRead: a workspace file in a cloud provider's
// folder, or whose directory is on a network filesystem the home is not on, is counted in
// StoredElsewhere and not read, not as an unreadable record. One on the same storage as the home
// is read.
func TestAWorkspaceFileStoredElsewhereIsCountedNotRead(t *testing.T) {
	home := t.TempDir()
	body := `{"folders":[{"path":"alpha"}]}`
	multiRootRecord(t, home, "aa", filepath.Join(home, "cloud", "a.code-workspace"), body)
	multiRootRecord(t, home, "bb", filepath.Join(home, "net", "b.code-workspace"), body)
	multiRootRecord(t, home, "cc", filepath.Join(home, "held", "c.code-workspace"), body)
	savedCloud, savedProbe := underCloudStorage, probeDir
	t.Cleanup(func() { underCloudStorage, probeDir = savedCloud, savedProbe })
	underCloudStorage = func(rel string) bool { return strings.HasPrefix(filepath.ToSlash(rel), "cloud") }
	probeDir = func(base, rel string) error {
		switch rel {
		case "net":
			return fsscan.ErrNetworkFilesystem
		case "held":
			// What the probe reports on Windows for a directory that is a provider's reparse point.
			return fsscan.ErrCloudPlaceholder
		}
		return savedProbe(base, rel)
	}
	scan := scanWorkspaces(home)
	want := map[fsscan.ErrClass]int{fsscan.ClassCloudPlaceholder: 2, fsscan.ClassNetworkFilesystem: 1}
	if !reflect.DeepEqual(scan.StoredElsewhere, want) || len(scan.Folders) != 0 || scan.UnreadableRecords != 0 {
		t.Errorf("scan = %+v, want both files counted as stored elsewhere and none read", scan)
	}
	sameAsHome := WorkspaceFolders(context.Background(), home, "", fsscan.ClassNetworkFilesystem,
		time.Now().Add(time.Minute), fsscan.ReadOpts{MaxSize: 1 << 20})
	if len(sameAsHome.Folders) != 1 || sameAsHome.StoredElsewhere[fsscan.ClassNetworkFilesystem] != 0 ||
		sameAsHome.StoredElsewhere[fsscan.ClassCloudPlaceholder] != 2 {
		t.Errorf("with a home on a network filesystem: %+v, want the network file read", sameAsHome)
	}
}

// TestAWorkspaceFileWithNoFoldersIsMalformed: a file that is not an object with a folders array --
// an empty object, null, or a null folders -- is counted as malformed; an empty array is a
// workspace with no folders.
func TestAWorkspaceFileWithNoFoldersIsMalformed(t *testing.T) {
	home := t.TempDir()
	for index, body := range []string{`{}`, `null`, `{"folders": null}`, `{"folders": []}`} {
		multiRootRecord(t, home, fmt.Sprintf("m%d", index),
			filepath.Join(home, fmt.Sprintf("m%d.code-workspace", index)), body)
	}
	if scan := scanWorkspaces(home); scan.MalformedRecords != 3 || len(scan.Folders) != 0 {
		t.Errorf("scan = %+v, want three malformed and no folders", scan)
	}
}

// TestListingsMergePerOrigin: the directories one origin covers report once, with their older
// records summed; a failed listing is kept per directory, and a different limit is a different
// listing.
func TestListingsMergePerOrigin(t *testing.T) {
	var scan ProjectListScan
	for _, listing := range []DirListing{
		{Limit: MaxWorkspaceEntries, Older: 3, Origin: OriginVSCodeWorkspace},
		{Truncated: true, Count: MaxWorkspaceEntries, Limit: MaxWorkspaceEntries, Older: 4500,
			Origin: OriginVSCodeWorkspace},
		{Class: fsscan.ClassDenied, Origin: OriginVSCodeWorkspace},
		{Class: fsscan.ClassRefusedPath, Origin: OriginVSCodeWorkspace},
		{Truncated: true, Count: MaxWorkspaceFileFolders, Limit: MaxWorkspaceFileFolders,
			Origin: OriginVSCodeWorkspace},
		{Limit: MaxWorkspaceEntries, Older: 1, Origin: OriginCursorWorkspace},
	} {
		scan.addListing(listing)
	}
	want := []DirListing{
		{Truncated: true, Count: MaxWorkspaceEntries, Limit: MaxWorkspaceEntries, Older: 4503,
			Origin: OriginVSCodeWorkspace},
		{Class: fsscan.ClassDenied, Origin: OriginVSCodeWorkspace},
		{Class: fsscan.ClassRefusedPath, Origin: OriginVSCodeWorkspace},
		{Truncated: true, Count: MaxWorkspaceFileFolders, Limit: MaxWorkspaceFileFolders,
			Origin: OriginVSCodeWorkspace},
		{Limit: MaxWorkspaceEntries, Older: 1, Origin: OriginCursorWorkspace},
	}
	if !reflect.DeepEqual(scan.Listings, want) {
		t.Errorf("listings =\n%+v\nwant\n%+v", scan.Listings, want)
	}
}

// countWorkspaceFileOpens counts the workspace files a scan goes on to read, through the storage
// probe each new file's directory gets first.
func countWorkspaceFileOpens(t *testing.T) *int {
	t.Helper()
	saved := probeDir
	t.Cleanup(func() { probeDir = saved })
	opens := 0
	probeDir = func(base, rel string) error {
		opens++
		return saved(base, rel)
	}
	return &opens
}

// TestAWorkspaceFileNamedByTwoEditorsKeepsBoth: a .code-workspace file that VS Code and Cursor
// both recorded is read once, and its folders are passed on under each editor, because the
// editor that recorded a project decides which of its files a caller reads there.
func TestAWorkspaceFileNamedByTwoEditorsKeepsBoth(t *testing.T) {
	home := t.TempDir()
	shared := filepath.Join(home, "ws", "shared.code-workspace")
	multiRootRecord(t, home, "code", shared, `{"folders":[{"path":"alpha"}]}`)
	cursor := filepath.Join(home, AppSupportFork("Cursor", "User", "workspaceStorage")[0])
	for _, hash := range []string{"one", "two"} {
		testutil.WriteFile(t, filepath.Join(cursor, hash, "workspace.json"),
			`{"workspace":"`+testutil.FileURL(shared)+`"}`)
	}
	opens := countWorkspaceFileOpens(t)
	scan := scanWorkspaces(home)
	alpha := filepath.Join(home, "ws", "alpha")
	want := []ListedFolder{{Recorded: alpha, Origin: OriginVSCodeWorkspace},
		{Recorded: alpha, Origin: OriginCursorWorkspace}}
	if !reflect.DeepEqual(scan.Folders, want) || *opens != 1 {
		t.Errorf("folders = %+v after %d reads, want alpha once per editor after one read",
			scan.Folders, *opens)
	}
}

// TestNoWorkspaceFileIsOpenedPastTheTotal: once MaxWorkspaceFileFoldersTotal folders are taken,
// a record naming a file not yet read is reported as a truncated listing and the file is not
// opened, so crafted records cannot make the scan read thousands of files.
func TestNoWorkspaceFileIsOpenedPastTheTotal(t *testing.T) {
	home := t.TempDir()
	var hundred []string
	for index := 0; index < MaxWorkspaceFileFolders; index++ {
		hundred = append(hundred, fmt.Sprintf(`{"path":"p%d"}`, index))
	}
	full := MaxWorkspaceFileFoldersTotal / MaxWorkspaceFileFolders
	for index := 0; index < full+5; index++ {
		multiRootRecord(t, home, fmt.Sprintf("f%02d", index),
			filepath.Join(home, fmt.Sprintf("w%02d", index), "x.code-workspace"),
			`{"folders":[`+strings.Join(hundred, ",")+`]}`)
	}
	opens := countWorkspaceFileOpens(t)
	scan := scanWorkspaces(home)
	wantListing := DirListing{Truncated: true, Count: MaxWorkspaceFileFoldersTotal,
		Limit: MaxWorkspaceFileFoldersTotal, Origin: OriginVSCodeWorkspace}
	if *opens != full || len(scan.Folders) != MaxWorkspaceFileFoldersTotal || len(scan.Listings) != 1 ||
		scan.Listings[0] != wantListing {
		t.Errorf("%d files read, %d folders, listings %+v; want %d, %d and %+v", *opens,
			len(scan.Folders), scan.Listings, full, MaxWorkspaceFileFoldersTotal, wantListing)
	}
}

// TestATruncatedFileTheTotalCutShortIsReportedOnce: a file listing more than
// MaxWorkspaceFileFolders folders, opened when the total has room for only 50 of them, is reported
// by the total's listing alone. Its own count=100 row claimed 100 folders were taken from it.
func TestATruncatedFileTheTotalCutShortIsReportedOnce(t *testing.T) {
	home := t.TempDir()
	storage := filepath.Join(home, AppSupportFork("Code", "User", "workspaceStorage")[0])
	folders := func(count int) string {
		var entries []string
		for index := 0; index < count; index++ {
			entries = append(entries, fmt.Sprintf(`{"path":"p%d"}`, index))
		}
		return `{"folders":[` + strings.Join(entries, ",") + `]}`
	}
	sizes := map[string]int{"big": MaxWorkspaceFileFolders + 50, "half": 50}
	full := MaxWorkspaceFileFoldersTotal/MaxWorkspaceFileFolders - 1
	for index := 0; index < full; index++ {
		sizes[fmt.Sprintf("f%02d", index)] = MaxWorkspaceFileFolders
	}
	now := time.Now()
	for hash, count := range sizes {
		multiRootRecord(t, home, hash, filepath.Join(home, hash, "x.code-workspace"), folders(count))
		// Records are read newest first, so the large file is read last, after 950 folders.
		modified := now
		if hash == "big" {
			modified = now.Add(-time.Hour)
		}
		if err := os.Chtimes(filepath.Join(storage, hash), modified, modified); err != nil {
			t.Fatal(err)
		}
	}
	scan := scanWorkspaces(home)
	want := []DirListing{{Truncated: true, Count: MaxWorkspaceFileFoldersTotal,
		Limit: MaxWorkspaceFileFoldersTotal, Origin: OriginVSCodeWorkspace}}
	if len(scan.Folders) != MaxWorkspaceFileFoldersTotal || !reflect.DeepEqual(scan.Listings, want) {
		t.Errorf("%d folders, listings %+v; want %d and %+v", len(scan.Folders), scan.Listings,
			MaxWorkspaceFileFoldersTotal, want)
	}
}
