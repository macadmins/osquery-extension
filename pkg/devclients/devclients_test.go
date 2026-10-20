package devclients

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/macadmins/osquery-extension/pkg/testutil"
)

// TestSnapRevisionIsNarrow: the `current` link is resolved by hand only when its target is a
// bare revision, because accepting any target would hand back the redirection that refusing
// symlinks exists to prevent.
func TestSnapRevisionIsNarrow(t *testing.T) {
	for target, want := range map[string]bool{
		"168": true, "x2": true, "": false, ".": false, "..": false, "x": false,
		"../../etc": false, "168/sub": false, `a\b`: false, "rev1": false,
	} {
		if got := isSnapRevision(target); got != want {
			t.Errorf("isSnapRevision(%q) = %v, want %v", target, got, want)
		}
	}
	if rel, ok := ResolveSnapPath(t.TempDir(), filepath.Join(".config", "Code")); !ok ||
		rel != filepath.Join(".config", "Code") {
		t.Errorf("a path with no snap pointer is returned unchanged, got %q %v", rel, ok)
	}
	if _, ok := ResolveSnapPath(t.TempDir(), filepath.Join("snap", "code", "current", ".config")); ok {
		t.Error("a snap path whose pointer is absent is not usable")
	}
}

// TestRedirectAppSupport covers the three outcomes: no redirect, a redirect inside the
// profile, and one outside it that must not be read.
func TestRedirectAppSupport(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "Users", "alice")
	source := filepath.Join(AppSupportDir(), "Code", "User", "workspaceStorage")
	if rewritten, usable := RedirectAppSupport(source, "", home); rewritten != "" || !usable {
		t.Errorf("no redirect: got %q %v", rewritten, usable)
	}
	inside := filepath.Join(home, "Roaming2")
	rewritten, usable := RedirectAppSupport(source, inside, home)
	if !usable || rewritten != filepath.Join("Roaming2", "Code", "User", "workspaceStorage") {
		t.Errorf("redirect inside the profile: got %q %v", rewritten, usable)
	}
	if _, usable := RedirectAppSupport(source, filepath.Join(string(filepath.Separator), "srv"), home); usable {
		t.Error("a redirect outside the profile is not usable")
	}
	if rewritten, usable := RedirectAppSupport(".claude.json", inside, home); rewritten != "" || !usable {
		t.Errorf("a dotfile is unaffected by the redirect: got %q %v", rewritten, usable)
	}
	if !WithinHome(filepath.Join(home, "x"), home) || WithinHome(filepath.Join(home, "..", "bob"), home) {
		t.Error("WithinHome misclassified a path")
	}
}

// TestCollectorContainsMergesAndCaps covers every way a recorded path is handled: admitted,
// merged with an earlier sighting from another client, and refused for each reason.
func TestCollectorContainsMergesAndCaps(t *testing.T) {
	home := t.TempDir()
	collector := NewCollector(home, 2)
	index, ok := collector.Add(filepath.Join(home, "code", "a"), OriginClaudeJSON, false)
	if !ok || index != 0 {
		t.Fatalf("first project: index %d admitted %v", index, ok)
	}
	if index, ok := collector.Add(testutil.FileURL(filepath.Join(home, "code", "a")), OriginVSCodeWorkspace, true); !ok || index != 0 {
		t.Errorf("a repeat from another client merges into index 0, got %d %v", index, ok)
	}
	collector.Add(filepath.Join(home, "..", "elsewhere"), OriginClaudeJSON, false)
	collector.Add("relative/path", OriginClaudeJSON, false)
	collector.Add("vscode-remote://ssh-remote+box/p", OriginVSCodeWorkspace, true)
	collector.Add(filepath.Join(home, "code", "b"), OriginCodexTOML, false)
	collector.Add(filepath.Join(home, "code", "c"), OriginCodexTOML, false) // over the limit
	// A repeat at the limit is still merged, because it adds no project.
	if _, ok := collector.Add(filepath.Join(home, "code", "b"), OriginClaudeJSON, false); !ok {
		t.Error("a repeat at the limit is admitted")
	}

	projects := collector.Projects()
	if len(projects) != 2 || projects[0].Rel != filepath.Join("code", "a") ||
		projects[0].Abs != filepath.Join(home, "code", "a") {
		t.Fatalf("projects = %+v", projects)
	}
	wantOrigins := map[Origin]struct{}{OriginClaudeJSON: {}, OriginVSCodeWorkspace: {}}
	if !reflect.DeepEqual(projects[0].Origins, wantOrigins) {
		t.Errorf("origins = %v, want both clients", projects[0].Origins)
	}
	want := Refusals{Outside: 1, Remote: 1, Malformed: 1, Truncated: true}
	if got := collector.Refusals(); got != want {
		t.Errorf("refusals = %+v, want %+v", got, want)
	}
}

// TestClaudeEntriesSortedAndRaw: keys come back sorted and the values undecoded, so a caller
// decides which fields of an entry it reads.
func TestClaudeEntriesSortedAndRaw(t *testing.T) {
	data := "\xEF\xBB\xBF" + `{"projects":{"/b":{"x":1},"/a":{"lastSessionFirstPrompt":"secret"}},"other":1}`
	entries, err := ClaudeEntries([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Recorded != "/a" || entries[1].Recorded != "/b" {
		t.Fatalf("entries = %+v", entries)
	}
	if string(entries[1].Raw) != `{"x":1}` {
		t.Errorf("raw value = %s", entries[1].Raw)
	}
	if _, err := ClaudeEntries([]byte("{not json")); err == nil {
		t.Error("malformed JSON is an error")
	}
	if _, err := ClaudeEntries([]byte("\xEF\xBB\xBF null\n")); !errors.Is(err, ErrNullDocument) {
		t.Errorf("a null document: %v, want ErrNullDocument", err)
	}
	if entries, err := ClaudeEntries([]byte(`{}`)); err != nil || len(entries) != 0 {
		t.Errorf("no projects key: %v %v", entries, err)
	}
}

// TestCodexEntriesDecodeOnRequest: an entry whose fields a caller does not ask for is never
// decoded, so an unexpected type in it costs nothing.
func TestCodexEntriesDecodeOnRequest(t *testing.T) {
	data := `
[projects."/z"]
trust_level = "trusted"
[projects."/a"]
trust_level = 7
`
	entries, err := CodexEntries([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Recorded != "/a" || entries[1].Recorded != "/z" {
		t.Fatalf("entries = %+v", entries)
	}
	var trust struct {
		TrustLevel string `toml:"trust_level"`
	}
	if err := entries[1].Decode(&trust); err != nil || trust.TrustLevel != "trusted" {
		t.Errorf("decode: %v %q", err, trust.TrustLevel)
	}
	if err := entries[0].Decode(&trust); err == nil {
		t.Error("a mistyped field fails only the entry that is decoded")
	}
	if _, err := CodexEntries([]byte("[projects")); err == nil {
		t.Error("malformed TOML is an error")
	}
}

// TestWorkspaceFoldersReadsEachForkAndCountsFailures builds a workspaceStorage directory for
// two forks and checks the folders, the per-fork origin, and each counted failure.
func TestWorkspaceFoldersReadsEachForkAndCountsFailures(t *testing.T) {
	home := t.TempDir()
	codeStorage := filepath.Join(home, AppSupportFork("Code", "User", "workspaceStorage")[0])
	cursorStorage := filepath.Join(home, AppSupportFork("Cursor", "User", "workspaceStorage")[0])
	testutil.WriteFile(t, filepath.Join(codeStorage, "aa", "workspace.json"),
		`{"folder":"`+testutil.FileURL(filepath.Join(home, "code", "one"))+`"}`)
	// A multi-root record naming a workspace file that is no longer there, which is silent.
	testutil.WriteFile(t, filepath.Join(codeStorage, "bb", "workspace.json"),
		`{"workspace":"`+testutil.FileURL(filepath.Join(home, "gone.code-workspace"))+`"}`)
	testutil.WriteFile(t, filepath.Join(codeStorage, "cc", "workspace.json"), `{not json`)
	testutil.WriteFile(t, filepath.Join(codeStorage, "dd", "unrelated.txt"), "")
	testutil.WriteFile(t, filepath.Join(cursorStorage, "ee", "workspace.json"),
		`{"folder":"`+testutil.FileURL(filepath.Join(home, "code", "two"))+`"}`)

	scan := WorkspaceFolders(context.Background(), home, "", fsscan.ClassNone, time.Now().Add(time.Minute),
		fsscan.ReadOpts{MaxSize: 1 << 20})
	want := []ListedFolder{
		{Recorded: testutil.FileURL(filepath.Join(home, "code", "one")), Origin: OriginVSCodeWorkspace, FileURL: true},
		{Recorded: testutil.FileURL(filepath.Join(home, "code", "two")), Origin: OriginCursorWorkspace, FileURL: true},
	}
	if !reflect.DeepEqual(scan.Folders, want) {
		t.Errorf("folders = %+v, want %+v", scan.Folders, want)
	}
	if scan.MalformedRecords != 1 || scan.UnreadableRecords != 0 || scan.Stopped || len(scan.Listings) != 0 {
		t.Errorf("scan = %+v", scan)
	}
}

// TestWorkspaceFoldersReportsTruncationAndStop covers the read bound and a cancelled query, the
// two ways the enumeration returns less than the directory holds. Only more entries than
// MaxWorkspaceEntries is truncation; the records past MaxWorkspaceDirs are counted as older.
func TestWorkspaceFoldersReportsTruncationAndStop(t *testing.T) {
	home := t.TempDir()
	storage := filepath.Join(home, AppSupportFork("Code", "User", "workspaceStorage")[0])
	for index := 0; index <= MaxWorkspaceEntries; index++ {
		if err := os.MkdirAll(filepath.Join(storage, "w"+strconv.Itoa(index)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	scan := WorkspaceFolders(context.Background(), home, "", fsscan.ClassNone, time.Now().Add(time.Minute),
		fsscan.ReadOpts{MaxSize: 1 << 20})
	want := DirListing{Truncated: true, Count: MaxWorkspaceEntries, Limit: MaxWorkspaceEntries,
		Older: MaxWorkspaceEntries - MaxWorkspaceDirs, Origin: OriginVSCodeWorkspace}
	if len(scan.Listings) != 1 || scan.Listings[0] != want {
		t.Errorf("listings = %+v, want %+v", scan.Listings, want)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if scan := WorkspaceFolders(cancelled, home, "", fsscan.ClassNone, time.Now().Add(time.Minute),
		fsscan.ReadOpts{MaxSize: 1 << 20}); !scan.Stopped {
		t.Error("a cancelled query stops the enumeration and says so")
	}
}

// TestWorkspaceFoldersKeepsTheMostRecentRecords: of more records than MaxWorkspaceDirs, the most
// recently modified are read and the rest counted as older, whatever their names. The newest
// three sort last by name, so a listing in name order would drop them.
func TestWorkspaceFoldersKeepsTheMostRecentRecords(t *testing.T) {
	home := t.TempDir()
	storage := filepath.Join(home, AppSupportFork("Code", "User", "workspaceStorage")[0])
	total := MaxWorkspaceDirs + 3
	base := time.Now().Add(-time.Duration(total) * time.Hour)
	for index := 0; index < total; index++ {
		name := fmt.Sprintf("w%04d", index)
		dir := filepath.Join(storage, name)
		testutil.WriteFile(t, filepath.Join(dir, "workspace.json"),
			`{"folder":"`+testutil.FileURL(filepath.Join(home, "code", name))+`"}`)
		// Later names are more recent.
		modified := base.Add(time.Duration(index) * time.Hour)
		if err := os.Chtimes(dir, modified, modified); err != nil {
			t.Fatal(err)
		}
	}
	scan := WorkspaceFolders(context.Background(), home, "", fsscan.ClassNone, time.Now().Add(time.Minute),
		fsscan.ReadOpts{MaxSize: 1 << 20})
	if len(scan.Folders) != MaxWorkspaceDirs {
		t.Fatalf("read %d folders, want %d", len(scan.Folders), MaxWorkspaceDirs)
	}
	newest := testutil.FileURL(filepath.Join(home, "code", fmt.Sprintf("w%04d", total-1)))
	if scan.Folders[0].Recorded != newest {
		t.Errorf("first folder = %q, want the newest, %q", scan.Folders[0].Recorded, newest)
	}
	for _, folder := range scan.Folders {
		for index := 0; index < 3; index++ {
			if folder.Recorded == testutil.FileURL(filepath.Join(home, "code", fmt.Sprintf("w%04d", index))) {
				t.Errorf("an older record was read: %s", folder.Recorded)
			}
		}
	}
	want := DirListing{Limit: MaxWorkspaceEntries, Older: 3, Origin: OriginVSCodeWorkspace}
	if len(scan.Listings) != 1 || scan.Listings[0] != want {
		t.Errorf("listings = %+v, want %+v", scan.Listings, want)
	}
}

// TestNewerFilesDoNotDisplaceAWorkspaceRecord: MaxWorkspaceDirs regular files, each newer than
// the one record directory, are not records, so the record is still read and nothing is counted
// as older.
func TestNewerFilesDoNotDisplaceAWorkspaceRecord(t *testing.T) {
	home := t.TempDir()
	storage := filepath.Join(home, AppSupportFork("Code", "User", "workspaceStorage")[0])
	record := filepath.Join(storage, "record")
	project := testutil.FileURL(filepath.Join(home, "code", "project"))
	testutil.WriteFile(t, filepath.Join(record, "workspace.json"), `{"folder":"`+project+`"}`)
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(record, past, past); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < MaxWorkspaceDirs; index++ {
		testutil.WriteFile(t, filepath.Join(storage, fmt.Sprintf("f%04d", index)), "")
	}
	scan := WorkspaceFolders(context.Background(), home, "", fsscan.ClassNone, time.Now().Add(time.Minute),
		fsscan.ReadOpts{MaxSize: 1 << 20})
	if len(scan.Folders) != 1 || scan.Folders[0].Recorded != project || len(scan.Listings) != 0 ||
		scan.UnreadableRecords != 0 {
		t.Errorf("scan = %+v, want the record read and nothing counted", scan)
	}
}

func TestStripBOM(t *testing.T) {
	if got := string(StripBOM([]byte("\xEF\xBB\xBF{}"))); got != "{}" {
		t.Errorf("StripBOM = %q", got)
	}
	if got := string(StripBOM([]byte("{}"))); got != "{}" {
		t.Errorf("StripBOM without a mark = %q", got)
	}
}

// recentProjectsXML is the layout GoLand 2026.2 writes, reduced to what the reader uses, with
// one entry per key given. A key containing "hidden:" is written with hidden="true".
func recentProjectsXML(keys ...string) string {
	var entries strings.Builder
	for _, key := range keys {
		hidden := ""
		if rest, ok := strings.CutPrefix(key, "hidden:"); ok {
			key, hidden = rest, ` hidden="true"`
		}
		entries.WriteString(`<entry key="` + key + `"><value><RecentProjectMetaInfo frameTitle="t"` + hidden +
			`><option name="build" value="GO-262" /></RecentProjectMetaInfo></value></entry>`)
	}
	return `<application><component name="RecentProjectsManager"><option name="additionalInfo"><map>` +
		entries.String() + `</map></option><option name="lastOpenedProject" value="$USER_HOME$/x" />` +
		`</component></application>`
}

// TestJetBrainsProjects reads each product's list, expands $USER_HOME$, skips the IDE's own
// hidden scratch workspace and the Toolbox app's directories, and counts a list that does not
// parse. A product that never opened a project has no list and is silent.
func TestJetBrainsProjects(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, AppSupportDir(), "JetBrains")
	testutil.WriteFile(t, filepath.Join(root, "GoLand2026.2", "options", "recentProjects.xml"), recentProjectsXML(
		"$USER_HOME$/Documents/GitHub/svc",
		"hidden:$APPLICATION_CONFIG_DIR$/projects/GoLandWorkspace",
		"$PROJECT_DIR$/elsewhere",
	))
	testutil.WriteFile(t, filepath.Join(root, "PyCharm2026.2", "options", "recentProjects.xml"), recentProjectsXML(
		"$USER_HOME$/PycharmProjects/tool"))
	testutil.WriteFile(t, filepath.Join(root, "IntelliJIdea2026.2", "options", "other.xml"), "<application/>")
	testutil.WriteFile(t, filepath.Join(root, "IdeaIC2025.3", "options", "recentProjects.xml"), "<application><unclosed>")
	testutil.WriteFile(t, filepath.Join(root, "Toolbox", "options", "recentProjects.xml"),
		recentProjectsXML("$USER_HOME$/should/not/appear"))

	scan := JetBrainsProjects(context.Background(), home, "", time.Now().Add(time.Minute),
		fsscan.ReadOpts{MaxSize: 1 << 20})
	var got []string
	for _, folder := range scan.Folders {
		if folder.Origin != OriginJetBrainsRecent || folder.FileURL {
			t.Errorf("folder %+v", folder)
		}
		got = append(got, folder.Recorded)
	}
	want := []string{
		filepath.Join(home, "Documents", "GitHub", "svc"),
		"$PROJECT_DIR$/elsewhere",
		filepath.Join(home, "PycharmProjects", "tool"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("folders =\n%q\nwant\n%q", got, want)
	}
	if scan.MalformedRecords != 1 || scan.UnreadableRecords != 0 || len(scan.Listings) != 0 || scan.Stopped {
		t.Errorf("scan = %+v", scan)
	}

	// An unexpanded placeholder reaches the collector and is counted as an unusable path.
	collector := NewCollector(home, MaxProjects)
	for _, folder := range scan.Folders {
		collector.Add(folder.Recorded, folder.Origin, folder.FileURL)
	}
	if len(collector.Projects()) != 2 || collector.Refusals().Malformed != 1 {
		t.Errorf("projects %+v refusals %+v", collector.Projects(), collector.Refusals())
	}

	if scan := JetBrainsProjects(context.Background(), t.TempDir(), "", time.Now().Add(time.Minute),
		fsscan.ReadOpts{MaxSize: 1 << 20}); len(scan.Folders) != 0 || len(scan.Listings) != 0 {
		t.Errorf("a home with no JetBrains directory is silent, got %+v", scan)
	}
}

// TestRecentProjectsLayout: a recentProjects.xml that parses but is not laid out the way this
// reader knows is reported, so a JetBrains release that renames an element does not read as a
// list with no projects. The two forms IntelliJ writes for an empty list are silent.
func TestRecentProjectsLayout(t *testing.T) {
	entry := `<entry key="$USER_HOME$/svc"><value><RecentProjectMetaInfo /></value></entry>`
	for _, tc := range []struct {
		name       string
		xml        string
		recognized bool
		entries    int
	}{
		{"the known layout", recentProjectsXML("$USER_HOME$/svc"), true, 1},
		{"no components: every property at its default", `<application />`, true, 0},
		{"no additionalInfo: an empty project list",
			`<application><component name="RecentProjectsManager"><option name="lastProjectLocation" value="$USER_HOME$/GolandProjects" /></component></application>`, true, 0},
		{"a renamed component",
			`<application><component name="RecentProjectsManagerV2"><option name="additionalInfo"><map>` + entry + `</map></option></component></application>`, false, 0},
		{"a renamed map option",
			`<application><component name="RecentProjectsManager"><option name="projectInfo"><map>` + entry + `</map></option></component></application>`, false, 0},
		{"an unfamiliar element in the map",
			`<application><component name="RecentProjectsManager"><option name="additionalInfo"><map><item key="$USER_HOME$/svc" /></map></option></component></application>`, false, 0},
		{"additionalInfo holding a list instead of a map",
			`<application><component name="RecentProjectsManager"><option name="additionalInfo"><list><option value="$USER_HOME$/svc" /></list></option></component></application>`, false, 0},
		{"additionalInfo with no content",
			`<application><component name="RecentProjectsManager"><option name="additionalInfo" /></component></application>`, false, 0},
		{"additionalInfo with an empty map",
			`<application><component name="RecentProjectsManager"><option name="additionalInfo"><map /></option></component></application>`, true, 0},
		{"an entry with no key",
			`<application><component name="RecentProjectsManager"><option name="additionalInfo"><map><entry><value /></entry></map></option></component></application>`, false, 0},
		{"another root element",
			`<project><component name="RecentProjectsManager"><option name="additionalInfo"><map>` + entry + `</map></option></component></project>`, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var file recentProjectsFile
			if err := xml.Unmarshal([]byte(tc.xml), &file); err != nil {
				t.Fatal(err)
			}
			entries, recognized := recentEntries(file)
			if recognized != tc.recognized || len(entries) != tc.entries {
				t.Errorf("recognized %v entries %d, want %v and %d", recognized, len(entries), tc.recognized, tc.entries)
			}
		})
	}

	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, AppSupportDir(), "JetBrains", "GoLand2026.2", "options", "recentProjects.xml"),
		`<application><component name="RecentProjectsManagerV2"><option name="additionalInfo"><map>`+entry+`</map></option></component></application>`)
	scan := JetBrainsProjects(context.Background(), home, "", time.Now().Add(time.Minute), fsscan.ReadOpts{MaxSize: 1 << 20})
	if len(scan.Folders) != 0 || scan.MalformedRecords != 1 {
		t.Errorf("an unfamiliar layout gave folders %v malformed %d, want none and 1", scan.Folders, scan.MalformedRecords)
	}
}

// TestAnOverlongProjectPathIsMalformed: a recorded path whose absolute form is longer than
// MaxProjectPathLen, or whose recorded form could not contain to one that short, is counted as
// malformed and not admitted, so no row publishes it.
func TestAnOverlongProjectPathIsMalformed(t *testing.T) {
	home := t.TempDir()
	collector := NewCollector(home, MaxProjects)
	long := filepath.Join(home, strings.Repeat("a", MaxProjectPathLen))
	huge := filepath.Join(home, strings.Repeat("b", 4*MaxProjectPathLen))
	kept := filepath.Join(home, "svc")
	for _, recorded := range []string{long, huge, kept} {
		collector.Add(recorded, OriginClaudeJSON, false)
	}
	if got := collector.Projects(); len(got) != 1 || got[0].Abs != kept {
		t.Errorf("projects = %+v, want only the ordinary one", got)
	}
	if got := collector.Refusals().Malformed; got != 2 {
		t.Errorf("malformed = %d, want 2", got)
	}
}

// TestAFileURLAtTheLengthLimitIsAdmitted: a fully percent-encoded file URL whose decoded path is
// exactly MaxProjectPathLen bytes is admitted in both spellings the reader accepts, file:/// and
// file://localhost/, so the pre-parse bound refuses nothing that would decode within the limit.
func TestAFileURLAtTheLengthLimitIsAdmitted(t *testing.T) {
	home := t.TempDir()
	name := strings.Repeat("a", MaxProjectPathLen-len(home)-1)
	want := filepath.Join(home, name)
	if len(want) != MaxProjectPathLen {
		t.Fatalf("fixture path is %d bytes, want %d", len(want), MaxProjectPathLen)
	}
	slashedHome := filepath.ToSlash(home)
	if !strings.HasPrefix(slashedHome, "/") {
		slashedHome = "/" + slashedHome
	}
	// Every byte after the leading slash is percent-encoded, so the URL is as long as a path of
	// this length can make it.
	var encoded strings.Builder
	encoded.WriteString("/")
	for _, b := range []byte(slashedHome[1:] + "/" + name) {
		fmt.Fprintf(&encoded, "%%%02X", b)
	}
	for _, recorded := range []string{"file://" + encoded.String(), "file://localhost" + encoded.String()} {
		collector := NewCollector(home, MaxProjects)
		collector.Add(recorded, OriginVSCodeWorkspace, true)
		if got := collector.Projects(); len(got) != 1 || got[0].Abs != want {
			t.Errorf("%.30s...: projects = %d, refusals = %+v; want the project admitted",
				recorded, len(got), collector.Refusals())
		}
	}
	// The same path with a component that names no path bytes is refused as malformed, whatever
	// its length, so the answer does not depend on which spelling was recorded.
	for _, recorded := range []string{
		"file://user@localhost" + encoded.String(),
		"file://" + encoded.String() + "?ignored",
		"file://" + encoded.String() + "#ignored",
	} {
		collector := NewCollector(home, MaxProjects)
		collector.Add(recorded, OriginVSCodeWorkspace, true)
		if len(collector.Projects()) != 0 || collector.Refusals().Malformed != 1 {
			t.Errorf("%.30s...: projects = %d, refusals = %+v; want one malformed refusal",
				recorded, len(collector.Projects()), collector.Refusals())
		}
	}
}

// TestRecordedValuesAreBoundedAndNotCleaned: a recorded value longer than MaxRecordedPathLen is
// blanked as soon as it is read, and a JetBrains $USER_HOME$ path is expanded by concatenation,
// so a ".." in it reaches containment and is refused rather than cleaned away. A placeholder not
// followed by a separator is left as written. Each is counted as malformed.
func TestRecordedValuesAreBoundedAndNotCleaned(t *testing.T) {
	if got := boundedRecorded(strings.Repeat("a", MaxRecordedPathLen+1)); got != "" {
		t.Errorf("an overlong recorded value was kept (%d bytes)", len(got))
	}
	home := t.TempDir()
	if got := expandUserHome("$USER_HOME$", home); got != home {
		t.Errorf("expandUserHome($USER_HOME$) = %q, want the home", got)
	}
	collector := NewCollector(home, MaxProjects)
	for _, recorded := range []string{"$USER_HOME$/a/../b", "$USER_HOME$extra/svc", "$USER_HOME$/svc"} {
		collector.Add(expandUserHome(recorded, home), OriginJetBrainsRecent, false)
	}
	if got := collector.Projects(); len(got) != 1 || got[0].Abs != filepath.Join(home, "svc") {
		t.Errorf("projects = %+v, want only $USER_HOME$/svc", got)
	}
	if got := collector.Refusals().Malformed; got != 2 {
		t.Errorf("malformed = %d, want the .. path and the unseparated placeholder", got)
	}
}

// TestANullWorkspaceFolderIsMalformed: a record with no folder that names a workspace file is a
// multi-root workspace, silent when the file is absent. A folder that is null or not a string, a
// top-level null, an empty object and an empty workspace name are counted as malformed. A recorded key
// in ~/.claude.json longer than MaxRecordedPathLen is blanked as it is read.
func TestANullWorkspaceFolderIsMalformed(t *testing.T) {
	home := t.TempDir()
	storage := filepath.Join(home, AppSupportFork("Code", "User", "workspaceStorage")[0])
	testutil.WriteFile(t, filepath.Join(storage, "aa", "workspace.json"),
		`{"workspace":"`+testutil.FileURL(filepath.Join(home, "gone.code-workspace"))+`"}`)
	testutil.WriteFile(t, filepath.Join(storage, "bb", "workspace.json"), `{"folder":null}`)
	testutil.WriteFile(t, filepath.Join(storage, "cc", "workspace.json"), `{"folder":7}`)
	testutil.WriteFile(t, filepath.Join(storage, "dd", "workspace.json"), `null`)
	testutil.WriteFile(t, filepath.Join(storage, "ee", "workspace.json"), `{}`)
	testutil.WriteFile(t, filepath.Join(storage, "ff", "workspace.json"), `{"workspace":""}`)
	scan := WorkspaceFolders(context.Background(), home, "", fsscan.ClassNone, time.Now().Add(time.Minute),
		fsscan.ReadOpts{MaxSize: 1 << 20})
	if len(scan.Folders) != 0 || scan.MalformedRecords != 5 {
		t.Errorf("scan = %+v, want no folders and five malformed records: only aa is multi-root", scan)
	}
	entries, err := ClaudeEntries([]byte(`{"projects":{"` + strings.Repeat("a", MaxRecordedPathLen+1) + `":{}}}`))
	if err != nil || len(entries) != 1 || entries[0].Recorded != "" {
		t.Errorf("entries = %d, err = %v; want one entry with its overlong key blanked", len(entries), err)
	}
}
