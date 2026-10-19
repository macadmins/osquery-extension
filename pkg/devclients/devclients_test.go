package devclients

import (
	"context"
	"encoding/xml"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fileURL renders a path the way VS Code records a workspace folder: file:///Users/alice/x on
// POSIX and file:///C:/Users/alice/x on Windows, where the drive letter follows a third slash.
// Joining "file://" to a Windows path directly gives file://C:/..., whose host is "C:", which
// the reader correctly refuses as a remote location.
func fileURL(path string) string {
	slashed := filepath.ToSlash(path)
	if !strings.HasPrefix(slashed, "/") {
		slashed = "/" + slashed
	}
	return "file://" + slashed
}

// TestAppSupportPathsPerOS pins the three spellings of the application-support root and the
// extra Linux sandbox roots, which no single CI host can execute natively.
func TestAppSupportPathsPerOS(t *testing.T) {
	for goos, want := range map[string]string{
		"darwin":  filepath.Join("Library", "Application Support"),
		"windows": filepath.Join("AppData", "Roaming"),
		"linux":   ".config",
	} {
		if got := AppSupportDirFor(goos); got != want {
			t.Errorf("AppSupportDirFor(%q) = %q, want %q", goos, got, want)
		}
	}
	got := AppSupportForkFor("linux", "Code", "User")
	want := []string{
		filepath.Join(".config", "Code", "User"),
		filepath.Join("snap", "code", "current", ".config", "Code", "User"),
		filepath.Join(".var", "app", "com.visualstudio.code", "config", "Code", "User"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AppSupportForkFor(linux, Code) = %q, want %q", got, want)
	}
	if got := AppSupportForkFor("darwin", "Cursor", "User"); len(got) != 1 {
		t.Errorf("a non-Linux host has one root per fork, got %q", got)
	}
}

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
	if index, ok := collector.Add(fileURL(filepath.Join(home, "code", "a")), OriginVSCodeWorkspace, true); !ok || index != 0 {
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
	writeFile(t, filepath.Join(codeStorage, "aa", "workspace.json"),
		`{"folder":"`+fileURL(filepath.Join(home, "code", "one"))+`"}`)
	writeFile(t, filepath.Join(codeStorage, "bb", "workspace.json"), `{"workspace":"x.code-workspace"}`)
	writeFile(t, filepath.Join(codeStorage, "cc", "workspace.json"), `{not json`)
	writeFile(t, filepath.Join(codeStorage, "dd", "unrelated.txt"), "")
	writeFile(t, filepath.Join(cursorStorage, "ee", "workspace.json"),
		`{"folder":"`+fileURL(filepath.Join(home, "code", "two"))+`"}`)

	scan := WorkspaceFolders(context.Background(), home, "", time.Now().Add(time.Minute),
		fsscan.ReadOpts{MaxSize: 1 << 20})
	want := []WorkspaceFolder{
		{Recorded: fileURL(filepath.Join(home, "code", "one")), Origin: OriginVSCodeWorkspace, FileURL: true},
		{Recorded: fileURL(filepath.Join(home, "code", "two")), Origin: OriginCursorWorkspace, FileURL: true},
	}
	if !reflect.DeepEqual(scan.Folders, want) {
		t.Errorf("folders = %+v, want %+v", scan.Folders, want)
	}
	if scan.MalformedRecords != 1 || scan.UnreadableRecords != 0 || scan.Stopped || len(scan.Listings) != 0 {
		t.Errorf("scan = %+v", scan)
	}
}

// TestWorkspaceFoldersReportsTruncationAndStop covers the capped listing and a cancelled
// query, the two ways the enumeration returns less than the directory holds.
func TestWorkspaceFoldersReportsTruncationAndStop(t *testing.T) {
	home := t.TempDir()
	storage := filepath.Join(home, AppSupportFork("Code", "User", "workspaceStorage")[0])
	for index := 0; index <= MaxWorkspaceDirs; index++ {
		if err := os.MkdirAll(filepath.Join(storage, "w"+strconv.Itoa(index)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	scan := WorkspaceFolders(context.Background(), home, "", time.Now().Add(time.Minute),
		fsscan.ReadOpts{MaxSize: 1 << 20})
	if len(scan.Listings) != 1 || !scan.Listings[0].Truncated || scan.Listings[0].Count != MaxWorkspaceDirs {
		t.Errorf("listings = %+v, want one truncated listing of %d", scan.Listings, MaxWorkspaceDirs)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if scan := WorkspaceFolders(cancelled, home, "", time.Now().Add(time.Minute),
		fsscan.ReadOpts{MaxSize: 1 << 20}); !scan.Stopped {
		t.Error("a cancelled query stops the enumeration and says so")
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

// TestScanKeyFor: on Windows two accounts sharing a profile path are different keys, because
// discovery reads each account's own registry hive; elsewhere the path is the whole key.
func TestScanKeyFor(t *testing.T) {
	a := fsscan.UserHome{Name: "a", ID: "S-1-5-21-1", Path: `C:\Users\shared`}
	b := fsscan.UserHome{Name: "b", ID: "S-1-5-21-2", Path: `C:\Users\shared`}
	if ScanKeyFor("windows", a) == ScanKeyFor("windows", b) {
		t.Error("windows: accounts with different SIDs share a key")
	}
	for _, goos := range []string{"darwin", "linux"} {
		if ScanKeyFor(goos, a) != ScanKeyFor(goos, b) {
			t.Errorf("%s: a shared home is scanned twice", goos)
		}
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
	writeFile(t, filepath.Join(root, "GoLand2026.2", "options", "recentProjects.xml"), recentProjectsXML(
		"$USER_HOME$/Documents/GitHub/svc",
		"hidden:$APPLICATION_CONFIG_DIR$/projects/GoLandWorkspace",
		"$PROJECT_DIR$/elsewhere",
	))
	writeFile(t, filepath.Join(root, "PyCharm2026.2", "options", "recentProjects.xml"), recentProjectsXML(
		"$USER_HOME$/PycharmProjects/tool"))
	writeFile(t, filepath.Join(root, "IntelliJIdea2026.2", "options", "other.xml"), "<application/>")
	writeFile(t, filepath.Join(root, "IdeaIC2025.3", "options", "recentProjects.xml"), "<application><unclosed>")
	writeFile(t, filepath.Join(root, "Toolbox", "options", "recentProjects.xml"),
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
	writeFile(t, filepath.Join(home, AppSupportDir(), "JetBrains", "GoLand2026.2", "options", "recentProjects.xml"),
		`<application><component name="RecentProjectsManagerV2"><option name="additionalInfo"><map>`+entry+`</map></option></component></application>`)
	scan := JetBrainsProjects(context.Background(), home, "", time.Now().Add(time.Minute), fsscan.ReadOpts{MaxSize: 1 << 20})
	if len(scan.Folders) != 0 || scan.MalformedRecords != 1 {
		t.Errorf("an unfamiliar layout gave folders %v malformed %d, want none and 1", scan.Folders, scan.MalformedRecords)
	}
}
