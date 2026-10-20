package fsscan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/macadmins/osquery-extension/pkg/testutil"
)

// Containment is the whole of the security argument for reading a path a user's config file
// recorded, so the refusals are enumerated rather than sampled.
//
// Every row here is a shape a real client writes or a real attacker would: VS Code records
// remote-development URLs for a project on another host, a UNC file URL turns a recorded path
// into an outbound credential, and percent-encoding is the one decoding this repository does
// -- so %2e%2e%2f has to be refused after the decode rather than before it.
func TestContainProjectPath(t *testing.T) {
	const unixHome = "/Users/alice"
	const winHome = `C:\Users\alice`

	for _, tc := range []struct {
		name     string
		goos     string
		home     string
		recorded string
		fileURL  bool
		wantRel  string
		wantErr  error
	}{
		// The ordinary cases, which have to keep working.
		{name: "plain path under home", goos: "darwin", home: unixHome,
			recorded: "/Users/alice/code/project", wantRel: "code/project"},
		{name: "file URL under home", goos: "darwin", home: unixHome,
			recorded: "file:///Users/alice/code/project", fileURL: true, wantRel: "code/project"},
		// The home itself. Not degenerate: a user's home is routinely a recorded project and
		// ~/.mcp.json is a real configuration file, so refusing "." would lose it.
		{name: "the home itself", goos: "darwin", home: unixHome,
			recorded: "/Users/alice", wantRel: "."},
		// Trailing separators are tolerated. Clients leave them behind when they join a
		// name onto a root, and a trailing slash names the same directory.
		{name: "trailing separator", goos: "darwin", home: unixHome,
			recorded: "/Users/alice/code/", wantRel: "code"},
		// A space and a percent in a directory name, taken literally. A bare path is never
		// percent-decoded: a directory called "100%" is ordinary, and decoding would either
		// fail or name a different directory.
		{name: "literal percent in a bare path", goos: "darwin", home: unixHome,
			recorded: "/Users/alice/100%/x", wantRel: "100%/x"},
		// And decoded when a file URL really was recorded, which is how VS Code writes a
		// path containing a space.
		{name: "percent-decoded file URL", goos: "darwin", home: unixHome,
			recorded: "file:///Users/alice/My%20Code", fileURL: true, wantRel: "My Code"},
		// Components that name no path bytes are refused rather than discarded, so a path cannot
		// be accepted in one spelling and refused in another.
		{name: "file URL with userinfo", goos: "darwin", home: unixHome,
			recorded: "file://user@localhost/Users/alice/code", fileURL: true, wantErr: ErrMalformedPath},
		{name: "file URL with a query", goos: "darwin", home: unixHome,
			recorded: "file:///Users/alice/code?ignored", fileURL: true, wantErr: ErrMalformedPath},
		{name: "file URL with an empty query", goos: "darwin", home: unixHome,
			recorded: "file:///Users/alice/code?", fileURL: true, wantErr: ErrMalformedPath},
		{name: "file URL with a fragment", goos: "darwin", home: unixHome,
			recorded: "file:///Users/alice/code#ignored", fileURL: true, wantErr: ErrMalformedPath},
		{name: "file URL with an empty fragment", goos: "darwin", home: unixHome,
			recorded: "file:///Users/alice/code#", fileURL: true, wantErr: ErrMalformedPath},
		{name: "a percent-encoded # is a path byte", goos: "darwin", home: unixHome,
			recorded: "file:///Users/alice/c%23", fileURL: true, wantRel: "c#"},
		// Decoded exactly once, which is the whole of the next three rows. url.Parse has
		// already decoded URL.Path, and decoding it again produced wrong answers on input
		// that is not unusual in any way.
		//
		// A literal percent sign in a directory name, which VS Code writes as %25. Decoded
		// once it is `100%`; decoded twice the lone `%` is not a valid escape, so a real
		// project was refused as malformed.
		{name: "file URL with an encoded percent", goos: "darwin", home: unixHome,
			recorded: "file:///Users/alice/100%25", fileURL: true, wantRel: "100%"},
		// The one that is not merely a missing row. A directory literally named
		// `repo%2Fchild` is written %252F; decoded twice it becomes `repo/child`, which
		// names a different directory and introduces a separator the recorded path never
		// had -- so the containment checks afterwards were run against a string the
		// filesystem does not have. It must stay one component.
		{name: "file URL with an encoded encoded separator", goos: "darwin", home: unixHome,
			recorded: "file:///Users/alice/repo%252Fchild", fileURL: true,
			wantRel: "repo%2Fchild"},
		// A space, to pin that one decode still happens and is not skipped along with the
		// second.
		{name: "file URL with an encoded space", goos: "darwin", home: unixHome,
			recorded: "file:///Users/alice/repo%20child", fileURL: true, wantRel: "repo child"},

		// Remote origins. Each names a filesystem that is not this one.
		{name: "vscode-remote", goos: "darwin", home: unixHome,
			recorded: "vscode-remote://ssh-remote+box/home/alice/p", fileURL: true,
			wantErr: ErrUnsupportedOrigin},
		{name: "ssh-remote", goos: "darwin", home: unixHome,
			recorded: "ssh-remote://box/home/alice/p", fileURL: true,
			wantErr: ErrUnsupportedOrigin},
		{name: "docker", goos: "darwin", home: unixHome,
			recorded: "docker://container/app", fileURL: true, wantErr: ErrUnsupportedOrigin},
		{name: "https", goos: "darwin", home: unixHome,
			recorded: "https://example.test/p", fileURL: true, wantErr: ErrUnsupportedOrigin},
		// The one that is not merely a missing row. file://server/share is a UNC path, so
		// opening it makes this host authenticate to a server named in a file the scanned
		// user controls.
		{name: "UNC file URL", goos: "darwin", home: unixHome,
			recorded: "file://server/share/project", fileURL: true,
			wantErr: ErrUnsupportedOrigin},
		// localhost is the one host a file URL may name, and it means this machine.
		{name: "localhost file URL", goos: "darwin", home: unixHome,
			recorded: "file://localhost/Users/alice/code", fileURL: true, wantRel: "code"},
		// A URL where none is permitted: the Claude and Codex project keys are bare paths.
		{name: "URL where none is allowed", goos: "darwin", home: unixHome,
			recorded: "file:///Users/alice/code", fileURL: false,
			wantErr: ErrUnsupportedOrigin},

		// Traversal, before and after decoding.
		{name: "literal dotdot", goos: "darwin", home: unixHome,
			recorded: "/Users/alice/../bob/p", wantErr: ErrMalformedPath},
		// The reason url.Parse's decode has to land before the ".." inspection rather than
		// after it: %2e%2e%2f must not survive into a path anyone resolves.
		{name: "encoded dotdot", goos: "darwin", home: unixHome,
			recorded: "file:///Users/alice/%2e%2e%2fbob/p", fileURL: true,
			wantErr: ErrMalformedPath},

		// Outside the home, which is a legitimate configuration this declines to follow
		// rather than a broken one -- hence a different sentinel.
		{name: "another user's home", goos: "darwin", home: unixHome,
			recorded: "/Users/other/x", wantErr: ErrNotContained},
		{name: "a shared directory", goos: "darwin", home: unixHome,
			recorded: "/Users/Shared/x", wantErr: ErrNotContained},
		// A sibling whose name merely starts with the home's. filepath.Rel gets this right
		// and a string prefix test would not.
		{name: "home-prefixed sibling", goos: "darwin", home: unixHome,
			recorded: "/Users/alicebackup/x", wantErr: ErrNotContained},

		// Malformed.
		{name: "empty", goos: "darwin", home: unixHome, recorded: "", wantErr: ErrMalformedPath},
		{name: "relative", goos: "darwin", home: unixHome,
			recorded: "code/project", wantErr: ErrMalformedPath},
		// NUL truncates a path where it is handed to the kernel, so the string Go inspects and the
		// path the kernel opens are different strings.
		{name: "NUL byte", goos: "darwin", home: unixHome,
			recorded: "/Users/alice/safe\x00/../../etc", wantErr: ErrMalformedPath},
		{name: "newline", goos: "darwin", home: unixHome,
			recorded: "/Users/alice/a\nb", wantErr: ErrMalformedPath},

		// Windows, reachable only because the OS is a parameter, so these cases run on every
		// host and not only on the windows-latest job.
		{name: "windows drive path", goos: "windows", home: winHome,
			recorded: `C:\Users\alice\code`, wantRel: `code`},
		// The leading slash is URL grammar, not path. Left in place this is not an absolute
		// Windows path, so every VS Code project on Windows would have been refused.
		{name: "windows file URL", goos: "windows", home: winHome,
			recorded: "file:///C:/Users/alice/code", fileURL: true, wantRel: `code`},
		// Windows paths are case-insensitive, so this is the same directory.
		{name: "windows case folding", goos: "windows", home: winHome,
			recorded: `c:\users\alice\code`, wantRel: `code`},
		{name: "windows forward slashes", goos: "windows", home: winHome,
			recorded: `C:/Users/alice/code`, wantRel: `code`},
		{name: "windows outside home", goos: "windows", home: winHome,
			recorded: `C:\Users\other\x`, wantErr: ErrNotContained},
		// Backslash is a separator on Windows, so the ".." inspection has to split on it.
		{name: "windows backslash dotdot", goos: "windows", home: winHome,
			recorded: `C:\Users\alice\..\other`, wantErr: ErrMalformedPath},
		// A UNC path names another host, so it is a remote origin, not a path outside the home;
		// with a drive letter after the separators it was contained as the local drive's.
		{name: "windows bare UNC", goos: "windows", home: winHome,
			recorded: `\\server\share\p`, wantErr: ErrUnsupportedOrigin},
		{name: "windows UNC naming the home", goos: "windows", home: winHome,
			recorded: `\\C:\Users\alice\repo`, wantErr: ErrUnsupportedOrigin},
		{name: "windows forward-slash UNC", goos: "windows", home: winHome,
			recorded: `//server/share/p`, wantErr: ErrUnsupportedOrigin},
		// Cleaned as Windows cleans it on every host, doubled and trailing separators included.
		{name: "windows doubled separators", goos: "windows", home: winHome,
			recorded: `C:\Users\alice\\code\`, wantRel: `code`},
		// macOS folds case like Windows: APFS is case-insensitive by default, so this is the
		// home's directory, and was counted as outside the home and never read.
		{name: "darwin case folding", goos: "darwin", home: unixHome,
			recorded: "/users/alice/code", wantRel: "code"},
		{name: "darwin case-folded sibling", goos: "darwin", home: unixHome,
			recorded: "/users/alicebackup/x", wantErr: ErrNotContained},
		// Linux does not.
		{name: "linux case differs", goos: "linux", home: "/home/alice",
			recorded: "/home/Alice/code", wantErr: ErrNotContained},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rel, err := containProjectPathFor(tc.goos, tc.home, tc.recorded, tc.fileURL)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if rel != "" {
					t.Errorf("a refused path returned rel = %q; it must return nothing a caller could open", rel)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if rel != tc.wantRel {
				t.Errorf("rel = %q, want %q", rel, tc.wantRel)
			}
		})
	}
}

// TestSameDirectoryKey: on Windows and macOS two spellings ContainProjectPath admits for one
// directory share a key, and the key matches strings.EqualFold, which relFor compares under, for
// a rune strings.ToLower does not fold: the long s folds with s. On Linux case is significant.
func TestSameDirectoryKey(t *testing.T) {
	for _, tc := range []struct {
		goos, left, right string
		same              bool
	}{
		{"windows", `Code\Repo`, `code\repo`, true},
		{"darwin", "Code/Repo", "code/repo", true},
		{"darwin", "code/ba\u017fe", "code/BASE", true},
		{"darwin", "code/repo", "code/repp", false},
		{"linux", "Code/Repo", "code/repo", false},
		{"linux", "code/repo", "code/repo", true},
	} {
		left, right := sameDirectoryKeyFor(tc.goos, tc.left), sameDirectoryKeyFor(tc.goos, tc.right)
		if (left == right) != tc.same {
			t.Errorf("%s: keys for %q and %q are %q and %q, want same = %v",
				tc.goos, tc.left, tc.right, left, right, tc.same)
		}
		if tc.goos != "linux" && (left == right) != strings.EqualFold(tc.left, tc.right) {
			t.Errorf("%s: keys for %q and %q disagree with strings.EqualFold", tc.goos, tc.left, tc.right)
		}
	}
}

// The prefix rule is a macOS convention and has to behave like one.
//
// Applied on every platform it was a false refusal: ~/Library/CloudStorage on Linux, or a
// Windows profile carrying that directory name, is an ordinary directory with ordinary local
// files in it, and every project beneath one lost its rows with "cloud placeholder" given as
// the reason. Parameterised on the OS rather than gated on runtime.GOOS inside the test, so
// both answers are reachable from whichever host happens to be running this.
func TestUnderCloudStorageAppliesOnDarwinOnly(t *testing.T) {
	cloudRels := []string{
		"Library/CloudStorage",
		"Library/CloudStorage/OneDrive/proj",
		"library/cloudstorage/OneDrive/proj", // case-insensitive volume by default
		"Library/Mobile Documents",
		"Library/Mobile Documents/com~apple~CloudDocs/proj",
	}
	for _, rel := range cloudRels {
		if !underCloudStorageFor("darwin", rel) {
			t.Errorf("darwin: %q must be treated as a file-provider volume", rel)
		}
		for _, goos := range []string{"linux", "windows"} {
			if underCloudStorageFor(goos, rel) {
				t.Errorf("%s: %q is an ordinary directory there and must not be refused",
					goos, rel)
			}
		}
	}
	// Not a prefix match on a longer name, on any platform. Library/CloudStorageOther is a
	// different directory than Library/CloudStorage.
	for _, rel := range []string{"code", "Library", "Library/CloudStorageOther", "Documents"} {
		if underCloudStorageFor("darwin", rel) {
			t.Errorf("darwin: %q is not a file-provider volume", rel)
		}
	}
}

// The cloud-placeholder refusal, both halves.
//
// This is the one check whose failure mode is not a missing row but a side effect: reading an
// evicted file asks the provider to download it, which can take minutes, is charged to a
// scheduled query against the watchdog, and leaves the machine different from how the query
// found it. The prefix rule is testable directly; the attribute rule is reachable only
// through the injected inspector, because no test can evict a file.
func TestReadProjectFileRefusesCloudPlaceholders(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, "Library", "CloudStorage", "OneDrive", ".mcp.json"), `{}`)
	testutil.WriteFile(t, filepath.Join(home, "Library", "Mobile Documents", "p", ".mcp.json"), `{}`)
	testutil.WriteFile(t, filepath.Join(home, "code", ".mcp.json"), `{}`)

	opts := ReadOpts{MaxSize: 1024}
	for _, projRel := range []string{
		filepath.Join("Library", "CloudStorage", "OneDrive"),
		filepath.Join("Library", "Mobile Documents", "p"),
	} {
		_, err := ReadProjectFile(home, projRel, ".mcp.json", opts)
		// End to end, and therefore per platform: these are mount points on macOS and
		// ordinary directories anywhere else, so off darwin the file must read.
		if runtime.GOOS == "darwin" {
			if !errors.Is(err, ErrCloudPlaceholder) {
				t.Errorf("%s: err = %v, want ErrCloudPlaceholder", projRel, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: a local file under a similarly named directory must read: %v",
				projRel, err)
		}
	}

	// An ordinary project directory reads, so the prefix rule has not swallowed everything.
	if data, err := ReadProjectFile(home, "code", ".mcp.json", opts); err != nil || string(data) != "{}" {
		t.Errorf("an ordinary project must read: %q %v", data, err)
	}

	// The attribute rule, through the seam. A file outside any cloud prefix that the
	// platform reports as evicted must still be refused: the prefixes are a backstop for
	// providers whose flag is not recognised, not the primary check.
	evicted := ReadOpts{MaxSize: 1024, CloudPlaceholder: func(*os.File) (bool, error) {
		return true, nil
	}}
	if _, err := ReadProjectFile(home, "code", ".mcp.json", evicted); !errors.Is(err, ErrCloudPlaceholder) {
		t.Errorf("an evicted file outside the known prefixes must be refused: %v", err)
	}

	// And an inspector that fails says nothing either way. Refusing on an attribute that
	// could not be read would report some other failure as the one refusal that tells an
	// operator their file provider is involved.
	broken := ReadOpts{MaxSize: 1024, CloudPlaceholder: func(*os.File) (bool, error) {
		return false, os.ErrPermission
	}}
	if _, err := ReadProjectFile(home, "code", ".mcp.json", broken); err != nil {
		t.Errorf("a failing placeholder check must not refuse a readable file: %v", err)
	}

	// The seam is handed the descriptor the read uses, not a path it has to resolve again.
	// os.SameFile against the file created above proves it. A second lookup by name would
	// let an intermediate component redirect this check.
	var seen os.FileInfo
	inspect := ReadOpts{MaxSize: 1024, CloudPlaceholder: func(file *os.File) (bool, error) {
		info, err := file.Stat()
		seen = info
		return false, err
	}}
	if _, err := ReadProjectFile(home, "code", ".mcp.json", inspect); err != nil {
		t.Fatalf("unexpected read failure: %v", err)
	}
	want, err := os.Stat(filepath.Join(home, "code", ".mcp.json"))
	if err != nil {
		t.Fatal(err)
	}
	if seen == nil || !os.SameFile(seen, want) {
		t.Error("the placeholder inspector was not handed the file that was read")
	}
}

// One level, bounded, sorted, and symlink-refusing. The generated-name directories this
// exists for -- VS Code profiles, Codex named profiles -- are the only thing a fixed path
// cannot reach, so losing them is silent.
func TestListDirNamesUnder(t *testing.T) {
	base := t.TempDir()
	for _, name := range []string{"zeta", "alpha", "mid"} {
		if err := os.MkdirAll(filepath.Join(base, "profiles", name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A child of a child, to pin that this does not recurse.
	testutil.WriteFile(t, filepath.Join(base, "profiles", "alpha", "deep", "mcp.json"), `{}`)

	names, err := ListDirNamesUnder(base, "profiles", 10)
	if err != nil {
		t.Fatal(err)
	}
	// Sorted, because these names reach a row: readdir order is filesystem order, and an
	// unsorted column makes differential logging report unchanged configuration as removed
	// and re-added.
	want := []string{"alpha", "mid", "zeta"}
	if len(names) != len(want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("names = %v, want %v", names, want)
		}
	}

	// The cap is reported, not applied in silence. A truncated listing is an incomplete
	// answer and the caller has to be able to say so.
	capped, err := ListDirNamesUnder(base, "profiles", 2)
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("exceeding the cap must be reported: %v", err)
	}
	if len(capped) != 2 {
		t.Errorf("capped = %v, want 2 names", capped)
	}

	// An empty directory is an answer, not a failure. (*os.File).ReadDir returns io.EOF when
	// n is positive and there is nothing left, so an empty directory and a fully-consumed one
	// are the same signal -- and returning that error made a directory this successfully
	// looked inside indistinguishable from one it could not open. The cost was concrete: an
	// empty VS Code User/profiles raised a home-scope unreadable warning, which flipped an
	// otherwise healthy global row to scan_complete=0, so the completeness filter threw away
	// valid results on a benign layout.
	if err := os.MkdirAll(filepath.Join(base, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	emptyNames, err := ListDirNamesUnder(base, "empty", 10)
	if err != nil {
		t.Fatalf("an empty directory must not be reported as unreadable: %v", err)
	}
	if len(emptyNames) != 0 {
		t.Errorf("emptyNames = %v, want no names", emptyNames)
	}
	// Truncation is signalled by ErrTooLarge alongside the names rather than by a separate
	// return, so "not truncated" is this assertion. Stated separately from the check above
	// because the two failures want different diagnoses: a non-nil ErrTooLarge here would
	// mean an empty listing had been confused with a capped one.
	if errors.Is(err, ErrTooLarge) {
		t.Errorf("an empty directory must not be reported as truncated: %v", err)
	}

	// A file where a directory was expected.
	testutil.WriteFile(t, filepath.Join(base, "afile"), `x`)
	if _, err := ListDirNamesUnder(base, "afile", 10); !errors.Is(err, ErrNotRegular) {
		t.Errorf("a file must be refused as not a directory: %v", err)
	}
}

// The Windows sync-provider prefixes, which close the one attribute a handle cannot report
// before causing the download it exists to prevent.
//
// FILE_ATTRIBUTE_RECALL_ON_OPEN is set on exactly the files whose provider starts fetching at
// CreateFile, so the handle-based check learns it too late. A string rule runs first. Driven
// per-OS so both branches are asserted from any host, not only on the windows-latest job.
func TestWindowsCloudPrefixes(t *testing.T) {
	for _, tc := range []struct {
		goos, rel string
		want      bool
	}{
		// Personal OneDrive, and the business form, which carries the tenant name.
		{"windows", `OneDrive\code\repo`, true},
		{"windows", `OneDrive - Contoso\code\repo`, true},
		{"windows", `onedrive - contoso\code\repo`, true},
		{"windows", "OneDrive", true},
		{"windows", `Dropbox\project`, true},
		{"windows", `Google Drive\project`, true},
		{"windows", `iCloudDrive\project`, true},
		// A project that merely starts with the same letters is not a provider directory.
		{"windows", `OneDriveNotes\project`, false},
		{"windows", `code\onedrive-notes\repo`, false},
		{"windows", `code\repo`, false},
		// The macOS prefixes are macOS conventions and must not fire here, which is the
		// defect this file already covers in the other direction.
		{"windows", `Library/CloudStorage/OneDrive/p`, false},
		// And the Windows set must not fire on macOS or Linux, where a directory called
		// OneDrive in the home is just a directory.
		{"darwin", `OneDrive/code/repo`, false},
		{"linux", `OneDrive/code/repo`, false},
		{"linux", `Dropbox/project`, false},
	} {
		if got := underCloudStorageFor(tc.goos, tc.rel); got != tc.want {
			t.Errorf("underCloudStorageFor(%q, %q) = %v, want %v",
				tc.goos, tc.rel, got, tc.want)
		}
	}
}

// TestListDirNamesCappedSeparatesShortFromFailed pins the three outcomes the helper exists to
// keep apart: a full listing, a capped one that still yields its names, and absence.
func TestListDirNamesCappedSeparatesShortFromFailed(t *testing.T) {
	base := t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		if err := os.MkdirAll(filepath.Join(base, "d", name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if names, truncated, err := ListDirNamesCapped(base, "d", 5); err != nil || truncated || len(names) != 3 {
		t.Errorf("full listing: %v %v %v", names, truncated, err)
	}
	if names, truncated, err := ListDirNamesCapped(base, "d", 2); err != nil || !truncated || len(names) != 2 {
		t.Errorf("capped listing: %v %v %v", names, truncated, err)
	}
	if names, truncated, err := ListDirNamesCapped(base, "missing", 2); err != nil || truncated || names != nil {
		t.Errorf("absent directory: %v %v %v", names, truncated, err)
	}
}

// TestListRecentDirNames: the newest entries are kept, newest first with the name breaking a
// tie, the rest are counted, and only more entries than the read limit is truncation.
func TestListRecentDirNames(t *testing.T) {
	base := t.TempDir()
	now := time.Now()
	for name, age := range map[string]time.Duration{
		"old": 4 * time.Hour, "newest": 0, "tie-b": time.Hour, "tie-a": time.Hour, "older": 3 * time.Hour,
	} {
		dir := filepath.Join(base, "d", name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(dir, now.Add(-age), now.Add(-age)); err != nil {
			t.Fatal(err)
		}
	}
	names, older, links, truncated, err := ListRecentDirNames(base, "d", 3, 10)
	if err != nil || truncated || older != 2 || links != 0 ||
		!reflect.DeepEqual(names, []string{"newest", "tie-a", "tie-b"}) {
		t.Errorf("keep 3 of 5: %v %d %d %v %v", names, older, links, truncated, err)
	}
	if names, older, _, truncated, err := ListRecentDirNames(base, "d", 3, 4); err != nil || !truncated ||
		len(names) != 3 || older != 1 {
		t.Errorf("read 4 of 5: %v %d %v %v", names, older, truncated, err)
	}
	if names, _, _, _, err := ListRecentDirNames(base, "missing", 3, 4); err != nil || names != nil {
		t.Errorf("absent directory: %v %v", names, err)
	}
}

// TestListRecentDirNamesRanksOnlyDirectories: files newer than every directory are not ranked,
// so they cannot push a directory past keep, and are not counted as older.
func TestListRecentDirNamesRanksOnlyDirectories(t *testing.T) {
	base := t.TempDir()
	old := filepath.Join(base, "d", "record")
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.json", "b.json", "c.vscdb"} {
		if err := os.WriteFile(filepath.Join(base, "d", name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	names, older, links, truncated, err := ListRecentDirNames(base, "d", 1, 10)
	if err != nil || truncated || older != 0 || links != 0 || !reflect.DeepEqual(names, []string{"record"}) {
		t.Errorf("one directory among newer files: %v %d %d %v %v", names, older, links, truncated, err)
	}
}

// TestProbeProjectDir: a local project directory probes clean, a missing one reports absence,
// and the network sentinel classifies as its own class. A network mount cannot be created in a
// test, so the local case is what exercises the platform's real filesystem check.
func TestProbeProjectDir(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "code", "svc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ProbeProjectDir(home, filepath.Join("code", "svc")); err != nil {
		t.Errorf("a local project directory = %v, want nil", err)
	}
	// The home itself recorded as a project: ContainProjectPath reports ".", and the probe opens
	// the home rather than refusing an empty path, so it reaches the network-filesystem check.
	if err := ProbeProjectDir(home, "."); err != nil {
		t.Errorf("the home as a project = %v, want nil", err)
	}
	if err := ProbeProjectDir(home, filepath.Join("code", "gone")); ClassifyError(err) != ClassAbsent {
		t.Errorf("a missing project directory = %v (%s), want absent", err, ClassifyError(err))
	}
	if got := ClassifyError(fmt.Errorf("probe: %w", ErrNetworkFilesystem)); got != ClassNetworkFilesystem {
		t.Errorf("the network sentinel classifies as %s", got)
	}
	if UnderCloudStorage(filepath.Join("code", "svc")) {
		t.Error("an ordinary project directory matched a cloud prefix")
	}
}

// TestProbeProjectDirRefusesAFile: a recorded project that is a regular file is refused by the
// probe, as a path through a non-directory is, rather than passing it and failing both reads.
func TestProbeProjectDirRefusesAFile(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, "notes.txt"), "not a project")
	if err := ProbeProjectDir(home, "notes.txt"); ClassifyError(err) != ClassRefusedPath {
		t.Errorf("a file probed as a project = %v (%s), want refused_path", err, ClassifyError(err))
	}
}

// TestListSubdirNames: only directories are listed, sorted, so files beside them are not names;
// more entries than the read limit is truncation; an absent directory is silent.
func TestListSubdirNames(t *testing.T) {
	base := t.TempDir()
	for _, name := range []string{"b", "a", "c"} {
		if err := os.MkdirAll(filepath.Join(base, "d", name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{".DS_Store", "0-file", "1-file"} {
		if err := os.WriteFile(filepath.Join(base, "d", name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if names, _, truncated, err := ListSubdirNames(base, "d", 10); err != nil || truncated ||
		!reflect.DeepEqual(names, []string{"a", "b", "c"}) {
		t.Errorf("three directories among files: %v %v %v", names, truncated, err)
	}
	if _, _, truncated, err := ListSubdirNames(base, "d", 5); err != nil || !truncated {
		t.Errorf("read limit 5 of 6 entries: %v %v", truncated, err)
	}
	if names, _, truncated, err := ListSubdirNames(base, "missing", 10); err != nil || truncated || names != nil {
		t.Errorf("absent directory: %v %v %v", names, truncated, err)
	}
}
