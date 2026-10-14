package fsscan

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// writeFile creates a file and every directory above it. Shared by the tests in this
// package rather than redeclared per file: the three that need it are split by build tag,
// and a per-file copy drifted in permissions the last time this was duplicated.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

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
		// NUL truncates a path at the syscall boundary, so the string Go inspects and the
		// path the kernel opens are different strings.
		{name: "NUL byte", goos: "darwin", home: unixHome,
			recorded: "/Users/alice/safe\x00/../../etc", wantErr: ErrMalformedPath},
		{name: "newline", goos: "darwin", home: unixHome,
			recorded: "/Users/alice/a\nb", wantErr: ErrMalformedPath},

		// Windows, reachable only because the OS is a parameter. There is no Windows CI
		// job, so a test that read runtime.GOOS would assert none of this anywhere.
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
		{name: "windows bare UNC", goos: "windows", home: winHome,
			recorded: `\\server\share\p`, wantErr: ErrNotContained},
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
	writeFile(t, filepath.Join(home, "Library", "CloudStorage", "OneDrive", ".mcp.json"), `{}`)
	writeFile(t, filepath.Join(home, "Library", "Mobile Documents", "p", ".mcp.json"), `{}`)
	writeFile(t, filepath.Join(home, "code", ".mcp.json"), `{}`)

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
	// os.SameFile against the file created above is what proves it: a second lookup by name
	// is what used to let an intermediate component redirect this check.
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
	writeFile(t, filepath.Join(base, "profiles", "alpha", "deep", "mcp.json"), `{}`)

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
	writeFile(t, filepath.Join(base, "afile"), `x`)
	if _, err := ListDirNamesUnder(base, "afile", 10); !errors.Is(err, ErrNotRegular) {
		t.Errorf("a file must be refused as not a directory: %v", err)
	}
}

// The Windows sync-provider prefixes, which close the one attribute a handle cannot report
// before causing the download it exists to prevent.
//
// FILE_ATTRIBUTE_RECALL_ON_OPEN is set on exactly the files whose provider starts fetching at
// CreateFile, so the handle-based check learns it too late. A string rule runs first. Driven
// per-OS so both branches are asserted from any host, which is the only way these run at all:
// there is no Windows CI job.
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
