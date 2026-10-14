package mcp_servers

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
)

// The per-OS configuration roots, asserted for every platform from whichever one runs the
// suite. Only macOS is developed on and CI runs only Linux, so without the OS being a
// parameter the Windows spelling and the Linux sandbox roots would be asserted by nothing.

func TestAppSupportDirPerOS(t *testing.T) {
	for goos, want := range map[string]string{
		"darwin":  filepath.Join("Library", "Application Support"),
		"windows": filepath.Join("AppData", "Roaming"),
		"linux":   ".config",
	} {
		if got := appSupportDirFor(goos); got != want {
			t.Errorf("appSupportDirFor(%q) = %q, want %q", goos, got, want)
		}
	}
	// An OS with no case of its own gets the macOS layout rather than an empty root, which
	// would silently turn every application-support path into a home-relative one.
	if got := appSupportDirFor("dragonfly"); got != filepath.Join("Library", "Application Support") {
		t.Errorf("unlisted OS fell through to %q", got)
	}
}

func TestAppSupportForkSandboxRoots(t *testing.T) {
	for _, tc := range []struct {
		name string
		goos string
		fork string
		want []string
	}{
		{
			name: "macOS has exactly one root",
			goos: "darwin", fork: "Code",
			want: []string{filepath.Join("Library", "Application Support", "Code", "User", "mcp.json")},
		},
		{
			name: "Windows has exactly one root",
			goos: "windows", fork: "Code",
			want: []string{filepath.Join("AppData", "Roaming", "Code", "User", "mcp.json")},
		},
		{
			// The gap this table closes: a snap or flatpak editor writes nowhere near
			// ~/.config, so the native root alone reports nothing for it.
			name: "Linux adds the snap and flatpak roots for a sandboxed fork",
			goos: "linux", fork: "Code",
			want: []string{
				filepath.Join(".config", "Code", "User", "mcp.json"),
				filepath.Join("snap", "code", "current", ".config", "Code", "User", "mcp.json"),
				filepath.Join(".var", "app", "com.visualstudio.code", "config", "Code", "User", "mcp.json"),
			},
		},
		{
			// The snap name and flatpak id follow no derivable rule, which is why they are
			// a table rather than a transformation of the fork name.
			name: "Insiders uses its own snap name and application id",
			goos: "linux", fork: "Code - Insiders",
			want: []string{
				filepath.Join(".config", "Code - Insiders", "User", "mcp.json"),
				filepath.Join("snap", "code-insiders", "current", ".config", "Code - Insiders", "User", "mcp.json"),
				filepath.Join(".var", "app", "com.visualstudio.code.insiders", "config", "Code - Insiders", "User", "mcp.json"),
			},
		},
		{
			// Cursor ships as AppImage and .deb, which write to ~/.config like a native
			// install. Inventing sandbox roots for it would add probes that never match.
			name: "a fork with no sandboxed channel gets no extra roots",
			goos: "linux", fork: "Cursor",
			want: []string{filepath.Join(".config", "Cursor", "User", "mcp.json")},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := appSupportForkFor(tc.goos, tc.fork, "User", "mcp.json")
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("appSupportForkFor(%q, %q) =\n  %q\nwant\n  %q", tc.goos, tc.fork, got, tc.want)
			}
		})
	}
}

// TestVSCodeFamilySourcesCoverEveryForkAndClient guards the generated source list against a
// fork silently dropping out of it, which the hand-written form made visible and generation
// does not.
func TestVSCodeFamilySourcesCoverEveryForkAndClient(t *testing.T) {
	sources := vscodeFamilySources()

	byClient := map[string]int{}
	for _, src := range sources {
		byClient[src.client]++
		if src.relPath == "" {
			t.Error("generated a source with an empty relPath")
		}
		if src.extract == nil {
			t.Errorf("source %q has no extractor", src.relPath)
		}
		if !src.jsonc {
			t.Errorf("source %q should be parsed as JSONC: VS Code permits comments", src.relPath)
		}
	}
	// Three forks report as vscode (Code, Insiders, VSCodium), and Cline's four host dirs
	// all report as cline. On a non-Linux host that is one path each.
	for client, atLeast := range map[string]int{
		"vscode": 3, "cursor": 1, "windsurf": 1, "cline": 4,
	} {
		if byClient[client] < atLeast {
			t.Errorf("client %q has %d sources, want at least %d", client, byClient[client], atLeast)
		}
	}

	// Every fork that keeps a user-scope config must appear, or that editor is invisible.
	for _, fork := range vscodeFamily {
		found := false
		for _, src := range sources {
			if filepath.Base(filepath.Dir(filepath.Dir(src.relPath))) == fork.dir {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("fork %q produced no user-scope source", fork.dir)
		}
	}
}

// TestScanKeySeparatesAccountsThatShareAHomeOnWindows pins the cache key against the bug the
// scan cache introduced.
//
// Two accounts can report the same profile path. On Windows discovery is not a pure function
// of that path: roamingRootFor resolves Roaming AppData from the registry hive named by the
// account's SID, so the same directory can yield different roots, different warnings and
// different rows per account. Keyed on path alone, the first account scanned decided the
// answer for every other and copyRowsFor relabelled it -- attributing one account's
// redirected AppData, or its "could not be determined" warning, to a different account.
//
// Everywhere else discovery does depend only on the directory, and a shared home should be
// scanned once; a key that always included the ID would silently undo the cache.
func TestScanKeySeparatesAccountsThatShareAHomeOnWindows(t *testing.T) {
	a := fsscan.UserHome{Name: "alice", ID: "S-1-5-21-1-2-3-1001", Path: `C:\Users\shared`}
	b := fsscan.UserHome{Name: "bob", ID: "S-1-5-21-1-2-3-1002", Path: `C:\Users\shared`}

	if scanKeyFor("windows", a) == scanKeyFor("windows", b) {
		t.Error("two SIDs sharing a profile path must not share a cache entry: each " +
			"resolves its own AppData location from its own registry hive")
	}
	// Off Windows the ID is not an input to discovery, so including it would scan a shared
	// home once per account for no benefit.
	for _, goos := range []string{"darwin", "linux"} {
		if scanKeyFor(goos, a) != scanKeyFor(goos, b) {
			t.Errorf("%s: a shared home should be scanned once, got %q vs %q",
				goos, scanKeyFor(goos, a), scanKeyFor(goos, b))
		}
		if scanKeyFor(goos, a) != a.Path {
			t.Errorf("%s: scanKey = %q, want the home path", goos, scanKeyFor(goos, a))
		}
	}
}

// TestProfileDirsCarryTheirClient pins the attribution that path-based classification cannot
// do once a directory has moved.
//
// The deleted classifier recognised the VS Code family by the conventional
// application-support root. Redirect Windows Roaming AppData and that root is no longer in
// the path, so a profile config was discovered, classified "unknown", and missed by
// `WHERE client = 'cursor'` -- present in the table and absent from the query an
// administrator would write.
//
// The enumeration already knows which fork's directory it is listing, so the pairing is
// carried instead of re-derived. That is also why the prefix-matching lookup this used to
// need is gone: a path is no longer classified after the fact, so there is no prefix to
// match and no sibling-name collision to defend against.
func TestProfileDirsCarryTheirClient(t *testing.T) {
	dirs := vscodeProfileDirs()
	if len(dirs) == 0 {
		t.Fatal("no profile directories generated")
	}
	byClient := map[string]int{}
	for _, dir := range dirs {
		if dir.client == "" {
			t.Errorf("profile directory %q carries no client", dir.relPath)
		}
		if dir.relPath == "" {
			t.Error("profile directory has no path")
		}
		// Every one must end in the generated-name parent, which is what makes a one-level
		// listing the right instrument: the child names are the profile ids.
		if filepath.Base(dir.relPath) != "profiles" {
			t.Errorf("profile directory %q does not name a profiles parent", dir.relPath)
		}
		byClient[dir.client]++
	}
	// Cursor and Windsurf report as themselves; Code, Insiders and VSCodium all as vscode.
	for client, atLeast := range map[string]int{"cursor": 1, "windsurf": 1, "vscode": 3} {
		if byClient[client] < atLeast {
			t.Errorf("client %q owns %d directories, want at least %d",
				client, byClient[client], atLeast)
		}
	}
	// And each client must be one the emitted enum accepts, or a profile-scoped row is
	// found and then rewritten to "unknown" at the boundary.
	for _, dir := range dirs {
		if _, ok := allowedClients[dir.client]; !ok {
			t.Errorf("profile directory client %q is not in allowedClients", dir.client)
		}
	}
}

// The one-level enumeration finds a profile-scoped config, which no fixed path can name.
//
// Without this the walk's removal would have silently lost every per-profile configuration on
// the host: the directory name is generated by the editor, so the user-scope mcp.json the
// probe list covers is a different file from the one a user with a work profile and a personal
// profile actually has.
func TestGeneratedProfileConfigsAreFound(t *testing.T) {
	home := t.TempDir()
	profileDir := filepath.Join(home, appSupport("Cursor", "User", "profiles", "-abc123de"))
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profileDir, "mcp.json"),
		[]byte(`{"servers":{"profile-scoped":{"command":"npx","args":["x"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// A Codex named profile, the other generated-name case.
	codexDir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexDir, "work.config.toml"),
		[]byte("[mcp_servers.named-profile]\ncommand = \"npx\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A file in the same directory that is not a Codex config, which isCodexTOMLPath must
	// keep out: config.toml is one of the commonest basenames on a developer machine, and
	// the narrowing is the only thing making the match mean anything.
	if err := os.WriteFile(filepath.Join(codexDir, "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	found := map[string]string{}
	for _, row := range serversOnly(discoverForTest("alice", home)) {
		found[row.ServerName] = row.Client
	}
	if found["profile-scoped"] != "cursor" {
		t.Errorf("a profile-scoped mcp.json was not attributed to cursor: %v", found)
	}
	if found["named-profile"] != "codex" {
		t.Errorf("a Codex named-profile config was not found: %v", found)
	}
}
