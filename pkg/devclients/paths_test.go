package devclients

import (
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
			// A snap or flatpak editor writes nowhere near ~/.config, so the native root alone
			// reports nothing for it.
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

// TestScanKeySeparatesAccountsThatShareAHome: two accounts can report the same home. Each read is
// judged against the account being scanned, so two identities sharing a directory can get
// different rows and refusals, and on Windows different AppData roots; they must not share a
// cache entry. Two accounts with the same identity and home still share one scan.
func TestScanKeySeparatesAccountsThatShareAHome(t *testing.T) {
	for _, pair := range [][2]fsscan.UserHome{
		{{Name: "alice", ID: "S-1-5-21-1-2-3-1001", Path: `C:\Users\shared`},
			{Name: "bob", ID: "S-1-5-21-1-2-3-1002", Path: `C:\Users\shared`}},
		{{Name: "root", ID: "0", Path: "/var/root"}, {Name: "daemon", ID: "1", Path: "/var/root"}},
	} {
		if ScanKey(pair[0]) == ScanKey(pair[1]) {
			t.Errorf("%s and %s share a home with different identities and must not share a "+
				"cache entry", pair[0].Name, pair[1].Name)
		}
	}
	twin := fsscan.UserHome{Name: "toor", ID: "0", Path: "/var/root"}
	if ScanKey(twin) != ScanKey(fsscan.UserHome{Name: "root", ID: "0", Path: "/var/root"}) {
		t.Error("two accounts with the same uid and home should share one scan")
	}
}

// TestSandboxConfigLocationsAreGeneratedAsProbePaths: a flatpak keeps configuration at
// ~/.var/app/<id>/config/... and a snap under ~/snap/<name>/current/.config/..., neither of
// which is the platform's application-support root. appSupportForkFor generates each sandbox
// location as an explicit path to probe, so a table looks for the file where it lives. Asserted
// through the OS-parameterized form, because the Linux branch is unreachable from a macOS test
// host.
func TestSandboxConfigLocationsAreGeneratedAsProbePaths(t *testing.T) {
	for _, tc := range []struct {
		goos, fork string
		wantAny    []string
	}{
		// Linux generates the native root plus both sandbox roots for the forks that have
		// an official sandboxed channel.
		{"linux", "Code", []string{
			".config/Code/User/mcp.json",
			"snap/code/current/.config/Code/User/mcp.json",
			".var/app/com.visualstudio.code/config/Code/User/mcp.json",
		}},
		{"linux", "VSCodium", []string{
			".config/VSCodium/User/mcp.json",
			"snap/codium/current/.config/VSCodium/User/mcp.json",
			".var/app/com.vscodium.codium/config/VSCodium/User/mcp.json",
		}},
		// Cursor ships as AppImage and .deb, which write to ~/.config like a native
		// install, so it has no sandbox roots and must not grow probes that cannot match.
		{"linux", "Cursor", []string{".config/Cursor/User/mcp.json"}},
		// Elsewhere there is exactly one root and no sandbox concept.
		{"darwin", "Code", []string{"Library/Application Support/Code/User/mcp.json"}},
		{"windows", "Code", []string{"AppData/Roaming/Code/User/mcp.json"}},
	} {
		got := appSupportForkFor(tc.goos, tc.fork, "User", "mcp.json")
		var slashed []string
		for _, path := range got {
			slashed = append(slashed, filepath.ToSlash(path))
		}
		if len(slashed) != len(tc.wantAny) {
			t.Errorf("%s/%s generated %v, want %v", tc.goos, tc.fork, slashed, tc.wantAny)
			continue
		}
		for _, want := range tc.wantAny {
			var found bool
			for _, have := range slashed {
				if have == want {
					found = true
				}
			}
			if !found {
				t.Errorf("%s/%s is missing the probe path %q; got %v",
					tc.goos, tc.fork, want, slashed)
			}
		}
	}
}
