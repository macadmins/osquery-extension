//go:build unix

package mcp_servers

import (
	"context"
	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// End-to-end coverage for the sandboxed Linux install layouts.
//
// The path-construction tests assert what strings are built. They cannot see either of the
// two reasons a correctly-built path still produced nothing: snap's `current` is a symlink
// and this package refuses to traverse symlinks, and a flatpak config sits outside the
// platform's application-support root so classification never matched it. Both bugs shipped
// with tests passing.
//
// Built with real symlinks, so these run on unix only. The behaviour under test is Linux's,
// but the mechanisms -- Readlink, refusing a non-revision target, classifying by path -- are
// identical on macOS, which is where this suite actually runs.
//
// Not named *_linux_test.go: Go derives an implicit GOOS constraint from that filename
// suffix, which would have excluded the file everywhere except Linux and left these tests
// running nowhere at all -- the same silence they exist to catch.

func TestResolveSnapPathRequiresARevisionTarget(t *testing.T) {
	home := t.TempDir()
	snapDir := filepath.Join(home, "snap", "code")
	if err := os.MkdirAll(filepath.Join(snapDir, "168"), 0o755); err != nil {
		t.Fatal(err)
	}
	const rel = "snap/code/current/.config/Code/User/mcp.json"

	// No pointer yet: not installed, so not resolvable and not an error.
	if _, ok := resolveSnapPath(home, rel); ok {
		t.Error("a missing current pointer should not resolve")
	}

	link := filepath.Join(snapDir, "current")
	if err := os.Symlink("168", link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	got, ok := resolveSnapPath(home, rel)
	if !ok {
		t.Fatal("a current -> 168 pointer should resolve")
	}
	want := filepath.Join("snap", "code", "168", ".config", "Code", "User", "mcp.json")
	if got != want {
		t.Errorf("resolved to %q, want %q", got, want)
	}

	// The whole point of resolving by hand is to keep what the symlink refusal gave us, so
	// a target that is not a revision must be refused rather than followed.
	for _, hostile := range []string{"../../../etc", "/etc", "..", "notarevision"} {
		_ = os.Remove(link)
		if err := os.Symlink(hostile, link); err != nil {
			continue
		}
		if _, ok := resolveSnapPath(home, rel); ok {
			t.Errorf("current -> %q was accepted; only a revision component may be", hostile)
		}
	}
}

// TestSnapConfigIsDiscoveredEndToEnd drives discoverForHome, not the helpers.
//
// The previous version called resolveSnapPath, then os.ReadFile, then the parser by hand. It
// passed while discovery was still broken, because the bug was in neither the resolver nor
// the parser but in the one line between them: the read was handed the unresolved path and
// walked back into the symlink it was supposed to avoid. A test that assembles the pipeline
// itself cannot see a pipeline that is wired wrong.
func TestSnapConfigIsDiscoveredEndToEnd(t *testing.T) {
	if appSupportDirFor("linux") != ".config" {
		t.Skip("linux application-support root is no longer .config")
	}
	home := t.TempDir()
	revision := filepath.Join(home, "snap", "code", "168", ".config", "Code", "User")
	if err := os.MkdirAll(revision, 0o755); err != nil {
		t.Fatal(err)
	}
	config := `{"servers":{"snap-server":{"command":"npx","args":["-y","x-mcp@1.0.0"]}}}`
	if err := os.WriteFile(filepath.Join(revision, "mcp.json"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("168", filepath.Join(home, "snap", "code", "current")); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	// discoverForHome, not the helpers underneath it. The bug this test exists for lived
	// between resolveSnapPath and the read, in the loop that calls both; a test that calls
	// either one directly cannot see it. The source list is host-OS-specific, so the snap
	// entry is substituted for the duration rather than relying on macOS to produce one.
	rel := filepath.Join("snap", "code", "current", ".config", "Code", "User", "mcp.json")
	original := homeProbes
	homeProbes = []probe{
		{relPath: rel, client: "vscode", jsonc: true, extract: extractEnvelopeSimple},
	}
	t.Cleanup(func() { homeProbes = original })

	rows := discoverForHome(context.Background(), fsscan.UserHome{Name: "alice", Path: home},
		time.Now().Add(time.Minute))
	var found bool
	for _, row := range rows {
		if row.Warning.empty() == false {
			t.Errorf("unexpected warning: %s", row.Warning.render())
		}
		if row.ServerName == "snap-server" {
			found = true
			if !strings.Contains(filepath.ToSlash(row.SourcePath), "/snap/code/168/") {
				t.Errorf("source_path = %q, should name the revision, not the pointer",
					row.SourcePath)
			}
		}
	}
	if !found {
		t.Fatalf("snap-installed config was not discovered; got %+v", rows)
	}
}

// The flatpak half of the same gap, asserted against the probe list that now carries it.
//
// A flatpak keeps configuration at ~/.var/app/<id>/config/..., which is not the platform's
// application-support root. The old design walked to the file and then worked backwards from
// its path to a client, so matching only the conventional root meant a flatpak-scoped
// mcp.json was found, matched no classification case, and was dropped with no diagnostic.
// That recogniser -- isAppSupportPathFor -- is gone along with the classifier it served.
//
// What replaces it is better and is what this now asserts: appSupportForkFor generates the
// sandbox location as an explicit path to probe, so the file is looked for where it lives
// rather than recognised after being stumbled upon. A path that is never generated is never
// read, which removes the failure mode entirely instead of fixing one instance of it.
//
// Asserted through the OS-parameterised form, because the Linux branch is unreachable from a
// macOS test host -- which is precisely how the gap survived being "tested" the first time.
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
