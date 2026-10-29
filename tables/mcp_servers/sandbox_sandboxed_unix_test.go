//go:build unix

package mcp_servers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/macadmins/osquery-extension/pkg/devclients"
	"github.com/macadmins/osquery-extension/pkg/fsscan"
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
	if _, ok := devclients.ResolveSnapPath(home, rel); ok {
		t.Error("a missing current pointer should not resolve")
	}

	link := filepath.Join(snapDir, "current")
	if err := os.Symlink("168", link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	got, ok := devclients.ResolveSnapPath(home, rel)
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
		if _, ok := devclients.ResolveSnapPath(home, rel); ok {
			t.Errorf("current -> %q was accepted; only a revision component may be", hostile)
		}
	}
}

// TestSnapConfigIsDiscoveredEndToEnd drives discoverForHome, not the helpers.
//
// The read has to be handed the resolved path, or it walks back into the symlink the
// resolution avoids. That wiring sits between devclients.ResolveSnapPath and the read, so a
// test that calls the resolver, os.ReadFile and the parser by hand cannot see it.
func TestSnapConfigIsDiscoveredEndToEnd(t *testing.T) {
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

	// The source list is host-OS-specific, so the snap entry is substituted for the duration
	// rather than relying on macOS to produce one.
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
