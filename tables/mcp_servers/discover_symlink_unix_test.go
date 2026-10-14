//go:build unix

package mcp_servers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
)

// Both tests here plant a symlink, so they are constrained to platforms that have one.
//
// The constraint is not only about os.Symlink needing privilege off-POSIX. On any platform
// where fsscan reports unsupported, ReadBoundedUnder returns errUnsupported before touching
// the filesystem, so the read yields a diagnostic rather than the silent refusal these
// assert. The tests would fail for a reason that has nothing to do with what they check.

func TestDiscoverForHome_SymlinkAttack_RefusedSilently(t *testing.T) {
	// Attacker scenario: home contains a symlink at .cursor/mcp.json pointing to /etc/passwd.
	// The component-wise open refuses the symlink at the kernel level. No leak.
	home := t.TempDir()
	cursorDir := filepath.Join(home, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(cursorDir, "mcp.json")); err != nil {
		t.Fatal(err)
	}
	rows := discoverForTest("alice", home)
	for _, r := range rows {
		if strings.HasSuffix(r.SourcePath, "/.cursor/mcp.json") {
			t.Errorf("symlink was followed: %#v", r)
		}
	}
}

// A project path recorded in a config file must be opened relative to the home with symlinks
// refused at every component, not just the last.
//
// The invariant is the one the deleted walker version asserted and it now matters more, not
// less. Containment runs once, when the project list is read, and the read happens afterwards
// -- so the user owns the directory and can swap it for a symlink in between. That is a
// genuine TOCTOU and a single-threaded test cannot sit inside the window, which is why this
// calls the read step directly with an already-swapped parent: that reproduces exactly the
// state the race would create.
//
// It is the reason ReadProjectFile never opens projectRef.Abs. Containment establishes a
// relative path and the read re-walks it from the home down, so a component replaced after
// the check fails the open rather than redirecting it. A string comparison performed earlier
// would have been satisfied by the path below and read the victim's file.
func TestProjectFileReadRefusesASymlinkedParentDirectory(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	victimDir := filepath.Join(root, "victim", "repo")
	if err := os.MkdirAll(victimDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(victimDir, ".mcp.json"),
		[]byte(`{"mcpServers":{"victim-secret":{"command":"npx","args":["x"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "code"), 0o755); err != nil {
		t.Fatal(err)
	}
	// code/repo is a symlink out of the home, as it would be mid-race. Containment was
	// satisfied before the swap: "code/repo" is relative to the home and carries no "..".
	if err := os.Symlink(victimDir, filepath.Join(home, "code", "repo")); err != nil {
		t.Fatal(err)
	}

	data, err := fsscan.ReadProjectFile(home, filepath.Join("code", "repo"), ".mcp.json",
		probeReadOpts(MaxFileSize))
	if err == nil {
		t.Fatalf("read through a symlinked parent into another user's config: %q", data)
	}
	// Silent, not a diagnostic. A planted symlink is an expected absence by this package's
	// contract, and emitting a warning row for it would publish the attacker's path.
	if !fsscan.IsExpectedAbsent(err) {
		t.Errorf("a refused symlink must read as expected absence, got %v", err)
	}

	// And the row-level consequence: the project probe produces nothing at all.
	rows := finishProcessing(home, data, err, filepath.Join(home, "code", "repo", ".mcp.json"),
		"alice", "claude_code", true, MaxFileSize, extractEnvelopeSimple)
	if len(rows) != 0 {
		t.Errorf("a refused read should be silent, got %+v", rows)
	}
}

// A skipped account must produce a diagnostic that survives the query which would ask about
// it. An aggregate row with an empty user was filtered out by `WHERE user = 'alice'`, so if
// Alice's home was the skipped one the caller got a clean empty result -- the exact ambiguity
// the warning machinery exists to prevent.
func TestDiscoverAllReportsSkippedHomesPerAccount(t *testing.T) {
	root := t.TempDir()
	// A usable home.
	if err := os.MkdirAll(filepath.Join(root, "bob", "code"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A home that is a symlink, which is refused rather than followed.
	if err := os.Symlink(filepath.Join(root, "bob"), filepath.Join(root, "alice")); err != nil {
		t.Fatal(err)
	}

	// Unfiltered: the skipped account is named.
	var found bool
	for _, row := range withoutStandingNotes(DiscoverAll(context.Background(), rosterOf(t, root), nil)) {
		if row.User == "alice" && row.Warning.empty() == false {
			found = true
		}
	}
	if !found {
		t.Error("no diagnostic names the skipped account")
	}

	// Filtered to exactly the skipped account: the diagnostic must still arrive, since this is
	// the query that would otherwise return nothing at all.
	rows := withoutStandingNotes(DiscoverAll(context.Background(), rosterOf(t, root), map[string]struct{}{"alice": {}}))
	// Fatal, not Error: the identity-contract check below indexes rows[0], so on an empty
	// result a non-fatal failure fell through into an out-of-range panic. That aborts the
	// whole test binary, so the real message here was replaced by a stack trace and every
	// later test in the package went unreported.
	if len(rows) != 1 || rows[0].User != "alice" || rows[0].Warning.empty() {
		t.Fatalf("a query for the skipped account must still explain itself: %+v", rows)
	}
	if rows[0].Transport != "unknown" || rows[0].Confidence != "low" {
		t.Errorf("diagnostic breaks the identity contract: %+v", rows[0])
	}

	// Filtered to the other account: no unrelated diagnostic.
	for _, row := range withoutStandingNotes(DiscoverAll(context.Background(), rosterOf(t, root), map[string]struct{}{"bob": {}})) {
		if row.User == "alice" {
			t.Errorf("a query for bob should not carry alice's diagnostic: %+v", row)
		}
	}
}
