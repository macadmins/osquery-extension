//go:build windows

package mcp_servers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/macadmins/osquery-extension/pkg/testutil"
)

// TestProjectFileReadRefusesAJunctionedParentDirectory is the Windows form of
// TestProjectFileReadRefusesASymlinkedParentDirectory: a project directory replaced by a
// junction to another account's repository is refused, not followed, and the probe produces no
// row. A junction needs no privilege, so it is what an unprivileged account can plant.
func TestProjectFileReadRefusesAJunctionedParentDirectory(t *testing.T) {
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
	testutil.Junction(t, filepath.Join(home, "code", "repo"), victimDir)

	data, err := fsscan.ReadProjectFile(home, filepath.Join("code", "repo"), ".mcp.json",
		probeReadOpts(MaxFileSize))
	if err == nil {
		t.Fatalf("read through a junctioned parent into another user's config: %q", data)
	}
	if !fsscan.IsExpectedAbsent(err) {
		t.Errorf("a refused junction must read as expected absence, got %v", err)
	}
	rows := finishProcessing(home, data, err, filepath.Join(home, "code", "repo", ".mcp.json"),
		"alice", "claude_code", true, MaxFileSize, extractEnvelopeSimple)
	if len(rows) != 0 {
		t.Errorf("a refused read should be silent, got %+v", rows)
	}
}

// init gives every test in this package the conventional roaming location on Windows. The
// tests' homes are temporary directories with no registry hive, so the real lookup would add an
// appdata_undetermined finding to each of them. fsscan's TestRoamingAppDataForTheCurrentAccount
// exercises the real lookup.
func init() {
	roamingAppDataFor = func(string, string) (string, bool, bool) { return "", false, true }
}
