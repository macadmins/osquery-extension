//go:build unix

package devclients

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/macadmins/osquery-extension/pkg/testutil"
)

// TestARefusedEditorDirectoryIsAListingFailure: a workspaceStorage or JetBrains directory
// reached through a symlink is reported as a listing that failed, with the refusal's class and
// the client's origin, rather than read as an editor that is not installed.
func TestARefusedEditorDirectoryIsAListingFailure(t *testing.T) {
	home := t.TempDir()
	elsewhere := t.TempDir()
	storage := filepath.Join(home, AppSupportFork("Code", "User", "workspaceStorage")[0])
	if err := os.MkdirAll(filepath.Dir(storage), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, storage); err != nil {
		t.Fatal(err)
	}
	jetbrains := filepath.Join(home, AppSupportDir(), "JetBrains")
	if err := os.Symlink(elsewhere, jetbrains); err != nil {
		t.Fatal(err)
	}
	opts := fsscan.ReadOpts{MaxSize: 1 << 20}
	deadline := time.Now().Add(time.Minute)
	for name, scan := range map[string]ProjectListScan{
		"workspaceStorage": WorkspaceFolders(context.Background(), home, "", fsscan.ClassNone, deadline, opts),
		"JetBrains":        JetBrainsProjects(context.Background(), home, "", deadline, opts),
	} {
		if len(scan.Listings) != 1 || scan.Listings[0].Truncated ||
			scan.Listings[0].Class != fsscan.ClassRefusedPath {
			t.Errorf("%s: listings = %+v, want one refused listing", name, scan.Listings)
			continue
		}
		want := map[string]Origin{"workspaceStorage": OriginVSCodeWorkspace,
			"JetBrains": OriginJetBrainsRecent}[name]
		if scan.Listings[0].Origin != want {
			t.Errorf("%s: origin = %q, want %q", name, scan.Listings[0].Origin, want)
		}
	}
}

// TestARefusedWorkspaceRecordIsCounted: a workspace.json that is a symlink exists and is not read,
// so it is counted as unreadable; an absent one is silent.
func TestARefusedWorkspaceRecordIsCounted(t *testing.T) {
	home := t.TempDir()
	storage := filepath.Join(home, AppSupportFork("Code", "User", "workspaceStorage")[0])
	if err := os.MkdirAll(filepath.Join(storage, "linked"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(storage, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "workspace.json")
	if err := os.WriteFile(target, []byte(`{"folder":"file:///elsewhere"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(storage, "linked", "workspace.json")); err != nil {
		t.Fatal(err)
	}
	scan := WorkspaceFolders(context.Background(), home, "", fsscan.ClassNone,
		time.Now().Add(time.Minute), fsscan.ReadOpts{MaxSize: 1 << 20})
	if scan.UnreadableRecords != 1 || len(scan.Folders) != 0 {
		t.Errorf("scan = %+v, want the symlinked record counted once", scan)
	}
}

// TestNewerLinksDoNotDisplaceAWorkspaceRecord: MaxWorkspaceDirs record directories that are
// symlinks, each newer than the one real record, cannot be read through, so each is counted as
// unreadable, and the real record is still read.
func TestNewerLinksDoNotDisplaceAWorkspaceRecord(t *testing.T) {
	home := t.TempDir()
	storage := filepath.Join(home, AppSupportFork("Code", "User", "workspaceStorage")[0])
	record := filepath.Join(storage, "record")
	project := testutil.FileURL(filepath.Join(home, "code", "project"))
	testutil.WriteFile(t, filepath.Join(record, "workspace.json"), `{"folder":"`+project+`"}`)
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(record, past, past); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	for index := 0; index < MaxWorkspaceDirs; index++ {
		if err := os.Symlink(elsewhere, filepath.Join(storage, fmt.Sprintf("l%04d", index))); err != nil {
			t.Fatal(err)
		}
	}
	scan := WorkspaceFolders(context.Background(), home, "", fsscan.ClassNone, time.Now().Add(time.Minute),
		fsscan.ReadOpts{MaxSize: 1 << 20})
	if len(scan.Folders) != 1 || scan.Folders[0].Recorded != project || len(scan.Listings) != 0 ||
		scan.UnreadableRecords != MaxWorkspaceDirs {
		t.Errorf("scan = %+v, want the record read and every link counted", scan)
	}
}
