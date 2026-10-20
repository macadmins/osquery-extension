//go:build unix

package fsscan

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/macadmins/osquery-extension/pkg/testutil"
)

// The cloud-placeholder preflight must not inspect anything outside the home.
//
// A preflight made by path, lstat(filepath.Join(home, rel)), resolves every intermediate
// component, so a project directory the scanned user replaces with a symlink aims that lookup
// wherever they like. On Windows the same redirection reaches a reparse point onto a UNC
// share, which would make this host authenticate to a server named in a file that user
// controls.
//
// The test asserts that the inspector is never reached. The read opens first, so the refusal
// happens at the substituted component, before there is any descriptor to inspect.
func TestReadProjectFilePlaceholderCheckNeverLeavesTheHome(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	testutil.WriteFile(t, filepath.Join(outside, "secrets", ".mcp.json"), `{"outside":true}`)
	testutil.WriteFile(t, filepath.Join(outside, "direct.json"), `{"outside":true}`)

	// Two redirections, and a path-based check follows both: an intermediate directory
	// replaced with a link, and the file itself replaced with one.
	if err := os.Symlink(outside, filepath.Join(home, "proj")); err != nil {
		t.Skipf("symlinks unsupported here: %v", err)
	}
	if err := os.Mkdir(filepath.Join(home, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, "real", ".mcp.json")
	if err := os.Symlink(filepath.Join(outside, "direct.json"), link); err != nil {
		t.Fatal(err)
	}

	for _, probe := range []struct {
		name    string
		projRel string
	}{
		{"intermediate component is a symlink out of the home", filepath.Join("proj", "secrets")},
		{"final component is a symlink out of the home", "real"},
	} {
		t.Run(probe.name, func(t *testing.T) {
			var inspected []string
			opts := ReadOpts{MaxSize: 1024, CloudPlaceholder: func(file *os.File) (bool, error) {
				inspected = append(inspected, file.Name())
				return false, nil
			}}
			data, err := ReadProjectFile(home, probe.projRel, ".mcp.json", opts)
			if err == nil {
				t.Fatalf("the redirected path must be refused, read %q instead", data)
			}
			if len(inspected) != 0 {
				t.Errorf("the placeholder inspector was handed %v: it must never be given a "+
					"file the traversal refused", inspected)
			}
			// A refused symlink is expected rather than a finding, and the refusal must not
			// carry the link's target: that string is chosen by the scanned user and the
			// caller puts this error's classification in a column.
			if !IsExpectedAbsent(err) {
				t.Errorf("a refused symlink must read as benign absence: %v", err)
			}
			if strings.Contains(err.Error(), outside) {
				t.Errorf("the refusal names where the link pointed: %v", err)
			}
		})
	}
}

// TestListRecentDirNamesCountsLinks: a symlink to a directory, newer than the one real
// directory, is counted in links rather than ranked, so it cannot push that directory past keep.
func TestListRecentDirNamesCountsLinks(t *testing.T) {
	base := t.TempDir()
	record := filepath.Join(base, "d", "record")
	if err := os.MkdirAll(record, 0o755); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(record, past, past); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"link-a", "link-b"} {
		if err := os.Symlink(t.TempDir(), filepath.Join(base, "d", name)); err != nil {
			t.Fatal(err)
		}
	}
	names, older, links, truncated, err := ListRecentDirNames(base, "d", 1, 10)
	if err != nil || truncated || older != 0 || links != 2 || !reflect.DeepEqual(names, []string{"record"}) {
		t.Errorf("one directory among newer links: %v %d %d %v %v", names, older, links, truncated, err)
	}
}

// TestListRecentDirNamesSkipsAFIFO: a FIFO among the records is neither ranked nor counted as a
// link. os.ModeIrregular marks a junction only on Windows, and no unix entry is reported with it.
func TestListRecentDirNamesSkipsAFIFO(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "d", "record"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(base, "d", "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	names, older, links, truncated, err := ListRecentDirNames(base, "d", 5, 10)
	if err != nil || truncated || older != 0 || links != 0 || !reflect.DeepEqual(names, []string{"record"}) {
		t.Errorf("one directory beside a FIFO: %v %d %d %v %v", names, older, links, truncated, err)
	}
}

// TestListSubdirNamesCountsLinks: a symlink to a directory is left out of the names and
// counted, so the caller can report the directory it stands for as one it could not list.
func TestListSubdirNamesCountsLinks(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "d", "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(base, "d", "linked")); err != nil {
		t.Fatal(err)
	}
	names, links, truncated, err := ListSubdirNames(base, "d", 10)
	if err != nil || truncated || links != 1 || !reflect.DeepEqual(names, []string{"real"}) {
		t.Errorf("one directory beside a link: %v %d %v %v", names, links, truncated, err)
	}
}
