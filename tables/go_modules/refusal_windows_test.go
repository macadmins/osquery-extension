//go:build windows

package go_modules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"

	"github.com/macadmins/osquery-extension/pkg/testutil"
)

// TestAJunctionedProjectIsNotReadOnWindows: a project recorded through a junction is not read,
// even when the junction's target stays inside the same home. The read refuses the junction
// the way the POSIX read refuses a symlink, and the refusal is silent, as it is for a symlinked
// project directory there.
func TestAJunctionedProjectIsNotReadOnWindows(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	testutil.WriteFile(t, filepath.Join(home, "real", "proj", "go.mod"), "module x\n\nrequire github.com/behind/junction v1.0.0\n")
	testutil.Junction(t, filepath.Join(home, "Developer"), filepath.Join(home, "real"))
	claudeList(t, home, filepath.Join(home, "Developer", "proj"))

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	for _, r := range rows {
		if r["module_path"] != "" {
			t.Errorf("a module was read through a junction: %v", r)
		}
	}
}

// TestAnInHomeSymlinkStaysRefusedOnWindows: a module file that is a symbolic link to a file in
// the same home is followed on POSIX and refused here, because fsscan has no Windows link reader.
// Beside a regular go.sum the refusal is a source_link_refused finding, as a link out of the
// home is on POSIX. Creating a symlink needs a privilege or Developer Mode, so it can skip.
func TestAnInHomeSymlinkStaysRefusedOnWindows(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	project := filepath.Join(home, "svc")
	testutil.WriteFile(t, filepath.Join(home, "shared", "go.mod"), "module y\n\nrequire github.com/linked/dep v1.0.0\n")
	testutil.WriteFile(t, filepath.Join(project, "go.sum"), "github.com/linked/dep v1.0.0 "+validHashField+"\n")
	if err := os.Symlink(filepath.Join(home, "shared", "go.mod"), filepath.Join(project, "go.mod")); err != nil {
		t.Skipf("creating a symlink needs a privilege here: %v", err)
	}
	claudeList(t, home, project)

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	for _, r := range rows {
		if r["mod_relationship"] != "" {
			t.Errorf("go.mod was read through a symlink: %v", r)
		}
	}
	if got := warnings(rows); len(got) != 1 || !strings.HasPrefix(got[0], "go.mod: "+warnSentences[warnSourceLinkRefused]) {
		t.Errorf("warnings = %v, want one go.mod source_link_refused row", got)
	}
}

// TestAHardLinkedModuleFileIsRefusedOnWindows: an NTFS hard link to another file passes every
// path check, so the read refuses a module file with more than one link and says so.
func TestAHardLinkedModuleFileIsRefusedOnWindows(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	project := filepath.Join(home, "svc")
	claudeList(t, home, project)
	elsewhere := filepath.Join(root, "elsewhere.mod")
	testutil.WriteFile(t, elsewhere, "module x\n\nrequire github.com/linked/secret v1.0.0\n")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(elsewhere, filepath.Join(project, "go.mod")); err != nil {
		t.Skipf("hard links unavailable on this volume: %v", err)
	}

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	if got := modules(rows); len(got) != 0 {
		t.Errorf("modules from a hard-linked file were published: %v", got)
	}
	if got := warnings(rows); len(got) != 1 || !strings.HasPrefix(got[0], "go.mod: "+warnSentences[warnProjectRefused]) {
		t.Errorf("warnings = %v, want one go.mod project_read_refused", got)
	}
}

// TestAJunctionedListDirectoryIsReportedOnWindows: ~/.codex replaced by a junction is refused,
// and the refusal is reported, because a refused list hides every project it records.
func TestAJunctionedListDirectoryIsReportedOnWindows(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	testutil.WriteFile(t, filepath.Join(root, "elsewhere", "config.toml"), "[projects.\"C:\\\\x\"]\n")
	testutil.Junction(t, filepath.Join(home, ".codex"), filepath.Join(root, "elsewhere"))

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	got := warnings(rows)
	if len(got) != 1 || !strings.HasPrefix(got[0], warnSentences[warnProjectListUnreadable]) {
		t.Errorf("warnings = %v, want one project_list_unreadable", got)
	}
	for _, r := range rows {
		if r["scan_complete"] != "0" {
			t.Errorf("row is complete despite a refused list: %v", r)
		}
	}
}

// init gives every test in this package the conventional roaming location on Windows. The
// tests' homes are temporary directories with no registry hive, so the real lookup would add an
// appdata_undetermined finding to each of them. fsscan's TestRoamingAppDataForTheCurrentAccount
// exercises the real lookup.
func init() {
	roamingAppDataFor = func(string, string) (string, bool, bool) { return "", false, true }
}
