//go:build windows

package go_modules

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"
)

// junction creates a directory junction at link that points at target. A junction needs no
// privilege on Windows, unlike a symlink, so it is the reparse point an unprivileged account
// can plant. The test is skipped if mklink is unavailable.
func junction(t *testing.T, link, target string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("mklink /J failed: %v: %s", err, output)
	}
}

// TestAJunctionedProjectIsNotReadOnWindows: a project recorded through a junction is not read,
// even when the junction's target stays inside the same home. The read refuses the junction
// the way the POSIX read refuses a symlink, and the refusal is silent, as it is for a symlinked
// project directory there.
func TestAJunctionedProjectIsNotReadOnWindows(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	writeFile(t, filepath.Join(home, "real", "proj", "go.mod"), "module x\n\nrequire github.com/behind/junction v1.0.0\n")
	junction(t, filepath.Join(home, "Developer"), filepath.Join(home, "real"))
	claudeList(t, home, filepath.Join(home, "Developer", "proj"))

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	for _, r := range rows {
		if r["module_path"] != "" {
			t.Errorf("a module was read through a junction: %v", r)
		}
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
	writeFile(t, elsewhere, "module x\n\nrequire github.com/linked/secret v1.0.0\n")
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
	writeFile(t, filepath.Join(root, "elsewhere", "config.toml"), "[projects.\"C:\\\\x\"]\n")
	junction(t, filepath.Join(home, ".codex"), filepath.Join(root, "elsewhere"))

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
