//go:build unix

package go_modules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/macadmins/osquery-extension/pkg/testutil"
)

// TestAHardLinkedModuleFileIsRefused: a hard link to another file passes every path check, so
// the read refuses a file with more than one link. The table reports the refusal and publishes
// nothing from the linked file.
func TestAHardLinkedModuleFileIsRefused(t *testing.T) {
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
		t.Skipf("hard links unavailable here: %v", err)
	}

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	if got := modules(rows); len(got) != 0 {
		t.Errorf("modules from a hard-linked file were published: %v", got)
	}
	got := warnings(rows)
	if len(got) != 1 || !strings.HasPrefix(got[0], "go.mod: "+warnSentences[warnProjectRefused]) {
		t.Errorf("warnings = %v, want one project_read_refused", got)
	}
	for _, r := range rows {
		if r["scan_complete"] != "0" {
			t.Error("a refused file leaves the project's listing short, so no row is complete")
		}
	}
}

// TestARefusedProjectListIsReported: a symlinked project list is still not followed, and its
// refusal is reported rather than read as absence. The list is the only record of the projects
// it names, so without a row the healthy list beside it would look like the whole inventory.
func TestARefusedProjectListIsReported(t *testing.T) {
	for _, refused := range []string{".claude.json", ".codex"} {
		t.Run(refused, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "alice")
			healthy := filepath.Join(home, "healthy")
			hidden := filepath.Join(home, "hidden")
			testutil.WriteFile(t, filepath.Join(healthy, "go.mod"), "module x\n\nrequire github.com/a/b v1.0.0\n")
			testutil.WriteFile(t, filepath.Join(hidden, "go.mod"), "module y\n\nrequire github.com/c/d v1.0.0\n")

			claudeTarget := filepath.Join(root, "claude.json")
			codexTarget := filepath.Join(root, "codex")
			if refused == ".claude.json" {
				testutil.WriteFile(t, claudeTarget, `{"projects":{"`+hidden+`":{}}}`)
				if err := os.Symlink(claudeTarget, filepath.Join(home, ".claude.json")); err != nil {
					t.Fatal(err)
				}
				testutil.WriteFile(t, filepath.Join(home, ".codex", "config.toml"), "[projects.\""+healthy+"\"]\n")
			} else {
				claudeList(t, home, healthy)
				testutil.WriteFile(t, filepath.Join(codexTarget, "config.toml"), "[projects.\""+hidden+"\"]\n")
				if err := os.Symlink(codexTarget, filepath.Join(home, ".codex")); err != nil {
					t.Fatal(err)
				}
			}

			rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
			if got := modules(rows); len(got) != 1 || !strings.Contains(got[0], "github.com/a/b") {
				t.Errorf("modules = %v, want only the healthy project's", got)
			}
			got := warnings(rows)
			if len(got) != 1 || !strings.HasPrefix(got[0], warnSentences[warnProjectListUnreadable]) {
				t.Errorf("warnings = %v, want one project_list_unreadable", got)
			}
			for _, r := range rows {
				if r["module_path"] != "" && r["scan_complete"] != "1" {
					t.Errorf("the healthy project is marked incomplete by the lost list: %v", r)
				}
			}
		})
	}
}

// TestAnUnreadableHomeIsOneRow: a home this process cannot open, such as root's when osqueryi
// runs as a user, gets one home_unreadable row rather than one row per client list.
func TestAnUnreadableHomeIsOneRow(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens a directory whatever its mode")
	}
	home := filepath.Join(t.TempDir(), "root")
	claudeList(t, home, filepath.Join(home, "svc"))
	if err := os.Chmod(home, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, 0o755) })

	rows := run(t, roster(map[string]string{"root": home}), table.QueryContext{})
	if len(rows) != 1 || !strings.HasPrefix(rows[0]["warning"], warnSentences[warnHomeUnreadable]) ||
		!strings.Contains(rows[0]["warning"], "reason=") || rows[0]["scan_complete"] != "0" {
		t.Errorf("rows = %v, want one home_unreadable row", rows)
	}
}

// TestOneSymlinkedModuleFileMarksTheProjectIncomplete: a go.mod that is a symbolic link out of
// the home, beside a regular go.sum, is not followed, and the go.sum rows are published marked
// incomplete, with a finding naming go.mod. Without it they would read as versions go.mod does
// not require. When both files are such links the project is silent, like a project behind a
// symlinked directory.
func TestOneSymlinkedModuleFileMarksTheProjectIncomplete(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	half := filepath.Join(home, "half")
	both := filepath.Join(home, "both")
	testutil.WriteFile(t, filepath.Join(root, "elsewhere.mod"), "module y\n\nrequire github.com/half/dep v1.0.0\n")
	testutil.WriteFile(t, filepath.Join(root, "elsewhere.sum"), "github.com/both/dep v1.0.0 "+validHashField+"\n")
	testutil.WriteFile(t, filepath.Join(half, "go.sum"), "github.com/half/dep v1.0.0 "+validHashField+"\n")
	if err := os.MkdirAll(both, 0o755); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		filepath.Join(half, "go.mod"): filepath.Join(root, "elsewhere.mod"),
		filepath.Join(both, "go.mod"): filepath.Join(root, "elsewhere.mod"),
		filepath.Join(both, "go.sum"): filepath.Join(root, "elsewhere.sum"),
	} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	claudeList(t, home, half, both)

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	if got := modules(rows); len(got) != 1 || !strings.Contains(got[0], "github.com/half/dep") {
		t.Errorf("modules = %v, want only the half project's go.sum row", got)
	}
	for _, r := range rows {
		if r["module_path"] != "" && r["scan_complete"] != "0" {
			t.Errorf("a row beside a refused go.mod reads as complete: %v", r)
		}
	}
	if got := warnings(rows); len(got) != 1 || !strings.HasPrefix(got[0], "go.mod: "+warnSentences[warnSourceLinkRefused]) {
		t.Errorf("warnings = %v, want one go.mod source_link_refused row", got)
	}
}

// TestASymlinkedGoModBesideAnEmptyGoSumIsReported: a go.sum that was read and holds no entries
// still makes the refused go.mod beside it a finding, so the project is not silent.
func TestASymlinkedGoModBesideAnEmptyGoSumIsReported(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	project := filepath.Join(home, "svc")
	testutil.WriteFile(t, filepath.Join(root, "elsewhere.mod"), "module y\n\nrequire github.com/a/b v1.0.0\n")
	testutil.WriteFile(t, filepath.Join(project, "go.sum"), "")
	if err := os.Symlink(filepath.Join(root, "elsewhere.mod"), filepath.Join(project, "go.mod")); err != nil {
		t.Fatal(err)
	}
	claudeList(t, home, project)

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	if got := warnings(rows); len(got) != 1 || !strings.HasPrefix(got[0], "go.mod: "+warnSentences[warnSourceLinkRefused]) {
		t.Errorf("warnings = %v, want one go.mod source_link_refused row", got)
	}
}

// TestAnInHomeSymlinkIsFollowedOneHop: a module file that is a symbolic link to a file in the same
// home is read as that file, with every check a module file gets. Each case links go.mod beside a
// regular go.sum and runs alone. A link to another link, a target that steps back after a named
// directory, a target on a network filesystem the home is not on, in a cloud folder, held by a
// cloud provider, or that is a directory, is refused as a link, and the local go.sum is still
// listed; nothing in the cloud folder is opened. So is a target behind a symlinked directory. A
// hard-linked target is refused as a hard link. A dangling link, and one whose path runs through
// a regular file, is an absent go.mod.
func TestAnInHomeSymlinkIsFollowedOneHop(t *testing.T) {
	const goMod = "module y\n\nrequire github.com/linked/dep v1.0.0\n"
	goSum := "github.com/linked/dep v1.0.0 " + validHashField + "\n"
	for name, tc := range map[string]struct {
		plant   func(t *testing.T, home string) string // returns the go.mod link's target
		source  string                                 // the dep row's mod_relationship
		warning warnCode                               // "" for a complete project
	}{
		"absolute target": {func(t *testing.T, home string) string {
			testutil.WriteFile(t, filepath.Join(home, "shared", "go.mod"), goMod)
			return filepath.Join(home, "shared", "go.mod")
		}, "direct", ""},
		"relative target": {func(t *testing.T, home string) string {
			testutil.WriteFile(t, filepath.Join(home, "shared", "go.mod"), goMod)
			return "../shared/go.mod"
		}, "direct", ""},
		"link to a link": {func(t *testing.T, home string) string {
			testutil.WriteFile(t, filepath.Join(home, "shared", "go.mod"), goMod)
			if err := os.Symlink(filepath.Join(home, "shared", "go.mod"), filepath.Join(home, "hop.mod")); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(home, "hop.mod")
		}, "", warnSourceLinkRefused},
		"steps back after a named directory": {func(t *testing.T, home string) string {
			testutil.WriteFile(t, filepath.Join(home, "svc", "real.mod"), goMod)
			if err := os.MkdirAll(filepath.Join(home, "svc", "vendor"), 0o755); err != nil {
				t.Fatal(err)
			}
			return "vendor/../real.mod"
		}, "", warnSourceLinkRefused},
		"target on a network filesystem": {func(t *testing.T, home string) string {
			testutil.WriteFile(t, filepath.Join(home, "net", "go.mod"), goMod)
			return filepath.Join(home, "net", "go.mod")
		}, "", warnSourceLinkRefused},
		"hard-linked target": {func(t *testing.T, home string) string {
			testutil.WriteFile(t, filepath.Join(home, "shared", "go.mod"), goMod)
			if err := os.Link(filepath.Join(home, "shared", "go.mod"), filepath.Join(home, "second.mod")); err != nil {
				t.Skipf("hard links unavailable here: %v", err)
			}
			return filepath.Join(home, "shared", "go.mod")
		}, "", warnProjectRefused},
		"dangling": {func(t *testing.T, home string) string {
			return filepath.Join(home, "missing.mod")
		}, "", ""},
		"through a regular file": {func(t *testing.T, home string) string {
			testutil.WriteFile(t, filepath.Join(home, "notadir"), "")
			return filepath.Join(home, "notadir", "go.mod")
		}, "", ""},
		// A symlinked directory partway to the target is a refusal, not a path that cannot
		// exist, so the link is declined rather than read as absent.
		"through a symlinked directory": {func(t *testing.T, home string) string {
			testutil.WriteFile(t, filepath.Join(home, "real", "deep", "go.mod"), goMod)
			if err := os.Symlink("real", filepath.Join(home, "linkdir")); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(home, "linkdir", "deep", "go.mod")
		}, "", warnSourceLinkRefused},
		"target in a cloud folder": {func(t *testing.T, home string) string {
			testutil.WriteFile(t, filepath.Join(home, "cloud", "go.mod"), goMod)
			return filepath.Join(home, "cloud", "go.mod")
		}, "", warnSourceLinkRefused},
		"target content held by a provider": {func(t *testing.T, home string) string {
			testutil.WriteFile(t, filepath.Join(home, "shared", "evicted.mod"), goMod)
			return filepath.Join(home, "shared", "evicted.mod")
		}, "", warnSourceLinkRefused},
		"target is a directory": {func(t *testing.T, home string) string {
			return "."
		}, "", warnSourceLinkRefused},
	} {
		t.Run(name, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "alice")
			project := filepath.Join(home, "svc")
			testutil.WriteFile(t, filepath.Join(project, "go.sum"), goSum)
			if err := os.Symlink(tc.plant(t, home), filepath.Join(project, "go.mod")); err != nil {
				t.Fatal(err)
			}
			claudeList(t, home, project)
			savedProbe, savedCloud, savedPlaceholder := probeProject, underCloudStorage, cloudPlaceholder
			t.Cleanup(func() { probeProject, underCloudStorage, cloudPlaceholder = savedProbe, savedCloud, savedPlaceholder })
			probeProject = func(home, rel string) error {
				switch {
				case rel == "net":
					return fsscan.ErrNetworkFilesystem
				case strings.HasPrefix(rel, "cloud"):
					t.Errorf("a directory in a cloud folder was opened: %s", rel)
				}
				return savedProbe(home, rel)
			}
			underCloudStorage = func(rel string) bool { return strings.HasPrefix(rel, "cloud") }
			cloudPlaceholder = func(file *os.File) (bool, error) {
				return strings.HasSuffix(file.Name(), "evicted.mod"), nil
			}

			rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
			wantComplete := "1"
			if tc.warning != "" {
				wantComplete = "0"
			}
			var deps []map[string]string
			for _, r := range rows {
				if r["module_path"] != "" {
					deps = append(deps, r)
				}
			}
			if len(deps) != 1 || deps[0]["module_path"] != "github.com/linked/dep" ||
				deps[0]["mod_relationship"] != tc.source || deps[0]["scan_complete"] != wantComplete {
				t.Errorf("module rows = %v, want one github.com/linked/dep row with mod_relationship %q "+
					"and scan_complete %s", deps, tc.source, wantComplete)
			}
			got := warnings(rows)
			if tc.warning == "" {
				if len(got) != 0 {
					t.Errorf("warnings = %v, want none", got)
				}
				return
			}
			if len(got) != 1 || !strings.HasPrefix(got[0], "go.mod: "+warnSentences[tc.warning]) {
				t.Errorf("warnings = %v, want one go.mod %s row", got, tc.warning)
			}
		})
	}
}

// TestALinkInAHomeRecordedAsAProjectIsFollowed: a home opened as a project, as an editor opened on
// ~ records it, reads a symlinked go.mod there like any other project's, though the link's
// directory is the home itself.
func TestALinkInAHomeRecordedAsAProjectIsFollowed(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	testutil.WriteFile(t, filepath.Join(home, "dotfiles", "go.mod"), "module y\n\nrequire github.com/linked/dep v1.0.0\n")
	if err := os.Symlink("dotfiles/go.mod", filepath.Join(home, "go.mod")); err != nil {
		t.Fatal(err)
	}
	claudeList(t, home, home)

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	if got := modules(rows); len(got) != 1 || !strings.Contains(got[0], "github.com/linked/dep") {
		t.Errorf("modules = %v, want the linked go.mod's requirement", got)
	}
	if got := warnings(rows); len(got) != 0 {
		t.Errorf("warnings = %v, want none", got)
	}
}

// TestAnUnopenableProjectDirectoryIsCountedOnce: a recorded project directory that cannot be
// opened, as macOS denies one without Full Disk Access, is one count for the user rather than a
// go.mod row and a go.sum row for files that were never reached.
func TestAnUnopenableProjectDirectoryIsCountedOnce(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens a directory whatever its mode")
	}
	home := filepath.Join(t.TempDir(), "alice")
	denied := filepath.Join(home, "denied")
	kept := filepath.Join(home, "kept")
	testutil.WriteFile(t, filepath.Join(denied, "go.mod"), "module x\n\nrequire github.com/a/b v1.0.0\n")
	testutil.WriteFile(t, filepath.Join(kept, "go.mod"), "module y\n\nrequire github.com/c/d v1.0.0\n")
	claudeList(t, home, denied, kept)
	if err := os.Chmod(denied, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(denied, 0o755) })

	rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
	got := warnings(rows)
	if len(got) != 1 || !strings.HasPrefix(got[0], warnSentences[warnProjectDirUnreadable]) ||
		!strings.Contains(got[0], "count=1") || !strings.Contains(got[0], "reason=denied") {
		t.Errorf("warnings = %v, want one project_directory_unreadable row with count=1 and reason=denied", got)
	}
	if mods := modules(rows); len(mods) != 1 || !strings.Contains(mods[0], "github.com/c/d") {
		t.Errorf("modules = %v, want the readable project's", mods)
	}
}

// TestWhatCountsAsAGoWorkspace: a symbolic link named go.work counts when it names a regular file
// in the home, and when it is not followed, out of the home or into a cloud folder, because it
// still shows a workspace; nothing in the cloud folder is opened. A link whose target cannot
// exist, because it names nothing or runs through a regular file, a link to a directory, and a
// directory named go.work do not count. Each case runs alone, so none can mask another.
func TestWhatCountsAsAGoWorkspace(t *testing.T) {
	for name, tc := range map[string]struct {
		plant func(t *testing.T, home, project string)
		count string // "" for no workspace row
	}{
		"symlinked go.work": {func(t *testing.T, home, project string) {
			testutil.WriteFile(t, filepath.Join(home, "shared.work"), "go 1.25\n\nuse .\n")
			if err := os.MkdirAll(project, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(home, "shared.work"), filepath.Join(project, "go.work")); err != nil {
				t.Fatal(err)
			}
		}, "count=1"},
		"go.work linked out of the home": {func(t *testing.T, home, project string) {
			if err := os.MkdirAll(project, 0o755); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(filepath.Dir(home), "shared.work")
			if err := os.Symlink(outside, filepath.Join(project, "go.work")); err != nil {
				t.Fatal(err)
			}
		}, "count=1"},
		"dangling go.work link": {func(t *testing.T, home, project string) {
			if err := os.MkdirAll(project, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(home, "missing.work"), filepath.Join(project, "go.work")); err != nil {
				t.Fatal(err)
			}
		}, ""},
		"go.work linked to a directory": {func(t *testing.T, home, project string) {
			if err := os.MkdirAll(filepath.Join(home, "workdir"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(project, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(home, "workdir"), filepath.Join(project, "go.work")); err != nil {
				t.Fatal(err)
			}
		}, ""},
		"go.work linked through a regular file": {func(t *testing.T, home, project string) {
			testutil.WriteFile(t, filepath.Join(home, "notadir"), "")
			if err := os.MkdirAll(project, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(home, "notadir", "go.work"), filepath.Join(project, "go.work")); err != nil {
				t.Fatal(err)
			}
		}, ""},
		"go.work linked into a cloud folder": {func(t *testing.T, home, project string) {
			testutil.WriteFile(t, filepath.Join(home, "cloud", "shared.work"), "go 1.25\n\nuse .\n")
			if err := os.MkdirAll(project, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(home, "cloud", "shared.work"), filepath.Join(project, "go.work")); err != nil {
				t.Fatal(err)
			}
		}, "count=1"},
		"directory named go.work": {func(t *testing.T, home, project string) {
			if err := os.MkdirAll(filepath.Join(project, "go.work"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "alice")
			project := filepath.Join(home, "svc")
			tc.plant(t, home, project)
			claudeList(t, home, project)
			savedProbe, savedCloud := probeProject, underCloudStorage
			t.Cleanup(func() { probeProject, underCloudStorage = savedProbe, savedCloud })
			underCloudStorage = func(rel string) bool { return strings.HasPrefix(rel, "cloud") }
			probeProject = func(home, rel string) error {
				if strings.HasPrefix(rel, "cloud") {
					t.Errorf("a directory in a cloud folder was opened: %s", rel)
				}
				return savedProbe(home, rel)
			}
			got := warnings(run(t, roster(map[string]string{"alice": home}), table.QueryContext{}))
			if tc.count == "" {
				if len(got) != 0 {
					t.Errorf("warnings = %v, want none", got)
				}
				return
			}
			if len(got) != 1 || !strings.HasPrefix(got[0], warnSentences[warnWorkspaceUnsupported]) ||
				!strings.Contains(got[0], tc.count) {
				t.Errorf("warnings = %v, want one go_workspace_unsupported row with %s", got, tc.count)
			}
		})
	}
}

// TestAGoWorkLinkToAProviderHeldTargetIsCounted: a followed go.work link whose target is refused
// as a storage provider's reparse point counts, because the link shows the project is a
// workspace.
func TestAGoWorkLinkToAProviderHeldTargetIsCounted(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	project := filepath.Join(home, "svc")
	testutil.WriteFile(t, filepath.Join(home, "shared", "shared.work"), "go 1.25\n\nuse .\n")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "shared", "shared.work"), filepath.Join(project, "go.work")); err != nil {
		t.Fatal(err)
	}
	claudeList(t, home, project)
	saved := openGoWork
	t.Cleanup(func() { openGoWork = saved })
	target := filepath.Join("shared", "shared.work")
	opened := false
	openGoWork = func(base, rel string) (*os.File, error) {
		if rel == target {
			opened = true
			return nil, fsscan.ErrCloudPlaceholder
		}
		return saved(base, rel)
	}
	got := warnings(run(t, roster(map[string]string{"alice": home}), table.QueryContext{}))
	if !opened {
		t.Fatal("the link was not followed to its target")
	}
	if len(got) != 1 || !strings.HasPrefix(got[0], warnSentences[warnWorkspaceUnsupported]) ||
		!strings.Contains(got[0], "count=1") {
		t.Errorf("warnings = %v, want one go_workspace_unsupported row with count=1", got)
	}
}

// TestAnInHomeSymlinkedProjectListIsFollowed: a ~/.claude.json or ~/.codex/config.toml that a
// dotfile manager links to a file in the same home is read as that file, so the projects it
// records are listed and no list is reported lost. A link out of the home is still refused and
// reported, which TestARefusedProjectListIsReported covers.
func TestAnInHomeSymlinkedProjectListIsFollowed(t *testing.T) {
	for _, list := range []string{".claude.json", filepath.Join(".codex", "config.toml")} {
		t.Run(list, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "alice")
			project := filepath.Join(home, "svc")
			testutil.WriteFile(t, filepath.Join(project, "go.mod"), "module x\n\nrequire github.com/a/b v1.0.0\n")
			target := filepath.Join(home, "dotfiles", "list")
			if list == ".claude.json" {
				testutil.WriteFile(t, target, `{"projects":{"`+project+`":{}}}`)
			} else {
				testutil.WriteFile(t, target, "[projects.\""+project+"\"]\n")
			}
			if err := os.MkdirAll(filepath.Dir(filepath.Join(home, list)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(home, list)); err != nil {
				t.Fatal(err)
			}
			rows := run(t, roster(map[string]string{"alice": home}), table.QueryContext{})
			if got := modules(rows); len(got) != 1 || !strings.Contains(got[0], "github.com/a/b") {
				t.Errorf("modules = %v, want the project the linked list records", got)
			}
			if got := warnings(rows); len(got) != 0 {
				t.Errorf("warnings = %v, want none", got)
			}
		})
	}
}
