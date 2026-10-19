//go:build unix

package go_modules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"
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
	writeFile(t, elsewhere, "module x\n\nrequire github.com/linked/secret v1.0.0\n")
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
			writeFile(t, filepath.Join(healthy, "go.mod"), "module x\n\nrequire github.com/a/b v1.0.0\n")
			writeFile(t, filepath.Join(hidden, "go.mod"), "module y\n\nrequire github.com/c/d v1.0.0\n")

			claudeTarget := filepath.Join(root, "claude.json")
			codexTarget := filepath.Join(root, "codex")
			if refused == ".claude.json" {
				writeFile(t, claudeTarget, `{"projects":{"`+hidden+`":{}}}`)
				if err := os.Symlink(claudeTarget, filepath.Join(home, ".claude.json")); err != nil {
					t.Fatal(err)
				}
				writeFile(t, filepath.Join(home, ".codex", "config.toml"), "[projects.\""+healthy+"\"]\n")
			} else {
				claudeList(t, home, healthy)
				writeFile(t, filepath.Join(codexTarget, "config.toml"), "[projects.\""+hidden+"\"]\n")
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

// TestOneSymlinkedModuleFileMarksTheProjectIncomplete: a go.mod that is a symbolic link beside a
// regular go.sum is not followed, and the go.sum rows are published marked incomplete, with a
// finding naming go.mod. Without it they would read as versions go.mod does not require. When
// both files are links the project is silent, like a project behind a symlinked directory.
func TestOneSymlinkedModuleFileMarksTheProjectIncomplete(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	half := filepath.Join(home, "half")
	both := filepath.Join(home, "both")
	writeFile(t, filepath.Join(home, "elsewhere.mod"), "module y\n\nrequire github.com/half/dep v1.0.0\n")
	writeFile(t, filepath.Join(home, "elsewhere.sum"), "github.com/both/dep v1.0.0 "+validHashField+"\n")
	writeFile(t, filepath.Join(half, "go.sum"), "github.com/half/dep v1.0.0 "+validHashField+"\n")
	if err := os.MkdirAll(both, 0o755); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		filepath.Join(half, "go.mod"): filepath.Join(home, "elsewhere.mod"),
		filepath.Join(both, "go.mod"): filepath.Join(home, "elsewhere.mod"),
		filepath.Join(both, "go.sum"): filepath.Join(home, "elsewhere.sum"),
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
