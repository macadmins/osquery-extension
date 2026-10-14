//go:build unix

package fsscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The cloud-placeholder preflight must not be the thing that leaves the home.
//
// It used to be made by path -- lstat(filepath.Join(home, rel)) -- and lstat resolves every
// intermediate component, so a project directory the scanned user had replaced with a symlink
// aimed that lookup wherever they liked. No content escaped, because the read that followed
// went through OpenBeneath, but the preflight inspected a file outside the home it was given;
// the same shape on Windows reaches a reparse point onto a UNC share, which would make this
// host authenticate to a server named in a file that user controls.
//
// What is asserted is that the inspector is never reached. Opening first means the refusal
// happens at the substituted component, before there is any descriptor to inspect -- so there
// is no "safe path" left to get wrong.
func TestReadProjectFilePlaceholderCheckNeverLeavesTheHome(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "secrets", ".mcp.json"), `{"outside":true}`)
	writeFile(t, filepath.Join(outside, "direct.json"), `{"outside":true}`)

	// Two shapes, because the old path-based check fell for both: an intermediate directory
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
