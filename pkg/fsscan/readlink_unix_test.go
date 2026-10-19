//go:build unix

package fsscan

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestReadLinkBeneath reads a link relative to a safely opened parent, refuses a symlinked
// parent rather than resolving through it, and rejects a name that is not one component.
func TestReadLinkBeneath(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "snap", "code", "168"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("168", filepath.Join(base, "snap", "code", "current")); err != nil {
		t.Fatal(err)
	}
	if target, err := ReadLinkBeneath(base, filepath.Join("snap", "code"), "current"); err != nil || target != "168" {
		t.Errorf("ReadLinkBeneath = %q %v, want 168", target, err)
	}
	if _, err := ReadLinkBeneath(base, filepath.Join("snap", "code"), "168"); err == nil {
		t.Error("a directory is not a symlink and must not read as one")
	}
	if _, err := ReadLinkBeneath(base, "snap", "code/current"); !errors.Is(err, ErrMalformedPath) {
		t.Errorf("a multi-component name: err = %v, want ErrMalformedPath", err)
	}

	// The parent reached through a symlink: the old path-based read resolved through it.
	elsewhere := t.TempDir()
	if err := os.MkdirAll(filepath.Join(elsewhere, "code"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("168", filepath.Join(elsewhere, "code", "current")); err != nil {
		t.Fatal(err)
	}
	linked := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(linked, "snap")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLinkBeneath(linked, filepath.Join("snap", "code"), "current"); err == nil {
		t.Error("a symlinked parent was followed")
	}
}

// TestProbeProjectDirRefusesASymlinkedProject: a project directory reached through a symlink
// is refused the way every read refuses it, rather than probed through the link.
func TestProbeProjectDirRefusesASymlinkedProject(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "real"), filepath.Join(home, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := ProbeProjectDir(home, "linked"); ClassifyError(err) != ClassRefusedPath {
		t.Errorf("a symlinked project directory = %v (%s), want refused_path", err, ClassifyError(err))
	}
}
