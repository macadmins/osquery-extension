//go:build unix

package devclients

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveSnapPathRefusesASymlinkedSnapDirectory: a ~/snap that is itself a symlink is
// refused, not resolved through, while an ordinary snap pointer still resolves.
func TestResolveSnapPathRefusesASymlinkedSnapDirectory(t *testing.T) {
	rel := filepath.Join("snap", "code", "current", ".config", "Code")

	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "snap", "code", "168"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("168", filepath.Join(home, "snap", "code", "current")); err != nil {
		t.Fatal(err)
	}
	if got, ok := ResolveSnapPath(home, rel); !ok || got != filepath.Join("snap", "code", "168", ".config", "Code") {
		t.Errorf("ordinary pointer: got %q %v", got, ok)
	}

	elsewhere := t.TempDir()
	if err := os.MkdirAll(filepath.Join(elsewhere, "code", "168"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("168", filepath.Join(elsewhere, "code", "current")); err != nil {
		t.Fatal(err)
	}
	linkedHome := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(linkedHome, "snap")); err != nil {
		t.Fatal(err)
	}
	if got, ok := ResolveSnapPath(linkedHome, rel); ok {
		t.Errorf("a symlinked ~/snap was resolved through, to %q", got)
	}
}
