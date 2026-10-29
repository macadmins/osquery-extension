package testutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Junction creates a directory junction at link that points at target, creating link's parent
// first. A junction needs no privilege on Windows, unlike a symlink, so it is the reparse point
// an unprivileged account can plant. The test is skipped if mklink is unavailable.
func Junction(t *testing.T, link, target string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("mklink /J failed: %v: %s", err, output)
	}
}
