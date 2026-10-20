// Package testutil holds fixture helpers shared by the tests of the tables and the packages
// they use. Tests build their fixtures at runtime, because symlinks, junctions, permissions and
// ownership cannot be checked into git, and those are what the code under test refuses.
//
// It imports nothing from this repository, so any package's tests can use it without an
// import cycle.
package testutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// WriteFile creates a file and every directory above it.
func WriteFile(t testing.TB, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// FileURL renders a path the way VS Code records a workspace folder: file:///Users/alice/x on
// POSIX and file:///C:/Users/alice/x on Windows, where the drive letter follows a third slash.
// Joining "file://" to a Windows path directly gives file://C:/..., whose host is "C:", which
// the reader correctly refuses as a remote location.
func FileURL(path string) string {
	slashed := filepath.ToSlash(path)
	if !strings.HasPrefix(slashed, "/") {
		slashed = "/" + slashed
	}
	return "file://" + slashed
}
