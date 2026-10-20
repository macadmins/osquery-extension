// Package testutil holds fixture helpers shared by the tests of the tables and the packages
// they use. Tests build their fixtures at runtime, because symlinks, junctions, permissions and
// ownership cannot be checked into git, and those are what the code under test refuses.
//
// It imports nothing from this repository, so any package's tests can use it without an
// import cycle.
package testutil

import (
	"encoding/json"
	"errors"
	"io/fs"
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

// AbsPath joins parts under the root of the volume the test runs on, so a fixture path is
// absolute on every platform: `/Users/alice` has no drive letter, and Windows does not count it
// as absolute.
func AbsPath(parts ...string) string {
	root := filepath.VolumeName(os.TempDir()) + string(filepath.Separator)
	return filepath.Join(append([]string{root}, parts...)...)
}

// JSONString quotes s as a JSON string. A Windows path concatenated into a fixture unquoted is
// not JSON: `C:\Users` holds the escape `\U`, which JSON does not define. Marshaling a string
// cannot fail.
func JSONString(s string) string {
	encoded, _ := json.Marshal(s)
	return string(encoded)
}

// SameFile reports whether a and b name one file, as two spellings that differ only in case do
// on a case-insensitive volume. A b that does not exist names no file.
func SameFile(t testing.TB, a, b string) bool {
	t.Helper()
	first, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.Stat(b)
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return os.SameFile(first, second)
}
