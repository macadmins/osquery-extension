package fsscan

import (
	"os"
	"path/filepath"
	"testing"
)

// The benign half of the classification, pinned on its own because the cost of getting it
// wrong is asymmetric. A failure wrongly called expected-absent disappears from the table
// with no warning attached; a nil error wrongly called expected-absent would make a
// successful read look like a missing file.
func TestIsExpectedAbsent(t *testing.T) {
	dir := t.TempDir()
	_, err := os.Open(filepath.Join(dir, "missing"))
	if !IsExpectedAbsent(err) {
		t.Errorf("ENOENT should be expected-absent: %v", err)
	}
	if IsExpectedAbsent(nil) {
		t.Errorf("nil error must not be expected-absent")
	}
}
