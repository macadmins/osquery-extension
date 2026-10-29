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

// TestProviderReparsePoint: of the components Windows reports as reparse points, a provider's --
// a Cloud Files directory or file, or anything with a recall or offline attribute -- is told
// apart from a link by the mode Go derives and the attributes Lstat returns. A junction is a
// directory without os.ModeDir, so it stays a link.
func TestProviderReparsePoint(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mode       os.FileMode
		attributes uint32
		want       bool
	}{
		{"ordinary file", 0o666, 0, false},
		{"ordinary directory", os.ModeDir | 0o777, fileAttributeDirectory, false},
		{"symbolic link", os.ModeSymlink | 0o666, 0, false},
		{"junction", os.ModeIrregular | 0o666, fileAttributeDirectory, false},
		{"provider directory", os.ModeIrregular | os.ModeDir | 0o777, fileAttributeDirectory, true},
		{"synced provider file", os.ModeIrregular | 0o666, 0, true},
		{"dehydrated provider file", os.ModeIrregular | 0o666, fileAttributeRecallOnDataAccess, true},
		{"directory to be listed on open", os.ModeIrregular | os.ModeDir | 0o777,
			fileAttributeDirectory | fileAttributeRecallOnOpen, true},
		{"directory-shaped reparse point moved offline", os.ModeIrregular | 0o666,
			fileAttributeDirectory | fileAttributeOffline, true},
	} {
		if got := providerReparsePoint(tc.mode, tc.attributes); got != tc.want {
			t.Errorf("%s: providerReparsePoint = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestListedKind: a listing skips a provider's reparse point that is not a directory as the file
// it holds, and keeps the type of a junction, a symbolic link and a provider's directory, which
// it counts as refused links.
func TestListedKind(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mode       os.FileMode
		attributes uint32
		want       os.FileMode
	}{
		{"ordinary file", 0o666, 0, 0},
		{"ordinary directory", os.ModeDir | 0o777, fileAttributeDirectory, os.ModeDir},
		{"symbolic link", os.ModeSymlink | 0o666, 0, os.ModeSymlink},
		{"junction", os.ModeIrregular | 0o666, fileAttributeDirectory, os.ModeIrregular},
		{"synced provider file", os.ModeIrregular | 0o666, 0, 0},
		{"dehydrated provider file", os.ModeIrregular | 0o666, fileAttributeRecallOnOpen, 0},
		{"provider directory", os.ModeIrregular | os.ModeDir | 0o777, fileAttributeDirectory,
			os.ModeIrregular | os.ModeDir},
	} {
		if got := listedKind(tc.mode, tc.attributes); got != tc.want {
			t.Errorf("%s: listedKind = %v, want %v", tc.name, got, tc.want)
		}
	}
}
