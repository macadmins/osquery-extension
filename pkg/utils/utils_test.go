package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFileExists: the answer comes from the FileSystem passed in, so a mock decides it without
// the disk, and the real filesystem, passed or nil, reports a file and its removal.
func TestFileExists(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	assert.True(t, FileExists(MockFileSystem{FileExists: true}, missing))
	assert.False(t, FileExists(MockFileSystem{FileExists: false}, missing))
	assert.False(t, FileExists(MockFileSystem{Err: os.ErrPermission}, missing))

	file := filepath.Join(t.TempDir(), "file")
	assert.NoError(t, os.WriteFile(file, nil, 0o600))
	assert.True(t, FileExists(OSFileSystem{}, file))
	assert.True(t, FileExists(nil, file))
	assert.False(t, FileExists(OSFileSystem{}, filepath.Dir(file)), "a directory is not a file")
	assert.NoError(t, os.Remove(file))
	assert.False(t, FileExists(OSFileSystem{}, file))
}

// TestFileExistsUnderARegularFile: a path below a regular file fails to stat with ENOTDIR rather
// than "not exist", and is reported as absent instead of dereferencing a nil FileInfo.
func TestFileExistsUnderARegularFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	assert.NoError(t, os.WriteFile(file, nil, 0o600))
	assert.False(t, FileExists(OSFileSystem{}, filepath.Join(file, "below")))
}

func TestBoolToString(t *testing.T) {
	// Test that BoolToString returns "true" for true
	assert.Equal(t, "true", BoolToString(true), "Expected true as string")

	// Test that BoolToString returns "false" for false
	assert.Equal(t, "false", BoolToString(false), "Expected false as string")
}
