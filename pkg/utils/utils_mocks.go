package utils

import (
	"os"
	"path/filepath"
	"time"
)

// MockFileSystem is a mock implementation of FileSystem for testing
type MockFileSystem struct {
	FileExists bool
	Err        error
}

func (m MockFileSystem) Stat(name string) (os.FileInfo, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	if m.FileExists {
		return mockFileInfo{name: name}, nil
	}
	return nil, os.ErrNotExist
}

// mockFileInfo is what MockFileSystem reports for a file it says exists: an empty regular file.
type mockFileInfo struct {
	name string
}

func (info mockFileInfo) Name() string       { return filepath.Base(info.name) }
func (info mockFileInfo) Size() int64        { return 0 }
func (info mockFileInfo) Mode() os.FileMode  { return 0o644 }
func (info mockFileInfo) ModTime() time.Time { return time.Time{} }
func (info mockFileInfo) IsDir() bool        { return false }
func (info mockFileInfo) Sys() any           { return nil }
