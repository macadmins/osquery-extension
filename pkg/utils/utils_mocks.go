package utils

import "os"

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
		return nil, nil
	}
	return nil, os.ErrNotExist
}
