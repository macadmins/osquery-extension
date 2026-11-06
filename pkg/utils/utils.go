package utils

import "os"

// FileExists reports whether filename names something other than a directory, asking fs; a nil
// fs is the real filesystem.
func FileExists(fs FileSystem, filename string) bool {
	if fs == nil {
		fs = OSFileSystem{}
	}
	info, err := fs.Stat(filename)
	// Any error leaves info nil, not only "not exist": a path that runs through a regular file
	// fails with ENOTDIR, and an unreadable parent with EACCES.
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func BoolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// FileSystem interface for os.Stat
type FileSystem interface {
	Stat(name string) (os.FileInfo, error)
}

// OSFileSystem is a concrete implementation of FileSystem using os package
type OSFileSystem struct{}

func (OSFileSystem) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}
