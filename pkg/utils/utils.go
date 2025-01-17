package utils

import "os"

func FileExists(fs FileSystem, filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
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
