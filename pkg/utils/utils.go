package utils

import "os"

func FileExists(filename string) bool {
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
