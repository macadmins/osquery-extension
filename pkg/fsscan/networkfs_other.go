//go:build !darwin && !linux

package fsscan

import "os"

// onNetworkFilesystem reports false on the remaining platforms. On Windows a project must lie
// inside the profile directory, and a folder redirected to a share leaves the profile and is
// refused by containment before anything is opened.
func onNetworkFilesystem(*os.File) bool { return false }
