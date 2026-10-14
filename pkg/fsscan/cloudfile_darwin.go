//go:build darwin

package fsscan

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// A cloud-backed file can be present as a name with no local content. iCloud Drive does this
// for ~/Documents and ~/Desktop when "Optimise Mac Storage" is on, and the modern OneDrive,
// Dropbox and Google Drive clients do it through the same File Provider mechanism under
// ~/Library/CloudStorage.
//
// Reading one is not a read. It is a synchronous download, of unbounded duration, charged to
// whatever process touched the file -- here a scheduled osquery query against a watchdog.
// Worse, it is a side effect: an inventory query that silently pulls a user's documents down
// from the network has changed the machine it was asked to describe.
//
// SF_DATALESS is the flag the kernel sets on such a file, and st_flags comes back from an
// fstat, so the placeholder is identified without reading a byte. That is the whole point:
// every other way of asking "is this file local" involves reading it.

// IsCloudPlaceholder reports whether file's content would have to be downloaded to read it.
//
// From the descriptor, not from a path. An os.Lstat here would be a second lookup by name,
// resolving every intermediate component again -- and the scanned user owns those components,
// so the answer could be about a file outside the home the descriptor came from. An fstat
// answers about the handle, which is the same reason checkDescriptor works the way it does.
func IsCloudPlaceholder(file *os.File) (bool, error) {
	info, err := file.Stat()
	if err != nil {
		return false, err
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, nil
	}
	return sys.Flags&unix.SF_DATALESS != 0, nil
}
