//go:build darwin

package fsscan

import (
	"os"

	"golang.org/x/sys/unix"
)

// onNetworkFilesystem reports whether file is on a filesystem the kernel does not mark as
// stored locally. MNT_LOCAL is set for local volumes and clear for NFS, SMB, AFP and WebDAV
// mounts, so one flag covers every network filesystem darwin mounts without naming them. A
// failed fstatfs is not evidence of anything, and the caller's reads report their own errors.
func onNetworkFilesystem(file *os.File) bool {
	var stat unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &stat); err != nil {
		return false
	}
	return stat.Flags&unix.MNT_LOCAL == 0
}
