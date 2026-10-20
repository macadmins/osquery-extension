//go:build linux

package fsscan

import (
	"os"

	"golang.org/x/sys/unix"
)

// networkFilesystemMagic are the statfs filesystem types of the network filesystems Linux
// mounts: NFS; SMB, in the SMB, SMB2 and CIFS variants the kernel reports; CephFS; and AFS.
// 9p is left out on purpose: WSL2 mounts the Windows drives at /mnt/c over 9p, and developers
// keep projects there.
var networkFilesystemMagic = []int64{
	unix.NFS_SUPER_MAGIC,
	unix.SMB_SUPER_MAGIC,
	unix.SMB2_SUPER_MAGIC,
	unix.CIFS_SUPER_MAGIC,
	unix.CEPH_SUPER_MAGIC,
	unix.AFS_SUPER_MAGIC,
}

// onNetworkFilesystem reports whether file is on a network filesystem. A failed fstatfs is not
// evidence of anything, and the caller's reads report their own errors.
func onNetworkFilesystem(file *os.File) bool {
	var stat unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &stat); err != nil {
		return false
	}
	// Statfs_t.Type is int64 on amd64 and narrower on some architectures; see
	// fileOnUserspaceFilesystem.
	for _, magic := range networkFilesystemMagic {
		if int64(stat.Type) == magic {
			return true
		}
	}
	return false
}
