//go:build linux

package fsscan

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Linux has no counterpart to the placeholder attributes the other two platforms expose.
//
// SF_DATALESS is a Darwin st_flags bit and the RECALL_ON_* attributes are NTFS ones. A Linux
// cloud client is a FUSE filesystem instead -- rclone, google-drive-ocamlfuse, onedriver --
// and FUSE carries nothing that says in advance whether a given file's content is local. So
// the per-file question the other platforms answer cannot be answered here at all.
//
// What can be answered is which filesystem the descriptor is on, and that is enough for the
// decision this package actually has to make. A read on a FUSE mount is serviced by a
// userspace process that may fetch the content over a network first, which is the same
// unbounded download the placeholder rules exist to prevent -- and worse here, because
// nothing bounds a read in progress: the query deadline is consulted between operations, not
// inside a syscall, and closing the descriptor from another goroutine cannot interrupt a
// blocked read on a regular file.
//
// This over-refuses, deliberately and in the same way the darwin and Windows prefix rules do.
// FUSE is not only cloud storage: sshfs, gocryptfs and AppImage mounts are all FUSE, and a
// project on one of those is refused even though its content is local. That is acceptable
// only because the refusal is *reported* rather than silent -- the row names the filesystem
// as the reason and marks the scan incomplete -- so an operator can see the coverage they
// lost instead of reading an empty result as an absence of servers.
//
// Network filesystems are deliberately not included, though NFS_SUPER_MAGIC and the SMB
// magics are just as reachable. An NFS-mounted home is the ordinary arrangement in a managed
// fleet, so refusing on it would inventory nothing at all for those accounts, and the thing
// that makes a dead NFS mount dangerous is that a read can block rather than that it can
// download. That is a separate problem with a separate remedy, bounding the read, and it is
// not improved by refusing every network home.

// fileOnUserspaceFilesystem reports why the open file must not be read, or nil.
//
// From the descriptor rather than the path, for the reason every check in this package works
// that way: a second lookup by name resolves every component again, and the scanned user owns
// those components.
func fileOnUserspaceFilesystem(file *os.File) error {
	var stat unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &stat); err != nil {
		// Not evidence of anything. A failure to identify the filesystem is not a reason to
		// refuse, and the read that follows produces a real diagnosis of its own.
		return nil
	}
	// The conversion is explicit because Statfs_t.Type is int64 on amd64 and uint32 on some
	// 32-bit architectures, so comparing it against the untyped constant directly does not
	// build everywhere.
	if int64(stat.Type) == int64(unix.FUSE_SUPER_MAGIC) {
		return fmt.Errorf("%w: FUSE", ErrUserspaceFilesystem)
	}
	return nil
}
