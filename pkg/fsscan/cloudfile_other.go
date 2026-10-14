//go:build !darwin && !windows

package fsscan

import "os"

// IsCloudPlaceholder reports false everywhere else.
//
// The flag has no counterpart. SF_DATALESS is a Darwin st_flags bit and the RECALL_ON_*
// attributes are NTFS ones; Linux's cloud clients are FUSE filesystems that either hold the
// content or fail the read, with no attribute saying which in advance.
//
// Reporting false rather than refusing is right here: on a platform where a placeholder
// cannot be identified, treating every file as one would stop the table reading anything.
// Nor do the caller's prefix rules fill the gap -- they name macOS mount points and apply on
// darwin only, because a Linux directory that happens to be called Library/CloudStorage is
// an ordinary directory.
func IsCloudPlaceholder(*os.File) (bool, error) {
	return false, nil
}
