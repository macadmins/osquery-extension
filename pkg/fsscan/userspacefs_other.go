//go:build !linux

package fsscan

import "os"

// fileOnUserspaceFilesystem reports nil everywhere else.
//
// darwin and Windows have userspace filesystems too. What this package checks on them is the
// per-file attribute a cloud provider sets when content is not local, which IsCloudPlaceholder
// reads. A userspace filesystem whose files do not carry that attribute is read on these
// platforms, not refused: no filesystem-type check is implemented for them.
func fileOnUserspaceFilesystem(*os.File) error { return nil }
