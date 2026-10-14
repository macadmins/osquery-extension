//go:build !linux

package fsscan

import "os"

// fileOnUserspaceFilesystem reports nil everywhere else.
//
// Not because other platforms have no userspace filesystems, but because they answer the
// narrower question directly: darwin and Windows both expose a per-file attribute saying the
// content is not local, which is what IsCloudPlaceholder reads. A filesystem-type check would
// refuse strictly more than that attribute does, for no additional protection.
func fileOnUserspaceFilesystem(*os.File) error { return nil }
