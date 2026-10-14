//go:build !unix && !windows

package fsscan

import (
	"os"
)

// This package reads files that another local user may control, so every open has to refuse
// symlinks at the kernel level. The primitives that do that are POSIX: O_NOFOLLOW and
// openat. Anything without them has no portable equivalent through the standard library, and
// a best-effort version that followed a reparse point would be worse than no table at all,
// because the caller could not tell the difference.
//
// So every open reports unsupported here rather than degrading. Callers surface that as a
// warning row. The package still compiles and links, which is what the build requires; it
// simply returns no rows.
//
// The constraint is `!unix` rather than `windows`. Go's `unix` tag names exactly the platforms
// x/sys/unix and the POSIX constants support, so `!windows` also selected the POSIX file for
// js, plan9 and wasip1, where those symbols do not exist and the cross-build failed. Windows
// is the target that matters here, but it is not the only one that is not POSIX.
//
// errUnsupported, the sentinel every function here returns, lives in openbeneath.go. It has
// to be nameable on every platform because ClassifyError maps it, and a sentinel declared
// only in the build that returns it cannot be classified in the build that reports it.

func openBeneathComponents(string, string, []string) (*os.File, error) {
	return nil, errUnsupported
}

// isRefusedOrNotDirectory has nothing to classify here: every open returns errUnsupported
// before the filesystem is consulted, so no ELOOP or ENOTDIR can arise. Reporting false keeps
// IsExpectedAbsent's ENOENT case, which os.Lstat can still produce, working as documented.
func isRefusedOrNotDirectory(error) bool {
	return false
}

// checkDescriptor has nothing to check: no descriptor reaches it, because every open above
// returns errUnsupported before the filesystem is consulted. Reporting nil rather than an
// error keeps the signature honest -- the checks did not fail, they were never reached.
func checkDescriptor(*os.File, os.FileInfo, ReadOpts) error {
	return nil
}
