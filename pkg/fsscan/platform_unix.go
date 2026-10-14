//go:build unix

package fsscan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// openBeneathComponents walks components one at a time from baseDir, opening each with
// O_NOFOLLOW so a symlink substituted at any intermediate fails with ELOOP. This is
// openat2(RESOLVE_NO_SYMLINKS) built portably out of iterated openat, which is what macOS
// has to do because it has no openat2.
// O_CLOEXEC on every descriptor this function opens. os.OpenFile sets it for us -- the
// runtime does it for every fd it owns -- but unix.Open and unix.Openat are raw syscalls and
// do not. Without it each intermediate directory handle and the final file handle survive an
// exec, and this extension is one process hosting many tables, several of which shell out.
// A descriptor onto another user's home directory, held open across an unrelated table's
// subprocess, is a handle that outlives every check this package makes to obtain it.
const (
	openBeneathDirFlags  = syscall.O_RDONLY | unix.O_DIRECTORY | syscall.O_NOFOLLOW | unix.O_CLOEXEC
	openBeneathFileFlags = syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | unix.O_CLOEXEC
)

func openBeneathComponents(baseDir, relPath string, components []string) (*os.File, error) {
	// O_DIRECTORY ensures baseDir is a directory; O_NOFOLLOW ensures baseDir is not itself
	// a symlink.
	currentFD, err := unix.Open(baseDir, openBeneathDirFlags, 0)
	if err != nil {
		return nil, fmt.Errorf("openbeneath: open base %q: %w", baseDir, err)
	}
	for i, component := range components {
		flags := openBeneathDirFlags
		if i == len(components)-1 {
			flags = openBeneathFileFlags
		}
		nextFD, err := unix.Openat(currentFD, component, flags, 0)
		// Always close the previous fd, even on error.
		_ = unix.Close(currentFD)
		if err != nil {
			return nil, fmt.Errorf("openbeneath: openat %q (component %d of %q): %w",
				component, i, relPath, err)
		}
		currentFD = nextFD
	}
	return os.NewFile(uintptr(currentFD), filepath.Join(baseDir, relPath)), nil
}

// isRefusedOrNotDirectory reports whether err is a symlink refusal or a traversal through a
// non-directory, the two errno cases IsExpectedAbsent treats as benign absence alongside
// ENOENT. Split out per-platform because ELOOP and ENOTDIR are not defined on every GOOS.
//
// Both the wrapped and unwrapped forms are checked: errors.Is walks a %w chain, while
// unix.Openat returns a bare syscall.Errno that only surfaces after OpenBeneath's fmt.Errorf
// wrap is unwound.
func isRefusedOrNotDirectory(err error) bool {
	if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
		return true
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return errors.Is(pathErr.Err, syscall.ELOOP) || errors.Is(pathErr.Err, syscall.ENOTDIR)
	}
	return false
}

// checkDescriptor applies ReadOpts' link-count and owner refusals to an already-open file.
//
// Both answers come from the fstat the caller already performed, so this costs no extra
// syscall and -- more to the point -- no second path lookup. A stat by name here would be a
// different question than "what did I open", and the gap between the two is exactly what the
// component-wise open exists to close.
func checkDescriptor(_ *os.File, info os.FileInfo, opts ReadOpts) error {
	if !opts.RefuseHardLinks && opts.OwnerUID == "" {
		return nil
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// No POSIX stat behind this FileInfo, so neither check can be answered. Refusing is
		// the direction to fail: the caller asked for a guarantee and this cannot supply it,
		// and silently reading anyway would report the file as having passed a check that
		// never ran.
		return fmt.Errorf("%w: link count and owner are unavailable for this file", ErrNotRegular)
	}
	// Nlink is uint16 on darwin and uint64 on linux, so the comparison is written against
	// the value rather than against a fixed-width type.
	if opts.RefuseHardLinks && sys.Nlink > 1 {
		return fmt.Errorf("%w: %d links", ErrHardLink, sys.Nlink)
	}
	if opts.OwnerUID != "" {
		owner := strconv.FormatUint(uint64(sys.Uid), 10)
		if owner != opts.OwnerUID {
			// Neither uid appears in the error. The expected one came from the roster and
			// the found one from the filesystem, and both are numbers a caller could
			// publish safely -- but the caller classifies this rather than printing it, so
			// there is nothing for them to be in.
			return ErrForeignOwner
		}
	}
	return nil
}
