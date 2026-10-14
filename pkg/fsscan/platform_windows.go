//go:build windows

package fsscan

// PARTIALLY VERIFIED. Exercised on a real Windows host: ordinary bounded reads of
// configuration under a user profile, and the case this file exists for -- a junction
// planted at a probed configuration path was refused rather than followed, producing no row
// and no warning, which is the designed silent-absence result.
//
// KNOWN GAP: not continuously exercised. There is no Windows CI job, so `go vet` and
// cross-compilation are the only automated checks that ever see this file, and the
// coverage gate cannot measure it at all. Nothing has stress-tested the post-open identity
// re-check against a path genuinely being replaced mid-traversal; that race is reasoned
// about rather than demonstrated.

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// Windows has no openat and no O_NOFOLLOW, so the guarantees this package rests on are
// rebuilt from different primitives. The property that has to hold is the same one the POSIX
// path enforces: a directory a local user controls must never redirect a read to a file
// outside the home being scanned.
//
// Three things stand in for O_NOFOLLOW:
//
//   - os.Root, which resolves every component beneath a directory handle and refuses any
//     component that resolves outside it. This is the direct analogue of the iterated
//     openat(O_NOFOLLOW) chain, and it is what closes the parent-substitution hole that a
//     path-based open leaves open.
//   - An Lstat check that rejects reparse points outright, so a junction or symlink is
//     refused rather than followed even when it stays inside the root.
//   - A post-open identity re-check (os.SameFile), which catches a path swapped between the
//     Lstat and the open.
//
// os.Root on its own would still differ from the POSIX path: it *follows* a symlink whose
// target stays inside the root, where O_NOFOLLOW refuses every symlink regardless. The
// per-component Lstat closes that difference, because openBeneathComponents checks every
// component and not just the last, so the same probed path gets the same answer on all
// three platforms.
//
// Creating a symlink on Windows normally requires SeCreateSymbolicLinkPrivilege, which an
// unprivileged user does not hold unless Developer Mode is enabled. Directory junctions need
// no privilege, which is why reparse points rather than symlinks are what the Lstat check
// is written against.

// reparsePointRefused reports that a path component is a reparse point (a junction, a
// symlink, a mount point) and was refused rather than followed. It is the Windows counterpart
// of ELOOP from an O_NOFOLLOW open.
var reparsePointRefused = errors.New("fsscan: path component is a reparse point")

// openBeneathComponents opens relPath under baseDir without letting any component escape
// baseDir.
//
// Structured as a chain: each directory is opened as a sub-root of the one before it, so
// every lookup is a single component resolved against its immediate parent's handle. That is
// the same shape as the POSIX iterated openat(O_NOFOLLOW) loop, and it matters for the same
// reason -- the parent a component is resolved against is one this function already opened
// and is holding, not a path re-resolved from the top on each step, so the prefix cannot be
// swapped underneath the traversal after it has been checked.
//
// os.Root refuses any component resolving outside its root. The per-component Lstat adds
// what os.Root does not do: refusing a reparse point that stays inside the root, so the
// Windows result matches the POSIX one for every probed path rather than only for escapes.
//
// One window remains, on the final component only: it is Lstat-ed and then opened, and those
// are two operations. The post-open identity check closes it -- if the name was swapped in
// between, the opened file is not the one that was checked and the open is refused.
func openBeneathComponents(baseDir, relPath string, components []string) (*os.File, error) {
	// The base is checked here, not merely trusted from whoever supplied it. The roster
	// Lstats a home before admitting it, but that happens once per query and this runs per
	// read, so a profile directory swapped for a junction in between would root the handle
	// -- and every read under it -- at the junction's target. The POSIX backend never had
	// this gap: O_NOFOLLOW on the base open refuses a swapped base in the same syscall.
	// os.OpenRoot has no equivalent, so the check and the identity re-check around it are
	// what close the window.
	baseBefore, err := os.Lstat(baseDir)
	if err != nil {
		return nil, fmt.Errorf("openbeneath: stat base %q: %w", baseDir, err)
	}
	if redirectsElsewhere(baseBefore.Mode()) {
		return nil, fmt.Errorf("openbeneath: %w: base %q", reparsePointRefused, baseDir)
	}
	current, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, fmt.Errorf("openbeneath: open base %q: %w", baseDir, err)
	}
	baseAfter, err := current.Stat(".")
	if err != nil || !os.SameFile(baseBefore, baseAfter) {
		_ = current.Close()
		if err != nil {
			return nil, fmt.Errorf("openbeneath: stat base %q: %w", baseDir, err)
		}
		return nil, fmt.Errorf("openbeneath: %w: base %q changed between check and open",
			reparsePointRefused, baseDir)
	}
	// Each intermediate root is closed as soon as its child is open; this closes whichever
	// one is current when the function returns, including on the error paths.
	defer func() { _ = current.Close() }()

	for i, component := range components[:len(components)-1] {
		before, err := lstatNoReparse(current, component, i, relPath)
		if err != nil {
			return nil, err
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			return nil, fmt.Errorf("openbeneath: open %q (component %d of %q): %w",
				component, i, relPath, err)
		}
		// The check and the open are two calls, so the directory can be replaced between
		// them. os.Root permits a reparse point that resolves inside its own root, which
		// is exactly why lstatNoReparse exists -- and it is also what makes the gap
		// reachable: a junction planted in that window points somewhere else within the
		// root and os.Root follows it without complaint. The final component has carried
		// an identity re-check since this was written; the directories leading to it had
		// none, so a swap one level up went unnoticed.
		after, statErr := next.Stat(".")
		if statErr != nil || !os.SameFile(before, after) {
			_ = next.Close()
			if statErr != nil {
				return nil, fmt.Errorf("openbeneath: stat %q (component %d of %q): %w",
					component, i, relPath, statErr)
			}
			return nil, fmt.Errorf("openbeneath: %w: %q changed between check and open "+
				"(component %d of %q)", reparsePointRefused, component, i, relPath)
		}
		_ = current.Close()
		current = next
	}

	last := components[len(components)-1]
	before, err := lstatNoReparse(current, last, len(components)-1, relPath)
	if err != nil {
		return nil, err
	}
	file, err := current.Open(last)
	if err != nil {
		return nil, fmt.Errorf("openbeneath: open %q: %w", relPath, err)
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("openbeneath: stat %q: %w", relPath, err)
		}
		return nil, fmt.Errorf("openbeneath: %w: %q changed between check and open",
			reparsePointRefused, relPath)
	}
	return file, nil
}

// lstatNoReparse stats one component against the handle of its immediate parent and refuses
// it if it is a reparse point. Junctions need no privilege to create on Windows, which is
// why they and not symlinks are the shape this is written against.
func lstatNoReparse(root *os.Root, name string, index int, relPath string) (os.FileInfo, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("openbeneath: lstat %q (component %d of %q): %w",
			name, index, relPath, err)
	}
	if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return nil, fmt.Errorf("openbeneath: %w: %q (component %d of %q)",
			reparsePointRefused, name, index, relPath)
	}
	return info, nil
}

// isRefusedOrNotDirectory reports whether err is a refusal to follow a reparse point or a
// traversal through a non-directory, the two cases IsExpectedAbsent treats as benign absence
// alongside ENOENT. These are the Windows counterparts of ELOOP and ENOTDIR.
//
// ERROR_DIRECTORY is what Windows returns for "a component of the path is not a directory".
// ERROR_CANT_ACCESS_FILE and ERROR_INVALID_REPARSE_DATA arise when a reparse point cannot be
// traversed.
//
// os.Root's own escape error is deliberately not matched. It is unexported and reads "path
// escapes from parent", so recognising it would mean comparing strings; os.ErrInvalid is not
// it either, despite being what root.go returns for several neighbouring cases -- those are
// operations on a *closed* Root, and treating one as benign absence would hide a real bug in
// this package. Nor is the match needed: splitSafeComponents rejects ".." and absolute paths
// before any component is opened, and lstatNoReparse refuses a reparse point at every
// component, so no call this package makes can reach os.Root with something that escapes.
func isRefusedOrNotDirectory(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, reparsePointRefused) {
		return true
	}
	for _, errno := range []windows.Errno{
		windows.ERROR_DIRECTORY,
		windows.ERROR_CANT_ACCESS_FILE,
		windows.ERROR_INVALID_REPARSE_DATA,
		windows.ERROR_REPARSE_TAG_INVALID,
	} {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}

// checkDescriptor applies ReadOpts' link-count refusal to an already-open file.
//
// The link count comes from GetFileInformationByHandle, which answers about the handle
// rather than about a path, so a replacement between the open and the check cannot change
// the answer. That is the same property the unix implementation relies on for its fstat.
//
// The owner check is deliberately not implemented here, and OwnerUID is refused rather than
// silently treated as satisfied. Comparing an NTFS owner means GetSecurityInfo, a SID
// conversion and a comparison against the roster's SID string, none of which has a CI job
// that would ever execute it; shipping it unexercised in the function whose whole purpose is
// a security guarantee is worse than declining the guarantee out loud. Refusing is what stops
// a caller believing a check ran that did not -- a successful read would otherwise look like
// an owner-verified one. Hard links are the vector that matters here and
// GetFileInformationByHandle does answer them, so the useful half is covered. Implementing
// the rest wants a Windows CI job first.
func checkDescriptor(f *os.File, _ os.FileInfo, opts ReadOpts) error {
	if opts.OwnerUID != "" {
		// Refused rather than passed. A caller that asked for an owner check and got a
		// successful read would believe the file was owner-verified, which is precisely the
		// half-applied guarantee this must not create.
		return fmt.Errorf("%w: owner verification is not implemented on this platform",
			ErrForeignOwner)
	}
	if !opts.RefuseHardLinks {
		return nil
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		return fmt.Errorf("%w: link count is unavailable for this file: %w", ErrNotRegular, err)
	}
	if info.NumberOfLinks > 1 {
		return fmt.Errorf("%w: %d links", ErrHardLink, info.NumberOfLinks)
	}
	return nil
}

// cloudPlaceholderFlags are the attributes that mark a file whose content is not local.
//
// RECALL_ON_OPEN and RECALL_ON_DATA_ACCESS are what OneDrive's Files On-Demand sets, the
// first for a fully dehydrated file and the second for a partially hydrated one. OFFLINE is
// the older HSM attribute and is included because a provider that sets only it would
// otherwise be read, and reading is the operation with the cost.
const cloudPlaceholderFlags = windows.FILE_ATTRIBUTE_RECALL_ON_OPEN |
	windows.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | windows.FILE_ATTRIBUTE_OFFLINE

// IsCloudPlaceholder reports whether the open file's content would have to be downloaded to
// read it.
//
// GetFileInformationByHandle rather than GetFileAttributesEx on a path. Both return the same
// FileAttributes word, but the path form resolves every component on the way, including any
// reparse point the scanned user planted -- so the question could be answered about a file,
// or a UNC share, outside the profile the descriptor came from, and the lookup itself would
// be the thing that went there. A handle cannot be redirected after it is held. The link
// count in checkDescriptor is read from the same call for the same reason.
//
// KNOWN GAP: inspecting a handle means the file is already open, and
// FILE_ATTRIBUTE_RECALL_ON_OPEN is by definition the attribute whose provider starts
// fetching at CreateFile. os.Root exposes no way to pass FILE_FLAG_OPEN_NO_RECALL, so that
// one attribute is now detected after the cost it exists to avoid has been incurred;
// RECALL_ON_DATA_ACCESS and OFFLINE are still caught before any byte is read. See the
// ordering note in ReadProjectFile.
func IsCloudPlaceholder(file *os.File) (bool, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return false, err
	}
	return info.FileAttributes&cloudPlaceholderFlags != 0, nil
}
