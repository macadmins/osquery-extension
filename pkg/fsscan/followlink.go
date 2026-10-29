package fsscan

import (
	"fmt"
	"io/fs"
	"path/filepath"
)

// LinkResult is what FollowLink decided about a symbolic link.
type LinkResult int

const (
	// LinkDeclined: the link is not followed, and the caller reports it as the refusal it was.
	LinkDeclined LinkResult = iota
	// LinkAbsent: the target cannot exist, because its directory is missing or a component of
	// its path is a regular file, so the link is a dangling one: an absent file.
	LinkAbsent
	// LinkFollowed: the target is opened, with every check the original read applied.
	LinkFollowed
)

// LinkChecks are the storage checks FollowLink applies to a link target's directory, and how
// ReadLinkTarget reads the target. A nil field uses UnderCloudStorage, ProbeProjectDir or a
// ReadProjectFile read. A table substitutes the checks in tests, because a cloud folder and a
// network mount cannot be created there, and sets Read to the reader the file the link stands
// for is read with, so a followed link is read the way that file would be.
type LinkChecks struct {
	UnderCloudStorage func(rel string) bool
	ProbeDir          func(base, rel string) error
	Read              func(base, rel string, opts ReadOpts) ([]byte, error)
}

// FollowLink resolves the symbolic link name inside relDir by one hop and returns the
// base-relative path of the file it names when a caller may read that file.
//
// The link is read by LinkTargetBeneath, so a target outside base, one that climbs above it, and
// one with a ".." after a named directory are declined. The target's directory then passes the
// checks a recorded project's directory passes, in the same order and before anything under it
// is opened: the cloud-folder rule on the path, then one probe, which must open the directory as
// local storage or as storage like base's, baseStorage. A directory the probe refuses through a
// symlink, or cannot open, declines the link. A link to another link is refused when the caller
// opens the result. Windows has no link reader in this package, so there every link is declined.
func FollowLink(base string, baseStorage ErrClass, relDir, name string, checks LinkChecks) (string,
	LinkResult) {
	underCloud, probe := checks.UnderCloudStorage, checks.ProbeDir
	if underCloud == nil {
		underCloud = UnderCloudStorage
	}
	if probe == nil {
		probe = ProbeProjectDir
	}
	target, err := LinkTargetBeneath(base, relDir, name)
	if err != nil || underCloud(target) {
		return "", LinkDeclined
	}
	probeErr := probe(base, filepath.Dir(target))
	switch storage := ClassifyError(probeErr); {
	case storage == ClassNone, storage == baseStorage:
		return target, LinkFollowed
	case storage == ClassAbsent, IsNotDirectory(probeErr):
		return "", LinkAbsent
	default:
		return "", LinkDeclined
	}
}

// ReadLinkTarget reads the file a symbolic link names, for a read of relDir/name that failed
// with refused, a ClassRefusedPath error. The target is read with checks.Read and opts, or by
// default through ReadProjectFile, so the hard-link refusal, the cloud attribute, the
// userspace-filesystem refusal and the size cap apply to it.
//
// A link FollowLink declines, a target that is not a regular file, a target that is itself a
// link, and a target whose content a cloud provider holds return refused unchanged, so the
// caller reports the link as it reports any refusal. A link whose target cannot exist returns an
// error ClassifyError reports as ClassAbsent.
func ReadLinkTarget(base string, baseStorage ErrClass, relDir, name string, opts ReadOpts,
	checks LinkChecks, refused error) ([]byte, error) {
	target, result := FollowLink(base, baseStorage, relDir, name, checks)
	switch result {
	case LinkDeclined:
		return nil, refused
	case LinkAbsent:
		return nil, fmt.Errorf("fsscan: the link's target cannot exist: %w", fs.ErrNotExist)
	}
	read := checks.Read
	if read == nil {
		read = func(base, rel string, opts ReadOpts) ([]byte, error) {
			return ReadProjectFile(base, filepath.Dir(rel), filepath.Base(rel), opts)
		}
	}
	data, err := read(base, target, opts)
	switch ClassifyError(err) {
	case ClassNotRegular, ClassRefusedPath, ClassCloudPlaceholder:
		return nil, refused
	}
	return data, err
}
