package fsscan

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// OpenBeneath opens relPath relative to baseDir while refusing to follow
// symlinks at ANY path component: including intermediates. This is
// equivalent to Linux's openat2(O_NOFOLLOW + RESOLVE_NO_SYMLINKS), built
// portably on macOS with iterated openat(O_NOFOLLOW).
//
// The threat this defends against: a user owns their home directory, so
// they can replace ANY intermediate directory with a symlink:
//
//	rm -rf ~/Library
//	ln -s /Users/victim/Library ~/Library
//
// Then a direct-path lookup like ~/Library/Application Support/Claude/foo.json
// resolves through the attacker's symlink to the victim's Library. Plain
// O_NOFOLLOW only protects the FINAL component. OpenBeneath protects all
// of them: each intermediate is opened with O_NOFOLLOW so a substituted
// symlink fails with ELOOP.
//
// baseDir is assumed already trusted (e.g., the result of ListUserHomes,
// which Lstat-checks user home dirs and refuses symlinks at /Users/*).
// relPath must NOT contain ".." or absolute path components: those are
// rejected. Components separated by OS path separators are walked one at
// a time.
//
// Returns an *os.File ready for reading, or an error. The caller closes the file as usual.
// The per-component open is platform-specific: platform_unix.go iterates openat(O_NOFOLLOW),
// platform_windows.go walks a chain of os.Root handles and Lstats each component to refuse a
// reparse point that stays inside the root, and platform_unsupported.go reports unsupported
// for everything else.
func OpenBeneath(baseDir, relPath string) (*os.File, error) {
	components, err := splitSafeComponents(relPath)
	if err != nil {
		return nil, err
	}
	if len(components) == 0 {
		return nil, errors.New("openbeneath: empty relative path")
	}
	return openBeneathComponents(baseDir, relPath, components)
}

// The refusals a read can report, as sentinels rather than as prose.
//
// A caller that wants to classify a failure -- to say which refusal happened, on a row that
// must not carry a byte the user chose -- cannot do that by reading an error's text: the text
// is the thing it is trying not to emit. Sentinels make the classification structural, and
// ClassifyError below closes it into an enum.
var (
	// ErrTooLarge means the file was bigger than the cap. Refused rather than truncated: a
	// truncated config parses as a different config, which is worse than no answer.
	ErrTooLarge = errors.New("fsscan: file exceeds the size cap")

	// ErrNotRegular means the opened descriptor is a directory, device, FIFO or socket.
	ErrNotRegular = errors.New("fsscan: not a regular file")

	// ErrGrewDuringRead means the file passed the size check and then grew past the cap
	// before the read finished, so what was read is not the whole file.
	ErrGrewDuringRead = errors.New("fsscan: file grew past the size cap during the read")

	// ErrHardLink means the file has more than one link and ReadOpts.RefuseHardLinks was
	// set. One of those links is the path that was opened; the others can be anywhere the
	// linking user could write, which is what makes the count worth refusing on.
	ErrHardLink = errors.New("fsscan: file has more than one hard link")

	// ErrForeignOwner means the file's owning uid is not the one ReadOpts.OwnerUID named.
	ErrForeignOwner = errors.New("fsscan: file is owned by another account")

	// errUnsupported reports that this platform has no symlink-refusing traversal.
	//
	// Declared here rather than in platform_unsupported.go, which builds for neither unix
	// nor windows: ClassifyError has to name it on every platform, and a sentinel visible
	// only in the build where it is returned cannot be classified anywhere else.
	errUnsupported = errors.New("fsscan: symlink-safe traversal requires POSIX openat and O_NOFOLLOW")
)

// ErrClass is the closed set of reasons a bounded read can fail.
//
// Closed, and spelled in bytes this package chose, because the caller emitting it is a
// virtual table column. A classification is safe to publish; an error string is not, since
// it carries the path and often the content that failed -- see the TOML parser, whose message
// quotes the offending token. The enum is what lets a warning column say *which* refusal
// happened without reproducing any of the input that caused it.
type ErrClass string

const (
	// ClassNone is the zero value: no error.
	ClassNone ErrClass = ""
	// ClassAbsent is a file that is not there.
	ClassAbsent ErrClass = "absent"
	// ClassRefusedPath is a symlink refused at some component, or a traversal through a
	// non-directory. One class rather than two because they are the same answer to the
	// caller -- the path does not name a file this package will read -- and because the two
	// errnos are produced interchangeably by the same substitution.
	ClassRefusedPath ErrClass = "refused_path"
	// ClassDenied is a permission failure.
	ClassDenied ErrClass = "denied"
	// ClassNotRegular is a directory, device, FIFO or socket where a file was expected.
	ClassNotRegular ErrClass = "not_regular"
	// ClassTooLarge is a file past the size cap.
	ClassTooLarge ErrClass = "too_large"
	// ClassGrewDuringRead is a file that outgrew the cap mid-read.
	ClassGrewDuringRead ErrClass = "grew_during_read"
	// ClassHardLink is a multiply-linked file refused by RefuseHardLinks.
	ClassHardLink ErrClass = "hard_link"
	// ClassForeignOwner is a file owned by an account other than the one expected.
	ClassForeignOwner ErrClass = "foreign_owner"
	// ClassUnsupported is a platform with no symlink-refusing traversal.
	ClassUnsupported ErrClass = "unsupported"
	// ClassCloudPlaceholder is a file whose content is not local.
	ClassCloudPlaceholder ErrClass = "cloud_placeholder"

	// ClassUserspaceFilesystem is a file on a filesystem whose reads are serviced by a
	// userspace process, so a read may fetch content on demand and cannot be bounded.
	ClassUserspaceFilesystem ErrClass = "userspace_filesystem"
	// ClassNetworkFilesystem is a project directory on a network filesystem.
	ClassNetworkFilesystem ErrClass = "network_filesystem"
	// ClassUnsupportedOrigin is a recorded location naming a filesystem that is not this
	// one: a remote-development URL, a UNC share.
	ClassUnsupportedOrigin ErrClass = "unsupported_origin"
	// ClassNotContained is a real absolute path lying outside the home it was recorded
	// under.
	ClassNotContained ErrClass = "not_contained"
	// ClassMalformedPath is a recorded string that is not a usable absolute path.
	ClassMalformedPath ErrClass = "malformed_path"
	// ClassOther is everything else. Present so the enum is total: a caller switching over
	// it cannot be handed a value it has no case for, which is the property that makes the
	// exhaustiveness test over the warning catalogue meaningful.
	ClassOther ErrClass = "other"
)

// ClassifyError maps a read failure onto the closed set.
//
// Order matters where the cases overlap. The specific sentinels are tested before the
// generic fs ones, and absence before denial: a path whose parent is unreadable can produce
// either on different platforms, and reporting it as absent would say the file is not there
// when what happened is that nobody looked.
func ClassifyError(err error) ErrClass {
	switch {
	case err == nil:
		return ClassNone
	case errors.Is(err, ErrTooLarge):
		return ClassTooLarge
	case errors.Is(err, ErrGrewDuringRead):
		return ClassGrewDuringRead
	case errors.Is(err, ErrHardLink):
		return ClassHardLink
	case errors.Is(err, ErrForeignOwner):
		return ClassForeignOwner
	case errors.Is(err, ErrNotRegular):
		return ClassNotRegular
	case errors.Is(err, ErrCloudPlaceholder):
		return ClassCloudPlaceholder
	case errors.Is(err, ErrUserspaceFilesystem):
		return ClassUserspaceFilesystem
	case errors.Is(err, ErrNetworkFilesystem):
		return ClassNetworkFilesystem
	case errors.Is(err, ErrUnsupportedOrigin):
		return ClassUnsupportedOrigin
	case errors.Is(err, ErrNotContained):
		return ClassNotContained
	case errors.Is(err, ErrMalformedPath):
		return ClassMalformedPath
	case errors.Is(err, errUnsupported):
		return ClassUnsupported
	case errors.Is(err, fs.ErrNotExist):
		return ClassAbsent
	case isRefusedOrNotDirectory(err):
		return ClassRefusedPath
	case errors.Is(err, fs.ErrPermission):
		return ClassDenied
	default:
		return ClassOther
	}
}

// IsNotDirectory reports whether err is a path that had to be a directory and was not: a
// component of the path is a file, so nothing beneath it can exist. ClassifyError reports it as
// ClassRefusedPath together with a refused symlink, and a caller that has to tell "cannot exist"
// from "would not follow" asks this.
func IsNotDirectory(err error) bool {
	return errors.Is(err, errNotDirectory)
}

// IsExpectedAbsent reports whether err from a read represents a benign "the file isn't there
// or shouldn't be read" case that the caller should silently skip:
//   - ENOENT: the file genuinely does not exist
//   - ELOOP: a symlink was refused, at any component
//   - ENOTDIR: a component on the way down is a file rather than a directory
//
// Symlink refusals in particular ARE expected when another local user plants a trap: the
// right response is to skip quietly, not to emit a warning row carrying the path they chose.
//
// Handles both wrapped (%w via fmt.Errorf) and unwrapped error chains.
//
// Expressed over ClassifyError rather than beside it. The two answer overlapping questions
// -- "which refusal was this" and "may I ignore it" -- and when they were separate
// implementations a sentinel added to one was silently missing from the other. Writing this
// as a switch over the enum means a new class has to be placed on one side of the line or
// the other, and the compiler does not care but the reader does: the list below IS the
// contract, and everything absent from it is reported.
func IsExpectedAbsent(err error) bool {
	switch ClassifyError(err) {
	case ClassAbsent, ClassRefusedPath:
		return true
	default:
		return false
	}
}

// ReadOpts carries the refusals a bounded read applies to the descriptor it opened.
//
// A struct rather than more positional parameters: the two new checks are both optional and
// both security-relevant, and a bare `true, ""` at a call site says nothing about which is
// which. Named fields also mean a later check can be added without touching callers that do
// not want it.
type ReadOpts struct {
	// MaxSize caps the bytes read. A larger file is refused with ErrTooLarge.
	MaxSize int64

	// OwnerUID refuses a file whose owning uid differs; "" disables the check.
	//
	// A string because the roster carries the uid as osquery reported it, and because the
	// identity on Windows is a SID rather than a number. A parameter rather than something
	// derived here specifically so the refusal is testable without privilege: a test passes
	// a uid that does not match a file it just created, which no amount of fixture setup
	// could otherwise arrange.
	OwnerUID string

	// RefuseHardLinks refuses a file with more than one link.
	//
	// A flag, not unconditional. A hard link under a directory one user controls can name a
	// file anywhere that user could read, and the link count is the only evidence of it
	// available from a descriptor. But hard links are also ordinary: dotfile managers link
	// configs into place, and pnpm and Homebrew link package contents, so a caller reading
	// anything inside a package store would lose nearly every file to this. Reading a
	// handful of named configuration files is the case where a second link is unexpected
	// enough to be worth refusing on, which is why the caller chooses.
	RefuseHardLinks bool

	// CloudPlaceholder overrides the platform's cloud-placeholder detection, which every read
	// consults on the descriptor it opened, before reading any of it.
	//
	// It takes the open file rather than a path, and that is the whole reason it reads the
	// way it does. The only path available here is the home joined to a relative path, and
	// inspecting that path -- lstat on POSIX, GetFileAttributesEx on Windows -- resolves
	// every component on the way, so a directory the scanned user had replaced answered the
	// question about a file outside the home. The preflight was reaching where the read
	// itself could not.
	//
	// Injected because no test can produce the thing it detects. SF_DATALESS is set by the
	// kernel when a file is genuinely evicted, which needs a real iCloud account and real
	// storage pressure; the RECALL_ON_* attributes need OneDrive Files On-Demand on a
	// Windows host. Without a seam here the one check whose failure mode is "an inventory
	// query downloaded the user's documents" would have no test at all.
	//
	// nil uses the real implementation, so production call sites say nothing about it.
	CloudPlaceholder func(*os.File) (bool, error)
}

// ReadBoundedUnder opens relPath inside baseDir refusing all symlinks (via OpenBeneath),
// then applies every check ReadOpts asks for before reading a byte.
func ReadBoundedUnder(baseDir, relPath string, opts ReadOpts) ([]byte, error) {
	f, err := OpenBeneath(baseDir, relPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return readGuarded(f, opts)
}

// readGuarded applies every check that can be made against an already-open descriptor, then
// reads.
//
// Shared by ReadBoundedUnder and ReadProjectFile so the two cannot drift. A refusal that
// applied to one and not the other would make the weaker one the path worth aiming at.
//
// The cloud-placeholder check comes first, so a file whose content a provider holds is refused
// before anything asks for its bytes, wherever it is: a project file, a file at a fixed path in
// the home, or a followed link's target, which can sit in an evicted ~/Documents outside every
// cloud-folder prefix. A failure to read the attribute is not evidence of a placeholder, so it
// does not refuse; the read below produces the real diagnosis, and refusing would relabel some
// other failure as the one refusal that tells an operator their provider is involved.
func readGuarded(f *os.File, opts ReadOpts) ([]byte, error) {
	placeholder := opts.CloudPlaceholder
	if placeholder == nil {
		placeholder = IsCloudPlaceholder
	}
	if evicted, attrErr := placeholder(f); attrErr == nil && evicted {
		return nil, fmt.Errorf("%w: content is not local", ErrCloudPlaceholder)
	}
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w", ErrNotRegular)
	}
	// Against the descriptor, not against the path. Everything above this established which
	// file was opened; a second lookup by name could be answered with a different one, so
	// the link count and the owner are read from the handle already in hand. That is the
	// whole reason this check sits here rather than beside the Lstat that chose the path.
	if err := checkDescriptor(f, info, opts); err != nil {
		return nil, err
	}
	if info.Size() > opts.MaxSize {
		return nil, fmt.Errorf("%w: %d bytes exceeds the %d byte cap",
			ErrTooLarge, info.Size(), opts.MaxSize)
	}
	// LimitReader+1 lets us detect post-Stat growth (e.g., a log being appended to).
	buf, err := io.ReadAll(io.LimitReader(f, opts.MaxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > opts.MaxSize {
		return nil, fmt.Errorf("%w", ErrGrewDuringRead)
	}
	return buf, nil
}

// splitSafeComponents decomposes relPath into path components, rejecting
// absolute paths and any ".." traversal.
// isPathSeparator adapts os.IsPathSeparator, which takes a byte, for strings.FieldsFunc,
// which supplies a rune. Separators are ASCII on every platform Go supports, so a non-ASCII
// rune is never one and the range check costs nothing.
func isPathSeparator(r rune) bool {
	return r < 0x80 && os.IsPathSeparator(byte(r))
}

// The Windows file attributes providerReparsePoint reads, written out rather than taken from
// golang.org/x/sys/windows so the rule is tested on every host.
const (
	fileAttributeDirectory          = 0x10     // FILE_ATTRIBUTE_DIRECTORY
	fileAttributeOffline            = 0x1000   // FILE_ATTRIBUTE_OFFLINE
	fileAttributeRecallOnOpen       = 0x40000  // FILE_ATTRIBUTE_RECALL_ON_OPEN
	fileAttributeRecallOnDataAccess = 0x400000 // FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
)

// providerReparsePoint reports whether a path component Windows reports as a reparse point was
// placed by a storage provider rather than being a link, from the mode and attributes
// os.Root.Lstat returned for it, without opening it. Both are refused; a provider's is reported
// as stored with a cloud provider, and a link stays a silent refusal.
//
// Go gives every reparse point other than a symbolic link, a socket or a deduplicated file
// os.ModeIrregular, and sets os.ModeDir on one only when its tag is not a name surrogate. A
// junction is a name surrogate and always a directory, so a reparse point that has ModeDir, or
// that is not a directory, is a provider's: a Cloud Files placeholder or synced file, a ProjFS
// file, a file an HSM moved offline, or a file WOF compressed, which is reported the same way.
// A recall or offline attribute says the content is not local whatever the component's shape.
func providerReparsePoint(mode os.FileMode, attributes uint32) bool {
	if mode&os.ModeSymlink != 0 || mode&os.ModeIrregular == 0 {
		return false
	}
	if attributes&(fileAttributeRecallOnOpen|fileAttributeRecallOnDataAccess|fileAttributeOffline) != 0 {
		return true
	}
	return mode.IsDir() || attributes&fileAttributeDirectory == 0
}

// listedKind is the type a directory listing gives an entry, from the mode Go derives and the
// Windows attributes. A provider's reparse point that is not a directory, such as a Cloud Files
// or WOF-compressed file, is the file it holds, so the listing skips it as a file rather than
// counting it as a refused link; a junction, a symbolic link and a provider's directory keep
// their type.
func listedKind(mode os.FileMode, attributes uint32) os.FileMode {
	kind := mode.Type()
	if providerReparsePoint(mode, attributes) && attributes&fileAttributeDirectory == 0 {
		kind &^= os.ModeIrregular
	}
	return kind
}

func splitSafeComponents(relPath string) ([]string, error) {
	if filepath.IsAbs(relPath) {
		return nil, errors.New("openbeneath: absolute path not permitted")
	}
	// Inspected before Clean, not after. Clean collapses a/../secret.json to secret.json, so
	// checking afterwards accepted an interior ".." that the documented contract rejects.
	// Nothing escaped -- Clean normalises within the base -- but a caller relying on the
	// contract to reason about which path was opened was being told the wrong thing.
	//
	// Split on every separator the platform honours, not just os.PathSeparator. Windows
	// accepts both "/" and "\\", and Clean rewrites the first into the second: splitting on
	// the native separator alone left "a/../secret.json" as a single part that matched
	// nothing, and Clean then collapsed the "..", so the guard passed and the interior ".."
	// the contract rejects was accepted. os.IsPathSeparator is the platform's own answer to
	// what separates a component, and on Unix it still admits only "/".
	for _, part := range strings.FieldsFunc(relPath, isPathSeparator) {
		if part == ".." {
			return nil, errors.New("openbeneath: '..' not permitted")
		}
	}
	cleaned := filepath.Clean(relPath)
	parts := strings.FieldsFunc(cleaned, isPathSeparator)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" || p == "." {
			continue
		}
		if p == ".." {
			return nil, errors.New("openbeneath: '..' not permitted")
		}
		out = append(out, p)
	}
	return out, nil
}

// ReadLinkBeneath reads the target of the symlink name inside the directory relDir, which is
// relative to base. relDir is opened one component at a time with symlinks refused, exactly as
// OpenBeneath opens it, and the link is then read relative to that open directory, so no
// component on the way is followed and nothing outside base is consulted. The link itself is
// read rather than followed. name must be a single path component.
//
// A path-based os.Lstat or os.Readlink is not equivalent: either resolves every intermediate
// component on the way, so a symlinked parent redirects the lookup outside base and a parent
// pointing at an unavailable mount blocks the call.
func ReadLinkBeneath(base, relDir, name string) (string, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("%w: %q is not a single path component", ErrMalformedPath, name)
	}
	// The base itself, when the link sits directly in it, is opened the way ProbeProjectDir
	// opens a home recorded as a project, because OpenBeneath needs at least one component.
	var dir *os.File
	var err error
	if components, splitErr := splitSafeComponents(relDir); splitErr == nil && len(components) == 0 {
		dir, err = openBaseDir(base)
	} else {
		dir, err = OpenBeneath(base, relDir)
	}
	if err != nil {
		return "", err
	}
	defer func() { _ = dir.Close() }()
	return readLinkAt(dir, name)
}

// LinkTargetBeneath resolves the symlink name inside relDir by one hop and returns the
// base-relative path it names, or ErrNotContained when that path is not beneath base. The link
// is read by ReadLinkBeneath, not followed. A caller opens the result with OpenBeneath, which
// refuses a symlink at every component, so a link to another link fails that open and a chain is
// never walked. Where readLinkAt is unsupported, Windows included, this returns that error.
//
// The target is resolved as text against relDir, which names the same file the kernel would only
// because relDir and the result are both opened with no symlink on the way. A ".." after a named
// component breaks that: the kernel resolves "vendor/../go.sum" from wherever vendor points,
// and filepath.Clean deletes vendor. Such a target, and any ".." in an absolute one, is refused
// rather than read as a different file. Leading ".." components are resolved from relDir, and
// only as far as base: base's own path was never opened component by component, so above it the
// text and the kernel can disagree, and a target that climbs above base is refused even when it
// would come back down into it.
func LinkTargetBeneath(base, relDir, name string) (string, error) {
	target, err := ReadLinkBeneath(base, relDir, name)
	if err != nil {
		return "", err
	}
	rel, err := ResolveBeneath(base, relDir, target)
	if err == nil && rel == "." {
		return "", fmt.Errorf("%w: link target %q is the base", ErrNotContained, target)
	}
	return rel, err
}

// ResolveBeneath resolves target, a path written as absolute or relative to relDir, which is
// relative to base, and returns the base-relative path it names, or "." for base itself. It
// applies LinkTargetBeneath's rules as text, without touching the filesystem: a ".." after a
// named component, and any ".." in an absolute target, is ErrMalformedPath, and a target outside
// base, or one whose leading ".." components climb above it, is ErrNotContained. A caller opens
// the result with OpenBeneath, which refuses a symlink at every component.
func ResolveBeneath(base, relDir, target string) (string, error) {
	components, err := splitSafeComponents(relDir)
	if err != nil {
		return "", err
	}
	named, climbs := filepath.IsAbs(target), 0
	for _, part := range strings.FieldsFunc(target, isPathSeparator) {
		if part == ".." && named {
			return "", fmt.Errorf("%w: target %q steps back after a named directory",
				ErrMalformedPath, target)
		}
		if part == ".." {
			if climbs++; climbs > len(components) {
				return "", fmt.Errorf("%w: target %q climbs above the base", ErrNotContained, target)
			}
		}
		named = named || (part != "." && part != "..")
	}
	resolved := target
	if !filepath.IsAbs(target) {
		resolved = filepath.Join(base, relDir, target)
	}
	rel, err := filepath.Rel(base, filepath.Clean(resolved))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: target %q", ErrNotContained, target)
	}
	return rel, nil
}
