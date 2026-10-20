package fsscan

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Reading a file at a path a client's configuration recorded, rather than at a path this
// package chose.
//
// The two are not the same problem. Every other path here is one the code names itself: a
// home from the roster, plus a relative path written down in Go source, so containment holds
// by construction. A *recorded* path came out of a configuration file a user controls -- the
// `projects` map in ~/.claude.json, the `folder` field in a VS Code workspace, the
// `[projects."..."]` tables in Codex's config.toml -- and it can name anything at all:
// another account's home, a UNC share, a remote development host, a directory that was
// deleted last week.
//
// So containment has to be established here rather than inherited. Doing it per caller was
// the alternative and it is the wrong shape: the checks below are easy to get subtly wrong
// (percent-decoding, a non-empty URL host, a ".." that Clean would collapse before anyone
// looked), and every caller wanting a project-local file needs all of them. One
// implementation, one place to fix, one place to test.

// The refusals containment and the project read can report, as sentinels so the caller can
// classify without reading a message that would carry the path back into a column.
var (
	// ErrUnsupportedOrigin means the recorded location does not name a path on this
	// filesystem: a remote-development URL, a UNC share, an opaque URL.
	ErrUnsupportedOrigin = errors.New("fsscan: recorded location is not a local filesystem path")

	// ErrMalformedPath means the recorded string is not a usable absolute path: empty, not
	// absolute, or carrying a NUL or another control character.
	ErrMalformedPath = errors.New("fsscan: recorded location is not a usable absolute path")

	// ErrNotContained means the recorded path is a real absolute path that lies outside the
	// home it was recorded under. Distinct from ErrMalformedPath because the two want
	// different reporting: a malformed entry is a broken config, while a path outside the
	// home is a legitimate configuration this scan deliberately declines to follow.
	ErrNotContained = errors.New("fsscan: path is not contained within the home")

	// ErrCloudPlaceholder means the file exists but its content is not local, so reading it
	// would make the provider download it.
	ErrCloudPlaceholder = errors.New("fsscan: file content is not local; reading it would download it")

	// ErrUserspaceFilesystem means the file is on a filesystem implemented in userspace, so
	// a read is serviced by another process that may fetch the content over a network first.
	// Distinct from ErrCloudPlaceholder because the evidence is different in kind: a
	// placeholder attribute names *this file* as non-local, while a filesystem type says only
	// that reads here are not bounded by local I/O. Folding them together would have the row
	// claim a cloud provider is involved when the mount might be sshfs or gocryptfs.
	ErrUserspaceFilesystem = errors.New("fsscan: file is on a userspace filesystem; a read may fetch it on demand")

	// ErrNetworkFilesystem means a project directory is on a network filesystem, so its
	// content is stored on another machine, where it is inventoried.
	ErrNetworkFilesystem = errors.New("fsscan: project is on a network filesystem")
)

// ProbeProjectDir opens a recorded project's directory beneath home, with the symlink refusal
// every read applies, and reports ErrNetworkFilesystem when the directory is on a network
// filesystem, or ErrUserspaceFilesystem when it is on a userspace one. A caller probes once per
// project, before reading any file in it, so a project on a network mount costs one directory
// open and none of its files are opened. Any other error is the open's own, for ClassifyError.
//
// A recorded project can be the home itself, which ContainProjectPath reports as ".". That has
// no component for OpenBeneath to open, so the home is opened directly, with the same refusal
// of a symlinked or redirected base, and still reaches the network-filesystem check.
func ProbeProjectDir(home, projRel string) error {
	var dir *os.File
	var err error
	if components, splitErr := splitSafeComponents(projRel); splitErr == nil && len(components) == 0 {
		dir, err = openBaseDir(home)
	} else {
		dir, err = OpenBeneath(home, projRel)
	}
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	// OpenBeneath opens its last component as a file, so a recorded project that is a regular
	// file opens too. It is refused here, as a path through a non-directory is, before its two
	// module files are looked for inside it.
	if info, statErr := dir.Stat(); statErr == nil && !info.IsDir() {
		return fmt.Errorf("fsscan: recorded project %q is not a directory: %w", projRel, errNotDirectory)
	}
	if onNetworkFilesystem(dir) {
		return ErrNetworkFilesystem
	}
	// A userspace filesystem, such as sshfs or rclone on Linux, is decided here too, so a project
	// on one costs this open and none of its files are opened.
	return fileOnUserspaceFilesystem(dir)
}

// UnderCloudStorage reports whether a home-relative path is inside a cloud storage provider's
// folder by the platform's prefix rule, which ReadProjectFile also applies. It is a string
// comparison, so a caller can decide from the recorded path alone, before anything is opened.
func UnderCloudStorage(rel string) bool { return underCloudStorage(rel) }

// ContainProjectPath turns a path recorded in a configuration file into a path relative to
// home, or refuses it.
//
// allowFileURL admits the one shape that is not a bare path: VS Code's workspace storage
// records its folder as a file:// URL. Everything else -- vscode-remote://, ssh-remote://,
// wsl+distro, docker://, http(s):// -- names a location that is not on this filesystem, and
// is refused rather than coerced into one.
//
// The returned rel is the ONLY form a caller may use to open anything. It is deliberately
// relative, because the guarantee is not "this string starts with the home" but "every
// component between the home and the file was opened with symlinks refused" -- and that is a
// property of ReadBoundedUnder, which needs the relative form. A caller that joins rel back
// onto home and opens the result has thrown the guarantee away.
//
// rel == "." is allowed and is not a degenerate case: a user's home is itself frequently a
// recorded project, and ~/.mcp.json is a configuration file worth probing.
func ContainProjectPath(home, recorded string, allowFileURL bool) (string, error) {
	return containProjectPathFor(runtime.GOOS, home, recorded, allowFileURL)
}

// containProjectPathFor takes the OS as a parameter for the same reason appSupportDirFor does
// in pkg/devclients: the Windows answers -- a drive letter after the URL's leading
// slash, a backslash separator -- are the ones no test on another host could otherwise reach,
// and taking the OS as a parameter asserts them on every host, not only on the windows-latest
// job.
func containProjectPathFor(goos, home, recorded string, allowFileURL bool) (string, error) {
	path := recorded
	// A URL only when it actually looks like one. Parsing unconditionally is wrong on
	// Windows: url.Parse reads `C:\Users\alice` as the scheme "c" with an opaque body, so
	// every Windows project path would have been refused as a remote origin. The "://"
	// test costs nothing and has no such collision.
	if strings.Contains(recorded, "://") {
		if !allowFileURL {
			return "", fmt.Errorf("%w: %s", ErrUnsupportedOrigin, "a URL was not expected here")
		}
		decoded, err := localPathFromFileURL(goos, recorded)
		if err != nil {
			return "", err
		}
		path = decoded
	}
	if path == "" {
		return "", fmt.Errorf("%w: empty", ErrMalformedPath)
	}
	// NUL and every other ASCII control character. NUL truncates a path where it is handed
	// to the kernel, so `/home/alice/safe\x00/../../etc` is one string to Go and another to the
	// kernel -- the check below would inspect a path nobody opens. The remaining control
	// characters are refused for a different reason: they cannot appear in a path a client
	// legitimately recorded, and they are exactly what a value crafted to disrupt a log line
	// or a column contains.
	for i := 0; i < len(path); i++ {
		if path[i] < 0x20 || path[i] == 0x7f {
			return "", fmt.Errorf("%w: control character at byte %d", ErrMalformedPath, i)
		}
	}
	if !isAbsFor(goos, path) {
		// A relative recorded path has no anchor. It is not relative to the home -- it is
		// relative to whatever directory the client happened to be in -- so there is no
		// sound way to resolve it and guessing the home would invent a location.
		return "", fmt.Errorf("%w: not absolute", ErrMalformedPath)
	}
	// A UNC path names another host, as a file URL with a host does, so it is a remote origin.
	// Refused before containment, which compares components and would read the leading
	// separators of `\\C:\Users\alice\repo` as nothing and contain it as the local drive's.
	if goos == "windows" && (strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, "//")) {
		return "", fmt.Errorf("%w: a UNC path names another host", ErrUnsupportedOrigin)
	}
	// Inspected before Clean, exactly as splitSafeComponents does and for the same reason:
	// Clean collapses `/home/alice/../bob` to `/home/bob`, which is inside no home anyone
	// recorded but is a perfectly ordinary-looking absolute path afterwards. Checking after
	// Clean would accept it and then report it as contained.
	for _, part := range strings.FieldsFunc(path, func(r rune) bool {
		return r == '/' || (goos == "windows" && r == '\\')
	}) {
		if part == ".." {
			return "", fmt.Errorf("%w: '..' component", ErrMalformedPath)
		}
	}
	// Trailing separators are tolerated rather than refused: recorded paths carry them
	// routinely -- a client that joined a directory name onto a root leaves one behind -- and
	// a trailing slash changes nothing about which directory is named. Clean removes it.
	cleaned := cleanFor(goos, path)
	rel, err := relFor(goos, home, cleaned)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrNotContained, err)
	}
	return rel, nil
}

// localPathFromFileURL decodes a file:// URL into a local path, refusing every other origin.
//
// sanitizeRemoteURL in the mcp_servers table looks like it should be reusable here and is
// not: it returns scheme and host only, discarding the path, and it returns "" when the host
// is empty -- which is precisely the shape of a valid `file:///Users/alice/project`. The two
// functions want opposite things from a URL, one keeping only the part that is safe to
// publish and this one keeping only the part that names a file.
func localPathFromFileURL(goos, raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: unparseable URL", ErrUnsupportedOrigin)
	}
	// Exactly "file". Not a prefix test and not a case-folded family: vscode-remote,
	// ssh-remote, wsl+ubuntu, docker and http(s) all name a filesystem that is not this
	// one, and a client that records one has told us the project is not here.
	if parsed.Scheme != "file" {
		return "", fmt.Errorf("%w: scheme is not file", ErrUnsupportedOrigin)
	}
	if parsed.Opaque != "" {
		// `file:something` rather than `file:///something`. There is no agreed meaning for
		// the opaque form of a file URL, so there is nothing to resolve.
		return "", fmt.Errorf("%w: opaque file URL", ErrUnsupportedOrigin)
	}
	// Any host other than localhost is a UNC path. `file://server/share/project` names
	// \\server\share\project, and opening it makes this host authenticate to a server named
	// in a file the scanned user controls -- so a recorded project path would become an
	// outbound credential. That is a worse outcome than a missing row by a wide margin.
	if parsed.Host != "" && !strings.EqualFold(parsed.Host, "localhost") {
		return "", fmt.Errorf("%w: file URL names a remote host", ErrUnsupportedOrigin)
	}
	// Userinfo, a query and a fragment name no path bytes, and VS Code never writes them in a
	// workspace folder. They are refused rather than discarded, so two spellings of one path
	// cannot get different answers, and so the length bound a caller applies before parsing
	// covers every URL this accepts. A raw "#" always starts a fragment, because a "#" in a path
	// is written %23, and testing for it catches an empty fragment, which url.Parse does not
	// record.
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || strings.Contains(raw, "#") {
		return "", fmt.Errorf("%w: file URL carries userinfo, a query or a fragment", ErrMalformedPath)
	}
	// url.Parse has already percent-decoded the path into URL.Path, and that is the decoded
	// form this returns. The ordering point still holds and is still the reason the refusals
	// above come first: %2e%2e%2f decodes to "../", so the decode has to happen before the
	// ".." inspection rather than after it, and the caller runs that inspection on what this
	// returns. Parse is simply what performs the decode.
	//
	// Decoding URL.Path a second time was the defect. It cost two things, both of them wrong
	// answers on ordinary input: a directory literally named `100%` arrives here as `100%`
	// and a second decode rejects it as a malformed escape, so a real project was refused;
	// and a directory literally named `repo%2Fchild` arrives as `repo%2Fchild` and a second
	// decode turns it into `repo/child`, which names a different directory and manufactures a
	// component boundary that was never in the recorded path -- so the checks the caller runs
	// afterwards were being applied to a string the filesystem does not have.
	//
	// There is no ErrMalformedPath return for a bad encoding because there is nothing left to
	// fail: url.Parse rejects a genuinely malformed escape itself, and that is the
	// ErrUnsupportedOrigin "unparseable URL" above.
	//
	// driveLetterPath only runs when a file:// scheme was actually present. A bare recorded
	// path never reaches here and is taken literally, because a directory genuinely named
	// `100%` is ordinary and decoding it would name a different directory -- or fail.
	return driveLetterPath(goos, parsed.Path), nil
}

// driveLetterPath turns a file URL's `/C:/Users/alice` into `C:/Users/alice` on Windows.
//
// The leading slash is part of the URL grammar, not part of the path: `file:///C:/x` has an
// empty authority and a path of `/C:/x`. Left in place it is not an absolute Windows path at
// all, so every Windows project recorded by VS Code would have been refused as non-absolute.
func driveLetterPath(goos, path string) string {
	if goos != "windows" {
		return path
	}
	if len(path) >= 3 && path[0] == '/' && isDriveLetterByte(path[1]) && path[2] == ':' {
		return path[1:]
	}
	return path
}

func isDriveLetterByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// The path primitives, taken per OS rather than from the host.
//
// filepath's own functions read runtime.GOOS, so on a macOS test host filepath.IsAbs reports
// false for `C:\Users\alice` and filepath.Rel treats a backslash as an ordinary character.
// Every Windows containment case would therefore have been reachable only on a Windows host.
// These four shim it, so the cases run on every host.
func isAbsFor(goos, path string) bool {
	if goos != "windows" {
		return strings.HasPrefix(path, "/")
	}
	if len(path) >= 3 && isDriveLetterByte(path[0]) && path[1] == ':' &&
		(path[2] == '\\' || path[2] == '/') {
		return true
	}
	// A UNC path is absolute, so it is reported as a remote origin rather than as malformed.
	return strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, "//")
}

func separatorFor(goos string) string {
	if goos == "windows" {
		return `\`
	}
	return "/"
}

// cleanFor is filepath.Clean for goos's separator, computed as text so every host gets the
// same answer: filepath.Clean on a macOS host leaves a backslash alone, and on a Windows host
// turns a slash into one.
func cleanFor(goos, value string) string {
	if goos != "windows" {
		return path.Clean(value)
	}
	cleaned := path.Clean(strings.ReplaceAll(value, `\`, "/"))
	return strings.ReplaceAll(cleaned, "/", `\`)
}

// relFor is filepath.Rel for a target already found absolute and free of "..": the components
// of target below base, compared one by one under goos's case rule. Windows and macOS fold
// case, because their default filesystems are case-insensitive, so a home of `/Users/Alice` and
// a recorded project of `/users/alice/code` name the same place, and a case-sensitive
// comparison reported the project as outside the home and never read it. The relative path is
// only ever opened beneath the home, so on a case-sensitive APFS volume a path that differs
// only in case is read through the home's spelling, inside the same home.
func relFor(goos, base, target string) (string, error) {
	separator := separatorFor(goos)
	baseParts := strings.Split(strings.TrimSuffix(cleanFor(goos, base), separator), separator)
	targetParts := strings.Split(strings.TrimSuffix(cleanFor(goos, target), separator), separator)
	if len(targetParts) < len(baseParts) {
		return "", errors.New("target is shorter than the home")
	}
	fold := goos == "windows" || goos == "darwin"
	for i, part := range baseParts {
		if part != targetParts[i] && (!fold || !strings.EqualFold(part, targetParts[i])) {
			return "", errors.New("target is not under the home")
		}
	}
	if len(targetParts) == len(baseParts) {
		return ".", nil
	}
	return strings.Join(targetParts[len(baseParts):], separator), nil
}

// SameDirectoryKey is the key under which two paths ContainProjectPath returned name the same
// directory. relFor admits a project recorded in another case on Windows and macOS, so a
// directory one client records as `Code/Repo` and another as `code/repo` is admitted twice --
// Codex lowercases every project key on Windows -- and a caller that merged on the path itself
// read it twice and published its rows twice.
func SameDirectoryKey(rel string) string {
	return sameDirectoryKeyFor(runtime.GOOS, rel)
}

// sameDirectoryKeyFor folds each rune to the smallest rune in its unicode.SimpleFold orbit,
// which is the equivalence strings.EqualFold tests, so two keys are equal exactly when relFor
// would match the paths component by component.
func sameDirectoryKeyFor(goos, rel string) string {
	if goos != "windows" && goos != "darwin" {
		return rel
	}
	return strings.Map(func(original rune) rune {
		smallest := original
		// SimpleFold steps through the runes that fold together and returns to original.
		for folded := unicode.SimpleFold(original); folded != original; folded = unicode.SimpleFold(folded) {
			smallest = min(smallest, folded)
		}
		return smallest
	}, rel)
}

// cloudStoragePrefixes are the home-relative directories under which macOS mounts a
// file-provider volume, where a file's content may not be local. See cloudPrefixesFor for
// the Windows set and for why both platforms need a string rule at all.
//
// A prefix rule as well as the attribute check below, because the two fail differently. The
// attribute check is exact but needs the file open to answer and says nothing about a file
// that is not there; the prefix rule is a string comparison, so it costs nothing, happens
// before anything is opened, and covers a provider whose placeholder flag this build does not
// recognise. Mobile Documents is iCloud Drive, which is
// what ~/Documents and ~/Desktop become under "Optimise Mac Storage"; CloudStorage is where
// the modern OneDrive, Dropbox and Google Drive clients mount.
var cloudStoragePrefixes = []string{
	"Library/Mobile Documents",
	"Library/CloudStorage",
}

// underCloudStorage reports whether a home-relative path lies in a file-provider volume.
func underCloudStorage(rel string) bool {
	return underCloudStorageFor(runtime.GOOS, rel)
}

// underCloudStorageFor takes the OS as a parameter for the same reason containProjectPathFor
// does, and here the parameter is load-bearing rather than only a test seam: each platform's
// prefixes are its own conventions. Applied elsewhere, a Linux project under
// ~/Library/CloudStorage, which is not a file-provider mount there, would have every file
// beneath it refused as a cloud placeholder. Linux is covered by no prefix, because it has no
// file-provider mechanism and no placeholder attribute to read, which cloudfile_other.go
// spells out.
//
// Case-insensitively, because the volume these name is on a case-insensitive filesystem by
// default and a comparison that missed `library/cloudstorage` would hand the caller exactly
// the download it is avoiding.
func underCloudStorageFor(goos, rel string) bool {
	prefixes, matchFirstComponent := cloudPrefixesFor(goos)
	if len(prefixes) == 0 {
		return false
	}
	// Normalised against the supplied OS rather than with filepath.ToSlash, which consults
	// runtime.GOOS and is a no-op off Windows. Using it meant every backslash-separated
	// Windows path stayed one unsplit string, so the prefix match could not fire -- the
	// whole point of taking goos as a parameter is that the Windows branch has to be
	// reachable from a host that is not Windows, where most of the tests run.
	slashed := strings.ToLower(rel)
	if goos == "windows" {
		slashed = strings.ReplaceAll(slashed, `\`, "/")
	}
	for _, prefix := range prefixes {
		lowered := strings.ToLower(prefix)
		if slashed == lowered || strings.HasPrefix(slashed, lowered+"/") {
			return true
		}
		// Windows business tenants name the directory "OneDrive - Contoso", so the first
		// component is matched as a prefix of itself rather than only in full. Scoped to the
		// first component so a project directory called "onedrive-notes" three levels down
		// is not swallowed.
		if matchFirstComponent {
			first := slashed
			if cut := strings.IndexByte(slashed, '/'); cut >= 0 {
				first = slashed[:cut]
			}
			if strings.HasPrefix(first, lowered+" - ") {
				return true
			}
		}
	}
	return false
}

// cloudPrefixesFor returns the home-relative directories this platform syncs, and whether a
// first component may extend the name.
//
// Windows is covered as well as macOS, and the reason is specific rather than symmetry.
// FILE_ATTRIBUTE_RECALL_ON_OPEN is by definition the attribute whose provider begins fetching
// at CreateFile, so a handle-based check learns it only after causing the download it exists
// to prevent -- and os.Root offers no FILE_FLAG_OPEN_NO_RECALL. A string rule runs before
// anything is opened, so for the locations a provider conventionally owns it closes that
// window without the handle-relative metadata lookup, which would be new Windows code that
// only the windows-latest job would exercise.
//
// What it costs, stated because it is a real loss: a project inside one of these directories
// is refused even when its files are fully hydrated -- "Always keep on this device" is common
// -- so a live configuration there is not listed. It is reported rather than dropped
// silently, which is the same trade the macOS entries have always made.
//
// Linux has neither a file-provider mechanism nor a placeholder attribute, so it has no
// prefixes and nothing to read; cloudfile_other.go spells that out.
func cloudPrefixesFor(goos string) (prefixes []string, matchFirstComponent bool) {
	switch goos {
	case "darwin":
		return cloudStoragePrefixes, false
	case "windows":
		return windowsCloudPrefixes, true
	default:
		return nil, false
	}
}

// windowsCloudPrefixes are the profile-relative directories Windows sync providers own.
//
// Each sits directly in the profile by default. OneDrive's Known Folder Move relocates
// Documents and Desktop beneath it, which is exactly where a user keeps projects, so this is
// the common case rather than an exotic one.
var windowsCloudPrefixes = []string{
	"OneDrive",
	"Dropbox",
	"Google Drive",
	"iCloudDrive",
}

// ReadProjectFile reads relFile inside a contained project directory.
//
// projRel must have come from ContainProjectPath. The absolute path is never opened: the read
// goes through OpenBeneath, which re-applies the checks from the home downwards and opens
// each component with symlinks refused. That is what makes the containment a guarantee about
// the bytes returned rather than a statement about a string -- a project directory that was
// inside the home when it was checked and is a symlink by the time it is opened fails the
// open.
//
// A caller supplies relFile and ReadOpts and nothing else: it does not have to know about
// percent-decoding, UNC hosts or cloud placeholders.
func ReadProjectFile(home, projRel, relFile string, opts ReadOpts) ([]byte, error) {
	rel := filepath.Join(projRel, relFile)
	// First, and without touching the filesystem. The whole point is that reading is the
	// expensive and side-effecting operation: asking a file provider for content it does not
	// hold starts a download of unbounded duration, charged to a scheduled query, and leaves
	// the machine different from how it was found. This rule is a string comparison, so it
	// can refuse before anything is opened.
	if underCloudStorage(rel) {
		return nil, fmt.Errorf("%w: under a cloud storage provider's volume", ErrCloudPlaceholder)
	}
	// One open, inspected before it is read, by readGuarded's placeholder check. A placeholder check made by path, against
	// filepath.Join(home, rel), would resolve every component on the way, as lstat and
	// GetFileAttributesEx do, so a directory the scanned user replaced could redirect the
	// metadata lookup out of the home -- on Windows as far as a reparse point onto a UNC
	// share, making this host authenticate to a server named in a file that user controls.
	// Inspecting the descriptor removes that second lookup, and reading through the same
	// descriptor means the file inspected is the file read.
	//
	// KNOWN GAP in this ordering: the file is open by the time the attribute check can
	// refuse it. That matters for exactly one attribute. FILE_ATTRIBUTE_RECALL_ON_OPEN is by
	// definition set on files whose provider begins fetching at CreateFile, and os.Root
	// offers no way to pass FILE_FLAG_OPEN_NO_RECALL, so a handle-based check learns it only
	// after causing the download it exists to prevent. RECALL_ON_DATA_ACCESS and OFFLINE are
	// still refused before a byte is read, and SF_DATALESS on macOS likewise.
	//
	// The prefix rule above is what narrows it: it is a string comparison that runs before
	// anything is opened, and it covers the Windows sync-provider directories as well as the
	// macOS ones, so the locations a provider conventionally owns -- including the
	// Documents and Desktop that OneDrive's Known Folder Move relocates -- are refused with
	// no syscall at all. What remains is a RECALL_ON_OPEN placeholder somewhere a provider
	// does not conventionally own.
	//
	// Closing that completely wants a metadata lookup anchored to the parent directory's
	// handle -- fstatat(AT_SYMLINK_NOFOLLOW) on POSIX, NtCreateFile against a RootDirectory
	// handle on Windows -- which would be new code, and on Windows exercised only by the
	// windows-latest job.
	file, err := OpenBeneath(home, rel)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	// Before readGuarded's per-file attribute check, because on the one platform where this
	// fires the attribute check cannot answer at all, and because it is the cheaper call. Only
	// here: a file at a fixed path in a home on a userspace filesystem is where that account's
	// configuration lives, so ReadBoundedUnder reads it.
	if reason := fileOnUserspaceFilesystem(file); reason != nil {
		return nil, reason
	}
	return readGuarded(file, opts)
}

// ListDirNamesUnder returns the names of the entries directly inside rel, which is relative
// to base. One level, no recursion, at most maxEntries names, sorted.
//
// This exists for the one thing a fixed path cannot express: a directory whose child names
// are generated. VS Code's per-profile configuration lives at
// User/profiles/<generated-id>/mcp.json and Codex's named profiles at
// ~/.codex/<profile>.config.toml, so without a one-level listing every per-profile
// configuration on the host is invisible -- and invisible silently, which is the failure mode
// this package is written against.
//
// It is not a traversal and must not become one. One ReadDir, no descent, a cap on the
// names returned, and the directory itself opened with symlinks refused at every component
// from base down. That bounds the work at a single directory read regardless of how much is
// inside it, which is the property that makes it safe to do at query time.
//
// Sorted because the names reach a table row. Readdir order is filesystem order, so an
// unsorted result makes a scheduled query with differential logging report the same unchanged
// configuration as removed and re-added whenever the directory is rewritten.
func ListDirNamesUnder(base, rel string, maxEntries int) ([]string, error) {
	dir, err := OpenBeneath(base, rel)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	info, err := dir.Stat()
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: not a directory", ErrNotRegular)
	}
	// maxEntries+1 so the caller can tell a directory that filled the cap from one that
	// happened to hold exactly that many. A truncated listing is an incomplete answer and
	// the caller has to be able to say so.
	entries, err := dir.ReadDir(maxEntries + 1)
	// io.EOF is end-of-directory, not a read failure. (*os.File).ReadDir is documented to
	// return io.EOF when n is positive and there is nothing left, so an empty directory and a
	// fully-consumed one produce the same signal -- and since the cap makes n positive here
	// always, an empty directory always arrives as an error. Not defensive: a directory this
	// opened, stat'd and read successfully was being reported as one it could not look inside,
	// and the caller has no way to tell "nothing there" from "could not look" apart from this.
	//
	// What it cost: an empty VS Code User/profiles directory raised a
	// profile_directory_unreadable warning with reason=other, which is home-scope, which
	// flipped an otherwise healthy global server row to scan_complete=0 -- so the completeness
	// filter discarded valid results on a perfectly benign layout. Every genuine read error is
	// still returned.
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	if len(names) > maxEntries {
		return names[:maxEntries], fmt.Errorf("%w: more than %d entries", ErrTooLarge, maxEntries)
	}
	return names, nil
}

// ListDirNamesCapped applies ListDirNamesUnder's two-part contract in one place.
//
// ListDirNamesUnder returns the names it could fit *and* ErrTooLarge, so a caller can use the
// partial listing and report the shortfall. A caller that tests only `err != nil` skips the
// level, so a directory holding more entries than the cap yields nothing instead of the capped
// list -- a bounded answer turned into a silently empty one.
//
// truncated separates "the listing was short" from "the listing failed". Absence is neither,
// and is reported as a nil error with no names, because most directories a client might
// create do not exist on most hosts. A regular file partway down the path is absence too,
// because nothing beneath it can exist. A symlink anywhere on the path is a refusal and is
// returned as an error: the directory exists, and the names in it are lost.
func ListDirNamesCapped(base, rel string, limit int) (names []string, truncated bool, err error) {
	names, err = ListDirNamesUnder(base, rel, limit)
	switch {
	case err == nil:
		return names, false, nil
	case errors.Is(err, ErrTooLarge):
		return names, true, nil
	case ClassifyError(err) == ClassAbsent, IsNotDirectory(err):
		return nil, false, nil
	default:
		return nil, false, err
	}
}

// ListRecentDirNames lists the directories directly inside rel, which is relative to base, and
// keeps the keep most recently modified, newest first, with the name breaking a tie so the
// order is the same on every run. older counts the directories read and not kept. At most
// readLimit entries are read; truncated reports that the directory held more, and the entries
// past readLimit are neither kept nor counted.
//
// Each entry's type and modification time are read relative to the open directory, without
// following a symlink, so a substituted entry cannot redirect the lookup out of base. Only a
// directory in its own right is ranked, so newer entries of another kind cannot push one past
// keep. links counts the symlinks and, on Windows, junctions, which the caller cannot read
// through and may report; a regular file, any other kind of entry and one removed since the
// listing are skipped. Absence and a regular file partway down the path are silent, and a
// refusal is an error, as in ListDirNamesCapped.
func ListRecentDirNames(base, rel string, keep, readLimit int) (names []string, older, links int,
	truncated bool, err error) {
	listed, links, truncated, err := listDirectories(base, rel, readLimit)
	if err != nil || listed == nil {
		return nil, 0, links, truncated, err
	}
	// Newest first, then by name.
	sort.Slice(listed, func(i, j int) bool {
		if !listed[i].modified.Equal(listed[j].modified) {
			return listed[i].modified.After(listed[j].modified)
		}
		return listed[i].name < listed[j].name
	})
	if len(listed) > keep {
		older = len(listed) - keep
		listed = listed[:keep]
	}
	names = make([]string, 0, len(listed))
	for _, entry := range listed {
		names = append(names, entry.name)
	}
	return names, older, links, truncated, nil
}

// ListSubdirNames lists the directories directly inside rel, which is relative to base, sorted,
// for a level whose child names are generated and only a directory can be one. At most
// readLimit entries are read, and truncated reports that the directory held more; the caller
// applies its own cap to the names, so files beside the directories cannot use it up, and it
// can tell which of the two bounds it reached. links counts the symlinks and junctions, which
// are left out because a read through one is refused, and which the caller reports as it
// reports a refused listing: the directory a link stands for exists. Any other entry that is
// not a directory is skipped, and so are absence and a regular file partway down the path; a
// refusal is an error.
func ListSubdirNames(base, rel string, readLimit int) (names []string, links int, truncated bool,
	err error) {
	listed, links, truncated, err := listDirectories(base, rel, readLimit)
	if err != nil || listed == nil {
		return nil, links, truncated, err
	}
	names = make([]string, 0, len(listed))
	for _, entry := range listed {
		names = append(names, entry.name)
	}
	sort.Strings(names)
	return names, links, truncated, nil
}

// datedName is a directory listDirectories found, with its modification time.
type datedName struct {
	name     string
	modified time.Time
}

// listDirectories reads at most readLimit entries directly inside rel and returns the ones that
// are directories in their own right, each entry's type and time read relative to the open
// directory without following a symlink. links counts the symlinks and junctions, and truncated
// reports more entries than readLimit. An absent directory, or one with a regular file partway
// down its path, returns nothing and no error.
func listDirectories(base, rel string, readLimit int) (dirs []datedName, links int, truncated bool,
	err error) {
	dir, err := OpenBeneath(base, rel)
	if err != nil {
		if ClassifyError(err) == ClassAbsent || IsNotDirectory(err) {
			return nil, 0, false, nil
		}
		return nil, 0, false, err
	}
	defer func() { _ = dir.Close() }()
	info, err := dir.Stat()
	if err != nil {
		return nil, 0, false, err
	}
	if !info.IsDir() {
		return nil, 0, false, fmt.Errorf("%w: not a directory", ErrNotRegular)
	}
	entries, err := dir.ReadDir(readLimit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, 0, false, err
	}
	if len(entries) > readLimit {
		entries, truncated = entries[:readLimit], true
	}
	dirs = make([]datedName, 0, len(entries))
	for _, entry := range entries {
		modified, kind, present := entryStat(dir, entry)
		switch {
		case !present:
		case redirectsElsewhere(kind):
			links++
		case kind.IsDir():
			dirs = append(dirs, datedName{entry.Name(), modified})
		}
	}
	return dirs, links, truncated, nil
}
