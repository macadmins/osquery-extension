package go_modules

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

	"github.com/macadmins/osquery-extension/pkg/redact"
)

// The values of mod_relationship, which says how go.mod requires a module version. It is empty
// when go.mod does not require that version.
const (
	// relationshipDirect and relationshipIndirect: a go.mod `require`, without and with the
	// `// indirect` marker.
	relationshipDirect   = "direct"
	relationshipIndirect = "indirect"
)

// moduleEntry is one module at one version that a project's go.mod requires, its go.sum
// records a hash for, or both. Version is the version the files state: a minimum for a
// requirement, and for a go.sum record a version the go command hashed, which need not be the
// one built.
type moduleEntry struct {
	Path    string
	Version string

	// ModRelationship is direct or indirect when go.mod requires this version, and empty when
	// it does not.
	ModRelationship string

	// What go.sum records for this version: for each kind of line, whether one exists and its hash.
	// The content line hashes the module's .zip, which the go command writes when it downloads
	// the module; the go.mod line hashes only the version's go.mod file, which the go command
	// also reads for versions it never builds, during minimal version selection. A Recorded
	// field is true when go.sum has at least one line of its kind. Its hash is that line's hash,
	// or empty when the lines disagree, because the go command trusts neither. So false is an
	// absent record, and true with an empty hash is a conflicting one.
	ModuleHashRecorded bool
	ModuleHash         string
	GoModHashRecorded  bool
	GoModHash          string

	// ReplaceModule and ReplaceVersion name the module a go.mod `replace` substitutes for this
	// requirement, when the replacement is a module. ReplaceLocal is true when it is a
	// directory instead. The directory itself is never published: it is a path the user
	// chose, and the fact an operator needs is that the requirement does not come from a
	// module proxy at all.
	ReplaceModule  string
	ReplaceVersion string
	ReplaceLocal   bool
}

// parseResult is what one file yielded.
type parseResult struct {
	Entries []moduleEntry

	// ProjectModule is the module path on a go.mod's `module` line: what the project calls
	// itself. A path outside the Go module grammar is counted in Dropped and left empty.
	ProjectModule string

	// Dropped counts entries whose module path or version is not in the Go module grammar.
	// They are not published, because a value outside the grammar is not something the go
	// command would accept as a dependency, and the column contract is that every value
	// matches a known format.
	Dropped int

	// MalformedLines counts go.sum lines that are not three fields.
	MalformedLines int

	// PartialLine is set when go.mod failed the strict parse and the lenient one recovered
	// its requirements. The strict parse fails for a directive it does not know and for a
	// malformed directive it does, such as a replace whose module target has no version.
	// Replacements are not read in that case, because the lenient parser ignores every
	// directive except module, go, require, retract and ignore. It is the line the strict
	// parser reported, or 1 when it reported none.
	PartialLine int

	// ConflictingReplaces counts the replace keys that two directives send to different
	// targets. The go command refuses a file with any.
	ConflictingReplaces int

	// ChecksumConflicts counts go.sum records -- one module version and one hash kind -- that
	// appear with different hashes. The go command treats a record with two sums as having
	// none it can trust.
	ChecksumConflicts int

	// Truncated is true when the file holds more entries than maxEntriesPerFile.
	Truncated bool
}

// errGoModUnparsable reports a go.mod that neither parser accepts. It carries no text from
// the file: the parser's own message quotes the offending line, and that line is user input.
var errGoModUnparsable = errors.New("go.mod could not be parsed")

// maxEntriesPerFile bounds the entries one file contributes, so a file's row count and memory
// do not grow with whatever a user writes into it. The largest go.sum measured on the
// development machine, Fleet's, holds about 600 distinct module versions in 1,218 lines; the
// cap is eight times that.
const maxEntriesPerFile = 5000

// validModule reports whether path and version are in the Go module grammar.
//
// The grammars are the Go team's, from golang.org/x/mod, rather than patterns written here:
// module.CheckImportPath for the path and semver.IsValid for the version. CheckImportPath is
// chosen over the stricter module.CheckPath because a go.mod may require a module with no
// dot in its first element, such as `example/internal`, when a replace directive points it
// at a local directory; CheckPath would drop that requirement, and the go command accepts it.
// Both grammars admit only letters, digits and a few punctuation characters, so neither a
// space nor an `=` can reach a module column.
func validModule(path, version string) bool {
	return module.CheckImportPath(path) == nil && semver.IsValid(version) && credentialFree(path, version)
}

// credentialFree reports whether no value contains a known credential format. The module
// grammar admits a path element such as ghp_ followed by thirty-six characters, and the parser
// never resolves a path, so the grammar alone does not keep a token out. The check uses only
// the formats ordinary names do not share (redact.ContainsDistinctiveToken), so a repository
// named sk-payments-service-client is listed. A value that matches is dropped and counted, never
// published rewritten, so nothing published differs from what the file states.
func credentialFree(values ...string) bool {
	for _, value := range values {
		if redact.ContainsDistinctiveToken(value) {
			return false
		}
	}
	return true
}

// validDownloadedModule applies the stricter rule for a module the go command fetches from a
// module proxy: a go.sum record and a replacement that names a module and version.
// module.Check requires a dot in the first path element, as a downloaded module needs, and
// that the version agrees with any major-version suffix on the path, so example.com/lib/v2
// with v1.0.0 is refused. A requirement does not need this check: a requirement may name a
// module a replace points at a local directory, and modfile already enforces the major-version
// pairing for requirements when it parses them.
func validDownloadedModule(path, version string) bool {
	return module.Check(path, version) == nil && credentialFree(path, version)
}

// parseGoMod reads the requirements and replacements from a go.mod.
//
// modfile.Parse is the strict parser the go command applies to a main module, and the only
// one that reads `replace`. When the strict parse fails -- for a directive a newer Go added, or
// for a malformed directive this version knows -- modfile.ParseLax recovers the requirements,
// and PartialLine records that replacements were not read.
func parseGoMod(data []byte) (parseResult, error) {
	var result parseResult
	file, strictErr := modfile.Parse("go.mod", data, nil)
	if strictErr != nil {
		lax, laxErr := modfile.ParseLax("go.mod", data, nil)
		if laxErr != nil {
			return parseResult{}, errGoModUnparsable
		}
		file = lax
		result.PartialLine = errorLine(strictErr)
	}

	if file.Module != nil {
		if module.CheckImportPath(file.Module.Mod.Path) == nil && credentialFree(file.Module.Mod.Path) {
			result.ProjectModule = file.Module.Mod.Path
		} else {
			result.Dropped++
		}
	}
	replaces := indexReplaces(file.Replace)
	result.ConflictingReplaces = len(replaces.conflicted)
	// required holds each module version already listed, so a version required twice is one
	// entry, keeping the first.
	required := make(map[module.Version]struct{}, len(file.Require))
	for _, require := range file.Require {
		if len(result.Entries) >= maxEntriesPerFile {
			result.Truncated = true
			break
		}
		if !validModule(require.Mod.Path, require.Mod.Version) {
			result.Dropped++
			continue
		}
		if _, repeated := required[require.Mod]; repeated {
			continue
		}
		required[require.Mod] = struct{}{}
		entry := moduleEntry{
			Path:            require.Mod.Path,
			Version:         require.Mod.Version,
			ModRelationship: relationshipDirect,
		}
		if require.Indirect {
			entry.ModRelationship = relationshipIndirect
		}
		applyReplace(&entry, replaces, &result)
		result.Entries = append(result.Entries, entry)
	}
	return result, nil
}

// replaceIndex holds a go.mod's replace directives keyed the way the go command keys them: by
// the module and version on the left, where an empty version is a separate key that applies to
// every version. Matching a requirement is then two map lookups, so the work is linear in the
// size of the file.
//
// conflicted holds each key that two directives send to different targets. The go command
// refuses such a file outright ("conflicting replacements", in toReplaceMap in
// cmd/go/internal/modload), so no target for that key is more correct than another, and a
// requirement it governs is published without a replacement. Directives that repeat the same
// target are not a conflict, and a version-specific key and the wildcard key for one module are
// different keys, so that combination is not a conflict either.
type replaceIndex struct {
	targets    map[module.Version]module.Version
	conflicted map[module.Version]struct{}
}

func indexReplaces(replaces []*modfile.Replace) replaceIndex {
	index := replaceIndex{
		targets:    make(map[module.Version]module.Version, len(replaces)),
		conflicted: make(map[module.Version]struct{}),
	}
	for _, replace := range replaces {
		if previous, seen := index.targets[replace.Old]; seen {
			if previous != replace.New {
				index.conflicted[replace.Old] = struct{}{}
			}
			continue
		}
		index.targets[replace.Old] = replace.New
	}
	return index
}

// applyReplace records the replacement that governs entry, if any.
//
// The version-specific key takes precedence over the wildcard key. A conflicted key governs the
// requirement and supplies no target, so the wildcard is not consulted in its place. A
// replacement with no version on its right is a directory. A module replacement that fails the
// rule for a downloaded module is counted as dropped and the requirement is still published,
// because the requirement itself is valid.
func applyReplace(entry *moduleEntry, replaces replaceIndex, result *parseResult) {
	for _, key := range []module.Version{{Path: entry.Path, Version: entry.Version}, {Path: entry.Path}} {
		target, ok := replaces.targets[key]
		if !ok {
			continue
		}
		if _, conflict := replaces.conflicted[key]; conflict {
			return
		}
		if target.Version == "" {
			entry.ReplaceLocal = true
			return
		}
		if !validDownloadedModule(target.Path, target.Version) {
			result.Dropped++
			return
		}
		entry.ReplaceModule = target.Path
		entry.ReplaceVersion = target.Version
		return
	}
}

// errorLine returns the line number a modfile error reports, or 1 when it reports none.
func errorLine(err error) int {
	var list modfile.ErrorList
	if errors.As(err, &list) && len(list) > 0 && list[0].Pos.Line > 0 {
		return list[0].Pos.Line
	}
	return 1
}

// maxGoSumLine bounds one go.sum line. A real line is a module path, a version and a hash,
// well under a kilobyte, so a longer line is counted as malformed without being split into
// fields, and the rest of the file is still read.
const maxGoSumLine = 64 << 10

// parseGoSum reads the module versions a go.sum records a hash for.
//
// Each line is `<module> <version> <hash>`. A version ending in `/go.mod` hashes that module
// version's go.mod file only; any other hashes the module's contents. Both are recorded: a
// go.sum can hold a go.mod hash with no content hash, for a version minimal version selection
// read requirements from and the build never downloaded. One entry is kept per module and
// version, recording for each kind of line whether one exists and its hash.
//
// A line counts as malformed unless it has three fields and a hash the go command accepts, so
// a file of placeholder or truncated hashes cannot pass as a complete listing. A record that
// appears twice with different hashes is counted as a conflict and its hash is not kept, and a
// module version that fails the rule for a downloaded module is counted as dropped. Lines are
// taken from the bytes already read, so one line, however long, costs only itself.
func parseGoSum(data []byte) parseResult {
	var result parseResult
	// The index into result.Entries for each module and version, or -1 once it was dropped,
	// so a version with both lines is counted once either way.
	seen := make(map[module.Version]int)
	// The first hash for each record, to compare repeats against. A record is one module
	// version and one hash kind, so a content hash and a go.mod hash never conflict.
	type sumRecord struct {
		version module.Version
		goMod   bool
	}
	hashes := make(map[sumRecord]string)
	conflicted := make(map[sumRecord]struct{})

	for line := range bytes.Lines(data) {
		if len(line) > maxGoSumLine {
			result.MalformedLines++
			continue
		}
		fields := bytes.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 3 || !validHash(fields[2]) {
			result.MalformedLines++
			continue
		}
		versionField, goModOnly := bytes.CutSuffix(fields[1], []byte("/go.mod"))
		key := module.Version{Path: string(fields[0]), Version: string(versionField)}
		record := sumRecord{version: key, goMod: goModOnly}
		hash := string(fields[2])
		index, duplicate := seen[key]
		if duplicate && index < 0 {
			continue // already dropped and counted once
		}
		if !duplicate {
			if !validDownloadedModule(key.Path, key.Version) {
				seen[key] = -1
				result.Dropped++
				continue
			}
			if len(result.Entries) >= maxEntriesPerFile {
				result.Truncated = true
				break
			}
			index = len(result.Entries)
			seen[key] = index
			result.Entries = append(result.Entries, moduleEntry{Path: key.Path, Version: key.Version})
		}
		if first, recorded := hashes[record]; !recorded {
			hashes[record] = hash
		} else if first != hash {
			if _, counted := conflicted[record]; !counted {
				conflicted[record] = struct{}{}
				result.ChecksumConflicts++
			}
		}
		entry := &result.Entries[index]
		_, untrusted := conflicted[record]
		if untrusted {
			hash = ""
		}
		if goModOnly {
			entry.GoModHashRecorded, entry.GoModHash = true, hash
			continue
		}
		entry.ModuleHashRecorded, entry.ModuleHash = true, hash
	}
	return result
}

// mergeEntries combines a project's go.mod requirements and go.sum records into one entry per
// module version: each requirement, in go.mod order, with what go.sum records for that exact
// module and version, then each go.sum version that go.mod does not require, in go.sum order.
//
// The match is exact, and the hashes are what go.sum recorded for that module and version. The
// go command hashes what it downloads, so a requirement that a replace directive sends to
// another module usually has its hashes under the replacement, listed as its own entry, and a
// requirement replaced by a local directory usually has none. Neither is guaranteed: adding a
// replace directive does not remove a record go.sum already held for the original version, and
// that record is attached here like any other.
func mergeEntries(requirements, records []moduleEntry) []moduleEntry {
	merged := make([]moduleEntry, 0, len(requirements)+len(records))
	position := make(map[module.Version]int, len(requirements))
	for _, requirement := range requirements {
		position[module.Version{Path: requirement.Path, Version: requirement.Version}] = len(merged)
		merged = append(merged, requirement)
	}
	for _, record := range records {
		at, required := position[module.Version{Path: record.Path, Version: record.Version}]
		if !required {
			merged = append(merged, record)
			continue
		}
		merged[at].ModuleHashRecorded = record.ModuleHashRecorded
		merged[at].ModuleHash = record.ModuleHash
		merged[at].GoModHashRecorded = record.GoModHashRecorded
		merged[at].GoModHash = record.GoModHash
	}
	return merged
}

// validHash reports whether a go.sum hash field is one the go command accepts: the algorithm
// name h1, a colon, and a base64-encoded SHA-256 digest. h1 is the only algorithm the go
// command supports; a line using another is counted as malformed rather than trusted.
func validHash(field []byte) bool {
	digest, ok := bytes.CutPrefix(field, []byte("h1:"))
	if !ok {
		return false
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(digest)))
	size, err := base64.StdEncoding.Decode(decoded, digest)
	return err == nil && size == sha256.Size
}
