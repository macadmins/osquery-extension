package go_modules

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// TestParseGoModRequirementsAndReplacements covers the forms a go.mod states a dependency in:
// a grouped and a single require, the indirect marker, a quoted path, and each kind of
// replacement.
func TestParseGoModRequirementsAndReplacements(t *testing.T) {
	data := []byte(`module example.com/project

go 1.25

require (
	github.com/direct/one v1.2.3
	github.com/indirect/two v0.4.0 // indirect
	"github.com/quoted/three" v1.0.0
	github.com/forked/four v1.1.0
	github.com/pinned/five v2.0.0+incompatible
	example/local v0.0.0
	github.com/short/six v1.2
)

require golang.org/x/single v0.1.0

replace github.com/forked/four => github.com/someone/four-fork v1.1.1

replace github.com/pinned/five => github.com/wildcard/five v2.0.2+incompatible

replace github.com/pinned/five v2.0.0+incompatible => github.com/patched/five v2.0.1+incompatible

replace github.com/pinned/five v9.9.9+incompatible => github.com/never/applies v1.0.0

replace example/local => ../local
`)
	result, err := parseGoMod(data)
	if err != nil {
		t.Fatal(err)
	}
	want := []moduleEntry{
		{Path: "github.com/direct/one", Version: "v1.2.3", ModRelationship: relationshipDirect},
		{Path: "github.com/indirect/two", Version: "v0.4.0", ModRelationship: relationshipIndirect},
		{Path: "github.com/quoted/three", Version: "v1.0.0", ModRelationship: relationshipDirect},
		{Path: "github.com/forked/four", Version: "v1.1.0", ModRelationship: relationshipDirect,
			ReplaceModule: "github.com/someone/four-fork", ReplaceVersion: "v1.1.1"},
		{Path: "github.com/pinned/five", Version: "v2.0.0+incompatible", ModRelationship: relationshipDirect,
			ReplaceModule: "github.com/patched/five", ReplaceVersion: "v2.0.1+incompatible"},
		{Path: "example/local", Version: "v0.0.0", ModRelationship: relationshipDirect, ReplaceLocal: true},
		// Canonicalized as the go command writes it.
		{Path: "github.com/short/six", Version: "v1.2.0", ModRelationship: relationshipDirect},
		{Path: "golang.org/x/single", Version: "v0.1.0", ModRelationship: relationshipDirect},
	}
	if !reflect.DeepEqual(result.Entries, want) {
		t.Errorf("entries =\n%+v\nwant\n%+v", result.Entries, want)
	}
	if result.Dropped != 0 || result.DroppedValues != 0 || result.PartialLine != 0 {
		t.Errorf("dropped %d, dropped values %d, partial line %d", result.Dropped, result.DroppedValues, result.PartialLine)
	}
	if result.ProjectModule != "example.com/project" {
		t.Errorf("project module = %q", result.ProjectModule)
	}
}

// TestParseGoModProjectModule: the module line is published only inside the module grammar, and
// a version required twice is one entry, keeping the first.
func TestParseGoModProjectModule(t *testing.T) {
	result, err := parseGoMod([]byte("module \"example.com/a --token=opaqueSecret\"\n\n" +
		"require (\n\texample.com/dep v1.0.0\n\texample.com/dep v1.0.0 // indirect\n)\n"))
	if err != nil {
		t.Fatal(err)
	}
	if result.ProjectModule != "" || result.DroppedValues != 1 || result.Dropped != 0 {
		t.Errorf("project module %q dropped values %d entries %d, want empty, 1 and 0",
			result.ProjectModule, result.DroppedValues, result.Dropped)
	}
	want := []moduleEntry{{Path: "example.com/dep", Version: "v1.0.0", ModRelationship: relationshipDirect}}
	if !reflect.DeepEqual(result.Entries, want) {
		t.Errorf("entries = %+v, want one direct entry", result.Entries)
	}
}

// TestParseGoModRecoversRequirementsFromAnUnknownDirective: a go.mod from a newer Go can hold a
// directive the strict parser rejects. The requirements are still listed, the replacement is
// not, and PartialLine says so.
func TestParseGoModRecoversRequirementsFromAnUnknownDirective(t *testing.T) {
	data := []byte(`module example.com/project

require github.com/kept/one v1.0.0

replace github.com/kept/one => github.com/fork/one v1.0.1

futuredirective something
`)
	result, err := parseGoMod(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 1 || result.Entries[0].Path != "github.com/kept/one" {
		t.Fatalf("entries = %+v", result.Entries)
	}
	if result.Entries[0].ReplaceModule != "" {
		t.Error("the lenient parser does not read replace, so none may be reported")
	}
	if result.PartialLine != 7 {
		t.Errorf("partial line = %d, want 7", result.PartialLine)
	}
}

// TestParseGoModDropsCraftedPaths is the test the grammar check exists for. modfile.Parse
// accepts any quoted string as a module path, including one holding a credential assignment
// or a space, so without validModule a crafted go.mod would put an opaque secret straight into
// module_path. Each crafted value is counted and none is published; the valid requirement
// beside them is still listed.
func TestParseGoModDropsCraftedPaths(t *testing.T) {
	const opaque = "opaqueSecretValue"
	data := []byte(`module example.com/project

require (
	github.com/good/one v1.0.0
	"--token=` + opaque + `" v1.0.0
	"github.com/a/` + opaque + ` --api-key" v1.0.0
	"github.com/x/--api-key=` + opaque + `" v1.0.0
)

replace github.com/good/one => "--token=` + opaque + `" v1.0.0
`)
	result, err := parseGoMod(data)
	if err != nil {
		t.Fatal(err)
	}
	want := []moduleEntry{{Path: "github.com/good/one", Version: "v1.0.0", ModRelationship: relationshipDirect}}
	if !reflect.DeepEqual(result.Entries, want) {
		t.Fatalf("entries = %+v, want only the valid requirement, with no replacement", result.Entries)
	}
	if result.Dropped != 3 || result.DroppedValues != 1 {
		t.Errorf("dropped = %d and %d values, want three requirements and one replacement",
			result.Dropped, result.DroppedValues)
	}
}

// TestParseGoModRejectsWhatTheGoCommandRejects: an invalid version fails the whole file, as
// it does for the go command, which refuses a go.mod with one.
func TestParseGoModRejectsWhatTheGoCommandRejects(t *testing.T) {
	data := []byte(`module example.com/project

require github.com/bad/two notaversion
`)
	if _, err := parseGoMod(data); err != errGoModUnparsable {
		t.Errorf("err = %v, want errGoModUnparsable", err)
	}
}

// TestParseGoModRejectsGarbage carries no text from the file in its error, because the
// parser's own message quotes the offending line.
func TestParseGoModRejectsGarbage(t *testing.T) {
	_, err := parseGoMod([]byte("module\n\"unterminated --token=opaqueSecret\n"))
	if err == nil {
		t.Fatal("garbage parsed")
	}
	if strings.Contains(err.Error(), "opaqueSecret") || err != errGoModUnparsable {
		t.Errorf("error = %v, want errGoModUnparsable with no file text", err)
	}
}

// validHashField is a hash in the form the go command writes: h1 and a base64 SHA-256 digest.
var validHashField = "h1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, sha256.Size))

// TestParseGoSum covers both record kinds, duplicates, malformed lines including hashes the go
// command would reject, and values outside the grammar.
func TestParseGoSum(t *testing.T) {
	hash := validHashField
	data := []byte(strings.Join([]string{
		"github.com/a/one v1.0.0 " + hash,
		"github.com/a/one v1.0.0/go.mod " + hash,
		"github.com/a/one v1.0.0 " + hash,
		"github.com/b/two v0.0.0-20240101000000-abcdef123456 " + hash,
		// A go.mod hash with no content hash: kept, and marked as such.
		"github.com/c/three v2.0.0+incompatible/go.mod " + hash,
		// A go.mod hash first and a content hash after it: one entry recording both.
		"github.com/d/four v1.0.0/go.mod " + hash,
		"github.com/d/four v1.0.0 " + hash,
		"two fields",
		"github.com/e/five v1.0.0 h1:not-a-hash",
		"github.com/e/five v1.0.0 h2:" + strings.TrimPrefix(hash, "h1:"),
		"github.com/e/five v1.0.0 h1:" + base64.StdEncoding.EncodeToString([]byte("short")),
		"github.com/f/six notaversion " + hash,
		"github.com/f/six notaversion/go.mod " + hash,
		"--token=secret v1.0.0 " + hash,
		"",
	}, "\n"))
	result := parseGoSum(data)
	var got []string
	for _, entry := range result.Entries {
		got = append(got, entry.Path+"@"+entry.Version+" "+recordedKinds(entry))
	}
	want := []string{
		"github.com/a/one@v1.0.0 module+go.mod",
		"github.com/b/two@v0.0.0-20240101000000-abcdef123456 module",
		"github.com/c/three@v2.0.0+incompatible go.mod",
		"github.com/d/four@v1.0.0 module+go.mod",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("entries =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Four malformed: a two-field line, a hash that is not base64, an algorithm the go command
	// does not support, and a digest of the wrong length. Two dropped: one invalid version,
	// counted once across its two lines, and one invalid path.
	if result.MalformedLines != 4 || result.Dropped != 2 {
		t.Errorf("malformed %d dropped %d, want 4 and 2", result.MalformedLines, result.Dropped)
	}
}

// TestParseGoSumBoundsLineLength: a line past maxGoSumLine is counted as malformed, and the
// lines around it are still read.
func TestParseGoSumBoundsLineLength(t *testing.T) {
	data := "example.com/before v1.0.0 " + validHashField + "\n" +
		strings.Repeat("a", maxGoSumLine+1) + " v1.0.0 " + validHashField + "\n" +
		"example.com/after v1.0.0 " + validHashField + "\n"
	result := parseGoSum([]byte(data))
	if result.MalformedLines != 1 || len(result.Entries) != 2 {
		t.Errorf("malformed %d entries %+v, want 1 and the two valid lines", result.MalformedLines, result.Entries)
	}
}

// TestParseGoModReplaceConflicts follows the go command's rule: replacements are keyed on the
// module and version on the left, the wildcard is its own key, and one key sent to two targets
// is a conflict the go command refuses. A conflicted key governs its requirements and supplies
// no target, so nothing arbitrary is published for them.
func TestParseGoModReplaceConflicts(t *testing.T) {
	for _, tc := range []struct {
		name          string
		replaces      string
		wantModule    string
		wantVersion   string
		wantConflicts int
	}{
		{"conflicting wildcards",
			"replace example.com/dep => example.com/a v1.0.0\nreplace example.com/dep => example.com/b v1.0.0\n",
			"", "", 1},
		{"conflicting version-specific",
			"replace example.com/dep v1.0.0 => example.com/a v1.0.0\nreplace example.com/dep v1.0.0 => example.com/b v1.0.0\n",
			"", "", 1},
		{"a conflicted version-specific key does not fall back to the wildcard",
			"replace example.com/dep => example.com/w v1.0.0\n" +
				"replace example.com/dep v1.0.0 => example.com/a v1.0.0\nreplace example.com/dep v1.0.0 => example.com/b v1.0.0\n",
			"", "", 1},
		{"identical duplicates",
			"replace example.com/dep => example.com/a v1.0.0\nreplace example.com/dep => example.com/a v1.0.0\n",
			"example.com/a", "v1.0.0", 0},
		{"wildcard and version-specific together",
			"replace example.com/dep => example.com/w v1.0.0\nreplace example.com/dep v1.0.0 => example.com/v v1.0.0\n",
			"example.com/v", "v1.0.0", 0},
		{"a conflict on a module nothing requires still counts",
			"replace example.com/other => example.com/a v1.0.0\nreplace example.com/other => example.com/b v1.0.0\n",
			"", "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte("module example.com/p\n\nrequire example.com/dep v1.0.0\n\n" + tc.replaces)
			result, err := parseGoMod(data)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Entries) != 1 {
				t.Fatalf("entries = %+v", result.Entries)
			}
			entry := result.Entries[0]
			if entry.ReplaceModule != tc.wantModule || entry.ReplaceVersion != tc.wantVersion {
				t.Errorf("replacement = %q %q, want %q %q",
					entry.ReplaceModule, entry.ReplaceVersion, tc.wantModule, tc.wantVersion)
			}
			if result.ConflictingReplaces != tc.wantConflicts {
				t.Errorf("conflicts = %d, want %d", result.ConflictingReplaces, tc.wantConflicts)
			}
		})
	}
}

// TestParseGoModRecoversFromAMalformedKnownDirective: the strict parse also fails for a
// directive it knows that is malformed -- here a replace whose module target has no version --
// and the requirements are still recovered.
func TestParseGoModRecoversFromAMalformedKnownDirective(t *testing.T) {
	data := []byte("module example.com/p\n\nrequire example.com/dep v1.0.0\n\nreplace example.com/dep => example.com/a\n")
	result, err := parseGoMod(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 1 || result.PartialLine != 5 {
		t.Errorf("entries %+v partial line %d, want one entry and line 5", result.Entries, result.PartialLine)
	}
}

// TestDownloadedModulesUseTheStricterRule: a go.sum record and a versioned replacement target
// name modules the go command downloads, so they must pass module.Check -- a dot in the first
// path element, and a version that agrees with a major-version suffix. A requirement keeps the
// looser rule, because it may name a module a replace points at a local directory.
func TestDownloadedModulesUseTheStricterRule(t *testing.T) {
	hash := validHashField
	sum := parseGoSum([]byte(strings.Join([]string{
		"example.com/lib/v2 v2.1.0 " + hash,
		"example.com/lib/v2 v1.0.0 " + hash,
		"local/lib v1.0.0 " + hash,
	}, "\n")))
	if len(sum.Entries) != 1 || sum.Entries[0].Version != "v2.1.0" || sum.Dropped != 2 {
		t.Errorf("go.sum entries %+v dropped %d, want only v2.1.0 and two dropped", sum.Entries, sum.Dropped)
	}

	mod, err := parseGoMod([]byte("module example.com/p\n\nrequire (\n\texample/local v0.0.0\n\texample.com/dep v1.0.0\n)\n\n" +
		"replace example/local => ../local\nreplace example.com/dep => local/fork v1.0.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(mod.Entries) != 2 || !mod.Entries[0].ReplaceLocal || mod.Entries[1].ReplaceModule != "" ||
		mod.DroppedValues != 1 || mod.Dropped != 0 {
		t.Errorf("go.mod entries %+v dropped values %d, want the local requirement kept and the dot-less target dropped",
			mod.Entries, mod.DroppedValues)
	}
}

// TestChecksumConflicts: one record with two different hashes is a conflict, counted once; the
// same hash repeated is not, and a content hash and a go.mod hash for one version never are.
func TestChecksumConflicts(t *testing.T) {
	other := "h1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, sha256.Size))
	result := parseGoSum([]byte(strings.Join([]string{
		"example.com/a v1.0.0 " + validHashField,
		"example.com/a v1.0.0 " + other,
		"example.com/a v1.0.0 " + other,
		"example.com/b v1.0.0 " + validHashField,
		"example.com/b v1.0.0 " + validHashField,
		"example.com/c v1.0.0 " + validHashField,
		"example.com/c v1.0.0/go.mod " + other,
	}, "\n")))
	if result.ChecksumConflicts != 1 || len(result.Entries) != 3 {
		t.Fatalf("conflicts %d entries %d, want 1 and 3", result.ChecksumConflicts, len(result.Entries))
	}
	want := []moduleEntry{
		// The go command trusts neither of a's content hashes, so neither is kept;
		// ModuleHashRecorded still says the record exists, which is how a conflict differs from an
		// absent record.
		{Path: "example.com/a", Version: "v1.0.0", ModuleHashRecorded: true},
		{Path: "example.com/b", Version: "v1.0.0", ModuleHashRecorded: true,
			ModuleHash: validHashField},
		{Path: "example.com/c", Version: "v1.0.0", ModuleHashRecorded: true,
			ModuleHash: validHashField, GoModHashRecorded: true, GoModHash: other},
	}
	if !reflect.DeepEqual(result.Entries, want) {
		t.Errorf("entries =\n%+v\nwant\n%+v", result.Entries, want)
	}
}

// TestMergeEntries: one entry per module version. A requirement takes go.sum's record for the
// exact same module and version; a replaced requirement with no record of its own has empty
// hash columns, because go.sum hashes the replacement, which is listed as its own entry; a
// version only go.sum records follows the requirements.
func TestMergeEntries(t *testing.T) {
	requirements := []moduleEntry{
		{Path: "example.com/a", Version: "v1.0.0", ModRelationship: relationshipDirect},
		{Path: "example.com/old", Version: "v0.1.0", ModRelationship: relationshipDirect,
			ReplaceModule: "example.com/new", ReplaceVersion: "v0.2.0"},
		{Path: "example.com/local", Version: "v0.0.0", ModRelationship: relationshipIndirect, ReplaceLocal: true},
	}
	records := []moduleEntry{
		{Path: "example.com/a", Version: "v0.9.0", GoModHashRecorded: true, GoModHash: "h1:old"},
		{Path: "example.com/new", Version: "v0.2.0", ModuleHashRecorded: true, ModuleHash: "h1:new"},
		{Path: "example.com/a", Version: "v1.0.0", ModuleHashRecorded: true,
			ModuleHash: "h1:a", GoModHashRecorded: true, GoModHash: "h1:amod"},
	}
	want := []moduleEntry{
		{Path: "example.com/a", Version: "v1.0.0", ModRelationship: relationshipDirect,
			ModuleHashRecorded: true, ModuleHash: "h1:a", GoModHashRecorded: true, GoModHash: "h1:amod"},
		{Path: "example.com/old", Version: "v0.1.0", ModRelationship: relationshipDirect,
			ReplaceModule: "example.com/new", ReplaceVersion: "v0.2.0"},
		{Path: "example.com/local", Version: "v0.0.0", ModRelationship: relationshipIndirect, ReplaceLocal: true},
		{Path: "example.com/a", Version: "v0.9.0", GoModHashRecorded: true, GoModHash: "h1:old"},
		{Path: "example.com/new", Version: "v0.2.0", ModuleHashRecorded: true, ModuleHash: "h1:new"},
	}
	if got := mergeEntries(requirements, records); !reflect.DeepEqual(got, want) {
		t.Errorf("merged =\n%+v\nwant\n%+v", got, want)
	}
}

// TestEntryCapIsReported: a file with more entries than the cap yields exactly the cap and
// says it was cut short, for both file kinds.
func TestEntryCapIsReported(t *testing.T) {
	var sumLines, requires []string
	for index := 0; index <= maxEntriesPerFile; index++ {
		path := "example.com/m" + strconv.Itoa(index)
		sumLines = append(sumLines, path+" v1.0.0 "+validHashField)
		requires = append(requires, "\t"+path+" v1.0.0")
	}
	sum := parseGoSum([]byte(strings.Join(sumLines, "\n")))
	if !sum.Truncated || len(sum.Entries) != maxEntriesPerFile {
		t.Errorf("go.sum: truncated %v entries %d", sum.Truncated, len(sum.Entries))
	}
	mod, err := parseGoMod([]byte("module example.com/p\n\nrequire (\n" + strings.Join(requires, "\n") + "\n)\n"))
	if err != nil || !mod.Truncated || len(mod.Entries) != maxEntriesPerFile {
		t.Errorf("go.mod: err %v truncated %v entries %d", err, mod.Truncated, len(mod.Entries))
	}
	exact := parseGoSum([]byte(strings.Join(sumLines[:maxEntriesPerFile], "\n")))
	if exact.Truncated {
		t.Error("a file holding exactly the cap was reported as cut short")
	}
}

// TestModulePathsWithACredentialFormatAreDropped: a module path containing a known credential
// format is dropped and counted, in go.mod, in go.sum and on the module line, never published
// rewritten. Ordinary repository names that share a broad token prefix are listed.
func TestModulePathsWithACredentialFormatAreDropped(t *testing.T) {
	const ordinarySK = "github.com/acme/sk-payments-service-client"
	const ordinaryGitLab = "github.com/acme/gitlab-ci-pipeline-exporter-tools"
	githubToken := "example.com/ghp_" + strings.Repeat("a", 36)
	openAIKey := "example.com/x/sk-proj-" + strings.Repeat("b", 24)
	mod, err := parseGoMod([]byte("module " + githubToken + "\n\nrequire (\n\t" + ordinarySK + " v1.0.0\n\t" +
		ordinaryGitLab + " v1.0.0\n\t" + githubToken + " v1.0.0\n\t" + openAIKey + " v1.0.0\n)\n"))
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, entry := range mod.Entries {
		paths = append(paths, entry.Path)
	}
	if mod.ProjectModule != "" || mod.Dropped != 2 || mod.DroppedValues != 1 ||
		strings.Join(paths, " ") != ordinarySK+" "+ordinaryGitLab {
		t.Errorf("go.mod: project module %q dropped %d values %d entries %v, want empty, 2, 1 and the two ordinary names",
			mod.ProjectModule, mod.Dropped, mod.DroppedValues, paths)
	}
	sum := parseGoSum([]byte(githubToken + " v1.0.0 " + validHashField + "\n" + ordinarySK + " v1.0.0 " + validHashField + "\n"))
	if len(sum.Entries) != 1 || sum.Entries[0].Path != ordinarySK || sum.Dropped != 1 {
		t.Errorf("go.sum: entries %+v dropped %d, want only the ordinary name and 1 dropped", sum.Entries, sum.Dropped)
	}
}

// TestADroppedModuleIsNotAlsoAConflict: two lines with different hashes for a module that is
// dropped are counted once, as dropped, not again as a checksum conflict.
func TestADroppedModuleIsNotAlsoAConflict(t *testing.T) {
	other := "h1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, sha256.Size))
	result := parseGoSum([]byte("local/lib v1.0.0 " + validHashField + "\nlocal/lib v1.0.0 " + other + "\n"))
	if result.Dropped != 1 || result.ChecksumConflicts != 0 {
		t.Errorf("dropped %d conflicts %d, want 1 and 0", result.Dropped, result.ChecksumConflicts)
	}
}

// TestARetainedRecordStaysOnAReplacedRequirement: adding a replace directive does not remove a
// record go.sum already held for the original version, so the exact match attaches it, for a
// module replacement and for a local one alike.
func TestARetainedRecordStaysOnAReplacedRequirement(t *testing.T) {
	requirements := []moduleEntry{
		{Path: "example.com/old", Version: "v1.0.0", ModRelationship: relationshipDirect,
			ReplaceModule: "example.com/new", ReplaceVersion: "v1.0.1"},
		{Path: "example.com/local", Version: "v0.1.0", ModRelationship: relationshipDirect, ReplaceLocal: true},
	}
	records := []moduleEntry{
		{Path: "example.com/old", Version: "v1.0.0", ModuleHashRecorded: true, ModuleHash: "h1:old"},
		{Path: "example.com/local", Version: "v0.1.0", GoModHashRecorded: true, GoModHash: "h1:local"},
	}
	merged := mergeEntries(requirements, records)
	if len(merged) != 2 || merged[0].ModuleHash != "h1:old" || merged[1].GoModHash != "h1:local" ||
		!merged[1].ReplaceLocal || merged[0].ReplaceModule != "example.com/new" {
		t.Errorf("merged = %+v, want each retained record on its replaced requirement", merged)
	}
}

// recordedKinds names the kinds of go.sum line an entry has, for compact test expectations.
func recordedKinds(entry moduleEntry) string {
	var kinds []string
	if entry.ModuleHashRecorded {
		kinds = append(kinds, "module")
	}
	if entry.GoModHashRecorded {
		kinds = append(kinds, "go.mod")
	}
	return strings.Join(kinds, "+")
}

// TestOverlongModuleValuesAreDropped: the Go grammar sets no length limit, and project_module is
// repeated on every row of its project, so a module path or version over its cap is dropped and
// counted, in go.mod, in go.sum and on the module line, never truncated.
func TestOverlongModuleValuesAreDropped(t *testing.T) {
	longPath := "example.com/" + strings.Repeat("a", maxModulePathLen)
	longVersion := "v1.0.0-" + strings.Repeat("a", maxVersionLen)
	result, err := parseGoMod([]byte("module " + longPath + "\n\nrequire (\n\t" + longPath +
		" v1.0.0\n\texample.com/ok " + longVersion + "\n\texample.com/kept v1.0.0\n)\n"))
	if err != nil {
		t.Fatal(err)
	}
	if result.ProjectModule != "" || result.Dropped != 2 || result.DroppedValues != 1 || len(result.Entries) != 1 ||
		result.Entries[0].Path != "example.com/kept" {
		t.Errorf("go.mod result = %+v, want the overlong module line and both overlong requirements dropped", result)
	}
	sum := parseGoSum([]byte(longPath + " v1.0.0 " + validHashField + "\nexample.com/kept v1.0.0 " +
		validHashField + "\n"))
	if sum.Dropped != 1 || len(sum.Entries) != 1 {
		t.Errorf("go.sum result = %+v, want the overlong path dropped", sum)
	}
}

// TestNonCanonicalVersionsAreDropped: semver accepts build metadata and shortened versions, which
// the go command never writes, so "+opaqueSecret123" cannot carry text a user chose into the
// version column and "v1.2" cannot sit beside go.mod's "v1.2.0" as a different version.
// +incompatible is canonical and is kept.
func TestNonCanonicalVersionsAreDropped(t *testing.T) {
	sum := parseGoSum([]byte("example.com/a v1.0.0+opaqueSecret123 " + validHashField + "\n" +
		"example.com/b v1.2 " + validHashField + "\n" +
		"example.com/c v2.0.0+incompatible " + validHashField + "\n"))
	if sum.Dropped != 2 || len(sum.Entries) != 1 || sum.Entries[0].Version != "v2.0.0+incompatible" {
		t.Errorf("go.sum result = %+v, want the two non-canonical versions dropped", sum)
	}
}

// TestTruncationNeedsAnEntryCut: a go.mod with exactly maxEntriesPerFile requirements is not
// truncated when the line after them is a duplicate or is dropped, only when it would have been
// listed.
func TestTruncationNeedsAnEntryCut(t *testing.T) {
	var lines strings.Builder
	lines.WriteString("module x\n\nrequire (\n")
	for index := range maxEntriesPerFile {
		lines.WriteString("\texample.com/m" + strconv.Itoa(index) + " v1.0.0\n")
	}
	full := lines.String()
	for extra, want := range map[string]bool{
		"\texample.com/m0 v1.0.0\n":                                      false, // a duplicate
		"\t\"example.com/ghp_" + strings.Repeat("a", 36) + "\" v1.0.0\n": false, // dropped
		"\texample.com/another v1.0.0\n":                                 true,
	} {
		result, err := parseGoMod([]byte(full + extra + ")\n"))
		if err != nil {
			t.Fatal(err)
		}
		if result.Truncated != want || len(result.Entries) != maxEntriesPerFile {
			t.Errorf("after %q: truncated = %v with %d entries, want %v with %d", extra, result.Truncated,
				len(result.Entries), want, maxEntriesPerFile)
		}
	}
}

// TestGoAndToolchainDirectives: the go and toolchain lines are recorded as declared; a toolchain
// outside the narrower grammar, or holding a credential format, is dropped and counted, never
// published. So is a go line the lenient parser rewrote: modfile.ParseLax cuts
// "1.24+--token=..." to "1.24" in both Version and Syntax.Token, so only the file's own bytes
// show the line said something else.
func TestGoAndToolchainDirectives(t *testing.T) {
	result, err := parseGoMod([]byte("module x\n\ngo 1.24.1\n\ntoolchain go1.24.2\n\nrequire example.com/a v1.0.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if result.GoDirective != "1.24.1" || result.ToolchainDirective != "go1.24.2" || result.DroppedValues != 0 {
		t.Errorf("result = %+v, want go 1.24.1 and toolchain go1.24.2", result)
	}
	for _, toolchain := range []string{"go1.21.0-ghp_" + strings.Repeat("a", 36), "go1.21.0-" + strings.Repeat("b", maxVersionLen)} {
		result, err := parseGoMod([]byte("module x\n\ngo 1.21\n\ntoolchain " + toolchain + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		if result.ToolchainDirective != "" || result.DroppedValues != 1 || result.GoDirective != "1.21" {
			t.Errorf("toolchain %.20s...: result = %+v, want the toolchain dropped and counted", toolchain, result)
		}
	}
	rewritten, err := parseGoMod([]byte("module x\n\ngo 1.24+--token=opaqueSecret\n\nrequire example.com/a v1.0.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if rewritten.GoDirective != "" || rewritten.DroppedValues != 1 || rewritten.PartialLine != 3 ||
		len(rewritten.Entries) != 1 {
		t.Errorf("rewritten go line: result = %+v, want it dropped and counted, the requirement listed", rewritten)
	}
	commented, err := parseGoMod([]byte("module x\n\ngo 1.24 // pinned for CI\n"))
	if err != nil {
		t.Fatal(err)
	}
	if commented.GoDirective != "1.24" || commented.DroppedValues != 0 {
		t.Errorf("go line with a comment: result = %+v, want 1.24 kept", commented)
	}
	for _, name := range []string{"default", "go1.21rc1", "go1.21.0-bigcorp"} {
		if !validToolchain(name) {
			t.Errorf("validToolchain(%q) = false", name)
		}
	}
}

// TestAHashMustBeCanonicalBase64: a digest whose padding bits are not zero decodes to the same
// bytes under the lenient decoder but is not what the go command writes, so it is malformed.
func TestAHashMustBeCanonicalBase64(t *testing.T) {
	canonical := "h1:" + strings.Repeat("A", 42) + "A="
	if !validHash([]byte(canonical)) {
		t.Errorf("%s is the canonical encoding of a zero digest", canonical)
	}
	// "B" sets the lowest of the last character's padding bits.
	if loose := "h1:" + strings.Repeat("A", 42) + "B="; validHash([]byte(loose)) {
		t.Errorf("%s has a padding bit set and is not a hash the go command writes", loose)
	}
}
