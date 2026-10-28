// Package go_modules implements the go_modules table: one row per Go module version that a
// project on this host requires in its go.mod, records a hash for in its go.sum, or both.
//
// It is an inventory of declarations and checksum records. It does not resolve the
// dependencies a build uses, and its hashes are records from go.sum, not a verification of any
// installed content.
//
// A row establishes what a manifest states, not which version a build uses. A go.mod
// requirement is a minimum, and minimal version selection can choose a higher version; a
// go.sum can record versions a build no longer needs. A row is therefore a candidate for a
// vulnerable-module advisory, to confirm with the go command in that project, rather than
// proof that the version is compiled in.
//
// Core osquery has no Go module reader. Fleet orbit's go_binaries reads the build information
// embedded in installed binaries under ~/go/bin and reports each binary's main module; this
// table reads project manifests.
//
// Credential handling. Every column holds a value from a closed set, an integer, a value checked
// against the Go module grammar or, for go_directive and toolchain_directive, their own
// grammars, a go.sum hash in its fixed form, the account's name and identifiers as osquery's
// users table reports them, or the project path. The project path is the one value with no
// grammar, because a user names their directories; it is redacted for known token formats and
// credential-named assignments and must be absolute, clean and inside the home it was found in,
// or it is emptied. A directory a user names after an opaque secret still reaches the column,
// which the table README states. The warning rows about a path a project_path constraint names
// carry that path as the query wrote it: the query writer's text, not a byte a scanned account
// chose.
package go_modules

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/osquery/osquery-go/plugin/table"

	"github.com/macadmins/osquery-extension/pkg/redact"
	"github.com/macadmins/osquery-extension/pkg/utils"
)

// GoModulesColumns returns the table schema. The columns run in the order a reader needs them:
// the module version, how go.mod declares it, the project and user it was found for, what
// go.sum records for it, and whether the project's listing is complete. The table README's
// "Column order" section gives the reasoning; mcp_servers follows the same order.
func GoModulesColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("module_path"),
		table.TextColumn("version"),
		// direct or indirect when go.mod requires this version; empty when it does not.
		table.TextColumn("mod_relationship"),
		// The module a go.mod replace directive substitutes, and its version.
		table.TextColumn("replace_module"),
		table.TextColumn("replace_version"),
		// 1 when a replace directive substitutes a local directory, which is not published.
		table.IntegerColumn("replace_local"),
		// The project's own module path, from the module line of its go.mod.
		table.TextColumn("project_module"),
		// The go and toolchain lines of the project's go.mod: what the project declares, not the
		// compiler a build used, which GOTOOLCHAIN, an installed compiler or CI can change.
		table.TextColumn("go_directive"),
		table.TextColumn("toolchain_directive"),
		table.TextColumn("project_path"),
		table.TextColumn("user"),
		// The uid column of osquery's users table, as core osquery's per-user tables publish it,
		// so `JOIN users USING (uid)` works. On Windows osquery fills it with the last component
		// of the SID, which two accounts can share; user_id holds the whole SID.
		table.BigIntColumn("uid"),
		// The uid on macOS and Linux, the SID on Windows, as osquery's users table reports it.
		table.TextColumn("user_id"),
		// What go.sum records for this version, for its contents and for its go.mod file: 1
		// when go.sum has a line of that kind, and the hash, as h1: and a base64 SHA-256 digest.
		// _recorded = 0 is an absent record; 1 with an empty hash is two lines that disagree.
		table.IntegerColumn("module_hash_recorded"),
		table.TextColumn("module_hash"),
		table.IntegerColumn("go_mod_hash_recorded"),
		table.TextColumn("go_mod_hash"),
		// 1 when the project's go.mod and go.sum were read in full. 0 on every diagnostic row.
		table.IntegerColumn("scan_complete"),
		table.TextColumn("warning"),
	}
}

// GoModulesGenerate generates the table's rows.
func GoModulesGenerate(ctx context.Context, queryContext table.QueryContext,
	socketPath string) ([]map[string]string, error) {
	return generate(ctx, queryContext,
		&utils.SocketOsqueryClienter{SocketPath: socketPath, Timeout: 10 * time.Second})
}

// generate is GoModulesGenerate with the osquery client injected, so tests drive it through a
// mock. main.go registers the table through utils.RecoverPanics, so a panic here becomes an
// error for the query rather than ending the extension process.
func generate(ctx context.Context, queryContext table.QueryContext,
	clienter utils.OsqueryClienter) ([]map[string]string, error) {
	userFilter := utils.EqualityConstraints(queryContext, "user")
	// `user = ''` selects the rows that belong to no account, which only a full scan produces.
	if _, wantsAccountlessRows := userFilter[""]; wantsAccountlessRows {
		userFilter = nil
	}
	pathFilter := utils.EqualityConstraints(queryContext, "project_path")
	// `project_path = ''` selects the user rows, which only a full scan produces.
	if _, wantsUserRows := pathFilter[""]; wantsUserRows {
		pathFilter = nil
	}
	found := discoverAll(ctx, clienter, userFilter, pathFilter)
	rows := make([]map[string]string, 0, len(found))
	for _, r := range found {
		rows = append(rows, publish(r))
	}
	return rows, nil
}

// The closed sets checked before publication: the file a warning is about, and
// mod_relationship. Every value comes from a constant in this package, and the check makes
// that a fact rather than a claim.
var (
	allowedSourceFiles      = map[string]struct{}{goModFile: {}, goSumFile: {}}
	allowedModRelationships = map[string]struct{}{relationshipDirect: {}, relationshipIndirect: {}}
)

// publish converts a row to the strings osquery receives, applying each column's rule.
func publish(r row) map[string]string {
	userID, _ := utils.PublishedUserID(r.UserID)
	// The module columns are published as parsed. Every value passed the Go module grammar,
	// which admits no space or `=`, and a value containing a known credential format was
	// dropped at parse time (credentialFree in parse.go).
	return map[string]string{
		// `user` is not constrained. osquery supplies it, it is the join key, and a grammar
		// here would break the column every realistic query filters on.
		"user":                 r.User,
		"uid":                  utils.PublishedUID(r.UID),
		"user_id":              userID,
		"project_path":         publishedProjectPath(r),
		"project_module":       r.ProjectModule,
		"go_directive":         r.GoDirective,
		"toolchain_directive":  r.Toolchain,
		"module_path":          r.Entry.Path,
		"version":              r.Entry.Version,
		"mod_relationship":     closedValue(r.Entry.ModRelationship, allowedModRelationships),
		"module_hash_recorded": utils.BoolToIntString(r.Entry.ModuleHashRecorded),
		"module_hash":          publishedHash(r.Entry.ModuleHash),
		"go_mod_hash_recorded": utils.BoolToIntString(r.Entry.GoModHashRecorded),
		"go_mod_hash":          publishedHash(r.Entry.GoModHash),
		"replace_module":       r.Entry.ReplaceModule,
		"replace_version":      r.Entry.ReplaceVersion,
		"replace_local":        utils.BoolToIntString(r.Entry.ReplaceLocal),
		"scan_complete":        utils.BoolToIntString(r.ScanComplete),
		"warning":              publishedWarning(r),
	}
}

// publishedProjectPath is the project_path column of a row: a path a project_path constraint
// named, as the query wrote it, or a discovered path under publishedPath's rule. A named path is
// the query writer's own text, not a byte any scanned account chose.
func publishedProjectPath(r row) string {
	if r.NamedPath {
		return r.ProjectPath
	}
	return publishedPath(r.ProjectPath, r.Home)
}

// namedPathForm reports whether a path a project_path constraint names is in the form
// project_path publishes -- absolute and clean -- and whether redaction would change it. A path
// that fails either test cannot equal any published project_path.
func namedPathForm(path string) (publishedForm, redacted bool) {
	// On Windows project_path never starts with two separators: a drive path recorded with a
	// `\\?\` or `\\.\` prefix is published without it, and a UNC path is never read.
	doubleSeparator := runtime.GOOS == "windows" &&
		(strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, "//"))
	publishedForm = filepath.IsAbs(path) && filepath.Clean(path) == path && !doubleSeparator
	return publishedForm, redact.Secret(redact.Path(path)) != path
}

// publishedPath applies the project path's rule: redacted, and emptied unless it is absolute,
// already clean, and inside the home it was found in. A directory-name grammar is impossible
// because users name their directories; these are the ways the column could be wrong rather
// than merely unwelcome.
func publishedPath(path, home string) string {
	if path == "" {
		return ""
	}
	if home == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ""
	}
	rel, err := filepath.Rel(home, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ""
	}
	return redact.Secret(redact.Path(path))
}

// publishedWarning renders a diagnostic row's warning. A finding about one module file is
// prefixed with that file's name and a colon, such as "go.sum: ", so a query can select the
// findings about one file with `warning LIKE 'go.sum:%'`. The name comes from a closed set.
func publishedWarning(r row) string {
	rendered := r.Warning.render()
	file := closedValue(r.SourceFile, allowedSourceFiles)
	if rendered == "" || file == "" {
		return rendered
	}
	return file + ": " + rendered
}

// publishedHash returns a go.sum hash if it is in the form the parser accepted, and ""
// otherwise. The parser already checked it; this makes the column's form a fact at the point
// of publication.
func publishedHash(hash string) string {
	if !validHash([]byte(hash)) {
		return ""
	}
	return hash
}

// closedValue returns value if it is in allowed, and "" otherwise.
func closedValue(value string, allowed map[string]struct{}) string {
	if _, ok := allowed[value]; ok {
		return value
	}
	return ""
}
