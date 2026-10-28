package mcp_servers

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"github.com/osquery/osquery-go/plugin/table"

	"github.com/macadmins/osquery-extension/pkg/redact"
	"github.com/macadmins/osquery-extension/pkg/utils"
)

// MCPServersColumns defines the schema for the mcp_servers virtual table.
//
// Credential-leak posture. The aim is to remove every place a credential is *routinely*
// found, not to claim that no user-controlled string can ever contain one:
//
//   - Raw `args` is not exposed at all. Arguments routinely carry opaque tokens that no
//     regex reliably detects, so the column is a count rather than the values.
//
//   - Full `command` is not exposed either. It becomes `command_basename` (e.g. "npx",
//     "uvx", "atlassian.sh"), which drops both the directory components and any
//     whitespace-embedded arguments. A path like /Users/x/api-key-AAAA/bin/tool therefore
//     reaches the row as "tool".
//
//   - `url_endpoint` is scheme+host only; path, query, fragment and userinfo are dropped
//     before the column is written, because tokens are common in all four.
//
//   - `env_keys` is JSON-encoded variable NAMES. Values are never extracted.
//
//   - `server_name`, `source_context`, `source_path`, `warning`, `package_name` and
//     `requested_spec` pass through redact.String, which replaces known-token-shape
//     substrings with [REDACTED]. Every one of them is sanitized again when the row is
//     built, so a column assembled after parsing is covered by the same rules as one read
//     out of a file.
//
//   - A flag-style assignment whose option name announces a credential -- `--token=`,
//     `--api-key=`, `--dd-key=` -- loses its value wherever one appears, as the whole of a
//     field or embedded in a longer one. This is the one case where an opaque value is
//     caught, because the option named it rather than the value being recognisable. The
//     value of such an option is also never reported as the package it precedes.
//
//     Embedded means the option is delimited: preceded by the start of the field or by any
//     character a flag name cannot contain, which covers a space, a path separator, a
//     bracket and non-ASCII whitespace alike. `weird--token=x` is deliberately left alone,
//     because dashes interior to a word do not start an option. An embedded value ends at
//     the next space, so in a path the remainder of the field goes with it. When the
//     assignment is the whole field, everything right of the first `=` is the value however
//     it is spelled -- spaces, newlines, further `=` signs -- so a multi-line value is
//     redacted whole rather than down to its first line. An assignment to an option this
//     file does not recognise keeps its value, but that value is examined in turn, so a
//     credential nested inside one -- `--verbose=--token=<secret>` -- is still found.
//
//   - Every remaining free-text column now has an enforced format rather than relying on
//     redaction. See allowlist.go. Redaction blocks *known* secret shapes, so an opaque
//     string matches none of them and passes through -- which is why a positive grammar per
//     column, dropping what does not match, is what actually closes the case.
//
// Residual risk, stated plainly because an absolute claim here would be false. Two columns
// have no grammar available and keep redaction alone:
//
//   - `source_path` is a filesystem path whose directory names the user chooses, and an
//     allowlist of directory names is not a thing that can exist. It keeps
//     `redact.Secret(redact.Path(...))` plus a structural assertion -- absolute, clean, under
//     the home -- so a user who names a directory after an opaque secret still puts it here.
//   - `user` is the join key osquery supplies. Constraining it would break
//     `WHERE user = '<name>'`, which is the query this table exists to answer.
//
// Narrowing one free-text column while others keep the property would be unsound, which is why
// all of them are narrowed together. The grammars constrain the format of a name, not a list
// of names: `terraform-mcp-server` and `computer-use-client-launcher` match
// `^[A-Za-z0-9][A-Za-z0-9._+-]*$` and are published unchanged, while `API_KEY=xyz npx -y pkg`
// does not, because a filename cannot contain an equals sign.
//
// The columns run in the order a reader needs them: the server, what it runs, whether it is
// live, the file and user it was found for, and whether the listing is complete. The table
// README's "Column order" section gives the reasoning; go_modules follows the same order.
func MCPServersColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("server_name"),
		table.TextColumn("client"),
		table.TextColumn("transport"),
		table.TextColumn("package_manager"),
		table.TextColumn("package_name"),
		table.TextColumn("requested_spec"),
		// The version the configuration pins, never the version installed: `npx` resolves
		// `@1.2.3` itself and may resolve it to something else, and an absent pin means
		// unpinned rather than unknown -- a distinction an operator correlating against a
		// vulnerability feed needs, and which `version` would hide.
		table.TextColumn("pinned_version"),
		table.TextColumn("confidence"),
		// Replaces the previous `command` column. Just the executable name,
		// no args, no flags, no paths. Whitespace-embedded args are stripped
		// before this is written, while a path that merely contains a space --
		// `C:\Program Files\nodejs\npx.cmd` -- is not mistaken for a pair of
		// them. command.go decides which of the two a field is.
		table.TextColumn("command_basename"),
		table.IntegerColumn("args_count"),
		table.TextColumn("url_endpoint"),
		table.TextColumn("env_keys"),
		table.IntegerColumn("disabled"),
		// Whether a declared server is actually live. Claude Code treats a server in a
		// project's .mcp.json as inert until approved, so `disabled = 0` on an unapproved
		// server was a false positive in a security inventory. Deliberately a separate
		// column: `disabled` means "the file said disabled", and folding approval into it
		// would make one column mean different things depending on the client.
		table.TextColumn("approval_state"),
		table.TextColumn("source_path"),
		table.TextColumn("source_context"),
		table.TextColumn("user"),
		// The uid column of osquery's users table, as core osquery's per-user tables publish it,
		// so `JOIN users USING (uid)` works. On Windows osquery fills it with the last component
		// of the SID, which two accounts can share; user_id holds the whole SID.
		table.BigIntColumn("uid"),
		table.TextColumn("user_id"),
		// 1 when every server declared in source_path was listed and, for a server a Claude Code
		// plugin declares, every source that plugin version's manifest declares was read. A
		// finding about the user rather than this file is a row of its own and changes no server
		// row. 0 on every diagnostic row.
		table.IntegerColumn("scan_complete"),
		table.TextColumn("warning"),
	}
}

// MCPServersGenerate is the table plugin callback. main.go registers it through
// utils.RecoverPanics, so an internal bug yields an error to the operator without taking down
// the extension process.
// KNOWN GAP: no test in this repository executes SQL
// against a registered table, for this table or any other. The tests below call generate
// directly with a hand-built QueryContext, which proves the generator honours a constraint
// it is handed but says nothing about whether osquery hands it one. The row counts quoted
// in the pull request come from running osqueryi by hand, so nothing fails in CI if they
// stop being true.
func MCPServersGenerate(ctx context.Context, queryContext table.QueryContext, socketPath string) ([]map[string]string, error) {
	return generate(ctx, queryContext,
		&utils.SocketOsqueryClienter{SocketPath: socketPath, Timeout: 10 * time.Second})
}

// generate is MCPServersGenerate with the osquery client injected, so tests drive it through
// utils.MockOsqueryClienter instead of needing a live socket. This is the shape sofa,
// wifi_network and alt_system_info already use.
func generate(ctx context.Context, queryContext table.QueryContext, clienter utils.OsqueryClienter) ([]map[string]string, error) {
	userFilter := userConstraint(queryContext)
	// ctx is osquery's, so a cancelled or abandoned query stops the walk rather than running
	// it out against the watchdog.
	servers := DiscoverAll(ctx, clienter, userFilter)

	rows := make([]map[string]string, 0, len(servers))
	for _, s := range servers {
		rows = append(rows, serverToRow(s))
	}
	return rows, nil
}

// userConstraint builds the set of usernames a query narrowed to, or nil to scan every home.
// See utils.EqualityConstraints for why a mixed operator list scans everything. An empty name
// selects the rows that belong to no account, which only a full scan produces.
func userConstraint(qc table.QueryContext) map[string]struct{} {
	users := utils.EqualityConstraints(qc, "user")
	if _, wantsAccountlessRows := users[""]; wantsAccountlessRows {
		return nil
	}
	return users
}

// serverToRow builds the emitted row, applying each column's allowlist.
//
// Every gate lives here rather than at the point the value was derived, for the same reason
// envKeyAllowed is called from three places and once more at publication: this is the last
// code a value passes through before it becomes a column, so a check here cannot be bypassed
// by a new producer. The derivation sites keep their own checks as well -- two gates in
// series, where the first one gives the warning somewhere specific to point at.
//
// A dropped column reports why. An empty value because the config said nothing and an empty
// value because the value did not match its format are different facts, and the second is
// one an operator may want to go and look at.
func serverToRow(s Server) map[string]string {
	// The warning a column drop records, if the row does not already carry one.
	//
	// Discovery findings take precedence over column drops, because they mean rows are
	// missing while a drop means one field of a present row is empty. A row with both keeps
	// the more serious.
	note := s.Warning
	recordDrop := func(code warnCode) {
		if note.empty() {
			note = warning{Code: code}
		}
	}

	basename, basenameDropped := allowedCommandBasename(
		redact.Secret(commandBasename(s.Command, len(s.Args) > 0)))
	if basenameDropped {
		recordDrop(warnCommandBasenameDropped)
	}

	// The identity triple is tied to the basename gate. A command this table could not
	// publish is a command it could not parse with confidence either, so reporting what
	// package that command installs would be a claim resting on a field that was dropped.
	packageName, requestedSpec, pinnedVersion := s.PackageName, s.RequestedSpec, s.PinnedVersion
	confidence := s.Confidence
	if basenameDropped {
		packageName, requestedSpec, pinnedVersion = "", "", ""
		confidence = "low"
	}
	packageName, requestedSpec, pinnedVersion, identityDropped := allowedIdentity(
		redact.Secret(packageName), redact.Secret(requestedSpec), redact.Secret(pinnedVersion))
	if identityDropped {
		confidence = "low"
		recordDrop(warnIdentityDropped)
	}

	// A row that never named a server keeps an empty column.
	//
	// The guard is on the raw name, before redaction, and it is load-bearing: every
	// diagnostic row has no server name, redact.Secret("") is "", and "" is one of the
	// conditions serverNameUnrepresentable reports -- so without this every diagnostic row
	// was emitted with `server_name = "[redacted:]"`, a placeholder for a name that never
	// existed, naming a file that was never read. Found by running the table rather than by
	// a test, because every unit test asserting on a placeholder supplied a real name.
	serverName := ""
	if s.ServerName != "" {
		serverName = redact.Secret(s.ServerName)
		if serverNameUnrepresentable(serverName) {
			// The placeholder is positional: it names the file the server came from,
			// relative to the home, plus an index when one file yields more than one. Not a
			// hash -- a server name is short and drawn from a small vocabulary, so a
			// truncated digest is brute-forceable offline, which is the oracle this must
			// not be. The index was assigned during discovery, where the other names in
			// the same file are visible.
			// Redacted in turn. The placeholder is built from the source file's path
			// relative to the home, and a path component is a name the user chose: a
			// project directory called `repo --token=opaqueSecret` put the assignment
			// straight into the replacement for a name that had just been redacted for
			// carrying one. Replacing an unpublishable value with a different
			// unpublishable value is not a fix.
			serverName = redact.Secret(serverNamePlaceholder(s.PlaceholderSource,
				s.PlaceholderIndex))
			recordDrop(warnServerNameUnrepresentable)
		}
	}

	// Redacted after validation, not instead of it. Containment proves the path is one this
	// table would have opened; it says nothing about what the user named the directory.
	sourceContext, contextDropped := allowedSourceContext(s.SourceContext, s.Home)
	sourceContext = redact.Secret(sourceContext)
	if contextDropped {
		recordDrop(warnSourceContextPathDropped)
	}

	endpoint := validatedEndpoint(redact.Secret(s.URL))
	if endpoint == "" && s.URL != "" {
		recordDrop(warnURLEndpointDropped)
	}

	envKeys, envDropped := filterEnvKeys(s.EnvKeys)
	if envDropped > 0 {
		recordDrop(warnEnvKeyDropped)
	}

	userID, userIDDropped := utils.PublishedUserID(s.UserID)
	if userIDDropped {
		recordDrop(warnUserIDDropped)
	}

	// source_path keeps redaction and gains a structural assertion. There is no grammar
	// available for a path whose directory names a user chooses, so this rules out the three
	// ways the column could be wrong rather than merely unpleasant: not absolute, not
	// already clean, or not under the home it was discovered in.
	sourcePath := redact.Secret(redact.Path(s.SourcePath))
	if !structurallySoundPath(s.SourcePath, s.Home) {
		sourcePath = ""
	}

	return map[string]string{
		// `user` is not constrained. It is the join key osquery supplies and the column
		// every realistic query filters on, so a grammar here would break the table's
		// purpose to protect a value this package did not choose and cannot improve.
		"user":    s.User,
		"uid":     utils.PublishedUID(s.UID),
		"user_id": userID,
		// redact.Secret, not redact.String, on every column a user's file can reach. It runs
		// redact.String first and then catches the one opaque case the token shapes cannot:
		// a flag assignment whose option name announces a credential. It is idempotent, so
		// the columns already sanitized during discovery are unaffected.
		"source_path":    sourcePath,
		"source_context": sourceContext,
		// The four enum columns. Closed by construction -- every value comes from a
		// constant in this package -- which was a documented claim with nothing enforcing
		// it. validateEnum turns it into a check, and a test asserts the sets cover
		// everything the package can produce so the check cannot drift into dropping
		// valid values.
		"client":      validateEnum(s.Client, allowedClients, "unknown"),
		"server_name": serverName,
		"transport":   validateEnum(s.Transport, allowedTransports, "unknown"),
		// Replaces the previous `command` column. Just the executable name, no args, no
		// flags, no paths, and now only if it matches the format a filename has.
		"command_basename": basename,
		// The length of the JSON args array as written, not the number of arguments the
		// launcher effectively receives. A config of {"command": "uvx pkg@1.0"} with no args
		// array reports 0 here while package_name and pinned_version are still inferred from
		// the token embedded in command, because identity inference re-splits command on
		// whitespace and this column deliberately does not. Reporting the raw array length
		// keeps the column a faithful description of the file.
		"args_count": strconv.Itoa(len(s.Args)),
		// Scheme and host only, and only if the scheme is one of the four MCP uses and the
		// host is hostname-shaped. A host is user-controlled through DNS, so a reduction to
		// the host alone would publish `aws.AKIA...example.com` unless redaction recognized
		// the embedded key; a grammar closes it structurally instead.
		"url_endpoint": endpoint,
		// env_keys: JSON-encoded variable NAMES, values never extracted, each name required
		// to be a C identifier. Per-element redaction happens before the marshal so the
		// marker lands inside the array rather than a raw value surviving inside a quoted
		// JSON string.
		"env_keys":        redactedJSONStringArray(envKeys),
		"package_manager": validateEnum(s.PackageManager, allowedPackageManagers, "unknown"),
		"package_name":    packageName,
		"requested_spec":  requestedSpec,
		// pinned_version: the version the config pins, never the version installed.
		"pinned_version": pinnedVersion,
		"confidence":     validateEnum(confidence, allowedConfidences, "low"),
		"disabled":       utils.BoolToIntString(s.Disabled),
		"approval_state": validateEnum(string(s.Approval), allowedApprovalStates,
			string(approvalNotApplicable)),
		"scan_complete": utils.BoolToIntString(s.ScanComplete),
		// Built from the warning catalogue, so every byte is one this package chose: a
		// sentence keyed by a code, decimal integers, closed-enum spellings, and one key
		// that passed a bare-identifier grammar. redact.ErrorText and redact.Secret still
		// run over the result, which is now defence in depth rather than the only defence.
		//
		// redact.Secret before ErrorText, not after: ErrorText truncates at 500 bytes, and a
		// flag assignment cut in half by that bound is harder to recognise than a whole one.
		"warning": redact.ErrorText(redact.Secret(note.render())),
	}
}

// redactedJSONStringArray applies redact.Secret to each element of ss, sorts
// deterministically, and JSON-marshals the result. Used for any column whose value is a
// JSON array of user-controlled strings. Per element rather than over the marshalled blob,
// so the marker lands inside the array instead of the raw value surviving inside a quoted
// JSON string.
func redactedJSONStringArray(ss []string) string {
	// The final env-key gate, applied here rather than only at the collection sites.
	//
	// There are three producers -- tomlEnvKeys, materialize, and anything a future
	// extractor adds -- and each gates its own output. This is the one that makes it a
	// guarantee instead of three disciplines: the column is built in exactly one place, so
	// a producer that forgets cannot bypass it. The earlier gates are not redundant, they
	// are what let the drop be attributed to a source rather than reported as a bare count.
	ss, _ = filterEnvKeys(ss)
	if len(ss) == 0 {
		// "[]" rather than "": the column is documented and tested as a JSON array, so a
		// consumer should be able to unpack every row the same way instead of special-casing
		// the empty one.
		return "[]"
	}
	cleaned := make([]string, len(ss))
	for i, s := range ss {
		cleaned[i] = redact.Secret(s)
	}
	sort.Strings(cleaned)
	b, err := json.Marshal(cleaned)
	if err != nil {
		return ""
	}
	return string(b)
}
