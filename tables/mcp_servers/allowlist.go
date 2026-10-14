package mcp_servers

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/macadmins/osquery-extension/pkg/redact"
)

// A positive grammar per column, which is the second thing the review asked for.
//
// The objection it answers is precise and correct. Redaction blocks *known* secret patterns:
// pkg/redact recognises issuer-prefixed token shapes and this package adds
// credential-named flag assignments. An opaque string with no recognisable structure matches
// none of them. So any column assembled from text a user typed can still carry a secret, and
// the table's own schema comment already admitted as much -- it listed `server_name`,
// `command_basename`, `source_path`, `package_name` and `env_keys` as residual risk and
// argued that narrowing one while five others kept the property would not be sound.
//
// That argument was right about the premise and wrong about the conclusion. Narrowing one
// column is unsound; narrowing all of them is the fix, and it is possible because each column
// has a format that real values obey:
//
//   - a command basename is a filename, so `API_KEY=xyz npx -y pkg` fails on the `=`;
//   - an environment variable name is a C identifier, so `TOKEN = abc123`'s value cannot
//     masquerade as a key;
//   - an endpoint's host is a hostname, so a DNS-embedded token fails structurally rather
//     than relying on redaction to recognise it;
//   - a package name and a version have published grammars already in this file.
//
// Two columns cannot be narrowed and are documented rather than pretended about.
// `source_path` is a filesystem path whose directory names a user chooses, and an allowlist
// of directory names is not a thing that exists; it keeps redaction plus a structural
// assertion. `user` is an OS-supplied join key and constraining it would break
// `WHERE user = ...`, which is the query this table exists to answer.
//
// Each gate reports what it dropped. A column that is empty because the value did not match
// is not the same as a column that is empty because the config said nothing, and the
// difference is the whole reason this table has a warning column.

// commandBasenameRe is the format of an executable filename.
//
// Leading-alphanumeric is stricter than the `^[A-Za-z0-9._+-]+$` the review suggested, which
// would admit `-foo` -- a value beginning with a dash is an option, not a program, and
// admitting one means admitting the shape a misparsed command line produces.
//
// Checked against the real basenames on the machine this was developed on, including the two
// the schema comment cited as the reason an allowlist was rejected: `terraform-mcp-server`
// and `computer-use-client-launcher` both pass, as do `npx`, `uvx`, `atlassian.sh`,
// `npx.cmd`, `node` and `python3`. The argument that an allowlist would gut the column
// assumed an allowlist of *names*; this is an allowlist of the format a name has.
//
// What it loses, stated rather than buried: a non-ASCII basename is dropped. Admitting
// Unicode letters reopens homoglyph confusion -- `nрx` with a Cyrillic er is a different
// program that reads as `npx` in any console -- and for a column an operator scans by eye
// that is a worse failure than a missing value.
var commandBasenameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

// maxCommandBasename bounds the column. A filename this long is not one a person typed.
const maxCommandBasename = 64

// allowedCommandBasename returns the basename if it matches the format, and reports whether
// it was dropped.
func allowedCommandBasename(candidate string) (string, bool) {
	if candidate == "" {
		// Nothing was declared, which is not a drop: a remote server has no command.
		return "", false
	}
	if len(candidate) > maxCommandBasename || !commandBasenameRe.MatchString(candidate) {
		return "", true
	}
	return candidate, false
}

// envKeyRe is the format of an environment variable name: a C identifier.
//
// POSIX permits rather more than this in principle, but every shell and every runtime treats
// a name outside this set as unusable, so a key that fails here is not a variable any server
// reads. That is what makes it a sound allowlist rather than a guess: the value it rejects
// could not have been doing the job the column describes.
//
// It is what closes `env = { TOKEN = abc123 }`. That TOML is invalid -- an unquoted value --
// so the parser fails and reports a position, and the secret never becomes a key. But the
// valid spelling `env = { TOKEN = "abc123" }` parses fine, and env *values* are already never
// read. The gate matters for the inverse: a config whose key is itself the secret, which is
// what a user does by accident when they paste into the wrong side of the pair.
var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// maxEnvKey bounds the column for the same reason maxCommandBasename does.
const maxEnvKey = 256

// envKeyAllowed is the one predicate every environment-variable name passes through.
//
// One function called from three places -- tomlEnvKeys, materialize, and a final gate where
// the column is marshalled -- rather than a check at whichever site someone remembered. The
// final gate is what makes it a guarantee: a future extractor that collects env keys and
// forgets this cannot bypass it, because the column is built in one place.
func envKeyAllowed(key string) bool {
	return key != "" && len(key) <= maxEnvKey && envKeyRe.MatchString(key)
}

// filterEnvKeys returns the keys that may be published and the count dropped.
func filterEnvKeys(keys []string) ([]string, int) {
	if len(keys) == 0 {
		return keys, 0
	}
	out := make([]string, 0, len(keys))
	dropped := 0
	for _, key := range keys {
		if envKeyAllowed(key) {
			out = append(out, key)
			continue
		}
		dropped++
	}
	return out, dropped
}

// endpointHostRe is the format of a host, with an optional port.
//
// sanitizeRemoteURL already reduces an endpoint to scheme and host, dropping the path, query,
// fragment and userinfo where tokens are common. What it could not do is constrain what is
// left: a host is user-controlled through DNS, so `https://aws.AKIAIOSFODNN7EXAMPLE.evil.test`
// survived it intact and the schema comment named exactly this case as relying on
// redactSecret to recognise the embedded shape. A grammar closes it structurally instead --
// the token is admissible as a DNS label, so recognition was always the wrong instrument.
var endpointHostRe = regexp.MustCompile(`^[A-Za-z0-9._-]+(:[0-9]{1,5})?$`)

// endpointIPv6Re is the bracketed literal form, which endpointHostRe cannot express because
// a colon separates the port there and every group here.
var endpointIPv6Re = regexp.MustCompile(`^\[[0-9A-Fa-f:.]+\](:[0-9]{1,5})?$`)

// allowedEndpointSchemes is the closed set of transports this table reports.
//
// The four MCP uses. Anything else -- a file URL, a custom scheme, a javascript URI -- is not
// an MCP endpoint, and reporting it would publish a string with no format at all.
var allowedEndpointSchemes = map[string]struct{}{
	"http": {}, "https": {}, "ws": {}, "wss": {},
}

// validatedEndpoint returns the endpoint if scheme and host both match, and "" otherwise.
//
// Applied to sanitizeRemoteURL's output rather than replacing it, so the path and userinfo
// are still dropped before anything here runs. Two gates in series: one removing the parts
// that are usually credentials, one constraining the part that remains.
func validatedEndpoint(sanitized string) string {
	if sanitized == "" {
		return ""
	}
	scheme, host, found := strings.Cut(sanitized, "://")
	if !found {
		// sanitizeRemoteURL also emits the scheme-less `//host` form for a network-path
		// reference. There is no scheme to validate, so the host is checked alone.
		if trimmed := strings.TrimPrefix(sanitized, "//"); trimmed != sanitized {
			if endpointHostRe.MatchString(trimmed) || endpointIPv6Re.MatchString(trimmed) {
				return sanitized
			}
		}
		return ""
	}
	if _, ok := allowedEndpointSchemes[strings.ToLower(scheme)]; !ok {
		return ""
	}
	if !endpointHostRe.MatchString(host) && !endpointIPv6Re.MatchString(host) {
		return ""
	}
	return sanitized
}

// dockerNameRe is dockerRefRe with the tag and digest removed, for validating the name half
// of a split reference.
var dockerNameRe = regexp.MustCompile(
	`^([a-z0-9][a-z0-9.-]*(:[0-9]+)?/)?` +
		`[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*$`)

// packageNameRe is packageSpecRe with the version removed, for the same purpose.
var packageNameRe = regexp.MustCompile(
	`^(@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*$`)

// pinnedVersionRe is the format of a version this table will publish.
//
// A colon is admitted for exactly one reason, as a closed alternative rather than as a
// character in the general pattern: a Docker digest reference is `sha256:` followed by
// sixty-four hex digits, and that is the one version-shaped value containing a colon. Left in
// the general pattern a colon would readmit `user:password`, which is the shape packageSpecRe
// was changed from a blacklist to a grammar to reject.
var pinnedVersionRe = regexp.MustCompile(
	`^([A-Za-z0-9][A-Za-z0-9.+_~*-]*|sha256:[a-f0-9]{64})$`)

// allowedIdentity validates the package triple as a unit and reports whether it was dropped.
//
// As a unit, because a partial identity is worse than none. `package_name = x` with an empty
// version is indistinguishable from a package that was deliberately left unpinned, so
// publishing a name whose version failed its grammar states something the config did not. The
// row keeps its command_basename and package_manager, which are separately gated, and reports
// confidence=low.
func allowedIdentity(name, spec, version string) (outName, outSpec, outVersion string, dropped bool) {
	if name == "" && spec == "" && version == "" {
		return "", "", "", false
	}
	nameOK := name == "" || packageNameRe.MatchString(name) || dockerNameRe.MatchString(name)
	versionOK := version == "" || pinnedVersionRe.MatchString(version)
	// A remote endpoint is its own requested_spec and has already been through
	// validatedEndpoint, so it is checked against that rather than against a package
	// grammar. Without this branch every mcp-remote row lost its spec.
	specOK := spec == "" || looksLikePackageSpec(spec) || dockerRefRe.MatchString(spec) ||
		validatedEndpoint(spec) == spec
	if nameOK && versionOK && specOK {
		return name, spec, version, false
	}
	return "", "", "", true
}

// userIDRe is the format of the two identities osquery reports: a POSIX uid or a Windows SID.
//
// A cheap gate rather than a thorough one. The value comes from osquery's own users table, so
// it is not a config file's bytes and the risk is low -- but the column is published and the
// format is completely known, so there is no reason to publish anything else.
var userIDRe = regexp.MustCompile(`^(S-1-[0-9-]+|[0-9]+)$`)

func allowedUserID(candidate string) (string, bool) {
	if candidate == "" {
		return "", false
	}
	if !userIDRe.MatchString(candidate) {
		return "", true
	}
	return candidate, false
}

// sourceContextTokens is the closed set of section names a source_context may report on its
// own, with no path attached.
//
// `projects[<path>].mcpServers` was the one free-text form: the path is a map key in
// ~/.claude.json, so a project directory named after a secret reached the column. It is now
// admitted only when the path passes the same containment a read does -- see
// allowedSourceContext -- and otherwise reduced to the bare token.
//
// Keeping the path at all is a deliberate trade. It is the only record of which project
// declared an inline server, and that is not recoverable from source_path, which names
// ~/.claude.json for every one of them. Dropping it would have made every inline
// project-scoped server indistinguishable from every other.
var sourceContextTokens = map[string]struct{}{
	"mcpServers":                {},
	"servers":                   {},
	"mcp_servers":               {},
	"projects.mcpServers":       {},
	"project.mcp_json":          {},
	"project.vscode_mcp_json":   {},
	"project.cursor_mcp_json":   {},
	"project.codex_config_toml": {},
	// Plugin-declared servers. Omitting this was not a near-miss: the token is fixed and
	// carries no path, so every healthy plugin row reached the boundary, failed the token
	// lookup, failed the path-bearing patterns too, and was emitted with an empty
	// source_context plus a warning saying its project path could not be published -- about
	// a row that has no project path. A set that must agree with its producers and does not
	// is the same defect class this table removed from discovery, so
	// TestEveryProducibleSourceContextIsAllowed now closes it.
	pluginSourceContext: {},
}

// The two path-bearing forms, split so the path can be validated on its own.
//
// Two patterns because the two shapes genuinely differ. ~/.claude.json's inline servers are
// labelled `projects[<path>].mcpServers`, naming both the project and the section inside its
// entry; a project-rooted probe is labelled `project.<file>[<path>]`, where the file IS the
// section. A single pattern covering both was the first attempt and matched neither, because
// the Claude form does not end at the bracket.
var (
	claudeProjectContextRe = regexp.MustCompile(`^(projects)\[(.*)\]\.mcpServers$`)
	probeProjectContextRe  = regexp.MustCompile(`^(project\.[a-z_]+)\[(.*)\]$`)
)

// allowedSourceContext validates the column and reports whether a path was dropped from it.
//
// Containment is not redaction, and conflating them cost a credential. A project directory
// named `repo --token=opaqueSecret` is perfectly well contained -- inside the home, no
// traversal -- so it passed this check and was emitted verbatim, while the same bytes inside
// source_path were redacted because that column runs redactSecret. The caller redacts what
// this returns; the two gates are independent and both are required.
//
// home is needed because validating the path means asking the same question a read asks: is
// this inside the home. Reusing fsscan.ContainProjectPath rather than writing a second,
// weaker check is the point -- a path this column publishes is a path the table would have
// been willing to open, which is a property a reader can state.
func allowedSourceContext(context, home string) (string, bool) {
	if context == "" {
		return "", false
	}
	if _, ok := sourceContextTokens[context]; ok {
		return context, false
	}
	groups := claudeProjectContextRe.FindStringSubmatch(context)
	suffix := "].mcpServers"
	if groups == nil {
		groups = probeProjectContextRe.FindStringSubmatch(context)
		suffix = "]"
	}
	if groups == nil {
		// Neither a known token nor a path-bearing form. There is nothing to reduce it to,
		// so it is dropped whole.
		return "", true
	}
	token, path := groups[1], groups[2]
	// The path is already relative to the home for a project-rooted probe and absolute for
	// a ~/.claude.json key, so both forms are offered to the containment check. Dropping to
	// the bare token keeps which *section* declared the server, which is the half that is
	// never user-controlled.
	if home != "" && path != "" {
		if rel, err := contained(home, path); err == nil {
			return token + "[" + rel + suffix, false
		}
	}
	return token, true
}

// contained accepts either an absolute recorded path or one already relative to the home.
//
// Both forms occur: ~/.claude.json's keys are absolute, and projectSourceContext writes the
// relative form a probe already validated. Which it is decides which check runs, and that
// branch is load-bearing rather than tidiness.
//
// Trying the absolute check and then falling back to rejoining was the first attempt and it
// was wrong in the one way that matters: filepath.Join("/Users/alice", "/tmp/evil") is
// "/Users/alice/tmp/evil", so an absolute path that had just been refused for lying outside
// the home came back contained, under a home it was never in. A path published as contained
// has to have been contained as written.
func contained(home, path string) (string, error) {
	if filepath.IsAbs(path) {
		return fsscan.ContainProjectPath(home, path, false)
	}
	// A relative path is re-validated by rejoining rather than trusted for having come from
	// a probe, so one carrying `..` is refused by the same code that refuses an absolute one.
	return fsscan.ContainProjectPath(home, filepath.Join(home, path), false)
}

// maxServerNamePlaceholderIndex bounds the `#2`, `#3` suffixes, so a file full of
// unrepresentable names cannot make the column unbounded.
const maxServerNamePlaceholderIndex = 999

// serverNamePlaceholder names an unrepresentable server by the file it came from.
//
// The requirement is that the column must not be an oracle for the name it replaces, and a
// hash is exactly that: a server name is short and drawn from a small vocabulary, so a
// truncated digest is brute-forceable offline in seconds. So this is positional instead --
// the source file's path relative to the home, plus an index when one file yields more than
// one.
//
// The trade is worth stating because it is a real loss. This traces to "which file, go and
// look", and it deliberately does not answer "is this the same server as last week". Durable
// correlation across a fleet needs a stable pseudonym, and a stable pseudonym is the
// attackable thing. Recorded as a follow-up rather than split half-way.
func serverNamePlaceholder(relSourcePath string, index int) string {
	// No source means no position to name, and `[redacted:]` names a file that was never
	// read -- a value this table emitted once already, for a different cause, and which is
	// worse than saying nothing. The marker alone is the honest answer: the name was refused
	// and nothing locates it. Reachable only when a row is published without having gone
	// through the discovery pass that assigns ordinals.
	if relSourcePath == "" {
		return redact.RedactedMark
	}
	if index > maxServerNamePlaceholderIndex {
		index = maxServerNamePlaceholderIndex
	}
	suffix := ""
	if index > 1 {
		suffix = "#" + strconv.Itoa(index)
	}
	return "[redacted:" + filepath.ToSlash(relSourcePath) + "]" + suffix
}

// maxServerName bounds the name column.
const maxServerName = 256

// serverNameRe is the format of a publishable server name.
//
// This column was the last free-text one left without a grammar, and it was checked only
// negatively: empty, the redaction marker alone, a control character, or too long. Everything
// else passed, so a configuration whose server *key* was `API_KEY=opaqueValue` or
// `Authorization: Bearer opaqueValue` published that key verbatim with no warning and
// `scan_complete = 1`. Redaction does not catch those, because every secret pattern it knows
// needs a leading `-` or a recognised prefix. The same reasoning that narrowed
// command_basename applies here and was simply not carried across.
//
// The shape is deliberately the same as commandBasenameRe: an alphanumeric first character,
// then alphanumerics, dot, underscore and hyphen. That admits every name a client or
// marketplace actually uses -- `crystal-mcp`, `google-workspace`, `node_repl`, `1password`,
// `io.github.example` -- and excludes the two things that make a name a carrier: `=`, which
// an assignment needs, and whitespace, which separates a header name from its value.
//
// Two costs, stated rather than buried. A name containing `@`, `/` or `:` is refused even
// though a person might reasonably type one, so a server called `foo@v2` loses its name. And
// a non-ASCII name is refused, for the homoglyph reason that applies to the launcher
// basename: a Cyrillic er in `nрx` reads as `npx` in any console, and a server name is
// exactly the string an operator would eyeball. Both losses are reported, never silent: the
// row gets the positional placeholder and warnServerNameUnrepresentable, so the server is
// still inventoried and still counted.
var serverNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// serverNameUnrepresentable reports whether a redacted name can be published.
//
// The empty and marker-only cases are tested explicitly even though the grammar refuses both,
// because they mean something different: the name was wholly a secret rather than merely the
// wrong shape, and a reader of this function should not have to derive that from a regex.
// Control characters and newlines need no separate loop any more -- the grammar excludes
// them, which is the point of stating a format instead of enumerating ways to fail.
func serverNameUnrepresentable(redacted string) bool {
	if redacted == "" || redacted == redact.RedactedMark {
		return true
	}
	if len(redacted) > maxServerName {
		return true
	}
	// The marker stands in for one name-shaped character before the grammar runs, because a
	// name that redaction has already cleaned should keep its marker rather than lose the
	// whole name to a placeholder. `[REDACTED]` contains brackets the grammar refuses, so
	// matching it directly would send every partially-redacted name down the placeholder
	// path -- discarding the readable half of `release-[REDACTED]` for no gain, since the
	// part that needed removing is already gone.
	//
	// Substituting rather than stripping is what keeps the check honest: `API_KEY=[REDACTED]`
	// becomes `API_KEY=x` and is still refused for its `=`, and
	// `Authorization: Bearer [REDACTED]` is still refused for its spaces. Only the marker
	// itself is forgiven, not the text around it.
	return !serverNameRe.MatchString(strings.ReplaceAll(redacted, redact.RedactedMark, "x"))
}

// validateEnum maps a value onto a closed set, substituting a documented fallback.
//
// The four enum columns -- client, transport, package_manager, confidence -- are closed by
// construction: every value comes from a constant in this package. That was a documented
// claim and nothing enforced it, so a future extractor could put anything in one and the
// column's contract would silently stop being true. This turns the claim into a check, and
// TestEveryProducibleEnumValueIsAllowed asserts the sets cover everything the package can
// actually produce, so the check cannot drift into dropping valid values.
func validateEnum(value string, allowed map[string]struct{}, fallback string) string {
	if value == "" {
		return fallback
	}
	if _, ok := allowed[value]; ok {
		return value
	}
	return fallback
}

var (
	allowedTransports = map[string]struct{}{
		"stdio": {}, "http": {}, "sse": {}, "unknown": {},
	}
	allowedConfidences = map[string]struct{}{
		"low": {}, "medium": {}, "high": {},
	}
	// allowedClients is every value any probe or lister can set, plus "unknown".
	allowedClients = map[string]struct{}{
		"claude_code": {}, "claude_desktop": {}, "cursor": {}, "windsurf": {},
		"gemini": {}, "copilot": {}, "codex": {}, "vscode": {}, "cline": {},
		"unknown": {},
	}
	// allowedPackageManagers is every value launcherIdentity can set, plus the remote
	// pseudo-manager and "unknown".
	allowedPackageManagers = map[string]struct{}{
		"npx": {}, "bunx": {}, "uvx": {}, "uv": {}, "pipx": {}, "docker": {},
		"python": {}, "node": {}, "deno": {}, "bun": {}, "mcp-remote": {},
		"unknown": {},
	}
	allowedApprovalStates = map[string]struct{}{
		string(approvalEnabled): {}, string(approvalNotApproved): {},
		string(approvalDisabled): {}, string(approvalNotApplicable): {},
		string(approvalUnknown): {},
	}
)

// structurallySoundPath asserts what can be asserted about source_path.
//
// A directory-name allowlist is impossible -- a user names their directories -- so this is
// the honest remainder: the path must be absolute, already clean, and under the home it was
// discovered in. That rules out a relative path, a path carrying `..`, and a path that drifted
// outside the home, which are the three ways the column could become wrong rather than merely
// unpleasant.
//
// The residual risk is documented rather than closed: a user who names a directory after a
// secret puts it in this column, and redactSecret will catch it only if it has a recognisable
// shape. That is stated in the table README under the redaction contract.
func structurallySoundPath(path, home string) bool {
	if path == "" || home == "" {
		return true // nothing to check against; the roster diagnostics have no home
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	rel, err := filepath.Rel(home, path)
	return err == nil && rel != ".." &&
		!strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
