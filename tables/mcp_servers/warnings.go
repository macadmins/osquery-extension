package mcp_servers

import (
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
)

// The warning column, as a closed catalogue rather than as assembled prose.
//
// The rule this file exists to enforce: no byte the scanned user chose can reach the
// `warning` column. Redaction cannot deliver that, and the review was right about why.
// pkg/redact recognises *known* secret shapes -- issuer-prefixed tokens, credential-named
// flag assignments -- so an opaque string with no recognisable structure passes through it
// untouched. Every column built by concatenating an error message was therefore one
// unrecognisable secret away from publishing it.
//
// The four worst offenders were all error text. `"parse: " + err.Error()` on a TOML document
// emitted BurntSushi's message, which quotes the token it failed on: a malformed
// `env = { TOKEN = abc123 }` put `abc123` in the column verbatim. The JSON path did the same
// through encoding/json's messages, the read path through the operating system's, and the
// skipped-entry notice was the only one of the four that was already safe.
//
// So the column is built from a sentence table keyed by a code this package declares, plus
// decimal integers, plus closed-enum spellings, plus -- in exactly one case -- a key that has
// already passed a bare-identifier grammar. There is no fifth source. redact.ErrorText and
// redactSecret still run over the result at the row boundary, which is now defence in depth
// rather than the only defence.

// warnCode names one thing that can go wrong. The set is closed: render refuses a code it
// has no sentence for, and a test enumerates every declared code to prove each has both a
// sentence and a completeness classification.
type warnCode string

const (
	// The roster, which concerns accounts rather than files.
	warnRosterUnreachable       warnCode = "roster_unreachable"
	warnRosterQueryFailed       warnCode = "roster_query_failed"
	warnRosterAccountUnnamed    warnCode = "roster_account_unnamed"
	warnAccountNotInRoster      warnCode = "account_not_in_roster"
	warnAccountNonLogin         warnCode = "account_non_login"
	warnAccountNoHome           warnCode = "account_no_home_declared"
	warnAccountHomeMissing      warnCode = "account_home_missing"
	warnAccountHomeUnstattable  warnCode = "account_home_unstattable"
	warnAccountHomeRedirected   warnCode = "account_home_redirected"
	warnAccountHomeNotDirectory warnCode = "account_home_not_directory"
	warnAccountsHomeUnusable    warnCode = "accounts_home_unusable"

	// One home's enumeration.
	warnHomeUnreadable         warnCode = "home_unreadable"
	warnBudgetExhaustedPreHome warnCode = "budget_exhausted_before_home"
	warnCancelledPreHome       warnCode = "cancelled_before_home"
	warnBudgetExhaustedOpening warnCode = "budget_exhausted_opening_home"
	warnBudgetExhaustedInHome  warnCode = "budget_exhausted_during_home"
	warnCancelledInHome        warnCode = "cancelled_during_home"
	warnAppDataUndetermined    warnCode = "appdata_undetermined"
	warnAppDataRedirectedOut   warnCode = "appdata_redirected_outside_profile"
	warnProfileListUnreadable  warnCode = "profile_directory_unreadable"

	// The project lists, which after this change are where every project-local config
	// comes from -- so a list that cannot be read costs the home its whole project
	// inventory rather than one file.
	warnProjectListUnreadable   warnCode = "project_list_unreadable"
	warnProjectListTruncated    warnCode = "project_list_truncated"
	warnProjectOutsideHome      warnCode = "project_outside_home"
	warnProjectMalformed        warnCode = "project_path_malformed"
	warnProjectRemoteOrigin     warnCode = "project_remote_origin"
	warnProjectCloudPlaceholder warnCode = "project_cloud_placeholder"
	warnProjectUserspaceFS      warnCode = "project_userspace_filesystem"
	warnProjectRefused          warnCode = "project_read_refused"
	warnProjectUntrusted        warnCode = "project_untrusted"
	warnProjectTrustUnknown     warnCode = "project_trust_unknown"
	// A settings file bearing approval evidence that exists and could not be used.
	warnApprovalSettingsUnreadable warnCode = "approval_settings_unreadable"

	// The VS Code workspace lists, kept separate from the per-profile directory codes so an
	// administrator can tell which evidence failed. Both used warnProfileListUnreadable
	// before, which named the wrong thing.
	warnWorkspaceListUnreadable   warnCode = "workspace_list_unreadable"
	warnWorkspaceListTruncated    warnCode = "workspace_list_truncated"
	warnWorkspaceRecordUnreadable warnCode = "workspace_record_unreadable"
	warnWorkspaceRecordMalformed  warnCode = "workspace_record_malformed"

	// Claude Code plugins, which declare their own servers under
	// ~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/.mcp.json.
	warnPluginListUnreadable      warnCode = "plugin_list_unreadable"
	warnPluginListTruncated       warnCode = "plugin_list_truncated"
	warnPluginSettingsUnreadable  warnCode = "plugin_settings_unreadable"
	warnPluginRecordsUnreadable   warnCode = "plugin_records_unreadable"
	warnPluginSuperseded          warnCode = "plugin_version_superseded"
	warnPluginManifestUnreadable  warnCode = "plugin_manifest_unreadable"
	warnPluginManifestUnsupported warnCode = "plugin_manifest_unsupported"
	warnPluginManifestTruncated   warnCode = "plugin_manifest_truncated"
	warnPluginManifestMissing     warnCode = "plugin_manifest_missing_source"
	warnPluginManifestInvalid     warnCode = "plugin_manifest_invalid_declaration"
	warnPluginShadowedDecl        warnCode = "plugin_declaration_shadowed"
	warnPluginSelectionUnknown    warnCode = "plugin_selection_unknown"

	// One source file.
	warnSourceUnreadable warnCode = "source_unreadable"
	warnSourceTooLarge   warnCode = "source_too_large"
	warnParseFailed      warnCode = "parse_failed"
	warnEntriesSkipped   warnCode = "entries_skipped"

	// One column of one row, dropped because it did not match its allowlist. These say a
	// field is empty rather than that a row is missing, which is why they do not degrade
	// completeness: every server that was declared is still listed.
	warnCommandBasenameDropped    warnCode = "command_basename_dropped"
	warnServerNameUnrepresentable warnCode = "server_name_unrepresentable"
	warnSourceContextPathDropped  warnCode = "source_context_path_dropped"
	warnURLEndpointDropped        warnCode = "url_endpoint_dropped"
	warnEnvKeyDropped             warnCode = "env_key_dropped"
	warnEnvHeaderLiteral          warnCode = "env_header_literal_value"
	warnIdentityDropped           warnCode = "identity_dropped"
	warnUserIDDropped             warnCode = "user_id_dropped"
	warnUnknownLauncherOption     warnCode = "unknown_launcher_option"
)

// parseShape names a malformed-document shape that has no position to report.
//
// Separate from warnCode because it answers a different question: the code says parsing
// failed, and this says what about the document defeated it. A closed enum for the same
// reason everything else here is one.
type parseShape string

const (
	shapeNone                parseShape = ""
	shapeUnterminatedComment parseShape = "unterminated_block_comment"
	shapeNotAnObject         parseShape = "top_level_is_not_an_object"
	shapeEnvelopeUndecodable parseShape = "envelope_present_but_undecodable"
	shapeWrongType           parseShape = "value_has_the_wrong_type"
	shapeUnknown             parseShape = "unrecognised"
)

// jsonValueKinds is the closed set of JSON value spellings that may be reported.
//
// encoding/json's UnmarshalTypeError carries a Value field, and it is nearly always one of
// these seven words -- but "nearly always" is not a guarantee a column can rest on, and the
// field is documented as a description rather than as an enum. Validated against this set, so
// a future Go release that puts something richer in there cannot widen the column's alphabet.
var jsonValueKinds = map[string]struct{}{
	"string": {}, "number": {}, "bool": {}, "array": {}, "object": {}, "null": {},
}

// identifierRe is the grammar a key must satisfy to be reported.
//
// This is the single exception to "nothing the user chose". A configuration key is the one
// detail that makes a parse failure actionable -- "line 14" sends someone to the right line,
// "line 14, key mcp_servers.github" tells them which server -- and a bare identifier cannot
// carry a credential shape: no quotes, no whitespace, no equals sign, no colon, no slash.
//
// It matters for TOML specifically. toml.ParseError.LastKey is user bytes, and TOML permits
// quoted keys, so `"my token is abc123" = 1` makes LastKey a sentence containing a secret.
// The review suggested reporting Position and LastKey; Position is a number and safe, and
// LastKey needs this gate, which is one step past what was asked for.
var identifierRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

// maxReportedKeyLength bounds the one user-chosen field that can be reported.
//
// The grammar already excludes every character a credential shape needs, so this is about
// the column rather than about disclosure: a key may legitimately be long, and a warning that
// is mostly one identifier is a warning nobody reads.
const maxReportedKeyLength = 64

// warning is one finding, as data rather than as a sentence.
//
// Every field is either an integer, a value from a closed enum, or -- for Key alone -- a
// string that has passed identifierRe. Assembling the sentence is render's job and happens
// at the row boundary, which is what makes the rule auditable: there is one function to read
// to know what can reach the column.
type warning struct {
	Code   warnCode
	Count  int   // a quantity: entries skipped, projects refused, bytes
	Limit  int64 // the bound a quantity was measured against
	Line   int   // a 1-based line number from a parser that reports one
	Offset int64 // a byte offset from a parser that reports one instead

	// Key is reported only when it passes identifierRe. Set it through withKey rather
	// than directly, so the gate cannot be bypassed by assignment.
	Key string

	Class fsscan.ErrClass // which refusal, from fsscan's closed set
	Shape parseShape      // what about the document defeated the parser
	Value string          // a JSON value kind, validated against jsonValueKinds
}

// empty reports whether this warning says anything. The zero value is "no finding", which is
// what a healthy server row carries.
func (w warning) empty() bool { return w.Code == "" }

// withKey sets Key only if the candidate passes the grammar, and reports nothing otherwise.
//
// A method rather than a check at the call site, because there are several call sites and the
// one that forgot would be the one that leaked. Over-length keys are dropped whole rather
// than truncated: a truncated identifier is not an identifier, and half of a quoted TOML key
// is exactly the shape that looks safe and is not.
func (w warning) withKey(candidate string) warning {
	if len(candidate) <= maxReportedKeyLength && identifierRe.MatchString(candidate) {
		w.Key = candidate
	}
	return w
}

// withValue sets Value only if the candidate is one of the JSON value spellings.
func (w warning) withValue(candidate string) warning {
	if _, ok := jsonValueKinds[candidate]; ok {
		w.Value = candidate
	}
	return w
}

// warnSentences is the only place a warning's words come from.
//
// One sentence per code, written to say what was lost rather than what failed: an operator
// reading this column is deciding whether to trust the row set, so "this account's
// configuration is not listed" is the useful half and the errno is not.
var warnSentences = map[warnCode]string{
	warnRosterUnreachable: "osquery could not be reached to list user accounts, so no " +
		"account's configuration was inspected",
	warnRosterQueryFailed: "the osquery users table could not be read, so no account " +
		"could be confirmed or ruled out",
	warnRosterAccountUnnamed: "the roster returned an account with no username, so it " +
		"could not be attributed or inspected and this account may be it",
	warnAccountNotInRoster: "no account of this name is in the roster osquery returned, " +
		"so nothing was scanned for it: the name may be misspelled, the account may have " +
		"been removed, or it may be one the roster does not enumerate",
	warnAccountNonLogin: "this account cannot log in, so it was not inspected and keeps " +
		"no editor or agent configuration",
	warnAccountNoHome: "this account declares no home directory, so there was nowhere " +
		"to look",
	warnAccountHomeMissing: "the home directory this account declares does not exist, " +
		"which may mean it is offline rather than absent, so its configuration is not listed",
	warnAccountHomeUnstattable: "this account's home directory could not be inspected, " +
		"so its configuration is not listed",
	warnAccountHomeRedirected: "this account's home directory is a symlink or reparse " +
		"point, which is not followed, so its configuration is not listed",
	warnAccountHomeNotDirectory: "the home directory this account declares is not a " +
		"directory, so its configuration is not listed",
	warnAccountsHomeUnusable: "accounts with no usable home directory were not inspected; " +
		"query a specific user to see which",

	warnHomeUnreadable: "this account's home directory could not be opened, so none of " +
		"its configuration is listed",
	warnBudgetExhaustedPreHome: "the query budget was exhausted before this account was " +
		"scanned, so none of its configuration is listed",
	warnCancelledPreHome: "the query was cancelled before this account was scanned, so " +
		"none of its configuration is listed",
	warnBudgetExhaustedOpening: "the query budget was exhausted opening this account's " +
		"home directory, so none of its configuration is listed",
	warnBudgetExhaustedInHome: "the query budget was exhausted part way through this " +
		"account, so some of its configuration may not be listed",
	warnCancelledInHome: "the query was cancelled part way through this account, so some " +
		"of its configuration may not be listed",
	warnAppDataUndetermined: "the roaming application data location could not be " +
		"determined for this account, so its editor and agent configuration may not be " +
		"listed; the conventional location was inspected instead",
	warnAppDataRedirectedOut: "roaming application data for this account is redirected " +
		"outside the profile, which is not inspected, so its editor and agent " +
		"configuration is not listed",
	warnProfileListUnreadable: "a per-profile configuration directory could not be " +
		"listed, so any profile-scoped servers in it are not listed",

	warnProjectListUnreadable: "the list of projects this client records could not be " +
		"read, so no project-local configuration was found for it",
	warnProjectListTruncated: "the list of projects this client records was longer than " +
		"this scan will follow, so projects past the limit were not inspected",
	warnProjectOutsideHome: "recorded projects lie outside this account's home and were " +
		"not inspected",
	warnProjectMalformed: "recorded project locations were not usable absolute paths and " +
		"were not inspected",
	warnProjectRemoteOrigin: "recorded projects are on another host rather than this " +
		"filesystem and were not inspected",
	warnProjectCloudPlaceholder: "recorded projects are held by a cloud storage provider " +
		"and were not inspected, because reading them would download their contents",
	warnProjectUserspaceFS: "recorded projects are on a filesystem implemented in " +
		"userspace, where a read may fetch their contents on demand, and were not inspected",
	warnProjectRefused: "a project configuration file was refused by a safety check " +
		"rather than being absent, so it exists and was deliberately not read",
	warnProjectUntrusted: "recorded projects are marked untrusted by their client, which " +
		"does not load project-scoped configuration for them, so any servers they declare " +
		"are not listed",
	warnProjectTrustUnknown: "the trust state of recorded projects could not be read, and " +
		"project-scoped configuration is only loaded for trusted projects, so any servers " +
		"they declare are not listed",
	warnApprovalSettingsUnreadable: "a settings file recording which project servers are " +
		"approved exists and could not be used, so the approval state of the servers it " +
		"governs is reported as unknown rather than guessed",

	warnWorkspaceListUnreadable: "an editor's workspace list could not be read, so the " +
		"projects it records and any configuration in them are not listed",
	warnWorkspaceListTruncated: "an editor's workspace list held more entries than this " +
		"scan reads, so projects past the limit are not inspected",
	warnWorkspaceRecordUnreadable: "workspace records exist and could not be read, so the " +
		"projects they name and any configuration in them are not listed",
	warnWorkspaceRecordMalformed: "workspace records could not be parsed, so the projects " +
		"they name and any configuration in them are not listed",

	warnPluginListUnreadable: "the installed plugin directory could not be listed, so any " +
		"servers declared by plugins are not listed",
	warnPluginListTruncated: "more installed plugins were found than this scan will probe, " +
		"so servers declared by plugins past the limit are not listed",
	warnPluginSettingsUnreadable: "the settings recording which plugins are enabled could " +
		"not be read, so plugin-declared servers are listed with an unknown approval state",
	warnPluginRecordsUnreadable: "the plugin installation records could not be read, so " +
		"it is not known which installed version the client would load",
	warnPluginSuperseded: "a plugin version is present in the cache but is not the " +
		"installation the client would load, so its servers may be from a superseded release",
	warnPluginManifestUnreadable: "a plugin manifest exists and could not be read, so any " +
		"MCP servers it declares are not listed",
	warnPluginManifestUnsupported: "a plugin manifest declares MCP servers in a bundle or " +
		"at a URL, which this table does not unpack or fetch, so they are not listed",
	warnPluginManifestTruncated: "a plugin manifest declares more MCP configuration sources " +
		"than this table will read, so some of its servers are not listed",
	warnPluginManifestMissing: "a plugin manifest names an MCP configuration file that " +
		"could not be read, so any servers it declares are not listed",
	warnPluginManifestInvalid: "a plugin manifest declares MCP servers with a value of a " +
		"type the field does not accept, so that declaration was not read",
	warnPluginShadowedDecl: "a higher-precedence declaration for this server could not be " +
		"read, so this definition may not be the one the client loads",
	warnPluginSelectionUnknown: "it could not be established whether this cached plugin " +
		"version is the installation the client would load",

	warnSourceUnreadable: "this configuration file could not be read, so any servers it " +
		"declares are not listed",
	warnSourceTooLarge: "this configuration file is larger than the limit this scan " +
		"reads, so the servers it declares are not listed",
	warnParseFailed: "this configuration file could not be parsed, so the servers it " +
		"declares are not listed",
	warnEntriesSkipped: "server entries in this file could not be decoded and are not " +
		"listed",

	warnCommandBasenameDropped: "the command name in this entry did not match the format " +
		"this column records and was dropped",
	warnServerNameUnrepresentable: "this server's name could not be published safely and " +
		"has been replaced with a placeholder naming the file it came from",
	warnSourceContextPathDropped: "the project path in this entry's location could not be " +
		"published and was dropped, leaving the section name",
	warnURLEndpointDropped: "the endpoint in this entry did not match the format this " +
		"column records and was dropped",
	warnEnvKeyDropped: "environment variable names in this entry did not match the " +
		"format this column records and were dropped",
	warnEnvHeaderLiteral: "this entry supplies an HTTP header value literally rather than " +
		"naming an environment variable, so the configuration file itself holds the " +
		"credential",
	warnIdentityDropped: "the package this entry launches could not be identified " +
		"unambiguously, so the package columns are empty rather than guessed",
	warnUserIDDropped: "the account identity the roster supplied was not in a recognised " +
		"form and was dropped",
	warnUnknownLauncherOption: "this entry passes an option this table does not recognise " +
		"to its launcher, so the package columns are empty rather than guessed: an " +
		"unrecognised option may or may not consume the value after it",
}

// warnScope says how far a finding reaches, which is what scan_complete is computed from.
type warnScope int

const (
	// scopeDescriptive: something is worth saying and nothing was lost. A dropped column
	// is this -- the server is still listed, one of its fields is empty.
	scopeDescriptive warnScope = iota
	// scopeSource: this file's listing is short. Only rows from that file are affected.
	scopeSource
	// scopeHome: this account's enumeration is short. Every row for the account is
	// affected, including rows from files that were read perfectly well, because the
	// question scan_complete answers is whether the enumeration that found them finished.
	scopeHome
)

// scope classifies every code, in one switch.
//
// One switch rather than a field on each constant, because this is the thing that must not
// drift from the code list: a code added without a scope is a row silently reported as
// complete when it is not. The exhaustiveness test walks warnSentences and requires every
// key to be classified here, so adding a code without touching this function fails the
// build's tests rather than quietly defaulting to "fine".
func (c warnCode) scope() warnScope {
	switch c {
	case warnRosterUnreachable, warnRosterQueryFailed, warnRosterAccountUnnamed,
		warnAccountNotInRoster, warnAccountNonLogin, warnAccountNoHome,
		warnAccountHomeMissing, warnAccountHomeUnstattable, warnAccountHomeRedirected,
		warnAccountHomeNotDirectory, warnAccountsHomeUnusable,
		warnHomeUnreadable, warnBudgetExhaustedPreHome, warnCancelledPreHome,
		warnBudgetExhaustedOpening, warnBudgetExhaustedInHome, warnCancelledInHome,
		warnAppDataUndetermined, warnAppDataRedirectedOut, warnProfileListUnreadable,
		warnProjectListUnreadable, warnProjectListTruncated,
		warnProjectCloudPlaceholder, warnProjectUserspaceFS, warnProjectRefused,
		warnWorkspaceListUnreadable, warnWorkspaceListTruncated,
		warnWorkspaceRecordUnreadable, warnWorkspaceRecordMalformed,
		warnPluginListUnreadable, warnPluginListTruncated, warnPluginSettingsUnreadable,
		warnPluginRecordsUnreadable, warnPluginManifestUnreadable,
		warnPluginManifestUnsupported, warnPluginManifestTruncated,
		warnPluginManifestMissing, warnPluginManifestInvalid:
		return scopeHome
	// warnPluginShadowedDecl is source-scoped, not home-scoped. It says this row's own
	// source may no longer be authoritative because a higher-precedence declaration over it
	// failed, which is a statement about that file. Home scope made one stale plugin
	// definition set scan_complete = 0 on every row for the account -- an unrelated Gemini
	// configuration included -- so `WHERE scan_complete = 1` lost otherwise usable inventory
	// for the whole host.
	case warnSourceUnreadable, warnSourceTooLarge, warnParseFailed, warnEntriesSkipped,
		warnPluginShadowedDecl:
		return scopeSource
	// A recorded project this table will not follow. Descriptive rather than degrading,
	// because these are the definition of what is searched rather than a scan cut short --
	// the same reasoning that makes a project the user never opened silent, and that made
	// the walk's depth limit raise no warning.
	//
	// Classifying them as home-scope was wrong in a way only running the table showed.
	// Opening a project outside your home is ordinary -- /tmp, /Volumes, a shared checkout,
	// another account's repository -- and once you have, that fact is permanent in the
	// client's project list. On the development machine 4 of 30 recorded projects are
	// outside the home, so every row for that account came back scan_complete = 0 forever,
	// which makes the predicate unusable and the column one nobody reads. It also made the
	// column say something false: the servers that were found were a complete listing of
	// their sources, and the enumeration did finish.
	//
	// What still degrades completeness is a project that IS in scope and could not be read:
	// a cloud placeholder, a refused file, or a project list that was unreadable or over
	// cap. Those are losses inside the boundary rather than the boundary itself.
	case warnProjectOutsideHome, warnProjectRemoteOrigin, warnProjectMalformed,
		warnProjectUntrusted, warnApprovalSettingsUnreadable,
		warnPluginSuperseded, warnPluginSelectionUnknown:
		return scopeDescriptive
	// Trust that could not be read is a loss rather than a boundary: the project may hold
	// configuration the client would load, and this scan cannot say.
	case warnProjectTrustUnknown:
		return scopeHome
	case warnCommandBasenameDropped, warnServerNameUnrepresentable,
		warnSourceContextPathDropped, warnURLEndpointDropped, warnEnvKeyDropped,
		warnEnvHeaderLiteral, warnIdentityDropped, warnUserIDDropped,
		warnUnknownLauncherOption:
		return scopeDescriptive
	default:
		// An unclassified code. Treated as the worst case rather than the best: a code
		// nobody placed is more likely to be a new failure than a new reassurance, and the
		// cost of being wrong in this direction is a row marked incomplete that was fine.
		return scopeHome
	}
}

// degradesCompleteness reports whether a row carrying this code can still be called a
// complete listing of its source.
//
// The empty code is handled explicitly, and it has to be: scope() sends an unrecognised code
// to scopeHome so a code nobody classified fails safe, and the zero warning's code is the
// empty string. Without this guard every *clean* row -- the overwhelming majority -- took
// that default and reported scan_complete = 0, which is the exact inversion of what the
// column means. The absence of a finding cannot degrade completeness.
func (c warnCode) degradesCompleteness() bool {
	if c == "" {
		return false
	}
	return c.scope() != scopeDescriptive
}

// render builds the column value.
//
// Everything appended here is from the sentence table, a decimal integer, a closed-enum
// spelling, or a Key that passed identifierRe. That list is the contract, and it is short
// enough to check by reading this function -- which is the point of concentrating it here
// instead of spreading it across the dozen places that used to concatenate an error.
func (w warning) render() string {
	if w.empty() {
		return ""
	}
	sentence, known := warnSentences[w.Code]
	if !known {
		// A code with no sentence. Reported as the code itself, which is a constant this
		// package declared, rather than as nothing: a row that says "something happened and
		// this build cannot say what" is still a row worth seeing, and the exhaustiveness
		// test exists so this never ships.
		return "unclassified finding (" + string(w.Code) + ")"
	}
	var details []string
	// Integers, rendered with strconv. No format string takes a user value.
	if w.Count > 0 {
		details = append(details, "count="+strconv.Itoa(w.Count))
	}
	if w.Limit > 0 {
		details = append(details, "limit="+strconv.FormatInt(w.Limit, 10))
	}
	if w.Line > 0 {
		details = append(details, "line="+strconv.Itoa(w.Line))
	}
	if w.Offset > 0 {
		details = append(details, "offset="+strconv.FormatInt(w.Offset, 10))
	}
	// Closed enums. Each is a constant from this package or from fsscan's ErrClass.
	if w.Class != "" && w.Class != fsscan.ClassNone {
		details = append(details, "reason="+string(w.Class))
	}
	if w.Shape != shapeNone {
		details = append(details, "shape="+string(w.Shape))
	}
	if w.Value != "" {
		details = append(details, "value="+w.Value)
	}
	// The one user-chosen field, already through the grammar. Checked again here rather
	// than trusted: withKey is the only intended setter, but the struct is assignable
	// within the package and this is the last point before the bytes become a column.
	if w.Key != "" && len(w.Key) <= maxReportedKeyLength && identifierRe.MatchString(w.Key) {
		details = append(details, "key="+w.Key)
	}
	if len(details) == 0 {
		return sentence
	}
	return sentence + " [" + strings.Join(details, "; ") + "]"
}

// warnCodes lists every declared code, for the exhaustiveness test.
//
// Derived from warnSentences rather than written out a second time: a hand-maintained list
// would be the thing that drifts, and then the test proving nothing drifted would be the
// thing that was wrong.
func warnCodes() []warnCode {
	out := make([]warnCode, 0, len(warnSentences))
	for code := range warnSentences {
		out = append(out, code)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// parseWarning turns a parser's error into a finding, reading its position and nothing else.
//
// This is the funnel the review named first and the one that leaked most concretely. Both
// parsers quote the input they failed on:
//
//   - BurntSushi/toml's ParseError.Message is the field carrying `found "abc123"`, so
//     `env = { TOKEN = abc123 }` -- unquoted, therefore invalid TOML -- put the token in the
//     column verbatim. Message is never read here.
//   - encoding/json's SyntaxError and UnmarshalTypeError messages name the offending value
//     and the Go type it would not fit.
//
// What is read instead is position: a line number from TOML, a byte offset from JSON. Both
// are integers, both are what an operator needs to go and look, and neither can carry a
// secret. Plus, for TOML only, the last key parsed -- which is user bytes and goes through
// identifierRe, because TOML permits quoted keys and `"my token is abc123" = 1` makes
// LastKey a sentence. That gate is one step past what the review suggested, which named
// Position and LastKey together without distinguishing them.
func parseWarning(err error) warning {
	base := warning{Code: warnParseFailed}
	if err == nil {
		return warning{}
	}

	// TOML. Position.Line rather than the deprecated Line field, which the library keeps
	// only for compatibility.
	var tomlErr *toml.ParseError
	if errors.As(err, &tomlErr) {
		return base.withKey(tomlErr.LastKey).withLine(tomlErr.Position.Line)
	}

	// JSON, malformed at the byte level.
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		out := base
		out.Offset = syntaxErr.Offset
		return out
	}

	// JSON, well-formed but the wrong type somewhere. Offset locates it; Field is our own
	// struct's field name, so it is a string this package chose; Value is encoding/json's
	// description of what it found, validated against the closed set of JSON value kinds
	// rather than trusted.
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		out := base
		out.Offset = typeErr.Offset
		out.Shape = shapeWrongType
		return out.withKey(typeErr.Field).withValue(typeErr.Value)
	}

	// The package's own parse sentinels, which carry no input by construction.
	if errors.Is(err, errNoDecodableEntries) {
		out := base
		out.Shape = shapeEnvelopeUndecodable
		return out
	}

	// Anything else. The error is deliberately discarded rather than summarised: an
	// unrecognised error type is exactly the case where nobody has checked what its message
	// contains, so the row says a parse failed and of what shape it could not tell.
	out := base
	out.Shape = shapeUnknown
	return out
}

// withLine sets Line, guarding the zero a parser reports when it has no position.
func (w warning) withLine(line int) warning {
	if line > 0 {
		w.Line = line
	}
	return w
}
