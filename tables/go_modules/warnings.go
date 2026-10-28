package go_modules

import (
	"strconv"
	"strings"

	"github.com/macadmins/osquery-extension/pkg/devclients"
	"github.com/macadmins/osquery-extension/pkg/fsscan"
)

// warnCode is one entry in this table's closed catalogue of findings.
//
// The warning column carries a sentence chosen from this catalogue plus integers and values
// from closed sets, and nothing else. No error text reaches it, because an error from a
// parser or the filesystem can quote the file or the path, and both are user input.
//
// Where a condition is the same one mcp_servers reports -- the account roster, the client
// project lists, the editor workspace records -- the code and sentence match that table's, so
// an operator reading either table sees one wording for one fact.
type warnCode string

const (
	warnRosterUnreachable    warnCode = "roster_unreachable"
	warnRosterQueryFailed    warnCode = "roster_query_failed"
	warnRosterAccountUnnamed warnCode = "roster_account_unnamed"
	warnAccountNotInspected  warnCode = "account_not_inspected"
	warnAccountsHomeUnusable warnCode = "accounts_home_unusable"
	warnHomeUnreadable       warnCode = "home_unreadable"
	warnAccountNotInRoster   warnCode = "account_not_in_roster"

	warnNamedPathNotPublished warnCode = "project_path_not_published_form"
	warnNamedPathOutsideHomes warnCode = "project_path_outside_scanned_homes"
	warnNamedPathNoRows       warnCode = "project_path_without_rows"

	warnBudgetExhaustedPreHome warnCode = "budget_exhausted_before_home"
	warnRowLimitPreHome        warnCode = "row_limit_reached_before_home"
	warnRowLimitInHome         warnCode = "row_limit_reached_during_home"
	warnOutputSizePreHome      warnCode = "output_size_reached_before_home"
	warnOutputSizeInHome       warnCode = "output_size_reached_during_home"
	warnCancelledPreHome       warnCode = "cancelled_before_home"
	warnBudgetExhaustedInHome  warnCode = "budget_exhausted_during_home"
	warnCancelledInHome        warnCode = "cancelled_during_home"

	warnAppDataUndetermined  warnCode = "appdata_undetermined"
	warnAppDataRedirectedOut warnCode = "appdata_redirected_outside_profile"

	warnProjectListUnreadable     warnCode = "project_list_unreadable"
	warnProjectListTruncated      warnCode = "project_list_truncated"
	warnWorkspaceListUnreadable   warnCode = "workspace_list_unreadable"
	warnWorkspaceListTruncated    warnCode = "workspace_list_truncated"
	warnWorkspaceRecordUnreadable warnCode = "workspace_record_unreadable"
	warnWorkspaceRecordMalformed  warnCode = "workspace_record_malformed"
	warnWorkspaceRecordsOlder     warnCode = "workspace_records_older"
	warnProjectOutsideHome        warnCode = "project_outside_home"
	warnProjectRemoteOrigin       warnCode = "project_remote_origin"
	warnProjectMalformed          warnCode = "project_path_malformed"
	warnProjectInCloudStorage     warnCode = "project_in_cloud_storage"
	warnProjectOnNetworkFS        warnCode = "project_on_network_filesystem"
	warnProjectOnUserspaceFS      warnCode = "project_on_userspace_filesystem"
	warnWorkspaceUnsupported      warnCode = "go_workspace_unsupported"
	warnSourceUserspaceFS         warnCode = "source_userspace_filesystem"
	warnProjectRefused            warnCode = "project_read_refused"
	warnProjectDirUnreadable      warnCode = "project_directory_unreadable"

	warnSourceUnreadable  warnCode = "source_unreadable"
	warnSourceLinkRefused warnCode = "source_link_refused"
	warnSourceTooLarge    warnCode = "source_too_large"
	warnGoModMalformed    warnCode = "go_mod_malformed"
	warnGoModPartial      warnCode = "go_mod_partial"
	warnReplaceConflict   warnCode = "go_mod_replace_conflict"
	warnChecksumConflict  warnCode = "go_sum_checksum_conflict"
	warnEntriesTruncated  warnCode = "entries_truncated"
	warnGoSumMalformed    warnCode = "go_sum_malformed"
	warnEntriesDropped    warnCode = "entries_dropped"
	warnValuesDropped     warnCode = "values_dropped"
)

// warnSentences holds the one sentence each code renders as.
var warnSentences = map[warnCode]string{
	warnRosterUnreachable: "osquery could not be reached to list user accounts, so no " +
		"account's projects were inspected",
	warnRosterQueryFailed: "the osquery users table could not be read, so no account " +
		"could be confirmed or ruled out",
	warnRosterAccountUnnamed: "the roster returned an account with no username, so it " +
		"could not be attributed or inspected and this account may be it",
	warnAccountNotInspected: "this account was not inspected; the reason gives the roster's " +
		"explanation",
	warnHomeUnreadable: "this account's home directory could not be opened, so none of its " +
		"projects are listed",
	warnAccountsHomeUnusable: "accounts with no usable home directory were not inspected; " +
		"query a specific user to see which",
	warnAccountNotInRoster: "no account of this name is in the roster osquery returned, " +
		"so nothing was scanned for it: the name may be misspelled, the account may have " +
		"been removed, or it may be one the roster does not enumerate",

	warnNamedPathNotPublished: "the project_path this query names is not written as " +
		"project_path publishes it, an absolute path with no trailing separator and no . or .. " +
		"component, so no row can match it and nothing was read for it",
	warnNamedPathOutsideHomes: "the project_path this query names is not inside the home of " +
		"any account this query scanned, so nothing was read for it",
	warnNamedPathNoRows: "no module row matches the project_path this query names, which is " +
		"inside this account's home: the directory has no go.mod or go.sum, or its module files " +
		"were not read; the same query without the project_path constraint shows any warning " +
		"about it",

	warnBudgetExhaustedPreHome: "the query budget was exhausted before this account was " +
		"scanned, so none of its projects are listed",
	warnCancelledPreHome: "the query was cancelled before this account was scanned, so none " +
		"of its projects are listed",
	warnRowLimitPreHome: "the query reached the number of module rows this table returns " +
		"before this account was scanned, so none of its modules are listed",
	warnRowLimitInHome: "the query reached the number of module rows this table returns part " +
		"way through this account, so some of its modules are not listed",
	warnOutputSizePreHome: "the query reached the number of bytes this table returns before " +
		"this account was scanned, so none of its modules are listed",
	warnOutputSizeInHome: "the query reached the number of bytes this table returns part way " +
		"through this account, so some of its modules are not listed",
	warnBudgetExhaustedInHome: "the query budget was exhausted part way through this " +
		"account, so some of its projects may not be listed",
	warnCancelledInHome: "the query was cancelled part way through this account, so some " +
		"of its projects may not be listed",

	warnAppDataUndetermined: "the roaming application data location could not be " +
		"determined for this account, so projects its editors record may not be listed; " +
		"the conventional location was inspected instead",
	warnAppDataRedirectedOut: "roaming application data for this account is redirected " +
		"outside the profile, which is not inspected, so projects its editors record are " +
		"not listed",

	warnProjectListUnreadable: "the list of projects this client records could not be " +
		"read, so those projects are not listed",
	warnProjectListTruncated: "the list of projects this client records was longer than " +
		"this scan will follow, so projects past the limit were not inspected",
	warnWorkspaceListUnreadable: "an editor's workspace list could not be read, so the " +
		"projects it records are not listed",
	warnWorkspaceListTruncated: "an editor's workspace list held more entries than this " +
		"scan reads, so projects past the limit are not inspected",
	warnWorkspaceRecordUnreadable: "workspace records exist and could not be read, so the " +
		"projects they name are not listed",
	warnWorkspaceRecordMalformed: "workspace records could not be parsed, so the projects " +
		"they name are not listed",
	warnWorkspaceRecordsOlder: "recorded project records older than the most recently used " +
		"ones this scan reads were not inspected",
	warnProjectOutsideHome: "recorded projects lie outside this account's home and were " +
		"not inspected",
	warnProjectRemoteOrigin: "recorded projects are on another host rather than this " +
		"filesystem and were not inspected",
	warnProjectMalformed: "recorded project locations were not usable absolute paths and " +
		"were not inspected",
	warnProjectInCloudStorage: "recorded projects are stored with a cloud storage provider " +
		"rather than on this machine's disk and were not read, so nothing was downloaded",
	warnWorkspaceUnsupported: "recorded projects have a go.work file, and workspace discovery " +
		"is not supported in this version: a module at the project root is listed, and the " +
		"other modules the workspace names are not",
	warnProjectOnNetworkFS: "recorded projects are on a network filesystem, unlike this " +
		"account's home, and were not read, so nothing was read over the network",
	warnProjectOnUserspaceFS: "recorded projects are on a filesystem implemented in userspace, " +
		"unlike this account's home, where a read may fetch their contents on demand, and were " +
		"not read",
	warnSourceUserspaceFS: "a module file in a recorded project is on a filesystem " +
		"implemented in userspace, where a read may fetch its contents on demand, and was " +
		"not read",
	warnProjectDirUnreadable: "project directories this account recorded could not be opened, " +
		"so their module files were not read",
	warnProjectRefused: "a module file in a recorded project was refused by a safety check " +
		"rather than being absent, so it exists and was deliberately not read",

	warnSourceUnreadable: "this module file could not be read, so what it records is missing " +
		"from this project's rows",
	warnSourceLinkRefused: "this module file is a symbolic link this scan did not follow, so what " +
		"it records is missing from this project's rows",
	warnSourceTooLarge: "this module file is larger than the limit this scan reads, so what it " +
		"records is missing from this project's rows",
	warnGoModMalformed: "this go.mod could not be parsed, so its requirements and replacements " +
		"are missing from this project's rows",
	warnGoModPartial: "this go.mod did not pass strict parsing; its requirements were " +
		"recovered and are listed, and its replace directives were not read",
	warnReplaceConflict: "replace directives in this go.mod send the same module to " +
		"different targets, which the go command refuses; the requirements they govern are " +
		"listed without a replacement",
	warnGoSumMalformed: "lines in this go.sum are not in the module, version and hash form " +
		"and were skipped",
	warnEntriesDropped: "entries in this file have a module path or version outside the Go " +
		"module grammar, longer than this table publishes, or containing a known credential " +
		"format, and are not listed",
	warnValuesDropped: "values in this go.mod, a replacement target or the module, go or " +
		"toolchain line, are outside their grammar, longer than this table publishes, or contain " +
		"a known credential format, so they are not published and the rows are listed with that " +
		"column empty",
	warnChecksumConflict: "this go.sum records different hashes for the same module version, " +
		"which the go command treats as a record it cannot trust; the module version is still " +
		"listed, without that hash",
	warnEntriesTruncated: "this module file lists more entries than this scan reads, so " +
		"entries past the limit are not listed",
}

// warning is one finding: a code, and the closed-set or integer details that qualify it.
type warning struct {
	Code   warnCode
	Count  int
	Limit  int64
	Line   int
	Class  fsscan.ErrClass       // which refusal, from fsscan's closed set
	Reason fsscan.OmissionReason // why the roster skipped an account, from fsscan's closed set
	Source devclients.Origin     // which client's project list, from devclients' closed set
}

func (w warning) empty() bool { return w.Code == "" }

// render produces the warning column. Every part is a catalogue sentence, an integer
// formatted with strconv, or a value from a closed set declared in this module.
func (w warning) render() string {
	if w.empty() {
		return ""
	}
	sentence, known := warnSentences[w.Code]
	if !known {
		return "unclassified finding (" + string(w.Code) + ")"
	}
	var details []string
	if w.Count > 0 {
		details = append(details, "count="+strconv.Itoa(w.Count))
	}
	if w.Limit > 0 {
		details = append(details, "limit="+strconv.FormatInt(w.Limit, 10))
	}
	if w.Line > 0 {
		details = append(details, "line="+strconv.Itoa(w.Line))
	}
	if w.Class != "" && w.Class != fsscan.ClassNone {
		details = append(details, "reason="+string(w.Class))
	}
	if w.Reason != "" {
		details = append(details, "reason="+string(w.Reason))
	}
	if w.Source != "" {
		details = append(details, "source="+string(w.Source))
	}
	if len(details) == 0 {
		return sentence
	}
	return sentence + " [" + strings.Join(details, "; ") + "]"
}
