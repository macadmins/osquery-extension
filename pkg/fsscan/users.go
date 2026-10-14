package fsscan

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/macadmins/osquery-extension/pkg/utils"
)

// The account roster comes from osquery, not from this package.
//
// osquery answers "which accounts exist on this host" better than an extension can
// reconstruct it: OpenDirectory on macOS, where local accounts are not in /etc/passwd at
// all, and the local account database on Windows, where the uuid column carries the SID.
//
// With one documented limit. On Linux the users table takes a hidden include_remote column
// that defaults to 0, so accounts served only by LDAP, SSSD or another NSS backend are
// absent unless it is set. Enumerating a whole remote directory is expensive enough that
// osquery makes it opt-in, and doing it unasked on every scheduled query is not a trade this
// table should make silently, so the local roster is used.
//
// That limit is documented rather than emitted. It used to produce a warning row on every
// Linux run, which made the warning column non-empty on every Linux host whether or not
// anything was wrong -- so the one predicate an operator would write to find real problems
// matched every host in the fleet, and the note itself became the thing they filtered out.
// A condition that is true of every run unconditionally is a property of the table, and the
// place to state a property of the table is its documentation. What survives is the
// per-account reporting: a name the roster never mentioned still gets a row saying so, which
// is what actually distinguishes a directory-served account from an absent one.
//
// An earlier version of this file enumerated /Users and /home directly and grew a parser
// for /etc/passwd, a reader for /etc/shells, an nsswitch.conf policy check, a uid heuristic,
// and a Windows ProfileList reader with SID resolution and ownership arbitration. All of it
// re-derived, less well, something the process on the other end of the socket already knew.
// Every account-roster defect found in review came from that code: compat treated as files,
// a uid floor that dropped real accounts, a partial /etc/shells read accepted as an
// allowlist, hundreds of serial domain SID lookups against the watchdog.
//
// There is no filesystem fallback when the query fails, and that is deliberate rather than
// an omission. The socket is how this extension returns rows at all: if it cannot be
// reached, osquery is not receiving results either, and substituting a guessed roster would
// only make the failure quieter.

// usersQuery asks for the whole account list. Filtering happens in Go rather than in a WHERE
// clause so the reasoning is visible and testable, and so one malformed row cannot change
// which accounts the query returns.
// UsersQuery is exported so tests in other packages can key a mock client on it without
// duplicating the string, which would silently stop matching if this one changed.
const UsersQuery = `SELECT uid, uuid, username, directory, shell FROM users`

// UsersRoot is the platform root under which user homes conventionally live.
//
// No longer the source of the roster; it survives as the path reported on a diagnostic that
// concerns the roster as a whole rather than one account, where there is no home directory
// to name.
var UsersRoot = defaultUsersRoot()

func defaultUsersRoot() string {
	switch runtime.GOOS {
	case "linux":
		return "/home"
	case "windows":
		return `C:\Users`
	default:
		return "/Users"
	}
}

// UserHome identifies one real user account by name, stable identity and home directory.
//
// ID is the identity the operating system records rather than the label a person sees: the
// uid on POSIX, the SID on Windows. osquery reports both in its users table, which is also
// the table an operator joins this one against.
type UserHome struct {
	Name string
	ID   string
	Path string
}

// OmissionReason is the closed set of reasons an account's home was not inspected.
//
// Carried alongside Reason rather than instead of it, because the two have different
// consumers. Reason is a sentence, which is what this package renders for a caller that
// simply wants to print it. Code is what a caller emitting a virtual table column needs: the
// sentence interpolates the account's shell, and a column that must be assembled only from
// bytes its own package chose cannot include a value read out of the account database. The
// distinction is small here and load-bearing for the caller -- see the mcp_servers warning
// catalogue, which is built on the rule that no byte it did not choose reaches the column.
type OmissionReason string

const (
	// OmittedNoUsername is a roster row carrying an identity and a home but no name.
	OmittedNoUsername OmissionReason = "no_username"
	// OmittedNonLoginShell is an account whose shell cannot log in.
	OmittedNonLoginShell OmissionReason = "non_login_shell"
	// OmittedNoHomeDeclared is an account record with no home directory at all.
	OmittedNoHomeDeclared OmissionReason = "no_home_declared"
	// OmittedHomeMissing is a declared home that does not exist, which is
	// indistinguishable from one that is offline.
	OmittedHomeMissing OmissionReason = "home_missing"
	// OmittedHomeUnstattable is a declared home that could not be stat'd for some other
	// reason, typically a permission failure on a parent.
	OmittedHomeUnstattable OmissionReason = "home_unstattable"
	// OmittedHomeRedirected is a declared home that is a symlink or a reparse point.
	OmittedHomeRedirected OmissionReason = "home_redirected"
	// OmittedHomeNotDirectory is a declared home that exists and is not a directory.
	OmittedHomeNotDirectory OmissionReason = "home_not_directory"
)

// Omission is one account that exists on the host but whose home was not inspected.
//
// Structured rather than a bare name because the fields answer different questions. Name is
// what a `WHERE user = ...` constraint matches, so without it the diagnostic is invisible to
// the query that asked for it. ID is what survives a rename and what a join uses. Path is
// the home the roster actually reported, which is not derivable from the name. Reason
// separates the failures an administrator would act on differently.
type Omission struct {
	Name   string
	ID     string
	Path   string
	Reason string
	Code   OmissionReason

	// HomeUnusable marks the omissions that are usually uninteresting and occasionally
	// critical: the account has no usable home to inspect, because none is declared,
	// because the declared one does not exist, or because it is not a directory.
	//
	// For a service account that never had a profile created, that is noise on every host.
	// For an LDAP account whose network home is offline, for a Windows account whose
	// profile has not been created yet, or for the specific user someone is asking about,
	// it is the answer. The caller cannot tell those apart, but it does know whether anyone
	// asked, so it aggregates these when nobody did and reports them individually when
	// someone did.
	HomeUnusable bool
}

// Warning renders this omission for the diagnostic row a caller emits in its place.
func (o Omission) Warning() string {
	who := o.Name
	if who == "" {
		who = o.ID
	}
	if who == "" {
		who = "an account"
	}
	return fmt.Sprintf("user home for %q was not inspected (%s), so this account's "+
		"configuration is not listed", who, o.Reason)
}

// UserHomes is the result of enumerating user homes: the homes found, the accounts that were
// not inspected, and whether the roster itself was complete.
type UserHomes struct {
	Homes []UserHome

	// Skipped describes the accounts that were not inspected, rather than counting them.
	// Named because the caller emits one diagnostic per skipped account and rows are
	// filtered by user: an aggregate row with an empty user is dropped by the most natural
	// query there is, so if that account was the skipped one the caller saw a clean empty
	// result.
	Skipped []Omission

	// NonLogin holds the rostered accounts that cannot log in and so were not inspected.
	//
	// Separate from Skipped rather than folded into it, because the two want opposite
	// default behaviour. A caller emits a row per Skipped account; a host has dozens of
	// service accounts, and a row each would bury the omissions that matter in an
	// inventory nobody narrowed. But dropping them entirely was worse in the one case that
	// counts: a caller reconciling requested names against what the roster accounted for
	// saw no trace of them, so `WHERE user = 'daemon'` was answered "no account of this
	// name is in the roster osquery returned" about an account the roster did return and
	// this package deliberately excluded. Reported here so a caller can stay quiet about
	// them until someone asks by name, and answer accurately when they do.
	NonLogin []Omission
}

// nonLoginShells mark an account that cannot log in and so keeps no editor or agent
// configuration.
//
// A shell check rather than a uid range: distributions disagree about where service uids
// fall, and a hard floor silently excluded real accounts on any host that chose differently.
// osquery supplies the shell, so this needs no /etc/shells of its own.
//
// A service account with an unusual-but-real shell still slips through -- _uucp on macOS has
// /usr/sbin/uucico -- and that is the right direction to fail. The cost is a handful of
// opens against a directory holding no MCP configuration; the cost of the opposite mistake
// is an account silently missing from a security inventory.
// An empty shell is deliberately absent. osquery populates this column from the account
// database, and Windows has no shell concept to populate it from, so treating empty as
// non-login would exclude every Windows account and return an empty table on the platform
// this cannot be tested on. Unknown is not the same as disqualifying, and the cost of
// inspecting an account that turns out to be a daemon is a few failed opens.
var nonLoginShells = map[string]struct{}{
	"/usr/bin/false": {}, "/bin/false": {},
	"/usr/sbin/nologin": {}, "/sbin/nologin": {}, "/usr/bin/nologin": {},
}

// errEmptyRoster reports that osquery returned no accounts, which is treated as the roster
// being unavailable rather than as a host with no users.
var errEmptyRoster = errors.New("the osquery users table returned no accounts, so the " +
	"roster is unavailable rather than empty")

// accountID picks the identity that actually identifies the account on this host.
//
// osquery reports both a uid and a uuid, and which one is the identity depends on the
// platform. On Windows the uuid holds the account SID, which is what names a registry hive
// and what an operator joins on; the uid there is a derived number. On macOS and Linux the
// uid is the identity and the uuid is a generated GUID or empty.
//
// Chosen by the value's shape rather than by runtime.GOOS so this stays testable on any
// host: only a Windows SID is spelled S-1-.
func accountID(row map[string]string) string {
	if uuid := row["uuid"]; strings.HasPrefix(uuid, "S-1-") {
		return uuid
	}
	return row["uid"]
}

// ListUserHomes returns one entry per real user home on the host, asking osquery for the
// account list and then checking each home is something this package can safely inspect.
//
// filter, when non-nil, restricts the result to those usernames. It is applied before any
// filesystem call, which is the whole reason it is a parameter rather than something the
// caller does afterwards. The check on each home is an Lstat, and an Lstat is not free: on a
// host with network or automounted homes it can block for the mount timeout, per account.
// Filtering afterwards meant `WHERE user = 'alice'` still stat'd every home on the box --
// so one dead mount belonging to an account nobody asked about delayed, or killed, a query
// scoped to a single local user.
func ListUserHomes(client utils.OsqueryClient, filter map[string]struct{}) (UserHomes, error) {
	// KNOWN GAP: this does not observe cancellation or
	// the caller's budget. osquery-go does provide QueryRowsContext -- the pinned revision
	// has it -- but utils.OsqueryClient does not name it, so no caller can reach it. An
	// already-cancelled query still runs this, and the socket timeout rather than the table
	// budget is what bounds it. Widening that shared interface belongs in its own change.
	rows, err := client.QueryRows(UsersQuery)
	if err != nil {
		return UserHomes{}, fmt.Errorf("querying the osquery users table: %w", err)
	}
	// Zero accounts is not an answer any supported OS can truthfully give. A virtual table
	// can log an internal failure -- an OpenDirectory error, observed on osquery 5.23.1 --
	// and still return an empty result set with no SQL error, which this would otherwise
	// have reported as a host that simply has no users, and therefore no MCP servers.
	if len(rows) == 0 {
		return UserHomes{}, errEmptyRoster
	}
	return homesFromUsers(rows, filter, os.Lstat), nil
}

// homesFromUsers turns osquery's user rows into a roster. Separated from the query so it is
// testable with the mock client the rest of this repository already uses.
//
// stat is injected for one reason: it is the only way to assert that the filter above runs
// before the filesystem is touched. Asserting on the *result* cannot distinguish "alice was
// filtered out" from "alice was stat'd and then filtered out", and those differ by every
// blocking syscall this change exists to avoid. A recorder stat in the test makes the
// ordering an observable fact instead of a claim in a comment.
func homesFromUsers(rows []map[string]string, filter map[string]struct{},
	stat func(string) (os.FileInfo, error)) UserHomes {
	var result UserHomes
	// Ordered before anything is decided. Accounts share a home directory -- on macOS
	// /var/root is listed for both root and daemon, and /var/empty for seventy-nine service
	// accounts -- and the first one seen claims it. osquery does not promise a row order,
	// so without this the account reported for a shared home could differ between two runs
	// over an unchanged host, which differential logging reports as a row removed and
	// re-added. Sorted by identity rather than name because that is what stays stable when
	// an account is renamed.
	ordered := append([]map[string]string(nil), rows...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return accountID(ordered[i]) < accountID(ordered[j])
	})

	for _, row := range ordered {
		name, home := row["username"], row["directory"]
		if name == "" {
			// A row with no username but a real identity and home is not nothing: it is an
			// account the roster could not represent, and the difference between that and
			// "this host has no such configuration" is the whole point of the warning
			// column. Reported with an empty Name, which the caller already handles --
			// aggregating it for an unconstrained query and repeating it under each
			// requested username for a constrained one, so SQLite cannot discard it.
			result.Skipped = append(result.Skipped, Omission{
				ID: accountID(row), Path: home, Code: OmittedNoUsername,
				Reason: "the roster returned an account with no username, so it could not " +
					"be attributed or inspected"})
			continue
		}
		// Narrowed here, between the nameless check above and the first filesystem call
		// below. Above it on purpose: a row with no username always passes, because its
		// absence of a name is roster-level uncertainty rather than a statement about any
		// particular account, and the caller repeats it under every requested name. Below
		// the shell and home checks would defeat the point -- those are cheap, but the stat
		// after them is not, and this has to sit in front of the expensive one.
		if filter != nil {
			if _, requested := filter[name]; !requested {
				continue
			}
		}
		if _, nonLogin := nonLoginShells[row["shell"]]; nonLogin {
			result.NonLogin = append(result.NonLogin, Omission{
				Name: name, ID: accountID(row), Path: home, Code: OmittedNonLoginShell,
				Reason: "this account cannot log in, its shell being " + row["shell"] +
					", so it keeps no editor or agent configuration"})
			continue
		}
		if home == "" {
			// A named account with no home declared is not the same as an account with no
			// configuration. On Windows and on directory-managed hosts an account record
			// routinely exists before a profile has been created.
			result.Skipped = append(result.Skipped, Omission{
				Name: name, ID: accountID(row), Code: OmittedNoHomeDeclared,
				Reason:       "this account declares no home directory, so there was nowhere to look",
				HomeUnusable: true})
			continue
		}
		// Accounts sharing a home are all kept. Dropping the later ones deduplicated the
		// wrong thing: a `WHERE user = 'bob'` query then found no home for Bob at all,
		// because Alice had claimed the directory before the constraint was ever consulted,
		// and the result was indistinguishable from Bob having no configuration. Avoiding
		// the duplicate filesystem work is the caller's job, and it can do it after
		// filtering; see the scan cache in DiscoverAll.
		info, err := stat(home)
		if err != nil {
			// Reported either way, including ENOENT. An absent home is indistinguishable
			// from an automounted or network home that is offline right now, and those are
			// exactly the accounts whose configuration exists but cannot be read at this
			// moment. Skipping them silently turned a transient outage into a confident
			// empty answer for a specifically requested user.
			reason, unusable := "home directory could not be stat'd", os.IsNotExist(err)
			code := OmittedHomeUnstattable
			if unusable {
				reason = "the home directory this account declares does not exist, which " +
					"may mean it is offline rather than absent"
				code = OmittedHomeMissing
			}
			result.Skipped = append(result.Skipped, Omission{
				Name: name, ID: accountID(row), Path: home, Code: code,
				Reason: reason, HomeUnusable: unusable})
			continue
		}
		if redirectsElsewhere(info.Mode()) {
			// Refusing to follow is deliberate -- never traverse out of the home reported
			// for an account -- but the account behind it still goes unrepresented.
			result.Skipped = append(result.Skipped, Omission{
				Name: name, ID: accountID(row), Path: home, Code: OmittedHomeRedirected,
				Reason: "home directory is a symlink or reparse point, which is not followed"})
			continue
		}
		if !info.IsDir() {
			// The declared home exists but is a file, a device, a socket. No configuration
			// can be read from it, and silently dropping the account reported it as having
			// none rather than as never having been looked at.
			result.Skipped = append(result.Skipped, Omission{
				Name: name, ID: accountID(row), Path: home, Code: OmittedHomeNotDirectory,
				Reason:       "the home directory this account declares is not a directory",
				HomeUnusable: true})
			continue
		}
		result.Homes = append(result.Homes, UserHome{Name: name, ID: accountID(row), Path: home})
	}
	return result
}

// redirectsElsewhere reports whether a directory entry is a link to somewhere else rather
// than a directory in its own right. Used for a declared home, and on Windows for the base
// every read is anchored to.
//
// ModeIrregular alongside ModeSymlink, because on Windows a junction is the shape that
// matters and Go does not report it as a symlink. Testing ModeSymlink alone admitted one:
// the account was accepted, the junction became the trusted base that OpenBeneath roots
// os.Root at, and every read for that user resolved under the junction's target instead of
// the profile the roster named. platform_windows.go has used both bits as the reparse
// signal since it was written; this check is the one place that did not, 180 lines from the
// code that gets it right.
//
// Junctions need no privilege to create, which is what makes this worth refusing rather
// than resolving.
func redirectsElsewhere(mode os.FileMode) bool {
	return mode&(os.ModeSymlink|os.ModeIrregular) != 0
}
