package devclients

import (
	"github.com/macadmins/osquery-extension/pkg/fsscan"
)

// ScanKey names everything per-account discovery depends on, so a result cached for one account
// is reused for another only where it would be identical: the account's identity and its home.
//
// The home path alone is wrong on every platform. Every read refuses a file another account
// owns, judged against the account being scanned, so the same directory read for two accounts
// with different uids can yield rows for one and owner_mismatch refusals for the other. On
// Windows discovery also resolves Roaming AppData from the registry hive named by the
// account's SID, so two accounts reporting the same profile path can have different roaming
// roots. Keyed on path alone, the first account scanned decides the answer for the rest, and
// relabeling its rows attributes one account's inventory, or its refusals, to another.
//
// Accounts that share both an identity and a home, as several POSIX accounts can share a uid,
// still share one scan.
func ScanKey(account fsscan.UserHome) string {
	return account.ID + "\x00" + account.Path
}
