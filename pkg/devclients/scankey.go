package devclients

import (
	"runtime"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
)

// ScanKey names everything per-account discovery depends on, so a result cached for one account
// is reused for another only where it would be identical.
//
// The home path alone is wrong on Windows. Discovery resolves Roaming AppData from the
// registry hive named by the account's SID, so two accounts reporting the same profile path
// can have different roaming roots, different warnings and different rows. Keyed on path
// alone, the first account scanned decides the answer for the rest, and relabeling the rows
// attributes one account's redirected AppData, or its "could not be determined" warning, to
// another.
//
// Elsewhere discovery is a pure function of the directory, so the path is the whole key and
// a shared home is scanned once.
func ScanKey(account fsscan.UserHome) string {
	return ScanKeyFor(runtime.GOOS, account)
}

// ScanKeyFor takes the OS as a parameter so the Windows rule is reachable from a test on any
// host; no CI job runs on Windows.
func ScanKeyFor(goos string, account fsscan.UserHome) string {
	if goos == "windows" {
		return account.ID + "\x00" + account.Path
	}
	return account.Path
}
