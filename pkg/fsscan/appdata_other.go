//go:build !windows

package fsscan

// RoamingAppDataFor is Windows-only. Elsewhere the per-user configuration root is a fixed
// location under the home -- ~/Library/Application Support, ~/.config -- with no per-account
// indirection a policy can move, so there is nothing to resolve and nothing to be uncertain
// about.
//
// ok is false to mean "not applicable here", which callers must distinguish from Windows's
// false, meaning "applicable but could not be determined". The caller does that by branching
// on GOOS rather than on this value alone.
func RoamingAppDataFor(string, string) (path string, redirected, ok bool) {
	return "", false, false
}
