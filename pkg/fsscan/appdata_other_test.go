//go:build !windows

package fsscan

import "testing"

// TestRoamingAppDataForIsNotApplicableOffWindows pins the contract of the non-Windows stub.
//
// The third return value carries two different meanings depending on platform, and the
// difference matters: on Windows false means "applicable but could not be determined", which
// the caller turns into a warning telling an administrator that account's configuration may
// be missing. Here it means "not applicable" -- there is no per-user indirection a policy can
// move, the root is a fixed subpath of the home — and no warning is owed. A caller that
// conflated the two would emit a spurious warning on every account on every macOS and Linux
// host, or suppress a real one on Windows.
func TestRoamingAppDataForIsNotApplicableOffWindows(t *testing.T) {
	path, redirected, ok := RoamingAppDataFor("S-1-5-21-1-2-3-1001", "/Users/alice")
	if ok {
		t.Error("ok must be false off Windows: there is no known folder to resolve")
	}
	if redirected {
		t.Error("redirected must be false: nothing can redirect a fixed subpath")
	}
	if path != "" {
		t.Errorf("path = %q, want empty", path)
	}
}
