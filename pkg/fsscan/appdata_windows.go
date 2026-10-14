//go:build windows

package fsscan

// PARTIALLY VERIFIED. Exercised on a real Windows host: resolution for the logged-on
// account through the already-mounted HKU\<SID> hive, redirection detected and reported
// when Roaming points outside the profile, and the account-scoped warning raised when the
// location cannot be determined. There is no Windows CI job, so nothing here is
// continuously exercised; `go vet` and cross-compilation are the only automated checks
// that see this file.
//
// Only a mounted hive is read. A logged-off account's NTUSER.DAT is not loaded, and that is
// a decision rather than a gap: an inventory query should not mount a registry hive.
//
// The previous version did, through RegLoadAppKey. That API is the right one for the job on
// paper -- private handle, no privilege, nothing published under HKEY_USERS -- but the job
// itself is wrong for a table that runs on a schedule. It opens a file another account owns,
// in a format whose parser is the kernel's, and it creates that file when it is absent, so
// the pre-check that stopped a read from writing was load-bearing. Against that, the thing
// it bought is one column for accounts that are not logged on, on the platform with no CI,
// via a path a single-user machine can never execute -- so it shipped unexercised and
// stayed that way.
//
// An account whose hive is not mounted now falls to the caller's existing "location could
// not be determined" diagnostic, which already says the right thing: this account's
// application-support configuration was not inspected. A missing row that announces itself
// is a better trade than a hive mount that works in theory.

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Roaming AppData is not always <profile>\AppData\Roaming.
//
// Windows lets Folder Redirection policy, or a user simply editing their shell-folder values,
// move the Roaming known folder to another volume or to a network share. On a host where
// that has been done, every VS Code, Claude Desktop and Cline configuration lives somewhere
// the conventional path does not reach, and a table that assumed the default reported those
// accounts as having no MCP servers at all.
//
// The redirected location is recorded per user in their own registry hive, under
// Shell Folders. A hive is mounted under HKEY_USERS only while that user is logged on, so
// this resolves the location for logged-on accounts and reports it as undetermined for the
// rest. See the header for why the alternative was removed rather than kept.
//
// The distinction that matters for correctness: failing to read the value is not the same as
// the value being absent. An unreadable hive means the Roaming location is unknown, and
// reporting the conventional path as though it were confirmed is what produced a clean empty
// result on a redirected host.

// shellFoldersKey holds the per-user known-folder overrides. The unexpanded form is
// preferred: the expanded twin caches a path resolved against whichever account's
// environment last wrote it, which is not this profile's when read from another context.
const (
	shellFoldersKey    = `Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
	shellFoldersValue  = "AppData"
	defaultRoamingPath = `AppData\Roaming`
)

// roamingAppData reports the Roaming AppData directory for one profile.
//
// ok is false when the location could not be established, which is deliberately distinct
// from it being the default: the caller turns that into a diagnostic rather than silently
// scanning the conventional path and calling the result complete.
func roamingAppData(sid, profileDir string) (path string, ok bool) {
	// Without a SID there is no hive to name, and HKU\<empty> is not a key that can be
	// opened. Checked rather than left to fail, because the empty string is what an account
	// with no identity in the roster supplies, and that is a routine case rather than an
	// error.
	if sid == "" {
		return "", false
	}
	if raw, found := shellFolderValue(sid); found {
		expanded := expandProfileVars(raw, profileDir)
		if expanded == "" {
			return "", false
		}
		return expanded, true
	}
	return "", false
}

// shellFolderValue reads the AppData entry from an account's mounted Shell Folders.
//
// One route, and it publishes nothing: HKU\<SID> is already mounted for a logged-on account,
// so this is an ordinary read of a key that exists independently of this process. An
// account whose hive is not mounted reports false, which the caller turns into a diagnostic.
func shellFolderValue(sid string) (string, bool) {
	return readShellFolder(registry.USERS, sid+`\`+shellFoldersKey)
}

// readShellFolder reads the AppData value from an already-mounted hive path.
func readShellFolder(root registry.Key, path string) (string, bool) {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer func() { _ = key.Close() }()
	value, _, err := key.GetStringValue(shellFoldersValue)
	if err != nil || value == "" {
		return "", false
	}
	return value, true
}

// expandProfileVars expands the one variable a Shell Folders value can be resolved against
// for another account, and refuses the rest.
//
// os.ExpandEnv is wrong here for the same reason the paths package derives roots from the
// home directory: %USERPROFILE% in the SYSTEM account's environment names SYSTEM's profile,
// so expanding with it would point every account at the same directory. The profile
// directory is what %USERPROFILE% means for the account being read, so that one substitutes
// exactly.
//
// %HOMEPATH% used to be substituted the same way and that was wrong twice over. It carries
// no drive -- Windows expands it as \Users\alice, with %HOMEDRIVE% holding C: -- so
// replacing it with a full profile path produces a string Windows would never produce. Worse,
// it is not a profile variable at all: on a domain-joined host HOMEDRIVE and HOMEPATH come
// from the account's directory home-folder attribute and commonly name a network share, so
// equating them with the local profile silently pointed AppData somewhere the account does
// not keep it -- and reported the result as confirmed. Resolving them properly needs that
// account's environment, which is the thing this file cannot read. Left unexpanded, so the
// guard below reports the location as undetermined.
func expandProfileVars(raw, profileDir string) string {
	expanded := raw
	for _, name := range []string{"%USERPROFILE%"} {
		if idx := strings.Index(strings.ToUpper(expanded), name); idx >= 0 {
			expanded = expanded[:idx] + profileDir + expanded[idx+len(name):]
		}
	}
	// Anything still unexpanded is a variable this does not know how to resolve for another
	// account; guessing would be worse than reporting the location as undetermined.
	if strings.Contains(expanded, "%") {
		return ""
	}
	return filepath.Clean(expanded)
}

// RoamingAppDataFor reports a profile's Roaming AppData directory and whether it differs
// from the conventional location, so a caller can warn rather than silently scan the wrong
// place.
//
// redirected is true only when the location was read and differs; an unreadable hive returns
// ok=false, which the caller must not treat as "the default applies".
func RoamingAppDataFor(sid, profileDir string) (path string, redirected, ok bool) {
	resolved, found := roamingAppData(sid, profileDir)
	if !found {
		return "", false, false
	}
	conventional := filepath.Join(profileDir, defaultRoamingPath)
	return resolved, !strings.EqualFold(filepath.Clean(resolved), conventional), true
}
