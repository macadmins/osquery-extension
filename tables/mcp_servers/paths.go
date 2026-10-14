package mcp_servers

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Per-OS application-data roots, derived from a user home rather than from the environment.
//
// Deriving them from the home directory is deliberate and not merely convenient: this table
// scans every user's home as root or SYSTEM, and the environment it can read is the
// daemon's, not theirs. %APPDATA% and $XDG_CONFIG_HOME describe the account running the
// process. Reconstructing the conventional location under each home is the only way to get
// the right answer for an account nobody is logged into.
//
// Everything else a client stores is a dotfile directly under the home -- .claude.json,
// .cursor/mcp.json, .codex/config.toml -- and those paths are identical on all three
// platforms, which is why only this one root needs to vary.

// appSupportDir is the directory, relative to a user home, where desktop applications keep
// per-user support files:
//
//	macOS    ~/Library/Application Support
//	Windows  %APPDATA%          -> ~/AppData/Roaming
//	Linux    ~/.config, which is $XDG_CONFIG_HOME's *default* and not necessarily its value
//
// KNOWN GAP on Linux: XDG_CONFIG_HOME can name any
// absolute directory, and Electron resolves a VS Code fork's userData under it when it is
// set, so a native install can keep its active mcp.json somewhere this never looks. Reading
// the variable is not available -- the environment belongs to the daemon's account, not to
// the account being scanned, which is the whole reason these roots are derived from the home
// directory. Resolving it per account needs a source that records it (a login manager or the
// user's own systemd environment), and until there is one this reports the conventional
// location only. The snap and flatpak handling below covers redirected sandboxes, not this.
//
// Windows Roaming rather than Local is correct for every client here: VS Code, Claude
// Desktop and the Cline extension all write user configuration to Roaming, reserving Local
// for caches and machine-specific state.
func appSupportDir() string {
	return appSupportDirFor(runtime.GOOS)
}

// appSupportDirFor takes the OS as a parameter so every platform's answer is reachable from
// a test on any host. The test, lint and coverage workflows run on ubuntu-latest and only the
// build workflow runs on macOS, so no job executes the Darwin branch and none executes the
// Windows one; parameterising the OS is what gets all three spellings asserted anywhere.
func appSupportDirFor(goos string) string {
	switch goos {
	case "windows":
		return filepath.Join("AppData", "Roaming")
	case "linux":
		return ".config"
	default:
		return filepath.Join("Library", "Application Support")
	}
}

// appSupport joins parts beneath the per-OS application-support root, producing a path
// relative to a user home with native separators.
func appSupport(parts ...string) string {
	return filepath.Join(append([]string{appSupportDir()}, parts...)...)
}

// linuxSandboxRoots maps a VS Code family fork's application-support directory name to the
// extra roots a sandboxed Linux install keeps its configuration under.
//
// A snap or flatpak editor does not write to ~/.config at all: the sandbox redirects the
// config directory into the app's own tree, so the user-scope mcp.json of a snap-installed
// VS Code lives at ~/snap/code/current/.config/Code/User/mcp.json and a flatpak's at
// ~/.var/app/com.visualstudio.code/config/Code/User/mcp.json. Without these the table
// reports nothing for that editor and says nothing about why, which is the silent
// incompleteness the warning column exists to avoid.
//
// Keyed per fork because the snap name and the flatpak application id are per fork and
// follow no derivable rule -- "Code - Insiders" is the snap "code-insiders" and the flatpak
// "com.visualstudio.code.insiders", while VSCodium is "codium" and "com.vscodium.codium".
//
// Only the forks with an official sandboxed channel appear. Cursor and Windsurf ship as
// AppImage and .deb, which write to ~/.config like a native install and are already covered
// by the default root; an entry for them would add two directory probes per user that can
// never match.
var linuxSandboxRoots = map[string][]string{
	"Code": {
		filepath.Join("snap", "code", "current", ".config"),
		filepath.Join(".var", "app", "com.visualstudio.code", "config"),
	},
	"Code - Insiders": {
		filepath.Join("snap", "code-insiders", "current", ".config"),
		filepath.Join(".var", "app", "com.visualstudio.code.insiders", "config"),
	},
	"VSCodium": {
		filepath.Join("snap", "codium", "current", ".config"),
		filepath.Join(".var", "app", "com.vscodium.codium", "config"),
	},
}

// appSupportFork returns every path, relative to a user home, under which fork keeps the
// named file: one per application-support root the fork can have on this OS.
//
// On macOS and Windows that is always exactly one. On Linux it is one plus the sandbox roots
// for forks that have them, so a host with both a native and a snap install of the same
// editor reports both rather than whichever the default root happens to hit. Probing a root
// that does not exist costs one failed open and produces no row.
func appSupportFork(fork string, parts ...string) []string {
	return appSupportForkFor(runtime.GOOS, fork, parts...)
}

// appSupportForkFor is appSupportFork with the OS supplied, for the same reason
// appSupportDirFor exists.
func appSupportForkFor(goos, fork string, parts ...string) []string {
	joined := append([]string{appSupportDirFor(goos), fork}, parts...)
	out := []string{filepath.Join(joined...)}
	if goos != "linux" {
		return out
	}
	for _, root := range linuxSandboxRoots[fork] {
		out = append(out, filepath.Join(append([]string{root, fork}, parts...)...))
	}
	return out
}

// vscodeFamily are the VS Code family editors that keep user-scope MCP configuration, each
// with the client name reported for it. Insiders and VSCodium report as "vscode" because
// they are the same editor and an operator filtering `client = 'vscode'` means all of them.
var vscodeFamily = []struct {
	dir    string
	client string
}{
	{"Code", "vscode"},
	{"Code - Insiders", "vscode"},
	{"Cursor", "cursor"},
	{"Windsurf", "windsurf"},
	{"VSCodium", "vscode"},
}

// clineHostDirs are the forks whose extension storage Cline writes into. Insiders is absent
// because the extension's storage path is shared with the stable channel.
var clineHostDirs = []string{"Code", "Cursor", "Windsurf", "VSCodium"}

// clineSettingsParts is the path below a fork's application-support directory where Cline
// keeps its MCP settings.
var clineSettingsParts = []string{
	"User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json",
}

// vscodeFamilySources builds the direct sources for the VS Code family: each fork's own
// user-scope mcp.json and each fork's Cline extension storage, once per application-support
// root that fork can have.
//
// Generated rather than written out because the list is the cross product of forks and
// roots, and on Linux that cross product is not uniform -- three of the five forks have two
// extra roots and two have none. The hand-written form had one line per path, which was
// already ten lines on macOS and would have been twenty-two here, with the per-fork sandbox
// names repeated in each.
//
// Each is a fixed path, so each is probed directly.
func vscodeFamilySources() []probe {
	var out []probe
	for _, fork := range vscodeFamily {
		for _, relPath := range appSupportFork(fork.dir, "User", "mcp.json") {
			out = append(out, probe{
				relPath: relPath,
				client:  fork.client,
				jsonc:   true,
				extract: extractEnvelopeSimple,
			})
		}
	}
	for _, dir := range clineHostDirs {
		for _, relPath := range appSupportFork(dir, clineSettingsParts...) {
			out = append(out, probe{
				relPath: relPath,
				client:  "cline",
				jsonc:   true,
				extract: extractEnvelopeSimple,
			})
		}
	}
	return out
}

// vscodeProfileDirs returns the per-fork directories holding one subdirectory per VS Code
// profile, each of which may carry its own mcp.json.
//
// The profile directory name is generated by the editor, so this is one of exactly two places
// in the table where a fixed path cannot name the file. It is read with
// fsscan.ListDirNamesUnder -- one directory read, no recursion, capped -- rather than by
// walking, which is the shape the review asked for and the only shape that reaches a
// generated name without reaching everything else as well.
//
// Dropping this rather than replacing it was the alternative, and it would have lost every
// per-profile configuration on the host in silence. A user with a work profile and a personal
// profile keeps a different mcp.json in each, and the user-scope file the probes above read is
// neither of them.
func vscodeProfileDirs() []profileRoot {
	var out []profileRoot
	for _, fork := range vscodeFamily {
		for _, relPath := range appSupportFork(fork.dir, "User", "profiles") {
			out = append(out, profileRoot{relPath: relPath, client: fork.client})
		}
	}
	return out
}

// profileRoot pairs a profile directory with the client that owns it.
//
// The pairing is carried rather than rediscovered. The deleted classifier worked backwards
// from a path to a client, recognising the VS Code family by the conventional
// application-support root -- which stops being in the path the moment Windows Roaming
// AppData is redirected. A profile config under a redirected root was then found, classified
// as "unknown", and invisible to `WHERE client = 'cursor'`: present in the table and absent
// from the query an administrator would actually write. The enumeration already knows which
// fork's directory it is listing, so it says so rather than leaving it to be inferred.
type profileRoot struct {
	relPath string
	client  string
}

// snapCurrentDir is the stable name snap gives the symlink pointing at the installed
// revision of a snap: ~/snap/<name>/current -> ~/snap/<name>/168.
const snapCurrentDir = "current"

// resolveSnapPath rewrites a relative path containing snap's `current` pointer to name the
// revision directory it points at, and reports whether the path is usable at all.
//
// Necessary because `current` is a symlink and this package refuses to traverse symlinks:
// every read under ~/snap/<name>/current failed with the refusal, and the refusal is
// indistinguishable from absence, so the snap paths could never produce a row. Refusing is
// right -- a symlink in a user-writable tree is exactly the redirection this package refuses
// to follow -- so the pointer is resolved explicitly instead, under rules that leave nothing
// for it to redirect to:
//
//   - the link is read with Readlink, which does not follow it;
//   - the target must be a single relative component, so it cannot escape ~/snap/<name>;
//   - the target must look like a snap revision, so it cannot name an arbitrary directory.
//
// The resolved path is then traversed by the ordinary component-by-component open, which
// still refuses a symlink anywhere else along it.
func resolveSnapPath(home, relPath string) (string, bool) {
	parts := strings.Split(filepath.ToSlash(relPath), "/")
	if len(parts) < 4 || parts[0] != "snap" || parts[2] != snapCurrentDir {
		return relPath, true // not a snap path; nothing to resolve
	}
	link := filepath.Join(home, parts[0], parts[1], snapCurrentDir)
	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		// Absent, or not the pointer we expect. Either way there is no revision to scan.
		return "", false
	}
	target, err := os.Readlink(link)
	if err != nil || !isSnapRevision(target) {
		return "", false
	}
	parts[2] = target
	return filepath.Join(parts...), true
}

// isSnapRevision reports whether a `current` link target is a plausible revision directory:
// a single relative component that is a revision number, optionally x-prefixed for a snap
// installed from a local file rather than the store.
//
// Deliberately narrow. The point of resolving the link by hand is to keep the guarantee the
// symlink refusal provided, and accepting an arbitrary target would hand it back.
func isSnapRevision(target string) bool {
	if target == "" || target == "." || target == ".." || strings.ContainsAny(target, `/\`) {
		return false
	}
	digits := strings.TrimPrefix(target, "x")
	if digits == "" {
		return false
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// The flatpak and snap sandbox locations are reached as explicit probe paths rather than
// recognised from a path after the fact.
//
// A path-shaped recogniser lived here -- isAppSupportPath, matching the platform's
// application-support root plus a flatpak `/.var/app/.../config/` marker -- because the walk
// found files first and had to work out afterwards which client owned them. appSupportForkFor
// already generates the sandbox roots per fork, so the probe list names those locations
// directly and there is nothing left to recognise. That also removes the case-sensitivity
// problem the deleted classifier documented: a generated path is compared by the filesystem,
// not by this package.
