package devclients

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
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

// AppSupportDir is the directory, relative to a user home, where desktop applications keep
// per-user support files:
//
//	macOS    ~/Library/Application Support
//	Windows  %APPDATA%          -> ~/AppData/Roaming
//	Linux    ~/.config, which is $XDG_CONFIG_HOME's *default* and not necessarily its value
//
// KNOWN GAP on Linux: XDG_CONFIG_HOME can name any absolute directory, and Electron resolves
// a VS Code fork's userData under it when it is set, so a native install can keep its active
// configuration somewhere this never looks. The daemon's own environment is the wrong source,
// because it belongs to the daemon's account, which is the reason these roots are derived from
// the home directory. Core osquery's process_envs table reports the environment of each
// running process, which an extension can query through its socket, but only while one of the
// account's processes is running, and each process can carry a different value. Until that is
// used, this reports the conventional location only. The snap and flatpak handling below
// covers redirected sandboxes, not this.
//
// Windows Roaming rather than Local is correct for every client here: VS Code, Claude
// Desktop and the Cline extension all write user configuration to Roaming, reserving Local
// for caches and machine-specific state.
func AppSupportDir() string {
	return AppSupportDirFor(runtime.GOOS)
}

// AppSupportDirFor takes the OS as a parameter so every platform's answer is reachable from
// a test on any host. The test, lint and coverage workflows run on ubuntu-latest and only the
// build workflow runs on macOS, so no job executes the Darwin branch and none executes the
// Windows one; parameterising the OS is what gets all three spellings asserted anywhere.
func AppSupportDirFor(goos string) string {
	switch goos {
	case "windows":
		return filepath.Join("AppData", "Roaming")
	case "linux":
		return ".config"
	default:
		return filepath.Join("Library", "Application Support")
	}
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

// AppSupportFork returns every path, relative to a user home, under which fork keeps the
// named file: one per application-support root the fork can have on this OS.
//
// On macOS and Windows that is always exactly one. On Linux it is one plus the sandbox roots
// for forks that have them, so a host with both a native and a snap install of the same
// editor reports both rather than whichever the default root happens to hit. Probing a root
// that does not exist costs one failed open and produces no row.
func AppSupportFork(fork string, parts ...string) []string {
	return AppSupportForkFor(runtime.GOOS, fork, parts...)
}

// AppSupportForkFor is AppSupportFork with the OS supplied, for the same reason
// AppSupportDirFor exists.
func AppSupportForkFor(goos, fork string, parts ...string) []string {
	joined := append([]string{AppSupportDirFor(goos), fork}, parts...)
	out := []string{filepath.Join(joined...)}
	if goos != "linux" {
		return out
	}
	for _, root := range linuxSandboxRoots[fork] {
		out = append(out, filepath.Join(append([]string{root, fork}, parts...)...))
	}
	return out
}

// Fork is one VS Code family editor: the directory name it uses under the application-support
// root, and the client name a table reports for it.
type Fork struct {
	Dir    string
	Client string
}

// VSCodeFamily are the VS Code family editors that keep user-scope configuration, each with
// the client name reported for it. Insiders and VSCodium report as "vscode" because they are
// the same editor and an operator filtering `client = 'vscode'` means all of them.
var VSCodeFamily = []Fork{
	{"Code", "vscode"},
	{"Code - Insiders", "vscode"},
	{"Cursor", "cursor"},
	{"Windsurf", "windsurf"},
	{"VSCodium", "vscode"},
}

// snapCurrentDir is the stable name snap gives the symlink pointing at the installed
// revision of a snap: ~/snap/<name>/current -> ~/snap/<name>/168.
const snapCurrentDir = "current"

// ResolveSnapPath rewrites a relative path containing snap's `current` pointer to name the
// revision directory it points at, and reports whether the path is usable at all.
//
// Necessary because `current` is a symlink and this package refuses to traverse symlinks:
// every read under ~/snap/<name>/current failed with the refusal, and the refusal is
// indistinguishable from absence, so the snap paths could never produce a row. Refusing is
// right -- a symlink in a user-writable tree is exactly the redirection this package refuses
// to follow -- so the pointer is resolved explicitly instead, under rules that leave nothing
// for it to redirect to:
//
//   - the link is read relative to its parent directory, opened with symlinks refused at
//     every component from the home down, and the link itself is not followed;
//   - the target must be a single relative component, so it cannot escape ~/snap/<name>;
//   - the target must look like a snap revision, so it cannot name an arbitrary directory.
//
// The resolved path is then traversed by the ordinary component-by-component open, which
// still refuses a symlink anywhere else along it.
func ResolveSnapPath(home, relPath string) (string, bool) {
	parts := strings.Split(filepath.ToSlash(relPath), "/")
	if len(parts) < 4 || parts[0] != "snap" || parts[2] != snapCurrentDir {
		return relPath, true // not a snap path; nothing to resolve
	}
	// Read relative to ~/snap/<name> opened with symlinks refused at every component, so a
	// symlinked ~/snap or ~/snap/<name> is refused rather than followed to resolve the link.
	// An absent pointer, or one that is not a symlink, fails the read, and either way there is
	// no revision to scan.
	target, err := fsscan.ReadLinkBeneath(home, filepath.Join(parts[0], parts[1]), snapCurrentDir)
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

// WithinHome reports whether an absolute path lies beneath home. Redirection inside the
// profile is still reachable by the ordinary bounded, symlink-refusing traversal; redirection
// outside it is not, because that traversal is anchored to the home on purpose.
func WithinHome(path, home string) bool {
	rel, err := filepath.Rel(home, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// RedirectAppSupport rewrites an application-support-relative path to sit under a redirected
// roaming root. It reports usable=false when the source cannot be reached at all, which is
// the out-of-profile case the caller has already warned about.
func RedirectAppSupport(relPath, appDataRoot, home string) (rewritten string, usable bool) {
	if appDataRoot == "" {
		return "", true // conventional location; relPath already correct
	}
	prefix := AppSupportDir() + string(os.PathSeparator)
	if !strings.HasPrefix(relPath, prefix) {
		return "", true // a dotfile source, unaffected by where AppData points
	}
	if !WithinHome(appDataRoot, home) {
		return "", false
	}
	rel, err := filepath.Rel(home, appDataRoot)
	if err != nil {
		return "", false
	}
	return filepath.Join(rel, strings.TrimPrefix(relPath, prefix)), true
}
