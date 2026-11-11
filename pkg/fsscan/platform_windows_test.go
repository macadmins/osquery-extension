//go:build windows

package fsscan

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/macadmins/osquery-extension/pkg/testutil"
)

// TestOpenBeneathRefusesAJunctionAtAnyComponent: a junction is refused wherever it sits in the
// path, including one whose target stays inside the base, which os.Root on its own would
// follow. The refusal classifies as refused_path, the Windows counterpart of ELOOP.
func TestOpenBeneathRefusesAJunctionAtAnyComponent(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, "real", "proj", "go.mod"), "module x\n")
	testutil.Junction(t, filepath.Join(home, "linked"), filepath.Join(home, "real"))

	for _, rel := range []string{
		filepath.Join("linked", "proj", "go.mod"), // the junction is an intermediate component
		"linked", // the junction is the final component
	} {
		file, err := OpenBeneath(home, rel)
		if err == nil {
			_ = file.Close()
			t.Errorf("OpenBeneath(%q) followed a junction", rel)
			continue
		}
		if class := ClassifyError(err); class != ClassRefusedPath {
			t.Errorf("OpenBeneath(%q) = %v (%s), want refused_path", rel, err, class)
		}
	}
	if err := ProbeProjectDir(home, filepath.Join("linked", "proj")); ClassifyError(err) != ClassRefusedPath {
		t.Errorf("ProbeProjectDir through a junction = %v, want refused_path", err)
	}
}

// TestOpenBeneathRefusesAJunctionedBase: a base directory that is itself a junction is refused,
// so a profile swapped for a junction cannot root every read at the junction's target.
func TestOpenBeneathRefusesAJunctionedBase(t *testing.T) {
	root := t.TempDir()
	testutil.WriteFile(t, filepath.Join(root, "elsewhere", "file"), "x")
	testutil.Junction(t, filepath.Join(root, "home"), filepath.Join(root, "elsewhere"))
	file, err := OpenBeneath(filepath.Join(root, "home"), "file")
	if err == nil {
		_ = file.Close()
		t.Fatal("OpenBeneath rooted a read at a junctioned base")
	}
	if !strings.Contains(err.Error(), "reparse point") {
		t.Errorf("err = %v, want a reparse-point refusal", err)
	}
}

// TestOpenBeneathRefusesASymlink: a symlink is a reparse point too. Creating one needs
// SeCreateSymbolicLinkPrivilege or Developer Mode, so the test is skipped without it.
func TestOpenBeneathRefusesASymlink(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, "real", "go.mod"), "module x\n")
	if err := os.Symlink(filepath.Join(home, "real"), filepath.Join(home, "linked")); err != nil {
		t.Skipf("creating a symlink needs a privilege this account lacks: %v", err)
	}
	if _, err := OpenBeneath(home, filepath.Join("linked", "go.mod")); ClassifyError(err) != ClassRefusedPath {
		t.Errorf("OpenBeneath through a symlink = %v, want refused_path", err)
	}
}

// TestReadProjectFileRefusesAHardLinkOnWindows: an NTFS hard link reports more than one link
// from GetFileInformationByHandle, and RefuseHardLinks refuses it.
func TestReadProjectFileRefusesAHardLinkOnWindows(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, "elsewhere.mod"), "module x\n")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(home, "elsewhere.mod"), filepath.Join(home, "proj", "go.mod")); err != nil {
		t.Skipf("hard links unavailable on this volume: %v", err)
	}
	_, err := ReadProjectFile(home, "proj", "go.mod", ReadOpts{MaxSize: 1 << 20, RefuseHardLinks: true})
	if ClassifyError(err) != ClassHardLink {
		t.Errorf("ReadProjectFile on a hard link = %v, want hard_link", err)
	}
}

// TestAnOrdinaryFileIsNotACloudPlaceholder runs the real attribute check on a local file.
func TestAnOrdinaryFileIsNotACloudPlaceholder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "go.mod")
	testutil.WriteFile(t, path, "module x\n")
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if placeholder, err := IsCloudPlaceholder(file); err != nil || placeholder {
		t.Errorf("IsCloudPlaceholder on a local file = %v, %v, want false", placeholder, err)
	}
}

// TestRoamingAppDataForTheCurrentAccount reads the running account's own hive, which is mounted
// because the account is logged on, and checks the answer against its profile.
func TestRoamingAppDataForTheCurrentAccount(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	path, redirected, ok := RoamingAppDataFor(user.User.Sid.String(), profile)
	if !ok || path == "" {
		t.Fatalf("RoamingAppDataFor the current account = %q, %v, %v, want a location", path, redirected, ok)
	}
	if !redirected && !strings.EqualFold(filepath.Clean(path), filepath.Join(profile, defaultRoamingPath)) {
		t.Errorf("an unredirected location = %q, want %q", path, filepath.Join(profile, defaultRoamingPath))
	}
}

// TestReadLinkBeneathIsUnsupportedOnWindows: Windows has no link reader here, so snap
// resolution, which is Linux only, and go_modules' one-hop follow of a symlinked module file
// both decline there. With its directory present it reports unsupported rather than an error
// about the path.
func TestReadLinkBeneathIsUnsupportedOnWindows(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "snap"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLinkBeneath(home, "snap", "current"); ClassifyError(err) != ClassUnsupported {
		t.Errorf("ReadLinkBeneath on Windows = %v (%s), want unsupported", err, ClassifyError(err))
	}
}

// TestAFileAsAnIntermediateComponentIsRefused: a path through a regular file is refused, as
// ENOTDIR is on POSIX, rather than read as absence, so a ~/.codex that is a file is reported.
func TestAFileAsAnIntermediateComponentIsRefused(t *testing.T) {
	home := t.TempDir()
	testutil.WriteFile(t, filepath.Join(home, "codex"), "not a directory")
	_, err := OpenBeneath(home, filepath.Join("codex", "config.toml"))
	if got := ClassifyError(err); got != ClassRefusedPath {
		t.Errorf("a path through a file = %v (%s), want refused_path", err, got)
	}
}

// TestReparseAttributesMatchWindows: the attribute values providerReparsePoint writes out are the
// ones golang.org/x/sys/windows defines, and its placeholder set is the one IsCloudPlaceholder
// reads.
func TestReparseAttributesMatchWindows(t *testing.T) {
	for _, tc := range []struct {
		name      string
		got, want uint32
	}{
		{"directory", fileAttributeDirectory, windows.FILE_ATTRIBUTE_DIRECTORY},
		{"offline", fileAttributeOffline, windows.FILE_ATTRIBUTE_OFFLINE},
		{"recall on open", fileAttributeRecallOnOpen, windows.FILE_ATTRIBUTE_RECALL_ON_OPEN},
		{"recall on data access", fileAttributeRecallOnDataAccess, windows.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS},
		{"placeholder set", fileAttributeRecallOnOpen | fileAttributeRecallOnDataAccess | fileAttributeOffline,
			cloudPlaceholderFlags},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %#x, want %#x", tc.name, tc.got, tc.want)
		}
	}
}

// TestExpandProfileVars: %USERPROFILE% is substituted as a prefix in any case, and a value with
// another variable, a variable anywhere else, a relative path or a ".." names no location this
// can determine. A UNC value is kept for the caller's containment check to refuse.
func TestExpandProfileVars(t *testing.T) {
	const profile = `C:\Users\alice`
	for _, tc := range []struct{ raw, want string }{
		{`%USERPROFILE%\AppData\Roaming`, `C:\Users\alice\AppData\Roaming`},
		{`%userprofile%\AppData\Roaming`, `C:\Users\alice\AppData\Roaming`},
		{`%USERPROFILE%/AppData/Roaming`, `C:\Users\alice\AppData\Roaming`},
		{`D:\Data\alice\AppData`, `D:\Data\alice\AppData`},
		{`\\server\share\alice\AppData`, `\\server\share\alice\AppData`},
		// Anywhere but the start is not where Windows writes it.
		{`C:\x\%USERPROFILE%\AppData`, ""},
		{"\u0131" + `%USERPROFILE%\AppData`, ""},
		{`%HOMEPATH%\AppData\Roaming`, ""},
		{`%USERPROFILE%\..\bob\AppData`, ""},
		{`%USERPROFILE%/../bob/AppData`, ""},
		{`AppData\Roaming`, ""},
	} {
		if got := expandProfileVars(tc.raw, profile); got != tc.want {
			t.Errorf("expandProfileVars(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// TestPrivilegedOwner: LocalSystem, BUILTIN\Administrators and TrustedInstaller pass an owner
// check for any account, and another SID does not.
func TestPrivilegedOwner(t *testing.T) {
	for sid, want := range map[string]bool{
		"S-1-5-18":     true,
		"S-1-5-32-544": true,
		"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true,
		"S-1-5-32-545":        false, // BUILTIN\Users
		"S-1-5-21-1-2-3-1001": false,
		"":                    false,
	} {
		if got := privilegedOwner(sid); got != want {
			t.Errorf("privilegedOwner(%q) = %v, want %v", sid, got, want)
		}
	}
}

// TestReadBoundedUnderChecksTheOwnerSID: a file the test creates reads for the process user's
// SID and is refused for another account's, unless its owner is privileged. A runner account
// can be an administrator, which makes new files Administrators-owned, so the actual owner is
// read and the assertion follows it.
func TestReadBoundedUnderChecksTheOwnerSID(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "f.json")
	testutil.WriteFile(t, path, `{}`)
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := tokenUser.User.Sid.String()
	if privilegedOwner(me) {
		t.Skip("the test runs as a privileged account, which every owner check passes")
	}
	// Required rather than skipped on failure, so this test always exercises the match against
	// the account's own SID and the refusal of another.
	if err := testutil.OwnAsTestAccount(base); err != nil {
		t.Fatalf("giving the fixture to the test account: %v", err)
	}
	if owner := fileOwner(t, path); owner != me {
		t.Fatalf("the fixture is owned by %s, want the test account %s", owner, me)
	}
	if _, err := ReadBoundedUnder(base, "f.json", ReadOpts{MaxSize: 1024, OwnerUID: me}); err != nil {
		t.Errorf("a file owned by the expected SID must read: %v", err)
	}
	_, err = ReadBoundedUnder(base, "f.json", ReadOpts{MaxSize: 1024, OwnerUID: "S-1-5-21-1-2-3-1001"})
	if !errors.Is(err, ErrOwnerMismatch) {
		t.Fatalf("expected ErrOwnerMismatch, got %v", err)
	}
	if got := ClassifyError(err); got != ClassOwnerMismatch {
		t.Errorf("ClassifyError = %q, want %q", got, ClassOwnerMismatch)
	}
}

// TestReadBoundedUnderReadsAPrivilegedOwnersFile: a file a privileged group owns, as a file an
// elevated administrator creates is, reads for any account.
func TestReadBoundedUnderReadsAPrivilegedOwnersFile(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "f.json")
	testutil.WriteFile(t, path, `{}`)
	if owner := fileOwner(t, path); !privilegedOwner(owner) {
		t.Skipf("the fixture is owned by %s, not a privileged owner", owner)
	}
	if _, err := ReadBoundedUnder(base, "f.json", ReadOpts{MaxSize: 1024,
		OwnerUID: "S-1-5-21-1-2-3-1001"}); err != nil {
		t.Errorf("a file a privileged owner holds must read for any account: %v", err)
	}
}

// fileOwner returns the SID that owns path.
func fileOwner(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	return owner.String()
}
