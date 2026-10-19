//go:build windows

package fsscan

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// junction creates a directory junction at link that points at target. A junction needs no
// privilege, unlike a symlink, so it is the reparse point an unprivileged account can plant and
// the one these tests use. The test is skipped if mklink is unavailable.
func junction(t *testing.T, link, target string) {
	t.Helper()
	if output, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("mklink /J failed: %v: %s", err, output)
	}
}

// TestOpenBeneathRefusesAJunctionAtAnyComponent: a junction is refused wherever it sits in the
// path, including one whose target stays inside the base, which os.Root on its own would
// follow. The refusal classifies as refused_path, the Windows counterpart of ELOOP.
func TestOpenBeneathRefusesAJunctionAtAnyComponent(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, "real", "proj", "go.mod"), "module x\n")
	junction(t, filepath.Join(home, "linked"), filepath.Join(home, "real"))

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
	writeFile(t, filepath.Join(root, "elsewhere", "file"), "x")
	junction(t, filepath.Join(root, "home"), filepath.Join(root, "elsewhere"))
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
	writeFile(t, filepath.Join(home, "real", "go.mod"), "module x\n")
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
	writeFile(t, filepath.Join(home, "elsewhere.mod"), "module x\n")
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
	writeFile(t, path, "module x\n")
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

// TestReadLinkBeneathIsUnsupportedOnWindows: the snap resolution it serves is Linux only, so
// with its directory present it reports unsupported rather than an error about the path.
func TestReadLinkBeneathIsUnsupportedOnWindows(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "snap"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLinkBeneath(home, "snap", "current"); ClassifyError(err) != ClassUnsupported {
		t.Errorf("ReadLinkBeneath on Windows = %v (%s), want unsupported", err, ClassifyError(err))
	}
}
