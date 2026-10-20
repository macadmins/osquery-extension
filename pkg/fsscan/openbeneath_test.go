//go:build unix

package fsscan

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenBeneath_HappyPath(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "a", "b", "c.json"), []byte(`hello`), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := OpenBeneath(base, "a/b/c.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	got, _ := io.ReadAll(f)
	if string(got) != "hello" {
		t.Errorf("got %q, want hello", got)
	}
}

func TestOpenBeneath_RefusesIntermediateSymlink(t *testing.T) {
	// This is the threat the function defends against. Build:
	//
	//   base/Library -> /tmp/xxx-target/   (intermediate symlink)
	//   target/Application Support/Claude/foo.json (the file we'd read if symlink followed)
	//
	// OpenBeneath must refuse to traverse "Library".
	base := t.TempDir()
	target := t.TempDir()
	deepRel := "Application Support/Claude/foo.json"
	if err := os.MkdirAll(filepath.Dir(filepath.Join(target, deepRel)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, deepRel), []byte("victim-data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(base, "Library")); err != nil {
		t.Fatal(err)
	}

	_, err := OpenBeneath(base, "Library/"+deepRel)
	if err == nil {
		t.Fatal("expected error, intermediate symlink should be refused")
	}
	// Should be ELOOP from O_NOFOLLOW.
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		if !errors.Is(pathErr.Err, syscall.ELOOP) {
			t.Logf("note: got non-ELOOP error (still refused, just verifying expected sentinel): %v", err)
		}
	}
}

// TestASymlinkedIntermediateDirectoryIsRefusedNotAbsent: a symlinked directory partway down the
// path is a refusal, which IsNotDirectory does not report, while a regular file partway down is
// a path that cannot exist, which it does. go_modules' linkTarget and ListDirNamesCapped both
// tell the two apart with IsNotDirectory.
func TestASymlinkedIntermediateDirectoryIsRefusedNotAbsent(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "real", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "real", "sub", "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "plain"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"link/sub/f", "link/sub"} {
		_, err := OpenBeneath(base, rel)
		if ClassifyError(err) != ClassRefusedPath || IsNotDirectory(err) {
			t.Errorf("%s: class %q, IsNotDirectory %v; want a refusal that is not a "+
				"non-directory: %v", rel, ClassifyError(err), IsNotDirectory(err), err)
		}
	}
	_, err := OpenBeneath(base, "plain/f")
	if ClassifyError(err) != ClassRefusedPath || !IsNotDirectory(err) {
		t.Errorf("a regular file partway down: class %q, IsNotDirectory %v; want a "+
			"non-directory: %v", ClassifyError(err), IsNotDirectory(err), err)
	}
}

// TestListDirNamesCappedReportsARefusedDirectory: a symlink anywhere on the path to a listed
// directory is an error the caller reports, while absence and a regular file partway down are
// silent, because nothing beneath them can exist.
func TestListDirNamesCappedReportsARefusedDirectory(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "real", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "plain"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"link", "link/sub"} {
		if _, _, err := ListDirNamesCapped(base, rel, 5); ClassifyError(err) != ClassRefusedPath {
			t.Errorf("%s: err = %v, want a refusal", rel, err)
		}
	}
	for _, rel := range []string{"missing", "plain/sub"} {
		if names, truncated, err := ListDirNamesCapped(base, rel, 5); err != nil || truncated || names != nil {
			t.Errorf("%s: %v %v %v, want silence", rel, names, truncated, err)
		}
	}
}

func TestOpenBeneath_RefusesFinalSymlink(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "target.json"), []byte(`x`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "target.json"), filepath.Join(base, "link.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBeneath(base, "link.json"); err == nil {
		t.Fatal("final-component symlink should be refused")
	}
}

func TestOpenBeneath_RefusesDotDot(t *testing.T) {
	base := t.TempDir()
	if _, err := OpenBeneath(base, "../etc/passwd"); err == nil {
		t.Fatal("'..' must be rejected")
	}
}

func TestOpenBeneath_RefusesAbsolute(t *testing.T) {
	base := t.TempDir()
	if _, err := OpenBeneath(base, "/etc/passwd"); err == nil {
		t.Fatal("absolute path must be rejected")
	}
}

func TestOpenBeneath_RefusesSymlinkedBaseDir(t *testing.T) {
	root := t.TempDir()
	realBase := filepath.Join(root, "real")
	if err := os.Mkdir(realBase, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realBase, "f.json"), []byte(`x`), 0o644); err != nil {
		t.Fatal(err)
	}
	linkedBase := filepath.Join(root, "link")
	if err := os.Symlink(realBase, linkedBase); err != nil {
		t.Fatal(err)
	}
	// baseDir itself is a symlink: must be refused.
	if _, err := OpenBeneath(linkedBase, "f.json"); err == nil {
		t.Fatal("symlinked baseDir must be refused")
	}
}

func TestReadBoundedUnder_HappyPath(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "f.json"), []byte(`hello`), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadBoundedUnder(base, "f.json", ReadOpts{MaxSize: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("%q", got)
	}
}

// TestReadBoundedUnderRefusesAPlaceholder: a file at a fixed path in the home that the platform
// reports as evicted is refused before it is read, as a project file is. Only ReadProjectFile
// consulted the attribute, so every home configuration file and followed link was read.
func TestReadBoundedUnderRefusesAPlaceholder(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "f.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	evicted := ReadOpts{MaxSize: 1024, CloudPlaceholder: func(*os.File) (bool, error) { return true, nil }}
	if _, err := ReadBoundedUnder(base, "f.json", evicted); ClassifyError(err) != ClassCloudPlaceholder {
		t.Errorf("an evicted file: %v, want cloud_placeholder", err)
	}
	broken := ReadOpts{MaxSize: 1024, CloudPlaceholder: func(*os.File) (bool, error) {
		return false, os.ErrPermission
	}}
	if data, err := ReadBoundedUnder(base, "f.json", broken); err != nil || string(data) != "{}" {
		t.Errorf("a failing attribute check: %q %v, want the file read", data, err)
	}
}

func TestReadBoundedUnder_SizeCapEnforced(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "f.json"), []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBoundedUnder(base, "f.json", ReadOpts{MaxSize: 5}); err == nil {
		t.Fatal("expected size cap error")
	}
}

// The contract says ".." is rejected. filepath.Clean ran first, so a/../secret.json collapsed
// to secret.json and was accepted -- nothing escaped, because Clean normalises within the base,
// but a caller reasoning about which path was opened was being told the wrong thing.
func TestSplitSafeComponentsRejectsInteriorDotDot(t *testing.T) {
	for _, rejected := range []string{
		"..",
		"../secret.json",
		"a/../secret.json",
		"a/b/../../secret.json",
		"a/../../outside.json",
	} {
		if _, err := splitSafeComponents(rejected); err == nil {
			t.Errorf("splitSafeComponents(%q) accepted a path containing ..", rejected)
		}
	}
	for _, accepted := range []string{
		".cursor/mcp.json",
		"Library/Application Support/Claude/claude_desktop_config.json",
		"./a/b.json",
		"a/./b.json",
	} {
		if _, err := splitSafeComponents(accepted); err != nil {
			t.Errorf("splitSafeComponents(%q) = %v, want accepted", accepted, err)
		}
	}
}

// A FIFO planted where a config file is expected must neither be read nor block the reader.
//
// O_NONBLOCK on the final component is what makes the open return at all: without it this
// hangs until something opens the other end, and the thing hanging is a root daemon inside
// osquery's watchdog timeout. O_NONBLOCK does not reject a FIFO, it only keeps the open from
// blocking, so the regular-file check is what turns it into a refusal.
func TestReadBoundedUnder_FIFODoesNotHang(t *testing.T) {
	base := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(base, "f.json"), 0o644); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	_, err := ReadBoundedUnder(base, "f.json", ReadOpts{MaxSize: 1024})
	if !errors.Is(err, ErrNotRegular) {
		t.Fatalf("a FIFO must be refused as not a regular file, got %v", err)
	}
}

// A refused symlink has to classify as benign absence, not as a finding.
//
// The refusal is expected whenever another local user plants a trap, and the error text
// carries the path they chose -- so a caller that reported it instead of skipping would be
// publishing attacker-supplied bytes into a table column.
func TestOpenBeneathSymlinkRefusalReadsAsExpectedAbsence(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "t.json"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "t.json"), filepath.Join(base, "l.json")); err != nil {
		t.Fatal(err)
	}
	_, err := ReadBoundedUnder(base, "l.json", ReadOpts{MaxSize: 1024})
	if err == nil {
		t.Fatal("expected the symlink to be refused")
	}
	if !IsExpectedAbsent(err) {
		t.Errorf("ELOOP not classified as benign absence: %v", err)
	}
	if got := ClassifyError(err); got != ClassRefusedPath {
		t.Errorf("ClassifyError = %q, want %q", got, ClassRefusedPath)
	}
}

// Every descriptor OpenBeneath opens carries FD_CLOEXEC.
//
// os.OpenFile sets it because the runtime does that for every fd it owns, but the traversal
// is built out of unix.Open and unix.Openat, which are raw syscalls and do not. This is one
// process hosting many tables and several of them shell out, so an fd left inheritable is a
// handle onto another user's home directory surviving into an unrelated subprocess -- past
// every check this package makes to obtain it.
func TestOpenBeneathDescriptorsAreCloseOnExec(t *testing.T) {
	home := t.TempDir()
	nested := filepath.Join(home, "Library", "Application Support", "Claude")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(nested, "claude_desktop_config.json")
	if err := os.WriteFile(target, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	file, err := OpenBeneath(home, filepath.Join("Library", "Application Support", "Claude",
		"claude_desktop_config.json"))
	if err != nil {
		t.Fatalf("OpenBeneath: %v", err)
	}
	defer func() { _ = file.Close() }()

	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("F_GETFD: %v", err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Error("the returned descriptor is inheritable across exec; a table that shells " +
			"out would hand this handle to its child")
	}
}
