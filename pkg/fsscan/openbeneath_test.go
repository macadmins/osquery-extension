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
