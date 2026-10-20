//go:build unix

package fsscan

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestReadLinkBeneath reads a link relative to a safely opened parent, refuses a symlinked
// parent rather than resolving through it, and rejects a name that is not one component.
func TestReadLinkBeneath(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "snap", "code", "168"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("168", filepath.Join(base, "snap", "code", "current")); err != nil {
		t.Fatal(err)
	}
	if target, err := ReadLinkBeneath(base, filepath.Join("snap", "code"), "current"); err != nil || target != "168" {
		t.Errorf("ReadLinkBeneath = %q %v, want 168", target, err)
	}
	if _, err := ReadLinkBeneath(base, filepath.Join("snap", "code"), "168"); err == nil {
		t.Error("a directory is not a symlink and must not read as one")
	}
	if _, err := ReadLinkBeneath(base, "snap", "code/current"); !errors.Is(err, ErrMalformedPath) {
		t.Errorf("a multi-component name: err = %v, want ErrMalformedPath", err)
	}

	// A parent reached through a symlink, which a path-based read would resolve through.
	elsewhere := t.TempDir()
	if err := os.MkdirAll(filepath.Join(elsewhere, "code"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("168", filepath.Join(elsewhere, "code", "current")); err != nil {
		t.Fatal(err)
	}
	linked := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(linked, "snap")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLinkBeneath(linked, filepath.Join("snap", "code"), "current"); err == nil {
		t.Error("a symlinked parent was followed")
	}
}

// TestLinkTargetBeneath resolves a link by one hop to a base-relative path, from relative and
// absolute targets, and refuses a target outside the base, one that climbs above the base and
// back, a ".." after a named component, which the kernel resolves through that component, and
// any ".." in an absolute target. A link directly in the base resolves too.
func TestLinkTargetBeneath(t *testing.T) {
	base := filepath.Join(t.TempDir(), "alice")
	if err := os.MkdirAll(filepath.Join(base, "svc"), 0o755); err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]string{
		"real.mod":                                 filepath.Join("svc", "real.mod"),
		"./real.mod":                               filepath.Join("svc", "real.mod"),
		"../shared/go.sum":                         filepath.Join("shared", "go.sum"),
		filepath.Join(base, "shared", "go.mod"):    filepath.Join("shared", "go.mod"),
		"../../alice/shared/go.mod":                "",
		"../../elsewhere.mod":                      "",
		filepath.Join(filepath.Dir(base), "x.mod"): "",
		"vendor/../real.mod":                       "",
		base + "/svc/../real.mod":                  "",
		"..":                                       "",
		"../..":                                    "",
	} {
		link := filepath.Join(base, "svc", "go.mod")
		_ = os.Remove(link)
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		got, err := LinkTargetBeneath(base, "svc", "go.mod")
		if want == "" {
			if err == nil {
				t.Errorf("target %q resolved to %q, want a refusal", target, got)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("target %q = %q %v, want %q", target, got, err, want)
		}
	}
	if _, err := LinkTargetBeneath(base, "svc", "absent"); err == nil {
		t.Error("a name that is not a link resolved")
	}
	if err := os.Symlink("shared/go.mod", filepath.Join(base, "go.mod")); err != nil {
		t.Fatal(err)
	}
	if got, err := LinkTargetBeneath(base, ".", "go.mod"); err != nil || got != filepath.Join("shared", "go.mod") {
		t.Errorf("a link in the base = %q %v, want shared/go.mod", got, err)
	}
	if err := os.Symlink("../alice/shared/go.sum", filepath.Join(base, "go.sum")); err != nil {
		t.Fatal(err)
	}
	if got, err := LinkTargetBeneath(base, ".", "go.sum"); err == nil {
		t.Errorf("a link in the base climbing above it resolved to %q", got)
	}
}

// TestProbeProjectDirRefusesASymlinkedProject: a project directory reached through a symlink
// is refused the way every read refuses it, rather than probed through the link.
func TestProbeProjectDirRefusesASymlinkedProject(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "real"), filepath.Join(home, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := ProbeProjectDir(home, "linked"); ClassifyError(err) != ClassRefusedPath {
		t.Errorf("a symlinked project directory = %v (%s), want refused_path", err, ClassifyError(err))
	}
	// A home that is itself a symlink, probed as the project ".", is refused the same way.
	if err := ProbeProjectDir(filepath.Join(home, "linked"), "."); ClassifyError(err) != ClassRefusedPath {
		t.Errorf("a symlinked home probed as a project = %v (%s), want refused_path", err, ClassifyError(err))
	}
}

// TestReadLinkTarget: a link to a file in the same base is read as that file; a link out of the
// base returns the original refusal unchanged; a dangling one is absent; and a link to a link
// keeps the refusal, so a chain is never walked.
func TestReadLinkTarget(t *testing.T) {
	base := t.TempDir()
	elsewhere := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "real"), []byte("inside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(elsewhere, "real"), []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		"in": "../real", "out": filepath.Join(elsewhere, "real"), "dangling": "../missing", "chain": "in",
	} {
		if err := os.Symlink(target, filepath.Join(base, "dir", name)); err != nil {
			t.Fatal(err)
		}
	}
	opts := ReadOpts{MaxSize: 1 << 10}
	read := func(name string) ([]byte, error) {
		refused := errors.New("the original refusal")
		data, err := ReadLinkTarget(base, ClassNone, "dir", name, opts, LinkChecks{}, refused)
		if err == refused {
			return nil, nil
		}
		if err == nil && data == nil {
			t.Fatalf("%s: neither data nor an error", name)
		}
		return data, err
	}
	if data, err := read("in"); string(data) != "inside" || err != nil {
		t.Errorf("in: %q %v, want the target's content", data, err)
	}
	for _, name := range []string{"out", "chain"} {
		if data, err := read(name); data != nil || err != nil {
			t.Errorf("%s: %q %v, want the original refusal", name, data, err)
		}
	}
	if _, err := read("dangling"); ClassifyError(err) != ClassAbsent {
		t.Errorf("dangling: %v, want absent", err)
	}
}

// TestReadLinkTargetUsesTheCallersReader: a followed target is read with checks.Read when set, so
// a link stands for its file under the same reader the file itself would get.
func TestReadLinkTargetUsesTheCallersReader(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "real"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	var readRel string
	checks := LinkChecks{Read: func(base, rel string, opts ReadOpts) ([]byte, error) {
		readRel = rel
		return []byte("from the caller's reader"), nil
	}}
	data, err := ReadLinkTarget(base, ClassNone, "", "link", ReadOpts{MaxSize: 10}, checks, errors.New("refused"))
	if err != nil || string(data) != "from the caller's reader" || readRel != "real" {
		t.Errorf("data %q, err %v, read %q; want the caller's reader on the target", data, err, readRel)
	}
}

// TestAFollowedPlaceholderIsDeclined: a link whose target the platform reports as evicted,
// read with ReadBoundedUnder as a home configuration file is, keeps the original refusal, so
// following the link cannot start the download the placeholder check exists to prevent.
func TestAFollowedPlaceholderIsDeclined(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "Documents"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "Documents", "claude.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("Documents", "claude.json"), filepath.Join(base, ".claude.json")); err != nil {
		t.Fatal(err)
	}
	refused := errors.New("the original refusal")
	opts := ReadOpts{MaxSize: 1 << 10, CloudPlaceholder: func(*os.File) (bool, error) { return true, nil }}
	data, err := ReadLinkTarget(base, ClassNone, "", ".claude.json", opts,
		LinkChecks{Read: ReadBoundedUnder}, refused)
	if err != refused || data != nil {
		t.Errorf("data %q, err %v, want the original refusal", data, err)
	}
}
