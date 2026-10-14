//go:build unix

package fsscan

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

// The two descriptor refusals, each driven by the only mechanism that can reach it without
// privilege.
//
// Both halves of S4 are asserted in one file on purpose. A half-applied owner check is worse
// than none: a reader who sees RefuseHardLinks working concludes the descriptor is checked,
// and acts as though the owner were checked too. Keeping the two assertions adjacent is the
// cheapest available guard against one of them being deleted as redundant.
func TestReadBoundedUnder_RefusesHardLink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "f.json")
	writeFile(t, target, `{}`)
	// os.Link is what makes this testable at all. A second link is indistinguishable from
	// the first from the filesystem's point of view -- there is no "original" -- which is
	// exactly why the link *count* is the only evidence available and why the refusal has
	// to be opt-in rather than a judgement about which path is legitimate.
	if err := os.Link(target, filepath.Join(base, "second.json")); err != nil {
		t.Skipf("hard links unsupported here: %v", err)
	}

	// Off by default: the flag exists because hard links are ordinary, and a table that
	// does not ask must still read the file.
	if _, err := ReadBoundedUnder(base, "f.json", ReadOpts{MaxSize: 1024}); err != nil {
		t.Errorf("a hard-linked file must still read when the refusal is not requested: %v", err)
	}

	_, err := ReadBoundedUnder(base, "f.json", ReadOpts{MaxSize: 1024, RefuseHardLinks: true})
	if !errors.Is(err, ErrHardLink) {
		t.Fatalf("expected ErrHardLink, got %v", err)
	}
	// Classified, not matched on text. The caller putting this in a column cannot read the
	// message -- it names the path -- so the enum is the whole interface.
	if got := ClassifyError(err); got != ClassHardLink {
		t.Errorf("ClassifyError = %q, want %q", got, ClassHardLink)
	}
	// And it must NOT read as benign absence. A hard link is a finding; swallowing it the
	// way a missing file is swallowed would make the refusal invisible.
	if IsExpectedAbsent(err) {
		t.Error("a hard-link refusal must not be reported as expected absence")
	}
}

func TestReadBoundedUnder_RefusesForeignOwner(t *testing.T) {
	base := t.TempDir()
	writeFile(t, filepath.Join(base, "f.json"), `{}`)

	// The real uid passes. Taken from the running process rather than assumed, so the test
	// says something on a host where tests run as root.
	me := strconv.Itoa(os.Getuid())
	if _, err := ReadBoundedUnder(base, "f.json", ReadOpts{MaxSize: 1024, OwnerUID: me}); err != nil {
		t.Errorf("a file owned by the expected uid must read: %v", err)
	}

	// A uid that cannot be this file's owner. This is the whole reason OwnerUID is a
	// parameter instead of being derived inside the package: the check needs a mismatch to
	// exercise it, and creating a file owned by another account needs privilege the test
	// does not have. Passing the wrong expectation produces the same code path as the real
	// attack -- a file whose owner is not the account whose home it was found under.
	foreign := strconv.Itoa(os.Getuid() + 1)
	if _, err := user.LookupId(foreign); err == nil {
		// Only cosmetic: the uid need not be unassigned, merely different.
		t.Logf("uid %s exists on this host, which does not affect the comparison", foreign)
	}
	_, err := ReadBoundedUnder(base, "f.json", ReadOpts{MaxSize: 1024, OwnerUID: foreign})
	if !errors.Is(err, ErrForeignOwner) {
		t.Fatalf("expected ErrForeignOwner, got %v", err)
	}
	if got := ClassifyError(err); got != ClassForeignOwner {
		t.Errorf("ClassifyError = %q, want %q", got, ClassForeignOwner)
	}
	if IsExpectedAbsent(err) {
		t.Error("an owner refusal must not be reported as expected absence")
	}
}

// The sentinels have to survive the wrapping the read functions apply, or errors.Is at the
// call site silently answers false and every refusal reads as ClassOther.
func TestClassifyErrorOverTheRealReadPath(t *testing.T) {
	base := t.TempDir()
	writeFile(t, filepath.Join(base, "big.json"), `0123456789`)
	if err := os.Mkdir(filepath.Join(base, "adir"), 0o755); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		rel  string
		opts ReadOpts
		want ErrClass
	}{
		{"too large", "big.json", ReadOpts{MaxSize: 2}, ClassTooLarge},
		{"absent", "nope.json", ReadOpts{MaxSize: 1024}, ClassAbsent},
		{"not regular", "adir", ReadOpts{MaxSize: 1024}, ClassNotRegular},
		{"no error", "big.json", ReadOpts{MaxSize: 1024}, ClassNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ReadBoundedUnder(base, tc.rel, tc.opts)
			if got := ClassifyError(err); got != tc.want {
				t.Errorf("ClassifyError(%v) = %q, want %q", err, got, tc.want)
			}
		})
	}
}
