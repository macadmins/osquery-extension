package mcp_servers

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/macadmins/osquery-extension/pkg/devclients"
	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/macadmins/osquery-extension/pkg/testutil"
)

// otherAccount is an identity that is not the account running the test, as the roster reports
// it: the uid one past the process's on POSIX, and a made-up SID on Windows.
func otherAccount() (uid, uuid string) {
	mine, sid := testutil.Account()
	if sid != "" {
		return "1001", "S-1-5-21-1-2-3-1001"
	}
	number, err := strconv.Atoi(mine)
	if err != nil {
		panic("the test account's uid is not a number: " + mine)
	}
	return strconv.Itoa(number + 1), ""
}

// TestAFileOwnedByAnotherAccountIsRefusedAndReported: a configuration file under a home whose
// roster identity is not the file's owner produces no server and a source_unreadable row naming
// the file with reason=owner_mismatch. The files belong to the test account, and the roster
// names another, which is the same refusal as another account's file under this one's home. The
// same file under the account that owns it is read, so the refusal is the owner check and not
// the fixture.
func TestAFileOwnedByAnotherAccountIsRefusedAndReported(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	config := filepath.Join(home, ".cursor", "mcp.json")
	testutil.WriteFile(t, config, `{"mcpServers":{"seeded":{"command":"npx"}}}`)
	if err := testutil.OwnAsTestAccount(home); err != nil {
		t.Logf("the fixture keeps the owner Windows gave it: %v", err)
	}
	if testutil.PrivilegedOwner(config) {
		t.Skip("a privileged account owns the fixture, and a privileged owner passes the check")
	}
	uid, uuid := otherAccount()
	notOwner := rosterFrom(map[string]string{"uid": uid, "uuid": uuid, "username": "alice",
		"directory": home, "shell": "/bin/zsh"})
	var reported bool
	for _, row := range withoutStandingNotes(DiscoverAll(context.Background(), notOwner, nil)) {
		if row.ServerName == "seeded" {
			t.Error("a file owned by another account was read")
		}
		if row.Warning.Code == warnSourceUnreadable && row.SourcePath == config {
			reported = row.Warning.Class == fsscan.ClassOwnerMismatch
		}
	}
	if !reported {
		t.Error("no source_unreadable row with reason=owner_mismatch names the file")
	}
	own := rosterOf(t, filepath.Dir(home))
	var read bool
	for _, row := range withoutStandingNotes(DiscoverAll(context.Background(), own, nil)) {
		read = read || row.ServerName == "seeded"
	}
	if !read {
		t.Error("the same file under the account that owns it was not read")
	}
}

// TestAHomeSharedWithAnotherAccountIsReadForEach: two accounts share one home whose configuration
// the account running the test owns. Each is scanned under its own identity, so the owner gets
// the server and the other account a source_unreadable row with reason=owner_mismatch, whichever
// of the two the roster orders first.
func TestAHomeSharedWithAnotherAccountIsReadForEach(t *testing.T) {
	home := filepath.Join(t.TempDir(), "shared")
	config := filepath.Join(home, ".cursor", "mcp.json")
	testutil.WriteFile(t, config, `{"mcpServers":{"seeded":{"command":"npx"}}}`)
	if err := testutil.OwnAsTestAccount(home); err != nil {
		t.Logf("the fixture keeps the owner Windows gave it: %v", err)
	}
	if testutil.PrivilegedOwner(config) {
		t.Skip("a privileged account owns the fixture, and a privileged owner passes the check")
	}
	mine, mySID := testutil.Account()
	beforeUID, beforeSID, afterUID, afterSID := testutil.IdentitiesAround(mine, mySID)
	for _, other := range [][2]string{{beforeUID, beforeSID}, {afterUID, afterSID}} {
		roster := rosterFrom(
			map[string]string{"uid": mine, "uuid": mySID, "username": "owner", "directory": home,
				"shell": "/bin/zsh"},
			map[string]string{"uid": other[0], "uuid": other[1], "username": "other", "directory": home,
				"shell": "/bin/zsh"})
		ownerRead, otherRead, otherRefused := false, false, false
		for _, row := range withoutStandingNotes(DiscoverAll(context.Background(), roster, nil)) {
			switch row.User {
			case "owner":
				ownerRead = ownerRead || row.ServerName == "seeded"
			case "other":
				otherRead = otherRead || row.ServerName == "seeded"
				otherRefused = otherRefused || (row.Warning.Code == warnSourceUnreadable &&
					row.Warning.Class == fsscan.ClassOwnerMismatch)
			}
		}
		if !ownerRead || otherRead || !otherRefused {
			t.Errorf("other uid %s: owner read %v, other read %v, other refused %v; want the "+
				"owner's server and the other account refused", other[0], ownerRead, otherRead,
				otherRefused)
		}
	}
}

// TestRefusalsWithDifferentReasonsAreSeparateRows: one project's .mcp.json is a hard link and
// another's belongs to the account running the test while the probe reads for a different
// account, so the first is refused for its link count and the second for its owner. Each reason
// is its own project_read_refused row rather than the second being counted into the first.
func TestRefusalsWithDifferentReasonsAreSeparateRows(t *testing.T) {
	home := t.TempDir()
	linked := filepath.Join(home, "linked", ".mcp.json")
	testutil.WriteFile(t, linked, `{"mcpServers":{}}`)
	if err := os.Link(linked, filepath.Join(home, "linked", "second-name.json")); err != nil {
		t.Skipf("hard links are unavailable here: %v", err)
	}
	owned := filepath.Join(home, "owned", ".mcp.json")
	testutil.WriteFile(t, owned, `{"mcpServers":{}}`)
	if err := testutil.OwnAsTestAccount(home); err != nil {
		t.Logf("the fixture keeps the owner Windows gave it: %v", err)
	}
	if testutil.PrivilegedOwner(owned) {
		t.Skip("a privileged account owns the fixture, and a privileged owner passes the check")
	}
	uid, uuid := otherAccount()
	owner := uid
	if uuid != "" {
		owner = uuid
	}
	claude := map[devclients.Origin]struct{}{devclients.OriginClaudeJSON: {}}
	projects := []projectRef{{Rel: "linked", Abs: filepath.Join(home, "linked"), Origins: claude},
		{Rel: "owned", Abs: filepath.Join(home, "owned"), Origins: claude}}
	rows, _ := probeProjects(context.Background(), home, owner, fsscan.ClassNone, "alice",
		time.Now().Add(time.Minute), map[string]struct{}{}, projects, nil)
	var reasons []fsscan.ErrClass
	for _, row := range rows {
		if row.Warning.Code == warnProjectRefused {
			reasons = append(reasons, row.Warning.Class)
		}
	}
	want := []fsscan.ErrClass{fsscan.ClassHardLink, fsscan.ClassOwnerMismatch}
	if !slices.Equal(reasons, want) {
		t.Errorf("project_read_refused reasons = %v, want %v", reasons, want)
	}
}
