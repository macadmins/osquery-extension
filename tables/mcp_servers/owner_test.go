package mcp_servers

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"

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
