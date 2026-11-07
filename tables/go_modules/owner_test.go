package go_modules

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/macadmins/osquery-extension/pkg/testutil"
	"github.com/macadmins/osquery-extension/pkg/utils"
)

// otherAccount is an identity that is not the account running the test, as the roster reports
// it: the uid one past the process's on POSIX, and a made-up SID on Windows.
func otherAccount() (uid, uuid string) {
	return distinctAccount(1)
}

// distinctAccount is the nth identity that is not the account running the test: the uid n past
// the process's on POSIX, and a made-up SID ending in 1000 + n on Windows.
func distinctAccount(n int) (uid, uuid string) {
	mine, sid := testutil.Account()
	if sid != "" {
		uid = strconv.Itoa(1000 + n)
		return uid, "S-1-5-21-1-2-3-" + uid
	}
	number, err := strconv.Atoi(mine)
	if err != nil {
		panic("the test account's uid is not a number: " + mine)
	}
	return strconv.Itoa(number + n), ""
}

// distinctID is distinctAccount's identity as UserHome.ID holds it: the SID, or else the uid.
func distinctID(n int) string {
	uid, uuid := distinctAccount(n)
	if uuid != "" {
		return uuid
	}
	return uid
}

// TestAFileOwnedByAnotherAccountIsRefusedAndReported: the project list under a home whose roster
// identity is not the file's owner is refused, so its project is not listed and a
// project_list_unreadable row carries reason=owner_mismatch. The files belong to the test
// account and the roster names another, which is the same refusal as another account's file
// under this one's home. Under the account that owns them the project is listed, so the refusal
// is the owner check and not the fixture.
func TestAFileOwnedByAnotherAccountIsRefusedAndReported(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	project := filepath.Join(home, "svc")
	claudeList(t, home, project)
	testutil.WriteFile(t, filepath.Join(project, "go.mod"), goMod)
	if err := testutil.OwnAsTestAccount(home); err != nil {
		t.Logf("the fixture keeps the owner Windows gave it: %v", err)
	}
	if testutil.PrivilegedOwner(filepath.Join(project, "go.mod")) {
		t.Skip("a privileged account owns the fixture, and a privileged owner passes the check")
	}

	uid, uuid := otherAccount()
	notOwner := &utils.MockOsqueryClienter{Data: map[string][]map[string]string{fsscan.UsersQuery: {
		{"uid": uid, "uuid": uuid, "username": "alice", "directory": home, "shell": "/bin/zsh"},
	}}}
	rows, err := generate(context.Background(), table.QueryContext{}, notOwner)
	if err != nil {
		t.Fatal(err)
	}
	reported := false
	for _, r := range rows {
		if r["module_path"] != "" {
			t.Errorf("a module was listed from a file owned by another account: %v", r)
		}
		listRefused := strings.HasPrefix(r["warning"], warnSentences[warnProjectListUnreadable])
		reported = reported || (listRefused &&
			strings.Contains(r["warning"], "reason="+string(fsscan.ClassOwnerMismatch)))
	}
	if !reported {
		t.Errorf("rows = %v, want a project_list_unreadable row with reason=owner_mismatch", rows)
	}

	own := roster(map[string]string{"alice": home})
	rows, err = generate(context.Background(), table.QueryContext{}, own)
	if err != nil {
		t.Fatal(err)
	}
	if moduleRows := len(modules(rows)); moduleRows == 0 {
		t.Errorf("the same files under the account that owns them listed nothing: %v", rows)
	}
}

// TestAHomeSharedWithAnotherAccountIsReadForEach: two accounts share one home whose files the
// account running the test owns. Each is scanned under its own identity, so the owner's modules
// are listed and the other account's read is refused with reason=owner_mismatch, whichever of
// the two the roster orders first.
func TestAHomeSharedWithAnotherAccountIsReadForEach(t *testing.T) {
	home := filepath.Join(t.TempDir(), "shared")
	project := filepath.Join(home, "svc")
	claudeList(t, home, project)
	testutil.WriteFile(t, filepath.Join(project, "go.mod"), goMod)
	if err := testutil.OwnAsTestAccount(home); err != nil {
		t.Logf("the fixture keeps the owner Windows gave it: %v", err)
	}
	if testutil.PrivilegedOwner(filepath.Join(project, "go.mod")) {
		t.Skip("a privileged account owns the fixture, and a privileged owner passes the check")
	}
	mine, mySID := testutil.Account()
	beforeUID, beforeSID, afterUID, afterSID := testutil.IdentitiesAround(mine, mySID)
	for _, other := range [][2]string{{beforeUID, beforeSID}, {afterUID, afterSID}} {
		clienter := &utils.MockOsqueryClienter{Data: map[string][]map[string]string{fsscan.UsersQuery: {
			{"uid": mine, "uuid": mySID, "username": "owner", "directory": home, "shell": "/bin/zsh"},
			{"uid": other[0], "uuid": other[1], "username": "other", "directory": home, "shell": "/bin/zsh"},
		}}}
		rows, err := generate(context.Background(), table.QueryContext{}, clienter)
		if err != nil {
			t.Fatal(err)
		}
		ownerModules, otherModules, otherRefused := 0, 0, false
		for _, r := range rows {
			switch r["user"] {
			case "owner":
				if r["module_path"] != "" {
					ownerModules++
				}
			case "other":
				if r["module_path"] != "" {
					otherModules++
				}
				otherRefused = otherRefused || strings.Contains(r["warning"],
					"reason="+string(fsscan.ClassOwnerMismatch))
			}
		}
		if ownerModules == 0 || otherModules != 0 || !otherRefused {
			t.Errorf("other uid %s: owner modules %d, other modules %d, other refused %v; want the "+
				"owner's modules and the other account refused", other[0], ownerModules, otherModules,
				otherRefused)
		}
	}
}
