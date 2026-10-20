package mcp_servers

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/macadmins/osquery-extension/pkg/utils"
)

// rosterOf builds a mock clienter that answers osquery's users query with one row per entry
// beneath root. The roster comes from the users table, so a test that runs discovery over a
// fixture tree supplies the accounts this way, not through a package-level variable that
// production code also reads.
func rosterOf(t *testing.T, root string) utils.OsqueryClienter {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("reading fixture root %q: %v", root, err)
	}
	var rows []map[string]string
	uid := 500
	for _, entry := range entries {
		// Every entry becomes an account, whatever type it is. Filtering on IsDir here
		// would make the helper pre-decide what the code under test exists to decide: a
		// symlinked home is reported by osquery like any other and must reach
		// homesFromUsers to be refused, but ReadDir reports it as not-a-directory, so
		// filtering would silently remove the case a test is written for.
		if entry.Name() == "Shared" || entry.Name()[0] == '.' {
			continue
		}
		uid++
		rows = append(rows, map[string]string{
			"uid":       strconv.Itoa(uid),
			"username":  entry.Name(),
			"directory": filepath.Join(root, entry.Name()),
			"shell":     "/bin/zsh",
		})
	}
	return &utils.MockOsqueryClienter{
		Data: map[string][]map[string]string{fsscan.UsersQuery: rows},
	}
}

// rosterFrom builds a clienter from explicit rows, for tests that need an account whose home
// is missing, is a symlink, or is otherwise not what ReadDir would report.
func rosterFrom(rows ...map[string]string) utils.OsqueryClienter {
	return &utils.MockOsqueryClienter{
		Data: map[string][]map[string]string{fsscan.UsersQuery: rows},
	}
}

// withoutStandingNotes drops roster-level rows and the diagnostics a platform raises on every
// run whatever the test is about, so a test can assert what it is actually measuring.
//
// A roster-level row is matched by a source path equal to the users root, which is the path
// genuine roster failures carry.
//
// On Windows, every account draws one roaming-application-data note. Resolving that location
// reads the account's registry hive, and a fixture home is a temp directory with no hive and
// no SID, so the lookup fails. The filter matches the code the table emits, so a change of
// wording cannot silently break it. Mocking the hive instead would stop the tests from
// exercising the resolution path they wrap.
//
// Without this filter, a test asserting an exact row count passes on macOS, where the note
// does not occur, and fails elsewhere for reasons unrelated to its subject.
func withoutStandingNotes(rows []Server) []Server {
	out := make([]Server, 0, len(rows))
	for _, row := range rows {
		if row.Warning.empty() == false && row.SourcePath == fsscan.UsersRoot {
			continue
		}
		if row.Warning.Code == warnAppDataUndetermined {
			continue
		}
		out = append(out, row)
	}
	return out
}
