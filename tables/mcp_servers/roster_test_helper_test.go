package mcp_servers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/fsscan"
	"github.com/macadmins/osquery-extension/pkg/utils"
)

// The roster now comes from osquery's users table, so a test that wants discovery to run
// over a fixture tree supplies the accounts rather than repointing a filesystem root.
//
// This replaces assigning fsscan.UsersRoot. That worked while the roster was a directory
// listing; it cannot work now, and more importantly it never should have been the mechanism
// -- it made every test depend on a package-level variable that production code also read.
//
// rosterOf builds a mock clienter answering the users query with one row per directory found
// beneath root, which is exactly the shape the old fixture trees already had.
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
		// filtering silently removed the case the test was written for.
		if entry.Name() == "Shared" || entry.Name()[0] == '.' {
			continue
		}
		uid++
		rows = append(rows, map[string]string{
			"uid":       itoa(uid),
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

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// withoutStandingNotes drops the diagnostics a platform raises on every run whatever the test
// is about, so a test can assert what it is actually measuring.
//
// Two of them, one per platform, and neither is a defect:
//
// One of them now, where there were two. The Linux roster-level note is gone: it fired on
// every single run, which made the warning column non-empty on every Linux host whether or
// not anything was wrong, so it is documentation rather than a row. The structural filter for
// a roster-level row -- source path equal to the users root -- is kept, because the genuine
// roster failures still use that shape.
//
// On Windows, one roaming-application-data note per account. Resolving that location reads
// the account's registry hive, and a fixture home is a temp directory with no hive and no
// SID, so the lookup fails and every fake account draws the row. Identified by identity with
// the constant the code emits, so improving the wording cannot silently stop the filter
// working. The alternative -- mocking the hive -- would mean the tests no longer exercise the
// resolution path they are wrapped around.
//
// Tests asserting exact row counts were written on macOS, where neither note exists, and
// failed elsewhere for reasons unrelated to their subject.
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
