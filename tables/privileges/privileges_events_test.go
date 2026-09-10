package privileges

import (
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
)

func eventsQueryContext(last string) table.QueryContext {
	constraints := map[string]table.ConstraintList{}
	if last != "" {
		constraints["last"] = table.ConstraintList{
			Constraints: []table.Constraint{
				{Operator: table.OperatorEquals, Expression: last},
			},
		}
	}
	return table.QueryContext{Constraints: constraints}
}

func TestPrivilegesEventsColumns(t *testing.T) {
	columns := PrivilegesEventsColumns()
	assert.Len(t, columns, 13)
	assert.Contains(t, columns, table.TextColumn("event_type"))
	assert.Contains(t, columns, table.TextColumn("user"))
	assert.Contains(t, columns, table.TextColumn("subject"))
	assert.Contains(t, columns, table.TextColumn("executable"))
	assert.Contains(t, columns, table.TextColumn("signing_id"))
	assert.Contains(t, columns, table.TextColumn("team_id"))
	assert.Contains(t, columns, table.TextColumn("cdhash"))
	assert.Contains(t, columns, table.IntegerColumn("pid"))
	assert.Contains(t, columns, table.IntegerColumn("ppid"))
	assert.Contains(t, columns, table.IntegerColumn("is_platform_binary"))
	assert.Contains(t, columns, table.IntegerColumn("is_es_client"))
	assert.Contains(t, columns, table.TextColumn("daemon_start_time"))
	assert.Contains(t, columns, table.TextColumn("last"))
}

func TestGenerateEventsFullHistory(t *testing.T) {
	runner := utils.Runner{Runner: utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			cliPath + " --history --json": {Output: validEventLine + "\n" + validEventLine + "\n"},
		},
	}}
	rows, err := generateEvents(eventsQueryContext(""), runner, utils.MockFileSystem{FileExists: true})
	assert.NoError(t, err)
	assert.Len(t, rows, 2)
	assert.Equal(t, map[string]string{
		"event_type":         "ADMIN_ADD",
		"user":               "henry",
		"subject":            "user",
		"executable":         "/Applications/Privileges.app/Contents/MacOS/PrivilegesDaemon",
		"signing_id":         "corp.sap.privileges.daemon",
		"team_id":            "7R5ZEU67FQ",
		"cdhash":             "330081dcbf4f3086cb71af1e1b0152be78fff23a",
		"pid":                "64557",
		"ppid":               "1",
		"is_platform_binary": "0",
		"is_es_client":       "0",
		"daemon_start_time":  "2026-08-11T09:26:42Z",
		"last":               "",
	}, rows[0])
}

func TestGenerateEventsLastConstraint(t *testing.T) {
	// Only the "--last 3h" invocation is registered: the test fails if the
	// constraint is not translated into CLI arguments.
	runner := utils.Runner{Runner: utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			cliPath + " --history --json --last 3h": {Output: validEventLine + "\n"},
		},
	}}
	rows, err := generateEvents(eventsQueryContext("3h"), runner, utils.MockFileSystem{FileExists: true})
	assert.NoError(t, err)
	assert.Len(t, rows, 1)
	assert.Equal(t, "3h", rows[0]["last"])
}

func TestGenerateEventsNotInstalled(t *testing.T) {
	// The history command is registered with output that WOULD produce a row
	// if consulted, so this test fails if the cliInstalled guard is removed
	// (MultiMockCmdRunner otherwise returns ("", nil) for unregistered
	// commands and would pass regardless of the guard).
	runner := utils.Runner{Runner: utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			cliPath + " --history --json": {Output: validEventLine + "\n", Err: nil},
		},
	}}
	rows, err := generateEvents(eventsQueryContext(""), runner, utils.MockFileSystem{FileExists: false})
	assert.NoError(t, err)
	assert.Empty(t, rows)
}

func TestGenerateEventsCLIFailure(t *testing.T) {
	// e.g. the system extension is disabled and the CLI exits non-zero.
	runner := utils.Runner{Runner: utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			cliPath + " --history --json": {Output: "", Err: assert.AnError},
		},
	}}
	rows, err := generateEvents(eventsQueryContext(""), runner, utils.MockFileSystem{FileExists: true})
	assert.NoError(t, err)
	assert.Empty(t, rows)
}

func TestGenerateEventsOlderCLIPrintsUsage(t *testing.T) {
	// Privileges before 2.6.0 has no --history command. The CLI treats it as
	// an unknown flag, prints its usage text to stderr and exits 0, so the
	// table must yield zero rows rather than an error or garbage rows.
	usage := "Usage: PrivilegesCLI <arg>\n\n" +
		"  -a, --add [-n, --reason text]\n\n" +
		"           Adds the current user to the admin group.\n"
	runner := utils.Runner{Runner: utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			cliPath + " --history --json": {Output: usage},
		},
	}}
	rows, err := generateEvents(eventsQueryContext(""), runner, utils.MockFileSystem{FileExists: true})
	assert.NoError(t, err)
	assert.Empty(t, rows)
}

func TestGenerateEventsEmptyOutput(t *testing.T) {
	runner := utils.Runner{Runner: utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			cliPath + " --history --json": {Output: ""},
		},
	}}
	rows, err := generateEvents(eventsQueryContext(""), runner, utils.MockFileSystem{FileExists: true})
	assert.NoError(t, err)
	assert.Empty(t, rows)
}
