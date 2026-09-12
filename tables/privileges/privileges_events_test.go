package privileges

import (
	"fmt"
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
	assert.Len(t, columns, 17)
	assert.Contains(t, columns, table.TextColumn("event_type"))
	assert.Contains(t, columns, table.TextColumn("principal"))
	assert.Contains(t, columns, table.TextColumn("subject"))
	assert.Contains(t, columns, table.TextColumn("executable"))
	assert.Contains(t, columns, table.TextColumn("signing_id"))
	assert.Contains(t, columns, table.TextColumn("team_id"))
	assert.Contains(t, columns, table.TextColumn("cdhash"))
	assert.Contains(t, columns, table.IntegerColumn("pid"))
	assert.Contains(t, columns, table.IntegerColumn("ppid"))
	assert.Contains(t, columns, table.IntegerColumn("uid"))
	assert.Contains(t, columns, table.IntegerColumn("gid"))
	assert.Contains(t, columns, table.IntegerColumn("auid"))
	assert.Contains(t, columns, table.IntegerColumn("responsible_pid"))
	assert.Contains(t, columns, table.IntegerColumn("is_platform_binary"))
	assert.Contains(t, columns, table.IntegerColumn("is_es_client"))
	assert.Contains(t, columns, table.TextColumn("process_start_time"))
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
	if !assert.Len(t, rows, 2) {
		return
	}
	assert.Equal(t, map[string]string{
		"event_type":         "ADMIN_ADD",
		"principal":          "henry",
		"subject":            "user",
		"executable":         "/Applications/Privileges.app/Contents/MacOS/PrivilegesDaemon",
		"signing_id":         "corp.sap.privileges.daemon",
		"team_id":            "7R5ZEU67FQ",
		"cdhash":             "330081dcbf4f3086cb71af1e1b0152be78fff23a",
		"pid":                "64557",
		"ppid":               "1",
		"uid":                "0",
		"gid":                "0",
		"auid":               "-1",
		"responsible_pid":    "64557",
		"is_platform_binary": "0",
		"is_es_client":       "0",
		"process_start_time": "2026-08-11T09:26:42Z",
		"last":               "",
	}, rows[0])
}

func TestGenerateEventsTamperEvent(t *testing.T) {
	// Tamper-protection events (CLONE, CREATE, DELETE, EXEC, RENAME) carry
	// the affected path in subject and have no principal. They must be
	// returned, not filtered out.
	runner := utils.Runner{Runner: utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			cliPath + " --history --json": {Output: tamperEventLine + "\n"},
		},
	}}
	rows, err := generateEvents(eventsQueryContext(""), runner, utils.MockFileSystem{FileExists: true})
	assert.NoError(t, err)
	if !assert.Len(t, rows, 1) {
		return
	}
	assert.Equal(t, "CLONE", rows[0]["event_type"])
	assert.Equal(t, "", rows[0]["principal"])
	assert.Equal(t, "/Applications/Privileges.app/Contents/Info.plist", rows[0]["subject"])
	assert.Equal(t, "/bin/cp", rows[0]["executable"])
	assert.Equal(t, "com.apple.cp", rows[0]["signing_id"])
	assert.Equal(t, "1", rows[0]["is_platform_binary"])
	assert.Equal(t, "2026-09-11T21:03:32Z", rows[0]["process_start_time"])
	assert.Equal(t, "501", rows[0]["uid"])
	assert.Equal(t, "20", rows[0]["gid"])
	assert.Equal(t, "501", rows[0]["auid"])
	assert.Equal(t, "21358", rows[0]["responsible_pid"], "the terminal that spawned cp")
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
	if !assert.Len(t, rows, 1) {
		return
	}
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

// sequenceRunner returns one canned result per call, in order, and counts
// the calls, for exercising the retry-on-timeout path.
type sequenceRunner struct {
	results []utils.MockCmdRunner
	calls   int
}

func (s *sequenceRunner) RunCmd(name string, arg ...string) ([]byte, error) {
	i := s.calls
	s.calls++
	if i >= len(s.results) {
		return nil, fmt.Errorf("unexpected call %d", i+1)
	}
	return s.results[i].RunCmd(name, arg...)
}

func (s *sequenceRunner) RunCmdWithStdin(name string, stdin string, arg ...string) ([]byte, error) {
	return s.RunCmd(name, arg...)
}

func TestGenerateEventsRetriesOnceAfterTimeout(t *testing.T) {
	// A stall means the helper never came up; the next attempt normally
	// answers within seconds, so one retry turns a stall into a delay.
	seq := &sequenceRunner{results: []utils.MockCmdRunner{
		{Err: fmt.Errorf("PrivilegesCLI: %w", utils.ErrCommandTimeout)},
		{Output: validEventLine + "\n"},
	}}
	rows, err := generateEvents(eventsQueryContext(""), utils.Runner{Runner: seq}, utils.MockFileSystem{FileExists: true})
	assert.NoError(t, err)
	assert.Len(t, rows, 1)
	assert.Equal(t, 2, seq.calls)
}

func TestGenerateEventsGivesUpAfterSecondTimeout(t *testing.T) {
	seq := &sequenceRunner{results: []utils.MockCmdRunner{
		{Err: fmt.Errorf("PrivilegesCLI: %w", utils.ErrCommandTimeout)},
		{Err: fmt.Errorf("PrivilegesCLI: %w", utils.ErrCommandTimeout)},
	}}
	rows, err := generateEvents(eventsQueryContext(""), utils.Runner{Runner: seq}, utils.MockFileSystem{FileExists: true})
	assert.ErrorIs(t, err, utils.ErrCommandTimeout)
	assert.Nil(t, rows)
	assert.Equal(t, 2, seq.calls, "exactly one retry")
}

func TestGenerateEventsNoRetryOnOtherErrors(t *testing.T) {
	// Non-timeout failures are environmental (extension disabled etc.) and
	// are not retried.
	seq := &sequenceRunner{results: []utils.MockCmdRunner{
		{Err: assert.AnError},
		{Output: validEventLine + "\n"},
	}}
	rows, err := generateEvents(eventsQueryContext(""), utils.Runner{Runner: seq}, utils.MockFileSystem{FileExists: true})
	assert.NoError(t, err)
	assert.Empty(t, rows)
	assert.Equal(t, 1, seq.calls)
}

func TestGenerateEventsCLITimeout(t *testing.T) {
	// A timeout is transient and worth surfacing, unlike the other CLI
	// failure modes, so it is returned as an error (osquery logs it) rather
	// than silently yielding zero rows.
	runner := utils.Runner{Runner: utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			cliPath + " --history --json": {Output: "", Err: fmt.Errorf("PrivilegesCLI: %w", utils.ErrCommandTimeout)},
		},
	}}
	rows, err := generateEvents(eventsQueryContext(""), runner, utils.MockFileSystem{FileExists: true})
	assert.ErrorIs(t, err, utils.ErrCommandTimeout)
	assert.Nil(t, rows)
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
