package privileges

import (
	"context"
	"strconv"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
)

func PrivilegesEventsColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("event_type"),
		table.TextColumn("user"),
		table.TextColumn("subject"),
		table.TextColumn("executable"),
		table.TextColumn("signing_id"),
		table.TextColumn("team_id"),
		table.TextColumn("cdhash"),
		table.IntegerColumn("pid"),
		table.IntegerColumn("ppid"),
		table.IntegerColumn("is_platform_binary"),
		table.IntegerColumn("is_es_client"),
		// The daemon process start time from the ESF data — NOT the time
		// of the privilege change. The JSON stream carries no per-event
		// timestamp.
		table.TextColumn("daemon_start_time"),
		// Parameter column: WHERE last = '3h' maps to `--last 3h`.
		table.TextColumn("last"),
	}
}

func PrivilegesEventsGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	// PrivilegesCLI writes all its output to stderr (with exit code 0), so a
	// combined stdout+stderr runner is required to capture it.
	r := utils.NewCombinedRunner()
	return generateEvents(queryContext, r, utils.OSFileSystem{})
}

func generateEvents(queryContext table.QueryContext, r utils.Runner, fs utils.FileSystem) ([]map[string]string, error) {
	last := ""
	if constraintList, present := queryContext.Constraints["last"]; present {
		for _, constraint := range constraintList.Constraints {
			if constraint.Operator == table.OperatorEquals {
				last = constraint.Expression
			}
		}
	}

	rows := []map[string]string{}

	if !cliInstalled(fs) {
		return rows, nil
	}

	args := []string{"--history", "--json"}
	if last != "" {
		args = append(args, "--last", last)
	}

	// A CLI failure here is an expected environmental state (most commonly
	// the Privileges system extension is disabled, which JSON output
	// requires), so it yields zero rows rather than an error.
	output, err := r.Runner.RunCmd(cliPath, args...)
	if err != nil {
		return rows, nil
	}

	for _, event := range parseEvents(output) {
		rows = append(rows, map[string]string{
			"event_type":         event.Privileges.EventType,
			"user":               event.Privileges.ID,
			"subject":            event.Privileges.Subject,
			"executable":         event.ESF.Process.Executable,
			"signing_id":         event.ESF.Process.SigningID,
			"team_id":            event.ESF.Process.TeamID,
			"cdhash":             event.ESF.Process.CDHash,
			"pid":                strconv.Itoa(event.ESF.Process.PID),
			"ppid":               strconv.Itoa(event.ESF.Process.PPID),
			"is_platform_binary": boolToIntString(event.ESF.Process.IsPlatformBinary),
			"is_es_client":       boolToIntString(event.ESF.Process.IsESClient),
			"daemon_start_time":  event.ESF.Process.StartTime,
			"last":               last,
		})
	}

	return rows, nil
}
