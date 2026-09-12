package privileges

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
)

// Per-attempt deadline for PrivilegesCLI, a safety net for a slow or
// unresponsive helper. Measured cold starts were mostly 2-5s and
// occasionally 13-14.5s, so 15s leaves headroom; one retry covers the
// rare unanswered attempt. Worst case 30s, well under osquery's 300s
// thrift_timeout.
const cliTimeout = 15 * time.Second

func PrivilegesEventsColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		// ADMIN_ADD / ADMIN_REMOVE for privilege changes, or one of CLONE,
		// CREATE, DELETE, RENAME, EXEC for the extension's tamper-protection
		// events on Privileges' own files and launchd jobs.
		table.TextColumn("event_type"),
		// privileges.id: the user or group whose membership changed; the
		// subject column says which. Empty for tamper-protection events.
		table.TextColumn("principal"),
		// "user" or "group" for privilege changes; the affected path for
		// tamper-protection events.
		table.TextColumn("subject"),
		table.TextColumn("executable"),
		table.TextColumn("signing_id"),
		table.TextColumn("team_id"),
		table.TextColumn("cdhash"),
		table.IntegerColumn("pid"),
		table.IntegerColumn("ppid"),
		// Effective uid/gid and audit uid of the acting process, from
		// esf.process.audit_token. -1 when the process has no audit session
		// (daemons). Named as in osquery's es_process_events.
		table.IntegerColumn("uid"),
		table.IntegerColumn("gid"),
		table.IntegerColumn("auid"),
		// pid of the responsible process (e.g. the terminal app behind a
		// shell), from esf.process.responsible_audit_token.
		table.IntegerColumn("responsible_pid"),
		table.IntegerColumn("is_platform_binary"),
		table.IntegerColumn("is_es_client"),
		// esf.process.start_time: the start time of the process that made
		// the change (not necessarily PrivilegesDaemon) — NOT the time of
		// the privilege change. The JSON stream carries no per-event
		// timestamp.
		table.TextColumn("process_start_time"),
		// Parameter column: WHERE last = '3h' maps to `--last 3h`.
		table.TextColumn("last"),
	}
}

func PrivilegesEventsGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	// PrivilegesCLI writes all its output to stderr (with exit code 0), so a
	// combined stdout+stderr runner is required to capture it. The deadline
	// is a safety net for a slow or unresponsive helper; see cliTimeout.
	r := utils.NewCombinedRunnerWithTimeout(cliTimeout)
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

	// Deliberately not passing --privilege-changes-only: the system
	// extension only records events on Privileges' own protected paths, so
	// the CLONE / CREATE / DELETE / RENAME / EXEC lines are tamper attempts
	// against Privileges and are worth reporting alongside the ADMIN_* ones.
	// Filter on event_type in SQL if only privilege changes are wanted.
	args := []string{"--history", "--json"}
	if last != "" {
		args = append(args, "--last", last)
	}

	// A timeout is transient and worth an operator's attention, so it is
	// returned as an error (osquery logs it). Any other CLI failure is an
	// expected environmental state (most commonly the Privileges system
	// extension is disabled, which JSON output requires) and yields zero
	// rows rather than an error.
	output, err := r.Runner.RunCmd(cliPath, args...)
	if errors.Is(err, utils.ErrCommandTimeout) {
		// The helper occasionally does not answer an attempt; a fresh
		// attempt usually does, so retry once before giving up.
		output, err = r.Runner.RunCmd(cliPath, args...)
	}
	if errors.Is(err, utils.ErrCommandTimeout) {
		return nil, err
	}
	if err != nil {
		return rows, nil
	}

	for _, event := range parseEvents(output) {
		rows = append(rows, map[string]string{
			"event_type":         event.Privileges.EventType,
			"principal":          event.Privileges.ID,
			"subject":            event.Privileges.Subject,
			"executable":         event.ESF.Process.Executable,
			"signing_id":         event.ESF.Process.SigningID,
			"team_id":            event.ESF.Process.TeamID,
			"cdhash":             event.ESF.Process.CDHash,
			"pid":                strconv.Itoa(event.ESF.Process.PID),
			"ppid":               strconv.Itoa(event.ESF.Process.PPID),
			"uid":                auditTokenField(event.ESF.Process.AuditToken, auditTokenEUID),
			"gid":                auditTokenField(event.ESF.Process.AuditToken, auditTokenEGID),
			"auid":               auditTokenField(event.ESF.Process.AuditToken, auditTokenAUID),
			"responsible_pid":    auditTokenField(event.ESF.Process.ResponsibleAuditToken, auditTokenPID),
			"is_platform_binary": boolToIntString(event.ESF.Process.IsPlatformBinary),
			"is_es_client":       boolToIntString(event.ESF.Process.IsESClient),
			"process_start_time": event.ESF.Process.StartTime,
			"last":               last,
		})
	}

	return rows, nil
}
