package unifiedlog

import (
	"context"
	"encoding/json"
	"math/big"
	"strconv"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
)

type UnifiedLog struct {
	TraceID                  uint64    `json:"traceID"`
	EventType                string    `json:"eventType"`
	FormatString             string    `json:"formatString"`
	ActivityIdentifier       int       `json:"activityIdentifier"`
	Subsystem                string    `json:"subsystem"`
	Category                 string    `json:"category"`
	ThreadID                 int       `json:"threadID"`
	SenderImageUUID          string    `json:"senderImageUUID"`
	Backtrace                Backtrace `json:"backtrace"`
	BootUUID                 string    `json:"bootUUID"`
	ProcessImagePath         string    `json:"processImagePath"`
	Timestamp                string    `json:"timestamp"`
	SenderImagePath          string    `json:"senderImagePath"`
	CreatorActivityID        big.Int   `json:"creatorActivityID"`
	MachTimestamp            int64     `json:"machTimestamp"`
	EventMessage             string    `json:"eventMessage"`
	ProcessImageUUID         string    `json:"processImageUUID"`
	ProcessID                int       `json:"processID"`
	SenderProgramCounter     int       `json:"senderProgramCounter"`
	ParentActivityIdentifier int       `json:"parentActivityIdentifier"`
	TimezoneName             string    `json:"timezoneName"`
}

type Frames struct {
	ImageOffset int    `json:"imageOffset"`
	ImageUUID   string `json:"imageUUID"`
}
type Backtrace struct {
	Frames []Frames `json:"frames"`
}

func UnifiedLogColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("trace_id"),
		table.TextColumn("event_type"),
		table.TextColumn("format_string"),
		table.TextColumn("activity_identifier"),
		table.TextColumn("subsystem"),
		table.TextColumn("category"),
		table.TextColumn("thread_id"),
		table.TextColumn("sender_image_uuid"),
		table.TextColumn("boot_uuid"),
		table.TextColumn("process_image_path"),
		table.TextColumn("timestamp"),
		table.TextColumn("sender_image_path"),
		table.TextColumn("creator_activity_id"),
		table.TextColumn("mach_timestamp"),
		table.TextColumn("event_message"),
		table.TextColumn("process_image_uuid"),
		table.TextColumn("process_id"),
		table.TextColumn("sender_program_counter"),
		table.TextColumn("parent_activity_identifier"),
		table.TextColumn("time_zone_name"),
		table.TextColumn("predicate"),
		table.TextColumn("last"),
		table.TextColumn("log_level"),
	}
}

func UnifiedLogGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	predicate := ""
	last := ""
	logLevel := ""

	if constraintList, present := queryContext.Constraints["predicate"]; present {
		// 'predicate' is in the where clause
		for _, constraint := range constraintList.Constraints {
			if constraint.Operator == table.OperatorEquals {
				predicate = constraint.Expression
			}
		}
	}

	if constraintList, present := queryContext.Constraints["last"]; present {
		// 'last' is in the where clause
		for _, constraint := range constraintList.Constraints {
			if constraint.Operator == table.OperatorEquals {
				last = constraint.Expression
			}
		}
	}

	if constraintList, present := queryContext.Constraints["log_level"]; present {
		// 'log_level' is in the where clause
		for _, constraint := range constraintList.Constraints {
			if constraint.Operator == table.OperatorEquals {
				logLevel = constraint.Expression
			}
		}
	}

	// If there's no predicate, return empty results. This prevents crashing
	// osquery or the extension when the table attempts to load everything in
	// the unified log. This behavior is consistent with osquery tables like
	// `file` and `hash`.
	if predicate == "" && last == "" {
		return []map[string]string{}, nil
	}

	r := utils.NewRunner()

	output, err := execute(predicate, last, logLevel, r)
	if err != nil {
		return nil, err
	}
	return output, nil
}

func execute(predicate string, last string, logLevel string, r utils.Runner) ([]map[string]string, error) {
	var output []map[string]string
	var unifiedlogs []UnifiedLog

	bin := "/usr/bin/log"
	args := []string{"show", "--style", "json"}

	if last != "" {
		args = append(args, "--last")
		args = append(args, last)
	}

	if logLevel == "debug" {
		args = append(args, "--debug")
		args = append(args, "--info")
	}

	if logLevel == "info" {
		args = append(args, "--info")
	}

	if predicate != "" {
		args = append(args, "--predicate")
		args = append(args, predicate)
	}

	stdout, err := r.Runner.RunCmd(bin, args...)
	if err != nil {
		return output, err
	}

	err = json.Unmarshal(stdout, &unifiedlogs)
	if err != nil {
		return output, err
	}

	for _, item := range unifiedlogs {
		output = append(output, map[string]string{
			"trace_id":                   strconv.FormatUint(item.TraceID, 10),
			"event_type":                 item.EventType,
			"format_string":              item.FormatString,
			"activity_identifier":        strconv.Itoa(item.ActivityIdentifier),
			"subsystem":                  item.Subsystem,
			"category":                   item.Category,
			"thread_id":                  strconv.Itoa(item.ThreadID),
			"sender_image_uuid":          item.SenderImageUUID,
			"boot_uuid":                  item.BootUUID,
			"process_image_path":         item.ProcessImagePath,
			"timestamp":                  item.Timestamp,
			"sender_image_path":          item.SenderImagePath,
			"creator_activity_id":        item.CreatorActivityID.String(),
			"mach_timestamp":             strconv.FormatInt(item.MachTimestamp, 10),
			"event_message":              item.EventMessage,
			"process_image_uuid":         item.ProcessImageUUID,
			"process_id":                 strconv.Itoa(item.ProcessID),
			"sender_program_counter":     strconv.Itoa(item.SenderProgramCounter),
			"parent_activity_identifier": strconv.Itoa(item.ParentActivityIdentifier),
			"timezone_name":              item.TimezoneName,
			"predicate":                  predicate,
			"last":                       last,
			"log_level":                  logLevel,
		})
	}

	return output, nil
}
