package unifiedlog

import (
	"context"
	"encoding/json"
	"os/exec"

	"github.com/kolide/osquery-go/plugin/table"
)

type UnifiedLog struct {
	TraceID                  int64     `json:"traceID"`
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
	CreatorActivityID        int64     `json:"creatorActivityID"`
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
		table.TextColumn("timestamp"),
		table.TextColumn("process_image_path"),
		table.TextColumn("event_message"),
		table.TextColumn("event_type"),
		table.TextColumn("subsystem"),
		table.TextColumn("predicate"),
		table.TextColumn("last"),
	}
}

func UnifiedLogGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	predicate := ""
	last := ""

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

	output, err := execute(predicate, last)
	if err != nil {
		return nil, err
	}
	return output, nil
}

func execute(predicate string, last string) ([]map[string]string, error) {
	var output []map[string]string
	var unifiedlogs []UnifiedLog
	bin := "/usr/bin/log"
	args := []string{"show", "--style", "json"}

	if predicate != "" {
		args = append(args, "--predicate")
		args = append(args, predicate)
	}

	if last != "" {
		args = append(args, "--last")
		args = append(args, last)
	}
	cmd := exec.Command(bin, args...)
	stdout, err := cmd.Output()
	if err != nil {
		return output, err
	}

	err = json.Unmarshal(stdout, &unifiedlogs)
	if err != nil {
		return output, err
	}

	for _, item := range unifiedlogs {
		output = append(output, map[string]string{
			"timestamp":          item.Timestamp,
			"process_image_path": item.ProcessImagePath,
			"event_message":      item.EventMessage,
			"event_type":         item.EventType,
			"subsystem":          item.Subsystem,
			"predicate":          predicate,
			"last":               last,
		})
	}

	return output, nil
}
