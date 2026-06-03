package unifiedlog

import (
	"context"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
)

func TestUnifiedLogColumns(t *testing.T) {
	columns := UnifiedLogColumns()
	assert.Contains(t, columns, table.TextColumn("time_zone_name"))
	assert.Contains(t, columns, table.TextColumn("predicate"))
	assert.Contains(t, columns, table.TextColumn("last"))
	assert.Contains(t, columns, table.TextColumn("log_level"))
}

func TestExecute(t *testing.T) {
	tests := []struct {
		name      string
		predicate string
		last      string
		logLevel  string
		mockCmd   utils.MockCmdRunner
		wantErr   bool
	}{
		{
			name:      "No predicate, no last, no logLevel",
			predicate: "",
			last:      "",
			logLevel:  "",
			mockCmd: utils.MockCmdRunner{
				Output: `[{"eventMessage": "test message"}]`,
				Err:    nil,
			},
			wantErr: false,
		},
		{
			name:      "With predicate",
			predicate: "eventMessage contains 'test'",
			last:      "",
			logLevel:  "",
			mockCmd: utils.MockCmdRunner{
				Output: `[{"eventMessage": "test message"}]`,
				Err:    nil,
			},
			wantErr: false,
		},
		{
			name:      "With last",
			predicate: "",
			last:      "1h",
			logLevel:  "",
			mockCmd: utils.MockCmdRunner{
				Output: `[{"eventMessage": "test message"}]`,
				Err:    nil,
			},
			wantErr: false,
		},
		{
			name:      "With logLevel debug",
			predicate: "",
			last:      "",
			logLevel:  "debug",
			mockCmd: utils.MockCmdRunner{
				Output: `[{"eventMessage": "test message"}]`,
				Err:    nil,
			},
			wantErr: false,
		},
		{
			name:      "With logLevel info",
			predicate: "",
			last:      "",
			logLevel:  "info",
			mockCmd: utils.MockCmdRunner{
				Output: `[{"eventMessage": "test message"}]`,
				Err:    nil,
			},
			wantErr: false,
		},
		{
			name:      "Command error",
			predicate: "",
			last:      "",
			logLevel:  "",
			mockCmd: utils.MockCmdRunner{
				Output: "",
				Err:    assert.AnError,
			},
			wantErr: true,
		},
		{
			name:      "JSON error",
			predicate: "eventMessage contains 'test'",
			mockCmd: utils.MockCmdRunner{
				Output: "not json",
				Err:    nil,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := utils.Runner{Runner: tt.mockCmd}
			output, err := execute(tt.predicate, tt.last, tt.logLevel, runner)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, output)
			}
		})
	}
}

func TestExecuteBuildsCompleteRows(t *testing.T) {
	runner := utils.Runner{Runner: utils.MockCmdRunner{
		Output: `[{
			"traceID": 42,
			"eventType": "logEvent",
			"formatString": "format",
			"activityIdentifier": 7,
			"subsystem": "com.example",
			"category": "default",
			"threadID": 123,
			"senderImageUUID": "sender-uuid",
			"bootUUID": "boot-uuid",
			"processImagePath": "/usr/bin/example",
			"timestamp": "2026-01-01 00:00:00.000000-0800",
			"senderImagePath": "/usr/lib/libexample.dylib",
			"creatorActivityID": 99,
			"machTimestamp": 1000,
			"eventMessage": "test message",
			"processImageUUID": "process-uuid",
			"processID": 456,
			"senderProgramCounter": 789,
			"parentActivityIdentifier": 6,
			"timezoneName": "America/Los_Angeles"
		}]`,
	}}

	output, err := execute("eventMessage contains 'test'", "1h", "debug", runner)
	assert.NoError(t, err)
	assert.Equal(t, []map[string]string{{
		"trace_id":                   "42",
		"event_type":                 "logEvent",
		"format_string":              "format",
		"activity_identifier":        "7",
		"subsystem":                  "com.example",
		"category":                   "default",
		"thread_id":                  "123",
		"sender_image_uuid":          "sender-uuid",
		"boot_uuid":                  "boot-uuid",
		"process_image_path":         "/usr/bin/example",
		"timestamp":                  "2026-01-01 00:00:00.000000-0800",
		"sender_image_path":          "/usr/lib/libexample.dylib",
		"creator_activity_id":        "99",
		"mach_timestamp":             "1000",
		"event_message":              "test message",
		"process_image_uuid":         "process-uuid",
		"process_id":                 "456",
		"sender_program_counter":     "789",
		"parent_activity_identifier": "6",
		"time_zone_name":             "America/Los_Angeles",
		"predicate":                  "eventMessage contains 'test'",
		"last":                       "1h",
		"log_level":                  "debug",
	}}, output)
}

func TestUnifiedLogGenerateWithoutPredicateOrLastReturnsEmpty(t *testing.T) {
	output, err := UnifiedLogGenerate(context.Background(), table.QueryContext{})
	assert.NoError(t, err)
	assert.Empty(t, output)
}

func TestGenerateWithRunnerUsesConstraints(t *testing.T) {
	output, err := generateWithRunner(table.QueryContext{
		Constraints: map[string]table.ConstraintList{
			"predicate": {Constraints: []table.Constraint{{
				Operator:   table.OperatorEquals,
				Expression: "eventMessage contains 'test'",
			}}},
			"last": {Constraints: []table.Constraint{{
				Operator:   table.OperatorEquals,
				Expression: "1h",
			}}},
			"log_level": {Constraints: []table.Constraint{{
				Operator:   table.OperatorEquals,
				Expression: "info",
			}}},
		},
	}, utils.Runner{Runner: utils.MockCmdRunner{Output: `[{"eventMessage":"test message"}]`}})
	assert.NoError(t, err)
	assert.Equal(t, "eventMessage contains 'test'", output[0]["predicate"])
	assert.Equal(t, "1h", output[0]["last"])
	assert.Equal(t, "info", output[0]["log_level"])
}
