package energyimpact

import (
	_ "embed"
	"errors"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
)

type recordingCmdRunner struct {
	output string
	err    error
	name   string
	args   []string
}

func (r *recordingCmdRunner) RunCmd(name string, arg ...string) ([]byte, error) {
	r.name = name
	r.args = append([]string(nil), arg...)
	return []byte(r.output), r.err
}

func (r *recordingCmdRunner) RunCmdWithStdin(name string, stdin string, arg ...string) ([]byte, error) {
	return r.RunCmd(name, arg...)
}

//go:embed test_powermetrics_output.plist
var testPlist string

func TestEnergyImpactColumns(t *testing.T) {
	columns := EnergyImpactColumns()

	// Should return 20 columns
	assert.Len(t, columns, 20)

	// Verify column names exist
	columnNames := make(map[string]bool)
	for _, col := range columns {
		columnNames[col.Name] = true
	}

	expectedColumns := []string{
		"pid", "name", "energy_impact", "energy_impact_per_s",
		"cputime_ns", "cputime_ms_per_s", "cputime_userland_ratio",
		"intr_wakeups", "intr_wakeups_per_s", "idle_wakeups", "idle_wakeups_per_s",
		"diskio_bytesread", "diskio_bytesread_per_s",
		"diskio_byteswritten", "diskio_byteswritten_per_s",
		"packets_received", "packets_sent", "bytes_received", "bytes_sent",
		"interval",
	}

	for _, name := range expectedColumns {
		assert.True(t, columnNames[name], "Expected column %s not found", name)
	}
}

func TestParseInterval(t *testing.T) {
	tests := []struct {
		name         string
		queryContext table.QueryContext
		expected     int
	}{
		{
			name:         "default",
			queryContext: table.QueryContext{Constraints: map[string]table.ConstraintList{}},
			expected:     defaultInterval,
		},
		{
			name: "equals constraint",
			queryContext: table.QueryContext{Constraints: map[string]table.ConstraintList{
				"interval": {Constraints: []table.Constraint{{
					Operator:   table.OperatorEquals,
					Expression: "2500",
				}}},
			}},
			expected: 2500,
		},
		{
			name: "invalid equals constraint",
			queryContext: table.QueryContext{Constraints: map[string]table.ConstraintList{
				"interval": {Constraints: []table.Constraint{{
					Operator:   table.OperatorEquals,
					Expression: "not-a-number",
				}}},
			}},
			expected: defaultInterval,
		},
		{
			name: "non equals constraint",
			queryContext: table.QueryContext{Constraints: map[string]table.ConstraintList{
				"interval": {Constraints: []table.Constraint{{
					Operator:   table.OperatorGreaterThan,
					Expression: "2500",
				}}},
			}},
			expected: defaultInterval,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseInterval(tt.queryContext))
		})
	}
}

func TestGenerateWithRunnerUsesParsedInterval(t *testing.T) {
	runner := &recordingCmdRunner{output: testPlist}
	queryContext := table.QueryContext{Constraints: map[string]table.ConstraintList{
		"interval": {Constraints: []table.Constraint{{
			Operator:   table.OperatorEquals,
			Expression: "5000",
		}}},
	}}

	results, err := generateWithRunner(
		queryContext,
		utils.Runner{Runner: runner},
		utils.MockFileSystem{FileExists: true},
	)
	assert.NoError(t, err)
	assert.Len(t, results, 3)
	assert.Equal(t, "5000", results[0]["interval"])
	assert.Equal(t, "/usr/bin/powermetrics", runner.name)
	assert.Contains(t, runner.args, "5000")
}

func TestBuildOutputFormatsValues(t *testing.T) {
	results := buildOutput([]task{{
		PID:                    1234,
		Name:                   "Safari",
		EnergyImpact:           125.555,
		EnergyImpactPerS:       12.554,
		CPUTimeNS:              500000000,
		CPUTimeMSPerS:          50.505,
		CPUTimeUserlandRatio:   0.755,
		IntrWakeups:            100,
		IntrWakeupsPerS:        10.555,
		IdleWakeups:            50,
		IdleWakeupsPerS:        5.255,
		DiskIOBytesRead:        1048576,
		DiskIOBytesReadPerS:    104857.655,
		DiskIOBytesWritten:     524288,
		DiskIOBytesWrittenPerS: 52428.855,
		PacketsReceived:        200,
		PacketsSent:            150,
		BytesReceived:          204800,
		BytesSent:              102400,
	}}, 2500)

	assert.Equal(t, []map[string]string{{
		"pid":                       "1234",
		"name":                      "Safari",
		"energy_impact":             "125.56",
		"energy_impact_per_s":       "12.55",
		"cputime_ns":                "500000000",
		"cputime_ms_per_s":          "50.51",
		"cputime_userland_ratio":    "0.76",
		"intr_wakeups":              "100",
		"intr_wakeups_per_s":        "10.55",
		"idle_wakeups":              "50",
		"idle_wakeups_per_s":        "5.25",
		"diskio_bytesread":          "1048576",
		"diskio_bytesread_per_s":    "104857.65",
		"diskio_byteswritten":       "524288",
		"diskio_byteswritten_per_s": "52428.86",
		"packets_received":          "200",
		"packets_sent":              "150",
		"bytes_received":            "204800",
		"bytes_sent":                "102400",
		"interval":                  "2500",
	}}, results)
}

func TestRunPowermetrics(t *testing.T) {
	tests := []struct {
		name       string
		mockCmd    utils.MockCmdRunner
		fileExist  bool
		interval   int
		wantErr    bool
		wantTasks  int
		checkFirst func(t *testing.T, tasks []task)
	}{
		{
			name: "Binary not present",
			mockCmd: utils.MockCmdRunner{
				Output: "",
				Err:    nil,
			},
			fileExist: false,
			interval:  1000,
			wantErr:   false,
			wantTasks: 0,
		},
		{
			name: "Successful execution",
			mockCmd: utils.MockCmdRunner{
				Output: testPlist,
				Err:    nil,
			},
			fileExist: true,
			interval:  1000,
			wantErr:   false,
			wantTasks: 3,
			checkFirst: func(t *testing.T, tasks []task) {
				// Verify first task (Safari)
				assert.Equal(t, 1234, tasks[0].PID)
				assert.Equal(t, "Safari", tasks[0].Name)
				assert.InDelta(t, 125.5, tasks[0].EnergyImpact, 0.01)
				assert.InDelta(t, 12.55, tasks[0].EnergyImpactPerS, 0.01)
				assert.Equal(t, int64(500000000), tasks[0].CPUTimeNS)
				assert.InDelta(t, 50.5, tasks[0].CPUTimeMSPerS, 0.01)
				assert.InDelta(t, 0.75, tasks[0].CPUTimeUserlandRatio, 0.01)
				assert.Equal(t, 100, tasks[0].IntrWakeups)
				assert.InDelta(t, 10.5, tasks[0].IntrWakeupsPerS, 0.01)
				assert.Equal(t, 50, tasks[0].IdleWakeups)
				assert.InDelta(t, 5.2, tasks[0].IdleWakeupsPerS, 0.01)
				assert.Equal(t, int64(1048576), tasks[0].DiskIOBytesRead)
				assert.InDelta(t, 104857.6, tasks[0].DiskIOBytesReadPerS, 0.01)
				assert.Equal(t, int64(524288), tasks[0].DiskIOBytesWritten)
				assert.InDelta(t, 52428.8, tasks[0].DiskIOBytesWrittenPerS, 0.01)
				assert.Equal(t, 200, tasks[0].PacketsReceived)
				assert.Equal(t, 150, tasks[0].PacketsSent)
				assert.Equal(t, int64(204800), tasks[0].BytesReceived)
				assert.Equal(t, int64(102400), tasks[0].BytesSent)

				// Verify DEAD_TASKS entry
				assert.Equal(t, -1, tasks[2].PID)
				assert.Equal(t, "DEAD_TASKS", tasks[2].Name)
			},
		},
		{
			name: "Command execution error",
			mockCmd: utils.MockCmdRunner{
				Output: "",
				Err:    errors.New("command error"),
			},
			fileExist: true,
			interval:  1000,
			wantErr:   true,
			wantTasks: 0,
		},
		{
			name: "Stat error",
			mockCmd: utils.MockCmdRunner{
				Output: "",
				Err:    nil,
			},
			fileExist: true,
			interval:  1000,
			wantErr:   true,
			wantTasks: 0,
		},
		{
			name: "Invalid plist output",
			mockCmd: utils.MockCmdRunner{
				Output: "invalid plist data",
				Err:    nil,
			},
			fileExist: true,
			interval:  1000,
			wantErr:   true,
			wantTasks: 0,
		},
		{
			name: "Custom interval",
			mockCmd: utils.MockCmdRunner{
				Output: testPlist,
				Err:    nil,
			},
			fileExist: true,
			interval:  5000,
			wantErr:   false,
			wantTasks: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := utils.Runner{Runner: tt.mockCmd}
			fs := utils.MockFileSystem{FileExists: tt.fileExist}
			if tt.name == "Stat error" {
				fs.Err = errors.New("stat error")
			}

			tasks, err := runPowermetrics(runner, fs, tt.interval)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, tasks, tt.wantTasks)
				if tt.checkFirst != nil && len(tasks) > 0 {
					tt.checkFirst(t, tasks)
				}
			}
		})
	}
}
