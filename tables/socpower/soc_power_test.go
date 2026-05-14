package socpower

import (
	_ "embed"
	"errors"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
)

//go:embed test_powermetrics_output.plist
var testPlist string

func TestSocPowerColumns(t *testing.T) {
	assert.Equal(t, []table.ColumnDefinition{
		table.TextColumn("cpu_power_mw"),
		table.TextColumn("gpu_power_mw"),
		table.TextColumn("ane_power_mw"),
		table.TextColumn("combined_power_mw"),
		table.TextColumn("gpu_active_ratio"),
		table.IntegerColumn("interval"),
	}, SocPowerColumns())
}

func TestParseInterval(t *testing.T) {
	assert.Equal(t, defaultInterval, parseInterval(table.QueryContext{}))
	assert.Equal(t, 5000, parseInterval(table.QueryContext{Constraints: map[string]table.ConstraintList{
		"interval": {Constraints: []table.Constraint{{
			Operator:   table.OperatorEquals,
			Expression: "5000",
		}}},
	}}))
	assert.Equal(t, defaultInterval, parseInterval(table.QueryContext{Constraints: map[string]table.ConstraintList{
		"interval": {Constraints: []table.Constraint{{
			Operator:   table.OperatorEquals,
			Expression: "bad",
		}}},
	}}))
}

func TestRunPowermetrics(t *testing.T) {
	tests := []struct {
		name        string
		mockCmd     utils.MockCmdRunner
		fileExists  bool
		interval    int
		wantErr     bool
		wantNil     bool
		checkResult func(t *testing.T, result *powermetricsOutput)
	}{
		{
			name:       "Binary not present",
			fileExists: false,
			interval:   3000,
			wantNil:    true,
		},
		{
			name: "Successful execution",
			mockCmd: utils.MockCmdRunner{
				Output: testPlist,
			},
			fileExists: true,
			interval:   3000,
			checkResult: func(t *testing.T, result *powermetricsOutput) {
				assert.InDelta(t, 9924.35, result.Processor.CPUPower, 0.01)
				assert.InDelta(t, 169.958, result.Processor.GPUPower, 0.01)
				assert.InDelta(t, 0.0, result.Processor.ANEPower, 0.01)
				assert.InDelta(t, 10094.3, result.Processor.CombinedPower, 0.01)
				assert.InDelta(t, 0.901357, result.GPU.IdleRatio, 0.0001)
			},
		},
		{
			name: "Command execution error",
			mockCmd: utils.MockCmdRunner{
				Err: errors.New("command error"),
			},
			fileExists: true,
			interval:   3000,
			wantErr:    true,
		},
		{
			name: "Invalid plist output",
			mockCmd: utils.MockCmdRunner{
				Output: "invalid plist data",
			},
			fileExists: true,
			interval:   3000,
			wantErr:    true,
		},
		{
			name:       "Stat error",
			fileExists: true,
			interval:   3000,
			wantErr:    true,
		},
		{
			name: "Custom interval",
			mockCmd: utils.MockCmdRunner{
				Output: testPlist,
			},
			fileExists: true,
			interval:   5000,
			checkResult: func(t *testing.T, result *powermetricsOutput) {
				assert.InDelta(t, 9924.35, result.Processor.CPUPower, 0.01)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := utils.Runner{Runner: tt.mockCmd}
			fs := utils.MockFileSystem{FileExists: tt.fileExists}
			if tt.name == "Stat error" {
				fs.Err = errors.New("stat failed")
			}

			result, err := runPowermetrics(runner, fs, tt.interval)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
				return
			}

			assert.NoError(t, err)

			if tt.wantNil {
				assert.Nil(t, result)
				return
			}

			if tt.checkResult != nil {
				tt.checkResult(t, result)
			}
		})
	}
}

func TestBuildOutputFormatsValues(t *testing.T) {
	rows := buildOutput(&powermetricsOutput{
		Processor: struct {
			CPUPower      float64 `plist:"cpu_power"`
			GPUPower      float64 `plist:"gpu_power"`
			ANEPower      float64 `plist:"ane_power"`
			CombinedPower float64 `plist:"combined_power"`
		}{
			CPUPower:      9924.345,
			GPUPower:      169.958,
			ANEPower:      0,
			CombinedPower: 10094.3,
		},
		GPU: struct {
			IdleRatio float64 `plist:"idle_ratio"`
		}{
			IdleRatio: 0.901357,
		},
	}, 5000)

	assert.Equal(t, []map[string]string{{
		"cpu_power_mw":      "9924.34",
		"gpu_power_mw":      "169.96",
		"ane_power_mw":      "0.00",
		"combined_power_mw": "10094.30",
		"gpu_active_ratio":  "0.0986",
		"interval":          "5000",
	}}, rows)
}

func TestGenerateWithRunner(t *testing.T) {
	rows, err := generateWithRunner(
		table.QueryContext{Constraints: map[string]table.ConstraintList{
			"interval": {Constraints: []table.Constraint{{
				Operator:   table.OperatorEquals,
				Expression: "5000",
			}}},
		}},
		utils.Runner{Runner: utils.MockCmdRunner{Output: testPlist}},
		utils.MockFileSystem{FileExists: true},
	)
	assert.NoError(t, err)
	assert.Len(t, rows, 1)
	assert.Equal(t, "5000", rows[0]["interval"])
}
