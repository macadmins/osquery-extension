package thermalthrottling

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

const throttlingPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>thermal_pressure</key>
	<string>Heavy</string>
</dict>
</plist>`

func TestThermalPressureColumns(t *testing.T) {
	assert.Equal(t, []table.ColumnDefinition{
		table.TextColumn("thermal_pressure"),
		table.IntegerColumn("is_throttling"),
		table.IntegerColumn("interval"),
	}, ThermalPressureColumns())
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
		name           string
		mockCmd        utils.MockCmdRunner
		fileExists     bool
		interval       int
		wantErr        bool
		wantNil        bool
		wantPressure   string
		wantThrottling bool
	}{
		{
			name:       "Binary not present",
			fileExists: false,
			interval:   1000,
			wantNil:    true,
		},
		{
			name: "Nominal - not throttling",
			mockCmd: utils.MockCmdRunner{
				Output: testPlist,
			},
			fileExists:     true,
			interval:       1000,
			wantPressure:   "Nominal",
			wantThrottling: false,
		},
		{
			name: "Heavy - throttling",
			mockCmd: utils.MockCmdRunner{
				Output: throttlingPlist,
			},
			fileExists:     true,
			interval:       1000,
			wantPressure:   "Heavy",
			wantThrottling: true,
		},
		{
			name: "Command execution error",
			mockCmd: utils.MockCmdRunner{
				Err: errors.New("command error"),
			},
			fileExists: true,
			interval:   1000,
			wantErr:    true,
		},
		{
			name: "Invalid plist output",
			mockCmd: utils.MockCmdRunner{
				Output: "invalid plist data",
			},
			fileExists: true,
			interval:   1000,
			wantErr:    true,
		},
		{
			name: "Custom interval",
			mockCmd: utils.MockCmdRunner{
				Output: testPlist,
			},
			fileExists:     true,
			interval:       5000,
			wantPressure:   "Nominal",
			wantThrottling: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := utils.Runner{Runner: tt.mockCmd}
			fs := utils.MockFileSystem{FileExists: tt.fileExists}

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

			assert.Equal(t, tt.wantPressure, result.ThermalPressure)

			isThrottling := result.ThermalPressure != "" && result.ThermalPressure != "Nominal"
			assert.Equal(t, tt.wantThrottling, isThrottling)
		})
	}
}

func TestRunPowermetricsStatError(t *testing.T) {
	runner := utils.Runner{Runner: utils.MockCmdRunner{}}
	fs := utils.MockFileSystem{Err: errors.New("permission denied")}
	result, err := runPowermetrics(runner, fs, 1000)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestBuildOutput(t *testing.T) {
	assert.Equal(t, []map[string]string{{
		"thermal_pressure": "Nominal",
		"is_throttling":    "0",
		"interval":         "1000",
	}}, buildOutput(&powermetricsOutput{ThermalPressure: "Nominal"}, 1000))

	assert.Equal(t, []map[string]string{{
		"thermal_pressure": "Heavy",
		"is_throttling":    "1",
		"interval":         "5000",
	}}, buildOutput(&powermetricsOutput{ThermalPressure: "Heavy"}, 5000))
}

func TestGenerateWithRunner(t *testing.T) {
	results, err := generateWithRunner(
		table.QueryContext{Constraints: map[string]table.ConstraintList{
			"interval": {Constraints: []table.Constraint{{
				Operator:   table.OperatorEquals,
				Expression: "5000",
			}}},
		}},
		utils.Runner{Runner: utils.MockCmdRunner{Output: throttlingPlist}},
		utils.MockFileSystem{FileExists: true},
	)
	assert.NoError(t, err)
	assert.Equal(t, []map[string]string{{
		"thermal_pressure": "Heavy",
		"is_throttling":    "1",
		"interval":         "5000",
	}}, results)
}
