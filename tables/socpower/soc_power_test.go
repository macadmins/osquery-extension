package socpower

import (
	_ "embed"
	"errors"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/stretchr/testify/assert"
)

//go:embed test_powermetrics_output.plist
var testPlist string

func TestSocPowerColumns(t *testing.T) {
	columns := SocPowerColumns()

	assert.Len(t, columns, 6)

	columnNames := make(map[string]bool)
	for _, col := range columns {
		columnNames[col.Name] = true
	}

	for _, name := range []string{"cpu_power_mw", "gpu_power_mw", "ane_power_mw", "combined_power_mw", "gpu_active_ratio", "interval"} {
		assert.True(t, columnNames[name], "expected column %s not found", name)
	}
}

func TestRunPowermetrics(t *testing.T) {
	tests := []struct {
		name         string
		mockCmd      utils.MockCmdRunner
		fileExists   bool
		interval     int
		wantErr      bool
		wantNil      bool
		checkResult  func(t *testing.T, result *powermetricsOutput)
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
