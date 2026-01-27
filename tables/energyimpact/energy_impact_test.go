package energyimpact

import (
	_ "embed"
	"errors"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/stretchr/testify/assert"
)

//go:embed test_powermetrics_output.plist
var testPlist string

func TestRunPowermetrics(t *testing.T) {
	tests := []struct {
		name        string
		mockCmd     utils.MockCmdRunner
		fileExist   bool
		interval    int
		wantErr     bool
		wantTasks   int
		checkFirst  func(t *testing.T, tasks []task)
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
