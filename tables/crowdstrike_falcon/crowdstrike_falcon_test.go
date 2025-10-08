package crowdstrike_falcon

import (
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestRunCrowdstrikeFalcon(t *testing.T) {
	tests := []struct {
		name      string
		mockCmd   utils.MockCmdRunner
		fileExist bool
		wantErr   bool
	}{
		{
			name: "Binary not present",
			mockCmd: utils.MockCmdRunner{
				Output: "",
				Err:    nil,
			},
			fileExist: false,
			wantErr:   false,
		},
		{
			name: "Command execution error",
			mockCmd: utils.MockCmdRunner{
				Output: "",
				Err:    errors.New("command error"),
			},
			fileExist: true,
			wantErr:   true,
		},
		{
			name: "Successful execution",
			mockCmd: utils.MockCmdRunner{
				Output: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>aid</key>
        <string>DEADBEEF</string>
        <key>falcon_version</key>
        <string>7.26.19707.0</string>
        <key>rfm</key>
        <false/>
        <key>sensor_loaded</key>
        <true/>
</dict>
</plist>`,
				Err: nil,
			},
			fileExist: true,
			wantErr:   false,
		},
		{
			name: "JSON unmarshal error",
			mockCmd: utils.MockCmdRunner{
				Output: `invalid json`,
				Err:    nil,
			},
			fileExist: true,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := utils.Runner{Runner: tt.mockCmd}
			fs := utils.MockFileSystem{FileExists: tt.fileExist}

			output, err := runCrowdstrikeFalcon(runner, fs)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.fileExist {
					assert.NotEmpty(t, output)
					if tt.name == "Successful execution" {
						expectedOutput := CrowdStrikeOutput{
							AgentID:                  "DEADBEEF",
							FalconVersion:            "7.26.19707.0",
							ReducedFunctionalityMode: false,
							SensorLoaded:             true}
						assert.Equal(t, expectedOutput, output)
					}
				} else {
					assert.Empty(t, output)
				}
			}
		})
	}
}
