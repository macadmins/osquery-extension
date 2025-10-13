package crowdstrike_falcon

import (
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestRunCrowdstrikeFalconDarwin(t *testing.T) {
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
        <string>F3EDC954D286243B5BD94130C2F2647D</string>
		<key>cid</key>
		<string>79391C24113773B01D8181C38C3E111A</string>
        <key>falcon_version</key>
        <string>7.26.19707.0</string>
        <key>rfm</key>
        <true/>
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
			name: "PLIST unmarshal error",
			mockCmd: utils.MockCmdRunner{
				Output: `invalid plist`,
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

			output, err := runCrowdstrikeFalconDarwin(runner, fs)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.fileExist {
					assert.NotEmpty(t, output)
					if tt.name == "Successful execution" {
						expectedOutput := CrowdStrikeOutput{
							AgentID:                  "F3EDC954D286243B5BD94130C2F2647D",
							CID:                      "79391C24113773B01D8181C38C3E111A",
							FalconVersion:            "7.26.19707.0",
							ReducedFunctionalityMode: true,
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

func TestRunCrowdstrikeFalconLinux(t *testing.T) {
	tests := []struct {
		name        string
		mockCmd     utils.MockCmdRunner
		fileExist   bool
		wantErr     bool
		mockOsqData map[string][]map[string]string
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
			name: "Successful execution (with loaded sensor)",
			mockCmd: utils.MockCmdRunner{
				Output: `cid="79391c24113773b01d8181c38c3e111a", aid="f3edc954d286243b5bd94130c2f2647d", version = 7.29.18202.0
rfm-state=true,`,
				Err: nil,
			},
			fileExist: true,
			wantErr:   false,
			mockOsqData: map[string][]map[string]string{
				"SELECT 1 FROM processes WHERE name like 'falcon-sensor%';": {{"1": "1"}},
			},
		},
		{
			name: "Successful execution (with unloaded sensor)",
			mockCmd: utils.MockCmdRunner{
				Output: `cid="79391c24113773b01d8181c38c3e111a", aid="f3edc954d286243b5bd94130c2f2647d", version = 7.29.18202.0
rfm-state=true,`,
				Err: nil,
			},
			fileExist: true,
			wantErr:   false,
			mockOsqData: map[string][]map[string]string{
				"SELECT 1 FROM processes WHERE name like 'falcon-sensor%';": {},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := utils.Runner{Runner: tt.mockCmd}
			fs := utils.MockFileSystem{FileExists: tt.fileExist}
			mockOsqueryClient := &utils.MockOsqueryClient{
				Data: tt.mockOsqData,
			}

			output, err := runCrowdstrikeFalconLinux(runner, fs, mockOsqueryClient)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.fileExist {
					assert.NotEmpty(t, output)
					if tt.name == "Successful execution (with loaded sensor)" {
						expectedOutput := CrowdStrikeOutput{
							AgentID:                  "f3edc954d286243b5bd94130c2f2647d",
							CID:                      "79391c24113773b01d8181c38c3e111a",
							FalconVersion:            "7.29.18202.0",
							ReducedFunctionalityMode: true,
							SensorLoaded:             true}
						assert.Equal(t, expectedOutput, output)
					} else if tt.name == "Successful execution (with unloaded sensor)" {
						expectedOutput := CrowdStrikeOutput{
							AgentID:                  "f3edc954d286243b5bd94130c2f2647d",
							CID:                      "79391c24113773b01d8181c38c3e111a",
							FalconVersion:            "7.29.18202.0",
							ReducedFunctionalityMode: true,
							SensorLoaded:             false}
						assert.Equal(t, expectedOutput, output)
					}
				} else {
					assert.Empty(t, output)
				}
			}
		})
	}
}
