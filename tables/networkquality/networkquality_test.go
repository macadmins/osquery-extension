package networkquality

import (
	"errors"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestRunNetworkQuality(t *testing.T) {
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
				Output: `{"dl_throughput": 20500, "ul_throughput": 10500}`,
				Err:    nil,
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

			output, err := runNetworkQuality(runner, fs)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.fileExist {
					assert.NotEmpty(t, output)
					if tt.name == "Successful execution" {
						expectedOutput := NetworkQualityOutput{DlThroughput: 20500, UlThroughput: 10500}
						assert.Equal(t, expectedOutput, output)
					}
				} else {
					assert.Empty(t, output)
				}
			}
		})
	}
}
