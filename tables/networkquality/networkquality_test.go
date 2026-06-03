package networkquality

import (
	"errors"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
)

func TestNetworkQualityColumns(t *testing.T) {
	assert.Equal(t, []table.ColumnDefinition{
		table.IntegerColumn("dl_throughput_kbps"),
		table.IntegerColumn("ul_throughput_kbps"),
		table.TextColumn("dl_throughput_mbps"),
		table.TextColumn("ul_throughput_mbps"),
	}, NetworkQualityColumns())
}

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
			name: "Successful execution with float responsiveness",
			mockCmd: utils.MockCmdRunner{
				Output: `{"dl_throughput": 20500, "ul_throughput": 10500, "responsiveness": 1180.154}`,
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
		{
			name: "File stat error",
			mockCmd: utils.MockCmdRunner{
				Output: "",
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
			if tt.name == "File stat error" {
				fs.Err = errors.New("stat failed")
			}

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
					if tt.name == "Successful execution with float responsiveness" {
						assert.Equal(t, 20500, output.DlThroughput)
						assert.Equal(t, 10500, output.UlThroughput)
						assert.InDelta(t, 1180.154, output.Responsiveness, 0.000001)
					}
				} else {
					assert.Empty(t, output)
				}
			}
		})
	}
}

func TestBuildOutputFormatsThroughput(t *testing.T) {
	rows := buildOutput(NetworkQualityOutput{
		DlThroughput: 20500000,
		UlThroughput: 10500000,
	})

	assert.Equal(t, []map[string]string{{
		"dl_throughput_kbps": "20500000",
		"ul_throughput_kbps": "10500000",
		"dl_throughput_mbps": "20.50",
		"ul_throughput_mbps": "10.50",
	}}, rows)
}

func TestGenerateWithRunner(t *testing.T) {
	rows, err := generateWithRunner(
		utils.Runner{Runner: utils.MockCmdRunner{Output: `{"dl_throughput": 20500000, "ul_throughput": 10500000}`}},
		utils.MockFileSystem{FileExists: true},
	)
	assert.NoError(t, err)
	assert.Equal(t, []map[string]string{{
		"dl_throughput_kbps": "20500000",
		"ul_throughput_kbps": "10500000",
		"dl_throughput_mbps": "20.50",
		"ul_throughput_mbps": "10.50",
	}}, rows)
}

func TestGenerateWithRunnerError(t *testing.T) {
	rows, err := generateWithRunner(
		utils.Runner{Runner: utils.MockCmdRunner{Err: errors.New("command failed")}},
		utils.MockFileSystem{FileExists: true},
	)
	assert.Error(t, err)
	assert.Nil(t, rows)
}
