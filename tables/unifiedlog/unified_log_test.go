package unifiedlog

import (
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/stretchr/testify/assert"
)

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
