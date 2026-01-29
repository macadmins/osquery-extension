package dockutil

import (
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDockutilColumns(t *testing.T) {
	columns := DockutilColumns()
	require.Len(t, columns, 2)
	assert.Equal(t, "version", columns[0].Name)
	assert.Equal(t, "path", columns[1].Name)
}

func TestRunDockutil(t *testing.T) {
	tests := []struct {
		name         string
		mockOutput   string
		mockErr      error
		fileExists   bool
		expectedVer  string
		expectedPath string
		shouldError  bool
	}{
		{
			name:         "dockutil installed - simple version",
			mockOutput:   "3.0.2\n",
			mockErr:      nil,
			fileExists:   true,
			expectedVer:  "3.0.2",
			expectedPath: dockutilPath,
			shouldError:  false,
		},
		{
			name:         "dockutil installed - version with prefix",
			mockOutput:   "dockutil-3.0.2\n",
			mockErr:      nil,
			fileExists:   true,
			expectedVer:  "3.0.2",
			expectedPath: dockutilPath,
			shouldError:  false,
		},
		{
			name:         "dockutil not installed",
			mockOutput:   "",
			mockErr:      nil,
			fileExists:   false,
			expectedVer:  "",
			expectedPath: "",
			shouldError:  false,
		},
		{
			name:         "dockutil command fails",
			mockOutput:   "",
			mockErr:      errors.New("command failed"),
			fileExists:   true,
			expectedVer:  "",
			expectedPath: "",
			shouldError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCmd := utils.MockCmdRunner{
				Output: tt.mockOutput,
				Err:    tt.mockErr,
			}
			runner := utils.Runner{Runner: mockCmd}
			fs := utils.MockFileSystem{FileExists: tt.fileExists}

			version, path, err := runDockutil(runner, fs)

			if tt.shouldError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedVer, version)
				assert.Equal(t, tt.expectedPath, path)
			}
		})
	}
}
