package privileges

import (
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
)

func TestPrivilegesInfoColumns(t *testing.T) {
	columns := PrivilegesInfoColumns()
	assert.Len(t, columns, 4)
	assert.Contains(t, columns, table.IntegerColumn("installed"))
	assert.Contains(t, columns, table.TextColumn("version"))
	assert.Contains(t, columns, table.TextColumn("build"))
	assert.Contains(t, columns, table.IntegerColumn("extension_enabled"))
}

func TestGenerateInfoInstalled(t *testing.T) {
	runner := utils.Runner{Runner: utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			cliPath + " --version":          {Output: "PrivilegesCLI 2.6.0 (193)\n"},
			cliPath + " --extension status": {Output: "System extension is enabled\n"},
		},
	}}
	rows, err := generateInfo(runner, utils.MockFileSystem{FileExists: true})
	assert.NoError(t, err)
	assert.Len(t, rows, 1)
	assert.Equal(t, map[string]string{
		"installed":         "1",
		"version":           "2.6.0",
		"build":             "193",
		"extension_enabled": "1",
	}, rows[0])
}

func TestGenerateInfoExtensionDisabled(t *testing.T) {
	runner := utils.Runner{Runner: utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			cliPath + " --version":          {Output: "PrivilegesCLI 2.6.0 (193)\n"},
			cliPath + " --extension status": {Output: "System extension is disabled\n"},
		},
	}}
	rows, err := generateInfo(runner, utils.MockFileSystem{FileExists: true})
	assert.NoError(t, err)
	assert.Len(t, rows, 1)
	assert.Equal(t, "0", rows[0]["extension_enabled"])
}

func TestGenerateInfoNotInstalled(t *testing.T) {
	// No commands registered: any CLI execution would return empty output,
	// but the point is the generate path must not need any.
	runner := utils.Runner{Runner: utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{},
	}}
	rows, err := generateInfo(runner, utils.MockFileSystem{FileExists: false})
	assert.NoError(t, err)
	assert.Len(t, rows, 1)
	assert.Equal(t, map[string]string{
		"installed":         "0",
		"version":           "",
		"build":             "",
		"extension_enabled": "0",
	}, rows[0])
}

func TestGenerateInfoCLIFailure(t *testing.T) {
	runner := utils.Runner{Runner: utils.MultiMockCmdRunner{
		Commands: map[string]utils.MockCmdRunner{
			cliPath + " --version":          {Output: "", Err: assert.AnError},
			cliPath + " --extension status": {Output: "", Err: assert.AnError},
		},
	}}
	rows, err := generateInfo(runner, utils.MockFileSystem{FileExists: true})
	assert.NoError(t, err)
	assert.Len(t, rows, 1)
	assert.Equal(t, map[string]string{
		"installed":         "1",
		"version":           "",
		"build":             "",
		"extension_enabled": "0",
	}, rows[0])
}
