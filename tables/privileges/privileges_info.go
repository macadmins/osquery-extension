package privileges

import (
	"context"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
)

func PrivilegesInfoColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.IntegerColumn("installed"),
		table.TextColumn("version"),
		table.TextColumn("build"),
		table.IntegerColumn("extension_enabled"),
	}
}

func PrivilegesInfoGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	// PrivilegesCLI writes all its output to stderr (with exit code 0), so a
	// combined stdout+stderr runner is required to capture it.
	r := utils.NewCombinedRunner()
	return generateInfo(r, utils.OSFileSystem{})
}

func generateInfo(r utils.Runner, fs utils.FileSystem) ([]map[string]string, error) {
	row := map[string]string{
		"installed":         "0",
		"version":           "",
		"build":             "",
		"extension_enabled": "0",
	}

	if !cliInstalled(fs) {
		return []map[string]string{row}, nil
	}
	row["installed"] = "1"

	// Expected environmental failures (CLI errors, unparseable output)
	// degrade fields rather than erroring, so fleet-wide queries succeed
	// on every machine.
	if versionOut, err := r.Runner.RunCmd(cliPath, "--version"); err == nil {
		version, build := parseVersion(string(versionOut))
		row["version"] = version
		row["build"] = build
	}

	if statusOut, err := r.Runner.RunCmd(cliPath, "--extension", "status"); err == nil {
		row["extension_enabled"] = boolToIntString(parseExtensionStatus(string(statusOut)))
	}

	return []map[string]string{row}, nil
}
