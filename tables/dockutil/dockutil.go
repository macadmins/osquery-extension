package dockutil

import (
	"context"
	"os"
	"strings"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/pkg/errors"
)

const dockutilPath = "/usr/local/bin/dockutil"

func DockutilColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("version"),
		table.TextColumn("path"),
	}
}

func DockutilGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string
	r := utils.NewRunner()
	fs := utils.OSFileSystem{}

	version, path, err := runDockutil(r, fs)
	if err != nil {
		return results, err
	}

	// Only add a row if dockutil is installed
	if version != "" {
		results = append(results, map[string]string{
			"version": version,
			"path":    path,
		})
	}

	return results, nil
}

func runDockutil(r utils.Runner, fs utils.FileSystem) (string, string, error) {
	// Check if dockutil exists
	_, err := fs.Stat(dockutilPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Not an error, just not installed
			return "", "", nil
		}
		return "", "", err
	}

	// Run dockutil --version
	out, err := r.Runner.RunCmd(dockutilPath, "--version")
	if err != nil {
		return "", "", errors.Wrap(err, "dockutil --version")
	}

	// Parse the output - typically "x.x.x" or "dockutil-x.x.x"
	version := strings.TrimSpace(string(out))
	version = strings.TrimPrefix(version, "dockutil-")

	return version, dockutilPath, nil
}
