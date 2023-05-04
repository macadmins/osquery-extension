package macos_rsr

import (
	"context"
	"os/exec"

	"github.com/osquery/osquery-go/plugin/table"
	"github.com/pkg/errors"
)

type RSROutput struct {
	ProductVersionExtra string
}

func MacOSRsrColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("product_version_extra"),
	}
}

func MacOSRsrGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	// only run on macOS 13 and greater
	theBytes, err := runSwVersCmd()
	if err != nil {
		return nil, errors.Wrap(err, "run sw_vers command")
	}

	rsrOutput := buildOutput(theBytes)
	if err != nil {
		return nil, errors.Wrap(err, "buildOutput")
	}

	return generateResults(rsrOutput), nil
}

func generateResults(rsrOutput RSROutput) []map[string]string {
	var results []map[string]string
	results = append(results, map[string]string{
		"product_version_extra": rsrOutput.ProductVersionExtra,
	})

	return results
}

func runSwVersCmd() ([]byte, error) {
	cmd := exec.Command("/usr/bin/sw_vers", "--ProductVersionExtra")
	out, err := cmd.Output()
	if err != nil {
		return out, errors.Wrap(err, "calling /usr/bin/sw_vers")
	}

	return out, nil
}

func buildOutput(input []byte) RSROutput {
	return RSROutput{ProductVersionExtra: string(input)}
}
