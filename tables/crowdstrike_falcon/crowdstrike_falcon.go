package crowdstrike_falcon

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/groob/plist"
	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/pkg/errors"
)

const falconCtlPath = "/Applications/Falcon.app/Contents/Resources/falconctl"

type CrowdStrikeOutput struct {
	AgentID                  string `plist:"aid"`
	CID                      string `plist:"cid"`
	FalconVersion            string `plist:"falcon_version"`
	ReducedFunctionalityMode bool   `plist:"rfm"`
	SensorLoaded             bool   `plist:"sensor_loaded"`
}

func CrowdstrikeFalconColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("agent_id"),
		table.TextColumn("cid"),
		table.TextColumn("falcon_version"),
		table.TextColumn("reduced_functionality_mode"),
		table.TextColumn("sensor_loaded"),
	}
}

func CrowdstrikeFalconGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string
	r := utils.NewRunner()
	fs := utils.OSFileSystem{}
	output, err := runCrowdstrikeFalcon(r, fs)
	if err != nil {
		fmt.Println(err)
		return results, err
	}

	results = append(results, map[string]string{
		"agent_id":                   output.AgentID,
		"cid":                        output.CID,
		"falcon_version":             output.FalconVersion,
		"reduced_functionality_mode": strconv.FormatBool(output.ReducedFunctionalityMode),
		"sensor_loaded":              strconv.FormatBool(output.SensorLoaded),
	})

	return results, nil
}

func runCrowdstrikeFalcon(r utils.Runner, fs utils.FileSystem) (CrowdStrikeOutput, error) {
	var output CrowdStrikeOutput

	_, err := fs.Stat(falconCtlPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return output, nil
		}
		return output, err
	}
	out, err := r.Runner.RunCmd(falconCtlPath, "info")
	if err != nil {
		return output, errors.Wrap(err, falconCtlPath+" info")
	}
	if err := plist.Unmarshal(out, &output); err != nil {
		return output, errors.Wrap(err, "unmarshalling falconctl output")
	}

	return output, nil
}
