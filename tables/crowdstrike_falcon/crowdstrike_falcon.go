package crowdstrike_falcon

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/groob/plist"
	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/pkg/errors"
)

var falconCtlPath = map[string]string{
	"linux":  "/opt/CrowdStrike/falconctl",
	"darwin": "/Applications/Falcon.app/Contents/Resources/falconctl",
}

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

	_, err := fs.Stat(falconCtlPath[runtime.GOOS])
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return output, nil
		}
		return output, err
	}
	switch runtime.GOOS {
	case "darwin":
		out, err := r.Runner.RunCmd(falconCtlPath[runtime.GOOS], "info")
		if err != nil {
			return output, errors.Wrap(err, falconCtlPath[runtime.GOOS]+" info")
		}
		if err := plist.Unmarshal(out, &output); err != nil {
			return output, errors.Wrap(err, "unmarshalling falconctl output")
		}
	case "linux":
		out, err := r.Runner.RunCmd(falconCtlPath[runtime.GOOS], "-g", "--aid")
		if err != nil {
			return output, errors.Wrap(err, falconCtlPath[runtime.GOOS]+" -g --aid")
		}
		agentIdRegex := regexp.MustCompile(`[a-f0-9]{16}`)
		output.AgentID = agentIdRegex.FindStringSubmatch(strings.ToLower(string(out)))[1]

		out, err = r.Runner.RunCmd(falconCtlPath[runtime.GOOS], "-g", "--cid")
		if err != nil {
			return output, errors.Wrap(err, falconCtlPath[runtime.GOOS]+" -g --cid")
		}
		cidRegex := regexp.MustCompile(`[a-f0-9]{16}`)
		output.CID = cidRegex.FindStringSubmatch(strings.ToLower(string(out)))[1]

		out, err = r.Runner.RunCmd(falconCtlPath[runtime.GOOS], "-g", "--rfm-state")
		if err != nil {
			return output, errors.Wrap(err, falconCtlPath[runtime.GOOS]+" -g --rfm-state")
		}
		rfmState := strings.Split(strings.ToLower(string(out)), "=")[1]
		output.ReducedFunctionalityMode = rfmState == "true"

		out, err = r.Runner.RunCmd(falconCtlPath[runtime.GOOS], "-g", "--version")
		if err != nil {
			return output, errors.Wrap(err, falconCtlPath[runtime.GOOS]+" -g --version")
		}
		version := strings.TrimSpace(strings.Split(strings.ToLower(string(out)), "=")[1])
		output.FalconVersion = version

	}

	return output, nil
}
