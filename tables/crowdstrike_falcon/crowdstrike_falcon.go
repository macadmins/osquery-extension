package crowdstrike_falcon

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/micromdm/plist"
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

func CrowdstrikeFalconGenerate(ctx context.Context, queryContext table.QueryContext, socketPath string) ([]map[string]string, error) {
	return generate(ctx, runtime.GOOS, utils.NewRunner(), utils.OSFileSystem{},
		utils.SocketClienter(socketPath))
}

// generate reads the sensor's state for goos; on Linux, when falconctl is installed, it opens one
// client through clienter to ask osquery whether the sensor is loaded, and closes it when the
// query returns.
func generate(ctx context.Context, goos string, r utils.Runner, fs utils.FileSystem,
	clienter utils.OsqueryClienter) ([]map[string]string, error) {
	var results []map[string]string
	var output = CrowdStrikeOutput{}
	var err error

	switch goos {
	case "darwin":
		output, err = runCrowdstrikeFalconDarwin(r, fs)
		if err != nil {
			fmt.Println(err)
			return nil, err
		}

	case "linux":
		// Without falconctl there is nothing to report, so no client to osquery is opened; a
		// falconctl that cannot be checked fails the query with that error, before any client.
		if _, err := fs.Stat(falconCtlPath["linux"]); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			return nil, err
		}
		// osquery-go cancels the context only once osquery has closed the connection, so a query
		// already cancelled has no reader, and opening a client can wait out the client's timeout.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		osqueryClient, err := clienter.NewOsqueryClient()
		if err != nil {
			return nil, err
		}
		defer osqueryClient.Close()
		output, err = runCrowdstrikeFalconLinux(ctx, r, fs, osqueryClient)
		if err != nil {
			fmt.Println(err)
			return nil, err
		}
	}

	results = append(results, map[string]string{
		"agent_id":                   strings.ToUpper(output.AgentID),
		"cid":                        strings.ToUpper(output.CID),
		"falcon_version":             output.FalconVersion,
		"reduced_functionality_mode": strconv.FormatBool(output.ReducedFunctionalityMode),
		"sensor_loaded":              strconv.FormatBool(output.SensorLoaded),
	})

	return results, nil
}

func runCrowdstrikeFalconLinux(ctx context.Context, r utils.Runner, fs utils.FileSystem,
	client utils.OsqueryClient) (CrowdStrikeOutput, error) {
	var output CrowdStrikeOutput

	_, err := fs.Stat(falconCtlPath["linux"])
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return output, nil
		}
		return output, err
	}

	falconProcessQuery := "SELECT 1 FROM processes WHERE name like 'falcon-sensor%';"
	// osquery-go sends the query even when the context is done, so check it before the call.
	if err := ctx.Err(); err != nil {
		return output, err
	}
	loadedState, err := client.QueryRowsContext(ctx, falconProcessQuery)
	if err != nil {
		return output, err
	}

	if len(loadedState) == 0 {
		output.SensorLoaded = false
	} else {
		output.SensorLoaded = true
	}

	out, err := r.Runner.RunCmd(falconCtlPath["linux"], "-g", "--aid", "--cid", "--rfm-state", "--version")
	if err != nil {
		return output, errors.Wrap(err, falconCtlPath["linux"]+" -g --aid --cid --rfm-state --version")
	}

	return HydrateCommandOutput(string(out), output), nil
}

func HydrateCommandOutput(cmdOut string, output CrowdStrikeOutput) CrowdStrikeOutput {
	out := strings.ToLower(cmdOut)

	agentIdRegex := regexp.MustCompile(`aid="([a-f0-9]{32})"`)
	maybeAgentID := agentIdRegex.FindStringSubmatch(out)
	if len(maybeAgentID) > 1 {
		output.AgentID = maybeAgentID[1]
	}

	cidRegex := regexp.MustCompile(`cid="([a-f0-9]{32})"`)
	maybeCID := cidRegex.FindStringSubmatch(out)
	if len(maybeCID) > 1 {
		output.CID = maybeCID[1]
	}

	versionRegex := regexp.MustCompile(`version\s?=\s?(\d\.\d{2}\.\d{5}\.\d)`)
	maybeVersion := versionRegex.FindStringSubmatch(out)
	if len(maybeVersion) > 1 {
		output.FalconVersion = maybeVersion[1]
	}

	// as of 7.29, `rfm-state` is always returned on a newline, and always has a trailing comma, but might be "not set"
	rfmStateRegex := regexp.MustCompile(`rfm-state\s?=\s?(true|false),?`)
	maybeRfmState := rfmStateRegex.FindStringSubmatch(out)
	if len(maybeRfmState) > 1 {
		output.ReducedFunctionalityMode = maybeRfmState[1] == "true"
	}

	return output
}

func runCrowdstrikeFalconDarwin(r utils.Runner, fs utils.FileSystem) (CrowdStrikeOutput, error) {
	var output CrowdStrikeOutput

	_, err := fs.Stat(falconCtlPath["darwin"])
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return output, nil
		}
		return output, err
	}

	out, err := r.Runner.RunCmd(falconCtlPath["darwin"], "info")
	if err != nil {
		return output, errors.Wrap(err, falconCtlPath["darwin"]+" info")
	}
	if err := plist.Unmarshal(out, &output); err != nil {
		return output, errors.Wrap(err, "unmarshalling falconctl output")
	}

	return output, nil
}
