package thermalthrottling

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/micromdm/plist"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/pkg/errors"
)

const defaultInterval = 1000

type powermetricsOutput struct {
	ThermalPressure string `plist:"thermal_pressure"`
}

func ThermalPressureColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("thermal_pressure"),
		table.IntegerColumn("is_throttling"),
		table.IntegerColumn("interval"),
	}
}

func ThermalPressureGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	interval := defaultInterval
	if constraintList, present := queryContext.Constraints["interval"]; present {
		for _, constraint := range constraintList.Constraints {
			if constraint.Operator == table.OperatorEquals {
				if parsed, err := strconv.Atoi(constraint.Expression); err == nil {
					interval = parsed
				}
			}
		}
	}

	r := utils.NewRunner()
	fs := utils.OSFileSystem{}
	result, err := runPowermetrics(r, fs, interval)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	if result == nil {
		return nil, nil
	}

	isThrottling := 0
	if result.ThermalPressure != "" && result.ThermalPressure != "Nominal" {
		isThrottling = 1
	}

	return []map[string]string{{
		"thermal_pressure": result.ThermalPressure,
		"is_throttling":    strconv.Itoa(isThrottling),
		"interval":         strconv.Itoa(interval),
	}}, nil
}

func runPowermetrics(r utils.Runner, fs utils.FileSystem, interval int) (*powermetricsOutput, error) {
	_, err := fs.Stat("/usr/bin/powermetrics")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	out, err := r.Runner.RunCmd(
		"/usr/bin/powermetrics",
		"-f", "plist",
		"-n", "1",
		"-i", strconv.Itoa(interval),
		"--samplers", "thermal",
	)
	if err != nil {
		return nil, errors.Wrap(err, "running powermetrics")
	}

	var output powermetricsOutput
	if err := plist.Unmarshal(out, &output); err != nil {
		return nil, errors.Wrap(err, "unmarshalling powermetrics output")
	}

	return &output, nil
}
