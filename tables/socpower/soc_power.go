package socpower

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

const defaultInterval = 3000

type powermetricsOutput struct {
	Processor struct {
		CPUPower      float64 `plist:"cpu_power"`
		GPUPower      float64 `plist:"gpu_power"`
		ANEPower      float64 `plist:"ane_power"`
		CombinedPower float64 `plist:"combined_power"`
	} `plist:"processor"`
	GPU struct {
		IdleRatio float64 `plist:"idle_ratio"`
	} `plist:"gpu"`
}

func SocPowerColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("cpu_power_mw"),
		table.TextColumn("gpu_power_mw"),
		table.TextColumn("ane_power_mw"),
		table.TextColumn("combined_power_mw"),
		table.TextColumn("gpu_active_ratio"),
		table.IntegerColumn("interval"),
	}
}

func SocPowerGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
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

	gpuActiveRatio := 1.0 - result.GPU.IdleRatio

	return []map[string]string{{
		"cpu_power_mw":      fmt.Sprintf("%.2f", result.Processor.CPUPower),
		"gpu_power_mw":      fmt.Sprintf("%.2f", result.Processor.GPUPower),
		"ane_power_mw":      fmt.Sprintf("%.2f", result.Processor.ANEPower),
		"combined_power_mw": fmt.Sprintf("%.2f", result.Processor.CombinedPower),
		"gpu_active_ratio":  fmt.Sprintf("%.4f", gpuActiveRatio),
		"interval":          strconv.Itoa(interval),
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
		"--samplers", "cpu_power,gpu_power,ane_power",
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
