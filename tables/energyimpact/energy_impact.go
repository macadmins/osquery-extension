package energyimpact

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

// powermetricsOutput represents the top-level plist structure from powermetrics
type powermetricsOutput struct {
	Tasks []task `plist:"tasks"`
}

// task represents individual process data from powermetrics
type task struct {
	PID                   int     `plist:"pid"`
	Name                  string  `plist:"name"`
	EnergyImpact          float64 `plist:"energy_impact"`
	EnergyImpactPerS      float64 `plist:"energy_impact_per_s"`
	CPUTimeNS             int64   `plist:"cputime_ns"`
	CPUTimeMSPerS         float64 `plist:"cputime_ms_per_s"`
	CPUTimeUserlandRatio  float64 `plist:"cputime_userland_ratio"`
	IntrWakeups           int     `plist:"intr_wakeups"`
	IntrWakeupsPerS       float64 `plist:"intr_wakeups_per_s"`
	IdleWakeups           int     `plist:"idle_wakeups"`
	IdleWakeupsPerS       float64 `plist:"idle_wakeups_per_s"`
	DiskIOBytesRead       int64   `plist:"diskio_bytesread"`
	DiskIOBytesReadPerS   float64 `plist:"diskio_bytesread_per_s"`
	DiskIOBytesWritten    int64   `plist:"diskio_byteswritten"`
	DiskIOBytesWrittenPerS float64 `plist:"diskio_byteswritten_per_s"`
	PacketsReceived       int     `plist:"packets_received"`
	PacketsSent           int     `plist:"packets_sent"`
	BytesReceived         int64   `plist:"bytes_received"`
	BytesSent             int64   `plist:"bytes_sent"`
}

// EnergyImpactColumns returns the column definitions for the energy_impact table
func EnergyImpactColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.IntegerColumn("pid"),
		table.TextColumn("name"),
		table.TextColumn("energy_impact"),
		table.TextColumn("energy_impact_per_s"),
		table.IntegerColumn("cputime_ns"),
		table.TextColumn("cputime_ms_per_s"),
		table.TextColumn("cputime_userland_ratio"),
		table.IntegerColumn("intr_wakeups"),
		table.TextColumn("intr_wakeups_per_s"),
		table.IntegerColumn("idle_wakeups"),
		table.TextColumn("idle_wakeups_per_s"),
		table.IntegerColumn("diskio_bytesread"),
		table.TextColumn("diskio_bytesread_per_s"),
		table.IntegerColumn("diskio_byteswritten"),
		table.TextColumn("diskio_byteswritten_per_s"),
		table.IntegerColumn("packets_received"),
		table.IntegerColumn("packets_sent"),
		table.IntegerColumn("bytes_received"),
		table.IntegerColumn("bytes_sent"),
		table.IntegerColumn("interval"),
	}
}

// EnergyImpactGenerate generates the table data when queried
func EnergyImpactGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string

	// Get interval from WHERE clause, default to 1000ms
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
	tasks, err := runPowermetrics(r, fs, interval)
	if err != nil {
		fmt.Println(err)
		return results, err
	}

	for _, t := range tasks {
		results = append(results, map[string]string{
			"pid":                      strconv.Itoa(t.PID),
			"name":                     t.Name,
			"energy_impact":            fmt.Sprintf("%.2f", t.EnergyImpact),
			"energy_impact_per_s":      fmt.Sprintf("%.2f", t.EnergyImpactPerS),
			"cputime_ns":               strconv.FormatInt(t.CPUTimeNS, 10),
			"cputime_ms_per_s":         fmt.Sprintf("%.2f", t.CPUTimeMSPerS),
			"cputime_userland_ratio":   fmt.Sprintf("%.2f", t.CPUTimeUserlandRatio),
			"intr_wakeups":             strconv.Itoa(t.IntrWakeups),
			"intr_wakeups_per_s":       fmt.Sprintf("%.2f", t.IntrWakeupsPerS),
			"idle_wakeups":             strconv.Itoa(t.IdleWakeups),
			"idle_wakeups_per_s":       fmt.Sprintf("%.2f", t.IdleWakeupsPerS),
			"diskio_bytesread":         strconv.FormatInt(t.DiskIOBytesRead, 10),
			"diskio_bytesread_per_s":   fmt.Sprintf("%.2f", t.DiskIOBytesReadPerS),
			"diskio_byteswritten":      strconv.FormatInt(t.DiskIOBytesWritten, 10),
			"diskio_byteswritten_per_s": fmt.Sprintf("%.2f", t.DiskIOBytesWrittenPerS),
			"packets_received":         strconv.Itoa(t.PacketsReceived),
			"packets_sent":             strconv.Itoa(t.PacketsSent),
			"bytes_received":           strconv.FormatInt(t.BytesReceived, 10),
			"bytes_sent":               strconv.FormatInt(t.BytesSent, 10),
			"interval":                 strconv.Itoa(interval),
		})
	}

	return results, nil
}

// runPowermetrics executes the powermetrics command and parses the output
func runPowermetrics(r utils.Runner, fs utils.FileSystem, interval int) ([]task, error) {
	var output powermetricsOutput

	// Check if powermetrics binary exists
	_, err := fs.Stat("/usr/bin/powermetrics")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	// Run powermetrics command
	out, err := r.Runner.RunCmd(
		"/usr/bin/powermetrics",
		"-f", "plist",
		"-n", "1",
		"-i", strconv.Itoa(interval),
		"--samplers", "tasks",
		"--show-process-energy",
	)
	if err != nil {
		return nil, errors.Wrap(err, "running powermetrics")
	}

	// Parse plist output
	if err := plist.Unmarshal(out, &output); err != nil {
		return nil, errors.Wrap(err, "unmarshalling powermetrics output")
	}

	return output.Tasks, nil
}
