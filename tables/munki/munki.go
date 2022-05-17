package munki

// This was originally based on https://github.com/kolide/launcher/blob/master/pkg/osquery/tables/munki/munki.go but they refactored it and I'm lazy...

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/groob/plist"
	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/pkg/errors"
)

type munkiReport struct {
	ConsoleUser           string
	StartTime             string
	EndTime               string
	Errors                []string
	Warnings              []string
	ProblemInstalls       []string
	ManagedInstallVersion string
	ManifestName          string
	ManagedInstalls       []managedInstall
}

type managedInstall struct {
	Installed        bool   `plist:"installed"`
	InstalledVersion string `plist:"installed_version"`
	Name             string `plist:"name"`
}

func MunkiInfoColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("version"),
		table.TextColumn("start_time"),
		table.TextColumn("end_time"),
		table.TextColumn("success"),
		table.TextColumn("errors"),
		table.TextColumn("warnings"),
		table.TextColumn("console_user"),
		table.TextColumn("problem_installs"),
		table.TextColumn("manifest_name"),
	}
}

func MunkiInfoGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	report, err := loadMunkiReport()
	if err != nil {
		return nil, err
	}

	if report == nil { // no files found
		return nil, nil
	}

	errors := strings.Join(report.Errors, ";")
	warnings := strings.Join(report.Warnings, ";")
	problemInstalls := strings.Join(report.ProblemInstalls, ";")

	results := []map[string]string{
		{
			"start_time":       report.StartTime,
			"end_time":         report.EndTime,
			"console_user":     report.ConsoleUser,
			"version":          report.ManagedInstallVersion,
			"success":          fmt.Sprintf("%v", len(report.Errors) == 0),
			"errors":           errors,
			"warnings":         warnings,
			"problem_installs": problemInstalls,
			"manifest_name":    report.ManifestName,
		},
	}

	return results, nil
}

func MunkiInstallsColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("installed_version"),
		table.TextColumn("installed"),
		table.TextColumn("name"),
		table.TextColumn("end_time"),
	}
}

func MunkiInstallsGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	report, err := loadMunkiReport()
	if err != nil {
		return nil, err
	}
	if report == nil {
		return nil, nil
	}
	var results []map[string]string

	for _, install := range report.ManagedInstalls {
		results = append(results, map[string]string{
			"installed_version": install.InstalledVersion,
			"installed":         fmt.Sprintf("%v", install.Installed),
			"name":              install.Name,
			"end_time":          report.EndTime,
		})
	}

	return results, nil

}

func loadMunkiReport() (*munkiReport, error) {
	var report munkiReport
	const reportPath = "/Library/Managed Installs/ManagedInstallReport.plist"
	if !utils.FileExists(reportPath) {
		return nil, nil
	}
	file, err := os.Open(reportPath)
	if err != nil {
		return &report, errors.Wrap(err, "open ManagedInstallReport file")
	}
	defer file.Close()

	if err := plist.NewDecoder(file).Decode(&report); err != nil {
		return &report, errors.Wrap(err, "decode ManagedInstallReport plist")
	}

	return &report, nil
}
