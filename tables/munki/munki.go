package munki

// This was originally based on https://github.com/kolide/launcher/blob/master/pkg/osquery/tables/munki/munki.go but they refactored it and I'm lazy...

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/micromdm/plist"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/pkg/errors"
)

// MunkiDate can unmarshal both string dates (Munki 6) and date objects (Munki 7)
type MunkiDate time.Time

// UnmarshalPlist handles plist unmarshaling for both string and date types
func (md *MunkiDate) UnmarshalPlist(unmarshal func(interface{}) error) error {
	// First try to unmarshal as time.Time (Munki 7 date format)
	var t time.Time
	if err := unmarshal(&t); err == nil {
		*md = MunkiDate(t)
		return nil
	}

	// If that fails, try to unmarshal as string (Munki 6 format)
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	// Parse the string into time
	t, err := time.Parse("2006-01-02 15:04:05 -0700", s)
	if err != nil {
		// Try RFC3339 format (ISO 8601) as fallback
		t, err = time.Parse(time.RFC3339, s)
		if err != nil {
			return fmt.Errorf("unable to parse date: %s", s)
		}
	}

	*md = MunkiDate(t)
	return nil
}

// String returns the date in Munki 6 format for consistency
func (md MunkiDate) String() string {
	t := time.Time(md)
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04:05 +0000")
}

type munkiReport struct {
	ConsoleUser           string
	StartTime             MunkiDate
	EndTime               MunkiDate
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
	DisplayName      string `plist:"display_name"`
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
	fs := utils.OSFileSystem{}
	report, err := loadMunkiReport(fs)
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
			"start_time":       report.StartTime.String(),
			"end_time":         report.EndTime.String(),
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
		table.TextColumn("display_name"),
	}
}

func MunkiInstallsGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	fs := utils.OSFileSystem{}
	report, err := loadMunkiReport(fs)
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
			"end_time":          report.EndTime.String(),
			"display_name":      install.DisplayName,
		})
	}

	return results, nil

}

// reportPath is defined as a global variable to ease testing.
var reportPath = "/Library/Managed Installs/ManagedInstallReport.plist"

func loadMunkiReport(fs utils.FileSystem) (*munkiReport, error) {
	var report munkiReport
	if !utils.FileExists(fs, reportPath) {
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
