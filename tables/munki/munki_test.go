package munki

import (
	"context"
	_ "embed"
	"os"
	"path/filepath"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
)

//go:embed test_ManagedInstallReport.plist
var testManagedInstallReport []byte

//go:embed test_ManagedInstallReport_munki7.plist
var testManagedInstallReportMunki7 []byte

func TestMunkiInstallsGenerate(t *testing.T) {
	reportPath = filepath.Join(t.TempDir(), "ManagedInstallReport.plist")
	err := os.WriteFile(reportPath, testManagedInstallReport, 0600)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := MunkiInstallsGenerate(context.Background(), table.QueryContext{})
	if err != nil {
		t.Fatal(err)
	}
	expectedRows := []map[string]string{
		{
			"installed_version": "105.0.5195.125",
			"installed":         "true",
			"name":              "Google Chrome",
			"end_time":          "2022-09-22 11:53:01 +0000",
			"display_name":      "Google Chrome Display Name",
		},
		{
			"installed_version": "1.1.7.81411",
			"installed":         "false",
			"name":              "Nudge",
			"end_time":          "2022-09-22 11:53:01 +0000",
			"display_name":      "Nudge Display Name",
		},
	}

	assert.Equal(t, rows, expectedRows, "Output rows are not equal")

}

func TestMunkiInstallsGenerateMunki7(t *testing.T) {
	reportPath = filepath.Join(t.TempDir(), "ManagedInstallReport.plist")
	err := os.WriteFile(reportPath, testManagedInstallReportMunki7, 0600)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := MunkiInstallsGenerate(context.Background(), table.QueryContext{})
	if err != nil {
		t.Fatal(err)
	}
	expectedRows := []map[string]string{
		{
			"installed_version": "128.0.6613.113",
			"installed":         "true",
			"name":              "Google Chrome",
			"end_time":          "2025-07-28 20:09:58 +0000",
			"display_name":      "Google Chrome",
		},
	}

	assert.Equal(t, rows, expectedRows, "Munki 7 output rows are not equal")
}

func TestMunkiInfoGenerateMunki7(t *testing.T) {
	reportPath = filepath.Join(t.TempDir(), "ManagedInstallReport.plist")
	err := os.WriteFile(reportPath, testManagedInstallReportMunki7, 0600)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := MunkiInfoGenerate(context.Background(), table.QueryContext{})
	if err != nil {
		t.Fatal(err)
	}
	expectedRows := []map[string]string{
		{
			"start_time":       "2025-07-28 20:08:30 +0000",
			"end_time":         "2025-07-28 20:09:58 +0000",
			"console_user":     "TestUser",
			"version":          "7.0.0",
			"success":          "true",
			"errors":           "",
			"warnings":         "",
			"problem_installs": "",
			"manifest_name":    "test-manifest",
		},
	}

	assert.Equal(t, rows, expectedRows, "Munki 7 info output rows are not equal")
}
