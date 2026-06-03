package munki

import (
	"context"
	_ "embed"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed test_ManagedInstallReport.plist
var testManagedInstallReport []byte

//go:embed test_ManagedInstallReport_munki7.plist
var testManagedInstallReportMunki7 []byte

//go:embed test_ManagedInstallReport_with_pending.plist
var testManagedInstallReportWithPending []byte

func withReportPath(t *testing.T) string {
	t.Helper()
	original := reportPath
	reportPath = filepath.Join(t.TempDir(), "ManagedInstallReport.plist")
	t.Cleanup(func() {
		reportPath = original
	})
	return reportPath
}

func TestMunkiInstallsGenerate(t *testing.T) {
	path := withReportPath(t)
	err := os.WriteFile(path, testManagedInstallReport, 0600)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := MunkiInstallsGenerate(context.Background(), table.QueryContext{})
	if err != nil {
		t.Fatal(err)
	}
	expectedRows := []map[string]string{
		{
			"installed_version":  "105.0.5195.125",
			"version_to_install": "",
			"installed":          "true",
			"name":               "Google Chrome",
			"end_time":           "2022-09-22 11:53:01 +0000",
			"display_name":       "Google Chrome Display Name",
		},
		{
			"installed_version":  "",
			"version_to_install": "1.1.8.90000",
			"installed":          "false",
			"name":               "Nudge",
			"end_time":           "2022-09-22 11:53:01 +0000",
			"display_name":       "Nudge Display Name",
		},
	}

	assert.Equal(t, rows, expectedRows, "Output rows are not equal")

}

func TestMunkiInstallsGenerateMunki7(t *testing.T) {
	path := withReportPath(t)
	err := os.WriteFile(path, testManagedInstallReportMunki7, 0600)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := MunkiInstallsGenerate(context.Background(), table.QueryContext{})
	if err != nil {
		t.Fatal(err)
	}
	expectedRows := []map[string]string{
		{
			"installed_version":  "128.0.6613.113",
			"version_to_install": "",
			"installed":          "true",
			"name":               "Google Chrome",
			"end_time":           "2025-07-28 20:09:58 +0000",
			"display_name":       "Google Chrome",
		},
	}

	assert.Equal(t, rows, expectedRows, "Munki 7 output rows are not equal")
}

func TestMunkiInfoGenerateMunki7(t *testing.T) {
	path := withReportPath(t)
	err := os.WriteFile(path, testManagedInstallReportMunki7, 0600)
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

func TestMunkiInstallsGenerateWithPendingVersions(t *testing.T) {
	path := withReportPath(t)
	err := os.WriteFile(path, testManagedInstallReportWithPending, 0600)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := MunkiInstallsGenerate(context.Background(), table.QueryContext{})
	if err != nil {
		t.Fatal(err)
	}

	// Verify we got all 3 items
	assert.Len(t, rows, 3, "Expected 3 rows")

	// Test installed item (no version_to_install)
	assert.Equal(t, "GoogleChrome", rows[0]["name"])
	assert.Equal(t, "true", rows[0]["installed"])
	assert.Equal(t, "130.0.6723.116", rows[0]["installed_version"])
	assert.Equal(t, "", rows[0]["version_to_install"], "Installed item should have empty version_to_install")

	// Test first pending item (1Password)
	assert.Equal(t, "1Password", rows[1]["name"])
	assert.Equal(t, "false", rows[1]["installed"])
	assert.Equal(t, "", rows[1]["installed_version"])
	assert.Equal(t, "8.10.44", rows[1]["version_to_install"], "Pending 1Password should have version_to_install")

	// Test second pending item (Slack)
	assert.Equal(t, "Slack", rows[2]["name"])
	assert.Equal(t, "false", rows[2]["installed"])
	assert.Equal(t, "", rows[2]["installed_version"])
	assert.Equal(t, "4.47.72", rows[2]["version_to_install"], "Pending Slack should have version_to_install")
}

func TestMunkiInstallsColumnsIncludesVersionToInstall(t *testing.T) {
	columns := MunkiInstallsColumns()

	// Find version_to_install column
	found := false
	for _, col := range columns {
		if col.Name == "version_to_install" {
			found = true
			break
		}
	}
	assert.True(t, found, "MunkiInstallsColumns should include version_to_install")
}

func TestMunkiInfoColumns(t *testing.T) {
	assert.Equal(t, []table.ColumnDefinition{
		table.TextColumn("version"),
		table.TextColumn("start_time"),
		table.TextColumn("end_time"),
		table.TextColumn("success"),
		table.TextColumn("errors"),
		table.TextColumn("warnings"),
		table.TextColumn("console_user"),
		table.TextColumn("problem_installs"),
		table.TextColumn("manifest_name"),
	}, MunkiInfoColumns())
}

func TestMunkiInstallsColumns(t *testing.T) {
	assert.Equal(t, []table.ColumnDefinition{
		table.TextColumn("installed_version"),
		table.TextColumn("version_to_install"),
		table.TextColumn("installed"),
		table.TextColumn("name"),
		table.TextColumn("end_time"),
		table.TextColumn("display_name"),
	}, MunkiInstallsColumns())
}

func TestMunkiInfoGenerateMissingReport(t *testing.T) {
	withReportPath(t)
	rows, err := MunkiInfoGenerate(context.Background(), table.QueryContext{})
	require.NoError(t, err)
	assert.Nil(t, rows)
}

func TestMunkiInstallsGenerateMissingReport(t *testing.T) {
	withReportPath(t)
	rows, err := MunkiInstallsGenerate(context.Background(), table.QueryContext{})
	require.NoError(t, err)
	assert.Nil(t, rows)
}

func TestLoadMunkiReportInvalidPlist(t *testing.T) {
	path := withReportPath(t)
	err := os.WriteFile(path, []byte("not plist"), 0600)
	require.NoError(t, err)

	report, err := loadMunkiReport(utils.MockFileSystem{FileExists: true})
	assert.Error(t, err)
	assert.NotNil(t, report)
	assert.ErrorContains(t, err, "decode ManagedInstallReport plist")
}

func TestMunkiDateUnmarshalInvalidString(t *testing.T) {
	var md MunkiDate
	err := md.UnmarshalPlist(func(v interface{}) error {
		switch target := v.(type) {
		case *time.Time:
			return errors.New("not a date")
		case *string:
			*target = "not a date"
			return nil
		default:
			return errors.New("unexpected target")
		}
	})
	assert.Error(t, err)
	assert.ErrorContains(t, err, "unable to parse date")
	assert.Empty(t, md.String())
}
