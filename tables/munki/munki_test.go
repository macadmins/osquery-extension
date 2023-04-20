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
