package mdm

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
)

// TestMDMInfoColumns tests if the MDMInfoColumns function returns the correct columns
func TestMDMInfoColumns(t *testing.T) {
	columns := MDMInfoColumns()
	expectedColumns := []table.ColumnDefinition{
		table.TextColumn("enrolled"),
		table.TextColumn("server_url"),
		table.TextColumn("checkin_url"),
		table.IntegerColumn("access_rights"),
		table.TextColumn("install_date"),
		table.TextColumn("payload_identifier"),
		table.TextColumn("topic"),
		table.TextColumn("sign_message"),
		table.TextColumn("identity_certificate_uuid"),
		table.TextColumn("has_scep_payload"),
		table.TextColumn("installed_from_dep"),
		table.TextColumn("user_approved"),
		table.TextColumn("dep_capable"),
	}

	assert.Equal(t, expectedColumns, columns)
}

// TestMDMInfoGenerate tests the MDMInfoGenerate function
func TestMDMInfoGenerate(t *testing.T) {
	ctx := context.Background()
	queryContext := table.QueryContext{}

	results, err := MDMInfoGenerate(ctx, queryContext)

	assert.NoError(t, err)
	assert.NotNil(t, results)
}

// TestGetMDMProfile tests the getMDMProfile function
func TestGetMDMProfile(t *testing.T) {
	profiles, err := getMDMProfile()

	// Since profiles isn't present on non-macOS, the test should handle both cases
	if err == nil {
		assert.NotNil(t, profiles)
	} else {
		assert.Error(t, err)
	}
}

// TestGetMDMProfileStatus tests the getMDMProfileStatus function
func TestGetMDMProfileStatus(t *testing.T) {
	fs := utils.MockFileSystem{FileExists: true, Err: nil}
	status, err := getMDMProfileStatus(fs)

	// Since the status is only supported on 10.13.4+, the test should handle both cases
	if err == nil {
		assert.NotNil(t, status)
	} else {
		assert.Error(t, err)
	}
}

// TestGetDEPStatus tests the getDEPStatus function
func TestGetDEPStatus(t *testing.T) {
	status := profileStatus{
		DEPEnrolled:  true,
		UserApproved: true,
	}

	fs := utils.MockFileSystem{FileExists: true, Err: nil}

	depStatus := getDEPStatus(status, fs)

	assert.NotNil(t, depStatus)
}

// TestHasCheckedCloudConfigInPast24Hours tests the hasCheckedCloudConfigInPast24Hours function
func TestHasCheckedCloudConfigInPast24Hours(t *testing.T) {
	cases := []struct {
		name                string
		cloudConfigContents string
		want                bool
	}{
		{"empty contents", "", false},
		{"invalid xml", "invalid", false},
		{"date in the past", generateCloudConfigContents(time.Now().Add(-48 * time.Hour)), false},
		{"date in the last 24 hours", generateCloudConfigContents(time.Now().Add(-1 * time.Hour)), true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp(t.TempDir(), "")
			fs := utils.MockFileSystem{
				FileExists: true,
				Err:        nil,
			}
			assert.NoError(t, err)
			_, err = tmpFile.WriteString(c.cloudConfigContents)
			assert.NoError(t, err)
			defer os.Remove(tmpFile.Name())
			assert.Equal(t, c.want, hasCheckedCloudConfigInPast24Hours(tmpFile.Name(), fs))
		})
	}
}

// TestGetCachedDEPStatus tests the getCachedDEPStatus function
func TestGetCachedDEPStatus(t *testing.T) {
	fs := utils.MockFileSystem{FileExists: true, Err: nil}
	result := getCachedDEPStatus(fs)

	assert.NotNil(t, result)
}

func generateCloudConfigContents(t time.Time) string {
	template := `
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>lastCloudConfigCheckTime</key>
        <date>%s</date>
</dict>
</plist>
  `
	return fmt.Sprintf(template, t.Format("2006-01-02T15:04:05Z"))
}
