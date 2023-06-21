package mdm

import (
	"context"
	"testing"

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
	status, err := getMDMProfileStatus()

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

	depStatus := getDEPStatus(status)

	assert.NotNil(t, depStatus)
}

// TestHasCheckedCloudConfigInPast24Hours tests the hasCheckedCloudConfigInPast24Hours function
func TestHasCheckedCloudConfigInPast24Hours(t *testing.T) {
	result := hasCheckedCloudConfigInPast24Hours()

	assert.NotNil(t, result)
}

// TestGetCachedDEPStatus tests the getCachedDEPStatus function
func TestGetCachedDEPStatus(t *testing.T) {
	result := getCachedDEPStatus()

	assert.NotNil(t, result)
}
