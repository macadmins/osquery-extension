package mdm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
)

func withMDMProfileFunc(t *testing.T, fn func() (*profilesOutput, error)) {
	t.Helper()
	original := getMDMProfileFunc
	getMDMProfileFunc = fn
	t.Cleanup(func() {
		getMDMProfileFunc = original
	})
}

func withMDMProfileStatusFunc(t *testing.T, fn func(utils.FileSystem) (profileStatus, error)) {
	t.Helper()
	original := getMDMProfileStatusFunc
	getMDMProfileStatusFunc = fn
	t.Cleanup(func() {
		getMDMProfileStatusFunc = original
	})
}

func withDEPStatusFunc(t *testing.T, fn func(profileStatus, utils.FileSystem) depStatus) {
	t.Helper()
	original := getDEPStatusFunc
	getDEPStatusFunc = fn
	t.Cleanup(func() {
		getDEPStatusFunc = original
	})
}

func withRunProfilesListCmd(t *testing.T, fn func() ([]byte, error)) {
	t.Helper()
	original := runProfilesListCmd
	runProfilesListCmd = fn
	t.Cleanup(func() {
		runProfilesListCmd = original
	})
}

func withRunProfilesStatusCmd(t *testing.T, fn func() ([]byte, error)) {
	t.Helper()
	original := runProfilesStatusCmd
	runProfilesStatusCmd = fn
	t.Cleanup(func() {
		runProfilesStatusCmd = original
	})
}

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
	withMDMProfileFunc(t, func() (*profilesOutput, error) {
		return &profilesOutput{ComputerLevel: []profilePayload{{
			ProfileIdentifier:  "com.example.mdm",
			ProfileInstallDate: "2026-01-01 00:00:00 +0000",
			ProfileItems: []profileItem{
				{
					PayloadType: "com.apple.mdm",
					PayloadContent: &payloadContent{
						AccessRights:            8191,
						CheckInURL:              "https://mdm.example.com/checkin",
						ServerURL:               "https://mdm.example.com/server",
						Topic:                   "com.apple.mgmt.External.example",
						IdentityCertificateUUID: "identity-uuid",
						SignMessage:             true,
					},
				},
				{PayloadType: "com.apple.security.scep"},
			},
		}}}, nil
	})
	withMDMProfileStatusFunc(t, func(fs utils.FileSystem) (profileStatus, error) {
		return profileStatus{DEPEnrolled: true, UserApproved: true}, nil
	})
	withDEPStatusFunc(t, func(status profileStatus, fs utils.FileSystem) depStatus {
		return depStatus{DEPCapable: true}
	})

	results, err := MDMInfoGenerate(context.Background(), table.QueryContext{})
	assert.NoError(t, err)
	assert.Equal(t, []map[string]string{{
		"enrolled":                  "true",
		"server_url":                "https://mdm.example.com/server",
		"checkin_url":               "https://mdm.example.com/checkin",
		"access_rights":             "8191",
		"install_date":              "2026-01-01 00:00:00 +0000",
		"payload_identifier":        "com.example.mdm",
		"sign_message":              "true",
		"topic":                     "com.apple.mgmt.External.example",
		"identity_certificate_uuid": "identity-uuid",
		"installed_from_dep":        "true",
		"user_approved":             "true",
		"has_scep_payload":          "true",
		"dep_capable":               "true",
	}}, results)
}

func TestMDMInfoGenerateUnenrolledWhenProfileMissing(t *testing.T) {
	withMDMProfileFunc(t, func() (*profilesOutput, error) {
		return nil, errors.New("profiles failed")
	})
	withMDMProfileStatusFunc(t, func(fs utils.FileSystem) (profileStatus, error) {
		return profileStatus{}, errors.New("status unsupported")
	})
	withDEPStatusFunc(t, func(status profileStatus, fs utils.FileSystem) depStatus {
		return depStatus{}
	})

	results, err := MDMInfoGenerate(context.Background(), table.QueryContext{})
	assert.NoError(t, err)
	assert.Equal(t, []map[string]string{{
		"enrolled":    "false",
		"dep_capable": "false",
	}}, results)
}

func TestGetMDMProfile(t *testing.T) {
	withRunProfilesListCmd(t, func() ([]byte, error) {
		return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>_computerlevel</key><array>
<dict>
<key>ProfileIdentifier</key><string>com.example.mdm</string>
<key>ProfileInstallDate</key><string>2026-01-01</string>
<key>ProfileItems</key><array/>
</dict>
</array>
</dict></plist>`), nil
	})

	profiles, err := getMDMProfile()
	assert.NoError(t, err)
	assert.Equal(t, "com.example.mdm", profiles.ComputerLevel[0].ProfileIdentifier)
}

func TestGetMDMProfileErrors(t *testing.T) {
	t.Run("command error", func(t *testing.T) {
		withRunProfilesListCmd(t, func() ([]byte, error) {
			return nil, errors.New("profiles failed")
		})
		profiles, err := getMDMProfile()
		assert.Error(t, err)
		assert.Nil(t, profiles)
		assert.ErrorContains(t, err, "calling /usr/bin/profiles")
	})

	t.Run("invalid plist", func(t *testing.T) {
		withRunProfilesListCmd(t, func() ([]byte, error) {
			return []byte("not plist"), nil
		})
		profiles, err := getMDMProfile()
		assert.Error(t, err)
		assert.Nil(t, profiles)
		assert.ErrorContains(t, err, "unmarshal profiles output")
	})
}

func TestGetMDMProfileStatus(t *testing.T) {
	withRunProfilesStatusCmd(t, func() ([]byte, error) {
		return []byte("Enrolled via DEP: Yes\nMDM enrollment: User Approved\n"), nil
	})
	fs := utils.MockFileSystem{FileExists: true, Err: nil}
	status, err := getMDMProfileStatus(fs)

	assert.NoError(t, err)
	assert.Equal(t, profileStatus{DEPEnrolled: true, UserApproved: true}, status)
}

func TestParseMDMProfileStatusErrors(t *testing.T) {
	_, err := parseMDMProfileStatus([]byte("Enrolled via DEP Yes\nMDM enrollment: User Approved\n"))
	assert.Error(t, err)
	assert.ErrorContains(t, err, "could not split the DEP Enrollment source")

	_, err = parseMDMProfileStatus([]byte("Enrolled via DEP: Yes\nMDM enrollment User Approved\n"))
	assert.Error(t, err)
	assert.ErrorContains(t, err, "could not split the DEP Enrollment status")

	_, err = parseMDMProfileStatus([]byte("Enrolled via DEP: Yes"))
	assert.Error(t, err)
	assert.ErrorContains(t, err, "could not split the DEP Enrollment status")
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
			defer func() {
				assert.NoError(t, os.Remove(tmpFile.Name()))
			}()
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
