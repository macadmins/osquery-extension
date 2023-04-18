package macos_profiles

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
)

//go:embed test_profiles_stdout.plist
var testProfileStdOut []byte

func TestMarshallProfileOutput(t *testing.T) {
	t.Parallel()
	expectedOutput := profilesOutput{}
	expectedOutput.ComputerLevel = []profilePayload{
		{
			ProfileIdentifier:        "com.company.mdm.com.apple.security.firewall",
			ProfileInstallDate:       "2023-03-31 01:14:38 +0000",
			ProfileDisplayName:       "Firewall",
			ProfileDescription:       "Enables the macOS firewall",
			ProfileVerificationState: "verified",
			ProfileUUID:              "597b4018-dbed-5b91-ad38-fd825711cd02",
			ProfileOrganization:      "Company",
			ProfileType:              "Configuration",
		},
		{
			ProfileIdentifier:        "com.company.profiles.PasswordPolicy",
			ProfileInstallDate:       "2023-03-31 01:14:36 +0000",
			ProfileDisplayName:       "Password Policy",
			ProfileDescription:       "Settings for Company Password Policy",
			ProfileVerificationState: "verified",
			ProfileUUID:              "45d9e37c-df62-5c6a-9808-18546fcacd22",
			ProfileOrganization:      "Company",
			ProfileType:              "Configuration",
		},
	}
	profiles, err := unmarshalProfilesOutput(testProfileStdOut)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, profiles, expectedOutput, "Expected output when parsing profiles not recieved")
}

func TestMacOSProfilesGenerate(t *testing.T) {
	t.Parallel()
	expectedRows := []map[string]string{
		{
			"identifier":         "com.company.mdm.com.apple.security.firewall",
			"install_date":       "2023-03-31 01:14:38 +0000",
			"display_name":       "Firewall",
			"description":        "Enables the macOS firewall",
			"verification_state": "verified",
			"uuid":               "597b4018-dbed-5b91-ad38-fd825711cd02",
			"organization":       "Company",
			"type":               "Configuration",
		},
		{
			"identifier":         "com.company.profiles.PasswordPolicy",
			"install_date":       "2023-03-31 01:14:36 +0000",
			"display_name":       "Password Policy",
			"description":        "Settings for Company Password Policy",
			"verification_state": "verified",
			"uuid":               "45d9e37c-df62-5c6a-9808-18546fcacd22",
			"organization":       "Company",
			"type":               "Configuration",
		},
	}
	profiles, err := unmarshalProfilesOutput(testProfileStdOut)
	if err != nil {
		t.Fatal(err)
	}
	rows := generateResults(profiles)
	assert.Equal(t, rows, expectedRows, "Output rows are not equal")
}
