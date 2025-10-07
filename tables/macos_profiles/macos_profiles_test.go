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
			PayloadChecksum:          "",
			ProfileItems: []any{
				map[string]any{
					"PayloadContent": map[string]any{
						"EnableFirewall": true,
					},
					"PayloadDisplayName":  "Firewall",
					"PayloadIdentifier":   "com.apple.security.firewall",
					"PayloadOrganization": "Company",
					"PayloadType":         "com.apple.security.firewall",
					"PayloadUUID":         "6EE63BCC-3E7C-48B2-AD15-D078EBAF25D0",
					"PayloadVersion":      uint64(1),
				},
			},
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
			PayloadChecksum:          "",
			ProfileItems: []any{
				map[string]any{
					"PayloadContent": map[string]any{
						"minLength": uint64(100),
					},
					"PayloadDisplayName": "Passcode",
					"PayloadIdentifier":  "com.company.profiles.PasswordPolicy",
					"PayloadType":        "com.apple.mobiledevice.passwordpolicy",
					"PayloadUUID":        "8CD569F8-58BF-443C-8CE3-75173D3F19D1",
					"PayloadVersion":     uint64(1),
				},
			},
		},
	}
	profiles, err := unmarshalProfilesOutput(testProfileStdOut)
	assert.NoError(t, err, "Error unmarshalling profiles output")

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
			"payload_checksum":   "f83dbedab1421631584052840aa182f0550e44a1bdaaea4608529e424c3e37de",
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
			"payload_checksum":   "f66e9debe2662f568b1c69dc679252d147ee805c41aac330feb7c1926568baab",
		},
	}
	profiles, err := unmarshalProfilesOutput(testProfileStdOut)
	assert.NoError(t, err, "Error unmarshalling profiles output")
	assert.NotNil(t, profiles, "Profiles should not be nil")
	rows, err := generateResults(profiles)
	assert.NoError(t, err, "Error generating results from profiles")
	assert.Equal(t, rows, expectedRows, "Output rows are not equal")
}
