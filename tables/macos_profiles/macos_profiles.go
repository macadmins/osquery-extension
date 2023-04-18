package macos_profiles

import (
	"context"
	"os/exec"

	"github.com/groob/plist"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/pkg/errors"
)

type profilesOutput struct {
	ComputerLevel []profilePayload `plist:"_computerlevel"`
}

type profilePayload struct {
	ProfileIdentifier        string
	ProfileInstallDate       string
	ProfileDisplayName       string
	ProfileDescription       string
	ProfileVerificationState string
	ProfileUUID              string
	ProfileOrganization      string
	ProfileType              string
}

func MacOSProfilesColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("identifier"),
		table.TextColumn("install_date"),
		table.TextColumn("display_name"),
		table.TextColumn("description"),
		table.TextColumn("verification_state"),
		table.TextColumn("uuid"),
		table.TextColumn("organization"),
		table.TextColumn("type"),
	}
}

func MacOSProfilesGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {

	theBytes, err := runProfilesCmd()
	if err != nil {
		return nil, errors.Wrap(err, "run profiles command")
	}

	profiles, err := unmarshalProfilesOutput(theBytes)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshalProfilesOutput")
	}

	return generateResults(profiles), nil
}

func generateResults(profiles profilesOutput) []map[string]string {
	var results []map[string]string
	for _, payload := range profiles.ComputerLevel {
		result := map[string]string{
			"identifier":         payload.ProfileIdentifier,
			"install_date":       payload.ProfileInstallDate,
			"display_name":       payload.ProfileDisplayName,
			"description":        payload.ProfileDescription,
			"verification_state": payload.ProfileVerificationState,
			"uuid":               payload.ProfileUUID,
			"organization":       payload.ProfileOrganization,
			"type":               payload.ProfileType,
		}
		results = append(results, result)
	}

	return results

}

func unmarshalProfilesOutput(theBytes []byte) (profilesOutput, error) {
	var profiles profilesOutput
	if err := plist.Unmarshal(theBytes, &profiles); err != nil {
		return profiles, errors.Wrap(err, "unmarshal profiles output")
	}

	return profiles, nil
}

func runProfilesCmd() ([]byte, error) {
	cmd := exec.Command("/usr/bin/profiles", "-C", "-o", "stdout-xml")
	out, err := cmd.Output()
	if err != nil {
		return out, errors.Wrap(err, "calling /usr/bin/profiles to get profile payloads")
	}

	return out, nil
}
