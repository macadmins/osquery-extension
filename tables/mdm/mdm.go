package mdm

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/groob/plist"
	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/pkg/errors"
)

type profilesOutput struct {
	ComputerLevel []profilePayload `plist:"_computerlevel"`
}

type profilePayload struct {
	ProfileIdentifier  string
	ProfileInstallDate string
	ProfileItems       []profileItem
}

type profileItem struct {
	PayloadContent *payloadContent
	PayloadType    string
}

type payloadContent struct {
	AccessRights            int
	CheckInURL              string
	ServerURL               string
	ServerCapabilities      []string
	Topic                   string
	IdentityCertificateUUID string
	SignMessage             bool
}

type profileStatus struct {
	DEPEnrolled  bool
	UserApproved bool
}

type depStatus struct {
	DEPCapable  bool `json:"dep_capable"`
	RateLimited bool `json:"rate_limited"`
}

type cloudConfigTimerCheck struct {
	LastCloudConfigCheckTime time.Time `plist:"lastCloudConfigCheckTime"`
}

const CloudConfigRecordFound = "/private/var/db/ConfigurationProfiles/Settings/.cloudConfigRecordFound"
const CloudConfigRecordNotFound = "/private/var/db/ConfigurationProfiles/Settings/.cloudConfigRecordNotFound"
const CloudConfigTimerCheck = "/private/var/db/ConfigurationProfiles/Settings/.cloudConfigTimerCheck"

func MDMInfoColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
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
}

func MDMInfoGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	// There might not be any profiles installed, but we still care if the device is DEP capable, so discard the error
	profiles, _ := getMDMProfile()

	depEnrolled, userApproved := "unknown", "unknown"
	status, err := getMDMProfileStatus()
	if err == nil { // only supported on 10.13.4+
		depEnrolled = strconv.FormatBool(status.DEPEnrolled)
		userApproved = strconv.FormatBool(status.UserApproved)
	}

	depstatus := getDEPStatus(status)
	depCapable := strconv.FormatBool(depstatus.DEPCapable)

	var enrollProfileItems []profileItem
	var results []map[string]string
	var mdmResults map[string]string
	for _, payload := range profiles.ComputerLevel {
		for _, item := range payload.ProfileItems {
			if item.PayloadContent == nil {
				continue
			}
			if item.PayloadType == "com.apple.mdm" {
				enrollProfile := item.PayloadContent
				enrollProfileItems = payload.ProfileItems
				mdmResults = map[string]string{
					"enrolled":                  "true",
					"server_url":                enrollProfile.ServerURL,
					"checkin_url":               enrollProfile.CheckInURL,
					"access_rights":             strconv.Itoa(enrollProfile.AccessRights),
					"install_date":              payload.ProfileInstallDate,
					"payload_identifier":        payload.ProfileIdentifier,
					"sign_message":              strconv.FormatBool(enrollProfile.SignMessage),
					"topic":                     enrollProfile.Topic,
					"identity_certificate_uuid": enrollProfile.IdentityCertificateUUID,
					"installed_from_dep":        depEnrolled,
					"user_approved":             userApproved,
				}
				break
			}
		}
	}
	if len(enrollProfileItems) != 0 {
		for _, item := range enrollProfileItems {
			if item.PayloadType == "com.apple.security.scep" {
				mdmResults["has_scep_payload"] = "true"
			}
		}
		results = append(results, mdmResults)
	} else {
		results = []map[string]string{{"enrolled": "false"}}
	}
	results[0]["dep_capable"] = depCapable
	return results, nil
}

func getMDMProfile() (*profilesOutput, error) {
	cmd := exec.Command("/usr/bin/profiles", "-L", "-o", "stdout-xml")
	out, err := cmd.Output()
	if err != nil {
		return nil, errors.Wrap(err, "calling /usr/bin/profiles to get MDM profile payload")
	}

	var profiles profilesOutput
	if err := plist.Unmarshal(out, &profiles); err != nil {
		return nil, errors.Wrap(err, "unmarshal profiles output")
	}

	return &profiles, nil
}

func getMDMProfileStatus() (profileStatus, error) {
	cmd := exec.Command("/usr/bin/profiles", "status", "-type", "enrollment")
	out, err := cmd.Output()
	if err != nil {
		return profileStatus{}, errors.Wrap(err, "calling /usr/bin/profiles to get MDM profile status")
	}
	lines := bytes.Split(out, []byte("\n"))
	depEnrollmentParts := bytes.SplitN(lines[0], []byte(":"), 2)
	if len(depEnrollmentParts) < 2 {
		return profileStatus{}, errors.Errorf("mdm: could not split the DEP Enrollment source %s", string(out))
	}
	enrollmentStatusParts := bytes.SplitN(lines[1], []byte(":"), 2)
	if len(enrollmentStatusParts) < 2 {
		return profileStatus{}, errors.Errorf("mdm: could not split the DEP Enrollment status %s", string(out))
	}
	return profileStatus{
		DEPEnrolled:  bytes.Contains(depEnrollmentParts[1], []byte("Yes")),
		UserApproved: bytes.Contains(enrollmentStatusParts[1], []byte("Approved")),
	}, nil
}

// Either get the live DEP capability status, or return from the cache if needed.
func getDEPStatus(status profileStatus) depStatus {
	// if we are enrolled via dep, we are by definion dep capable
	if status.DEPEnrolled {
		return depStatus{DEPCapable: true}
	}
	var depstatus depStatus
	hasAlreadyChecked := hasCheckedCloudConfigInPast24Hours()
	if !hasAlreadyChecked {
		cmd := exec.Command("/usr/bin/profiles", "show", "-type", "enrollment")
		out, err := cmd.CombinedOutput()
		if err != nil {
			if strings.Contains(string(out), "Request too soon") {
				depCapable := getCachedDEPStatus()
				depstatus.DEPCapable = depCapable
				return depstatus
			}
			return depstatus
		}

		lines := bytes.Split(out, []byte("\n"))

		if len(lines) > 3 {
			depstatus.DEPCapable = true
		}
	}

	depCapable := getCachedDEPStatus()
	depstatus.DEPCapable = depCapable

	return depstatus
}

// Returns true if the device has checked it's cloud config record in the past hour, false if the file is missing or the time is more thab 24 hours ago
func hasCheckedCloudConfigInPast24Hours() bool {
	if !utils.FileExists(CloudConfigTimerCheck) {
		return false
	}

	var cloudConfigTimerCheck cloudConfigTimerCheck
	plistFile, err := os.Open(CloudConfigTimerCheck)
	if err != nil {
		// could not open file
		return false
	}

	byteValue, err := io.ReadAll(plistFile)
	if err != nil {
		// could not read file to bytes
		return false
	}

	err = plist.Unmarshal(byteValue, &cloudConfigTimerCheck)
	if err != nil {
		// could not unmarshal file from bytes to cloudConfigTimerCheck type
		return false
	}

	dayAgo := time.Now().Add(-24 * time.Hour)
	return !cloudConfigTimerCheck.LastCloudConfigCheckTime.After(dayAgo)

}

// Will return true if the device appears to be DEP capable based on the on-disk contents, or false if not.
func getCachedDEPStatus() bool {
	if utils.FileExists(CloudConfigRecordNotFound) {
		return false
	}

	var cloudConfigRecordFound map[string]interface{}
	plistFile, err := os.Open(CloudConfigRecordFound)
	if err != nil {
		// could not open file
		return false
	}

	byteValue, err := io.ReadAll(plistFile)
	if err != nil {
		// could not read file to bytes
		return false
	}

	err = plist.Unmarshal(byteValue, &cloudConfigRecordFound)
	if err != nil {
		// could not unmarshal file from bytes to cloudConfigRecordFound interface
		return false
	}

	// if the CloudConfigFetchError key is present, this isn't a valid serial, else it looks good
	_, ok := cloudConfigRecordFound["CloudConfigFetchError"]
	return !ok
}
