package macosrsr

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/groob/plist"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/pkg/errors"
)

type RSROutput struct {
	RSRVersion   string
	MacOSVersion string
	FullVersion  string
	RSRSupported bool
}

type SystemVersionPlist struct {
	ProductBuildVersion string `plist:"ProductBuildVersion"`
	ProductVersion      string `plist:"ProductVersion"`
}

const systemVersionPath = "/System/Library/CoreServices/SystemVersion.plist"

func MacOSRsrColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("rsr_version"),
		table.TextColumn("macos_version"),
		table.TextColumn("full_macos_version"),
		table.TextColumn("rsr_supported"),
	}
}

func MacOSRsrGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	theBytes := []byte{}
	systemVersion, err := getSystemVersion()
	if err != nil {
		return nil, errors.Wrap(err, "getSystemVersion")
	}
	// only run on macOS 13 and greater
	isRsrCompatible, err := rsrCompatible(systemVersion)
	if err != nil {
		return nil, errors.Wrap(err, "rsrCompatible")
	}

	if isRsrCompatible {
		theBytes, err = runSwVersCmd()
		if err != nil {
			return nil, errors.Wrap(err, "run sw_vers command")
		}
	}

	rsrOutput := buildOutput(theBytes, systemVersion, isRsrCompatible)
	if err != nil {
		return nil, errors.Wrap(err, "buildOutput")
	}

	return generateResults(rsrOutput), nil
}

func generateResults(rsrOutput RSROutput) []map[string]string {
	var results []map[string]string
	results = append(results, map[string]string{
		"rsr_version":        rsrOutput.RSRVersion,
		"macos_version":      rsrOutput.MacOSVersion,
		"full_macos_version": rsrOutput.FullVersion,
		"rsr_supported":      strconv.FormatBool(rsrOutput.RSRSupported),
	})

	return results
}

func runSwVersCmd() ([]byte, error) {
	cmd := exec.Command("/usr/bin/sw_vers", "--ProductVersionExtra")
	out, err := cmd.Output()
	if err != nil {
		return out, errors.Wrap(err, "calling /usr/bin/sw_vers")
	}

	return out, nil
}

func buildOutput(input []byte, systemVersion SystemVersionPlist, rsrSupported bool) RSROutput {
	var out RSROutput
	if input != nil {
		out.RSRVersion = strings.TrimSpace(string(input))
	}

	if out.RSRVersion != "" {
		out.FullVersion = systemVersion.ProductVersion + " " + out.RSRVersion
	} else {
		out.FullVersion = systemVersion.ProductVersion
	}
	out.MacOSVersion = systemVersion.ProductVersion
	out.RSRSupported = rsrSupported

	return out
}

func getSystemVersion() (SystemVersionPlist, error) {

	bytes, err := readSystemVersionPlistToBytes()
	if err != nil {
		// Could not read system version plist to bytes
		return SystemVersionPlist{}, errors.Wrap(err, "readSystemVersionPlistToBytes")
	}

	return unmarshalSystemVersionBytesToStruct(bytes)
}

func readSystemVersionPlistToBytes() ([]byte, error) {
	var byteValue []byte

	plistFile, err := os.Open(systemVersionPath)
	if err != nil {
		// could not open file
		return byteValue, err
	}

	byteValue, err = io.ReadAll(plistFile)
	if err != nil {
		// could not read file to bytes
		return byteValue, err
	}

	return byteValue, nil
}

func unmarshalSystemVersionBytesToStruct(byteValue []byte) (SystemVersionPlist, error) {
	var systemVersionPlist SystemVersionPlist
	err := plist.Unmarshal(byteValue, &systemVersionPlist)
	if err != nil {
		// could not unmarshal file from bytes to systemVersionPlist struct
		return systemVersionPlist, err
	}

	return systemVersionPlist, nil
}

// Checks whether we are running on a macOS version that supports RSRs
func rsrCompatible(systemVersion SystemVersionPlist) (bool, error) {
	majorVersion := strings.Split(systemVersion.ProductVersion, ".")[0]

	majorVersionInt, err := strconv.Atoi(majorVersion)
	if err != nil {
		return false, err
	}

	if majorVersionInt >= 13 {
		return true, nil
	}

	return false, nil
}
