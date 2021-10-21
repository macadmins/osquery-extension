package crowdstrikefalconagent

import (
	"testing"
	"os"
)

const (
	_PLIST_TEST = `
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
	<plist version="1.0">
	<dict>
		<key>agent_info</key>
		<dict>
			<key>agentID</key>
			<string>12345678-0000-0000-0000-123456789012</string>
			<key>customerID</key>
			<string>12345678-0000-0000-0000-123456789012</string>
			<key>sensor_operational</key>
			<string>true</string>
			<key>version</key>
			<string>1.2.3456.0</string>
		</dict>
	</dict>
	</plist>
	`
	_PLIST_TEMP_NAME = "deleteme.tmp"
	_FAKE_UUID = "12345678-0000-0000-0000-123456789012"
	_FAKE_REASON = "because unit tests say so"
)

func TestCheckForCTLExistence(t *testing.T) {
	// this just checks for the existence of a file
	// so this could be anything, test for true/false.

	f, err := os.CreateTemp("", _PLIST_TEMP_NAME)
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(f.Name()) // clean up

	err = checkFalconCtl(f.Name())
	if err != nil {
		t.Fatal(err)
	}

	// this test should error
	err = checkFalconCtl(_PLIST_TEMP_NAME)
	if err == nil {
		t.Fatalf("this should fail, as the temp file should not exist.")
	}

}

func TestParseRead(t *testing.T) {
	// this checks to make sure it can decode
	// a fake plist/xml list

	ret, err := parseRead([]byte(_PLIST_TEST))
	if err != nil {
		t.Fatal(err)
	}

	if ret.AgentInfo.SensorOperational != "true" {
		t.Fatalf("ret.AgentInfo.Sensoroperational not expected value")
	}

	if ret.AgentInfo.AgentID != _FAKE_UUID {
		t.Fatalf("ret.AgentInfo.AgentID not expected value")
	}
}

func TestPrepareResults(t *testing.T) {
	// this checks to ensure
	// adequate results are presented.

	ret, err := parseRead([]byte(_PLIST_TEST))
	if err != nil {
		t.Fatal(err)
	}

	out, err := prepareResults(ret)
	if err != nil {
		t.Fatal(err)
	}

	if len(out) == 0 {
		t.Fatalf("returned zero length %v", out)
	}
}

func TestPrepareError(t *testing.T) {
	ret, _ := prepareError(_FAKE_REASON)
	if ret[0][_SENOR_OPERATIONAL] != _FAKE_REASON {
		t.Fatal("not expected value.")
	}
}

func TestInfoColumns(t *testing.T) {
	ret := InfoColums()

	for _, v := range ret {
		if v.Name == _AGENTID && v.Type == "TEXT" {
			return
		}
	}

	t.Fatal("unable to find correct value.")
}
