package wifi_network

import (
	"errors"
	"fmt"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"

	_ "embed"
)

//go:embed wdutil_out.txt
var wdutilOut []byte

type MockOsqueryClient struct{}

func (m MockOsqueryClient) QueryRow(query string) (map[string]string, error) {
	return map[string]string{"interface": "en0"}, nil
}

func (m MockOsqueryClient) Close() {}

type MockCommandExecutor struct{}

func (m MockCommandExecutor) ExecCommand(name string, args ...string) ([]byte, error) {
	fmt.Println(args)
	if args[1] == "en0" {
		return []byte("Current Wi-Fi Network: MyNetwork"), nil
	}
	// /usr/bin/wdutil info -q
	if args[0] == "info" {
		return wdutilOut, nil
	}
	return nil, errors.New("commad failed")
}

// TestExecCommand
func TestExecCommand(t *testing.T) {
	cmdExecutor := CmdExecutor{}
	result, err := cmdExecutor.ExecCommand("echo", "hello")
	assert.NoError(t, err)
	assert.Equal(t, "hello\n", string(result))
}

// TestWifiNetworkColumns
func TestWifiNetworkColumns(t *testing.T) {
	columns := WifiNetworkColumns()
	expectedColumns := []table.ColumnDefinition{
		table.TextColumn("ssid"),
		table.TextColumn("interface"),
		table.TextColumn("rssi"),
		table.TextColumn("noise"),
		table.TextColumn("channel"),
		table.TextColumn("channel_width"),
		table.TextColumn("channel_band"),
		table.TextColumn("transmit_rate"),
		table.TextColumn("security_type"),
		table.TextColumn("mode"),
	}
	assert.Equal(t, expectedColumns, columns)
}

// TestGetWifiStatus
func TestGetWifiStatus(t *testing.T) {
	mockOsqueryClient := MockOsqueryClient{}
	result, err := getWifiStatus(mockOsqueryClient)
	expected := map[string]string{"interface": "en0"}
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}

// TestGetValueFromResponse
func TestGetValueFromResponse(t *testing.T) {
	tt := []struct {
		name           string
		input          map[string]string
		key            string
		expectedResult string
		expectedError  bool
	}{
		{"Key exists", map[string]string{"interface": "en0"}, "interface", "en0", false},
		{"Key does not exist", map[string]string{"interface": "en0"}, "ssid", "", true},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			result, err := getValueFromResponse(tc.input, tc.key)
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}

// TestGetWifiNetworkName
func TestGetWifiNetworkName(t *testing.T) {
	tt := []struct {
		name           string
		input          string
		expectedResult string
		expectedError  bool
	}{
		{"Wifi network name exists", "en0", "MyNetwork", false},
		{"Wifi network name does not exist", "en000", "", true},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			mockCmdExecutor := MockCommandExecutor{}
			result, err := getWifiNetworkName(mockCmdExecutor, tc.input)
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}

// TestBuildWifiNetworkFromResponse
func TestBuildWifiNetworkFromResponse(t *testing.T) {
	tt := []struct {
		name           string
		input          map[string]string
		expectedResult *WifiNetwork
		expectedError  bool
	}{
		{
			"All keys exist",
			map[string]string{
				"interface":     "en0",
				"rssi":          "-50",
				"noise":         "-90",
				"channel":       "6",
				"channel_width": "20",
				"channel_band":  "2.4 GHz",
				"transmit_rate": "300 Mbps",
				"security_type": "",
				"mode":          "Station",
			},
			&WifiNetwork{
				SSID:         "MyNetwork",
				Interface:    "en0",
				RSSI:         "-50",
				Noise:        "-90",
				Channel:      "6",
				ChannelWidth: "20",
				ChannelBand:  "2.4 GHz",
				TransmitRate: "300 Mbps",
				SecurityType: "WPA3 Personal",
				Mode:         "Station",
			},
			false,
		},

		{
			"Key does not exist",
			map[string]string{
				"interface":     "en0",
				"rssi":          "-50",
				"noise":         "-90",
				"channel":       "6",
				"channel_width": "20",
				"channel_band":  "2.4 GHz",
			},
			nil,
			true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			mockCmdExecutor := MockCommandExecutor{}
			result, err := buildWifiNetworkFromResponse(mockCmdExecutor, tc.input)
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}

// TestBuildWifiNetworkResults
func TestBuildWifiNetworkResults(t *testing.T) {
	tt := []struct {
		name           string
		input          *WifiNetwork
		expectedResult []map[string]string
	}{
		{
			"Valid WifiNetwork",
			&WifiNetwork{
				SSID:         "MyNetwork",
				Interface:    "en0",
				RSSI:         "-50",
				Noise:        "-90",
				Channel:      "6",
				ChannelWidth: "20",
				ChannelBand:  "2.4 GHz",
				TransmitRate: "300 Mbps",
				SecurityType: "WPA2 Personal",
				Mode:         "Station",
			},
			[]map[string]string{
				{
					"ssid":          "MyNetwork",
					"interface":     "en0",
					"rssi":          "-50",
					"noise":         "-90",
					"channel":       "6",
					"channel_width": "20",
					"channel_band":  "2.4 GHz",
					"transmit_rate": "300 Mbps",
					"security_type": "WPA2 Personal",
					"mode":          "Station",
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			result := buildWifiNetworkResults(tc.input)
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}

func TestGetWdutilOutput(t *testing.T) {
	t.Log(wdutilOut)
	mockCmdExecutor := MockCommandExecutor{}
	result, err := getWdutilOutput(mockCmdExecutor)
	assert.NoError(t, err)
	t.Logf("Result: %s", result)
	assert.NotEmpty(t, result)
}

func TestExtractSecurityValue(t *testing.T) {
	expectedOutput := "WPA3 Personal"

	output := extractSecurityValue(string(wdutilOut), "en0")

	assert.Equal(t, expectedOutput, output)
}

func TestGetSecurityLevel(t *testing.T) {
	mockCmdExecutor := MockCommandExecutor{}
	result, err := getSecurityLevel(mockCmdExecutor, "en0")
	assert.NoError(t, err)
	assert.Equal(t, "WPA3 Personal", result)
}
