package wifi_network

import (
	"errors"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "embed"
)

//go:embed wdutil_out.txt
var wdutilOut []byte

type fakeCommandExecutor struct {
	responses map[string][]byte
	errors    map[string]error
	calls     []commandCall
}

type commandCall struct {
	name string
	args []string
}

func (f *fakeCommandExecutor) ExecCommand(name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, commandCall{name: name, args: args})
	if err := f.errors[name]; err != nil {
		return nil, err
	}
	if out, ok := f.responses[name]; ok {
		return out, nil
	}
	return nil, errors.New("command failed")
}

func happyCommandExecutor() *fakeCommandExecutor {
	return &fakeCommandExecutor{
		responses: map[string][]byte{
			"/usr/sbin/networksetup": []byte("Current Wi-Fi Network: MyNetwork\n"),
			"/usr/bin/wdutil":        wdutilOut,
		},
		errors: map[string]error{},
	}
}

type errorOsqueryClient struct {
	err error
}

func (e errorOsqueryClient) QueryRows(query string) ([]map[string]string, error) {
	return nil, e.err
}

func (e errorOsqueryClient) QueryRow(query string) (map[string]string, error) {
	return nil, e.err
}

func (e errorOsqueryClient) Close() {}

func wifiStatusFixture() map[string]string {
	return map[string]string{
		"interface":     "en0",
		"rssi":          "-50",
		"noise":         "-90",
		"channel":       "6",
		"channel_width": "20",
		"channel_band":  "2.4 GHz",
		"transmit_rate": "300 Mbps",
		"mode":          "Station",
	}
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
	mockOsqueryClient := &utils.MockOsqueryClient{
		Data: map[string][]map[string]string{
			"SELECT * FROM wifi_status;": {{"interface": "en0"}},
		},
	}
	result, err := getWifiStatus(mockOsqueryClient)
	expected := map[string]string{"interface": "en0"}
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}

func TestGetWifiStatusReturnsQueryErrors(t *testing.T) {
	expectedErr := errors.New("query failed")

	result, err := getWifiStatus(errorOsqueryClient{err: expectedErr})

	require.ErrorIs(t, err, expectedErr)
	assert.Nil(t, result)
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
		output         []byte
		err            error
		expectedResult string
		expectedError  string
	}{
		{
			name:           "Wifi network name exists",
			output:         []byte("Current Wi-Fi Network: MyNetwork\n"),
			expectedResult: "MyNetwork",
		},
		{
			name:           "Wifi network is disconnected",
			output:         []byte("You are not associated with an AirPort network.\n"),
			expectedResult: "",
		},
		{
			name:          "networksetup fails",
			err:           errors.New("networksetup failed"),
			expectedError: "failed to run networksetup",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			mockCmdExecutor := &fakeCommandExecutor{
				responses: map[string][]byte{"/usr/sbin/networksetup": tc.output},
				errors:    map[string]error{"/usr/sbin/networksetup": tc.err},
			}
			result, err := getWifiNetworkName(mockCmdExecutor, "en0")
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.expectedResult, result)
			require.Len(t, mockCmdExecutor.calls, 1)
			assert.Equal(t, "/usr/sbin/networksetup", mockCmdExecutor.calls[0].name)
			assert.Equal(t, []string{"-getairportnetwork", "en0"}, mockCmdExecutor.calls[0].args)
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
			wifiStatusFixture(),
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
			mockCmdExecutor := happyCommandExecutor()
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

func TestBuildWifiNetworkFromResponseReturnsCommandErrors(t *testing.T) {
	tt := []struct {
		name          string
		command       string
		expectedError string
	}{
		{
			name:          "networksetup error",
			command:       "/usr/sbin/networksetup",
			expectedError: "failed to run networksetup",
		},
		{
			name:          "wdutil error",
			command:       "/usr/bin/wdutil",
			expectedError: "failed to run wdutil",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			mockCmdExecutor := happyCommandExecutor()
			mockCmdExecutor.errors[tc.command] = errors.New("command failed")

			result, err := buildWifiNetworkFromResponse(mockCmdExecutor, wifiStatusFixture())

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedError)
			assert.Nil(t, result)
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
	mockCmdExecutor := happyCommandExecutor()
	result, err := getWdutilOutput(mockCmdExecutor)
	assert.NoError(t, err)
	assert.Equal(t, string(wdutilOut), result)
	require.Len(t, mockCmdExecutor.calls, 1)
	assert.Equal(t, "/usr/bin/wdutil", mockCmdExecutor.calls[0].name)
	assert.Equal(t, []string{"info", "-q"}, mockCmdExecutor.calls[0].args)
}

func TestGetWdutilOutputReturnsCommandErrors(t *testing.T) {
	mockCmdExecutor := happyCommandExecutor()
	mockCmdExecutor.errors["/usr/bin/wdutil"] = errors.New("wdutil failed")

	result, err := getWdutilOutput(mockCmdExecutor)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to run wdutil")
	assert.Empty(t, result)
}

func TestExtractSecurityValue(t *testing.T) {
	tt := []struct {
		name          string
		input         string
		interfaceName string
		expected      string
	}{
		{
			name:          "returns matching interface security",
			input:         string(wdutilOut),
			interfaceName: "en0",
			expected:      "WPA3 Personal",
		},
		{
			name: "returns empty for unmatched interface",
			input: `Interface Name: en1
Security: WPA2 Personal`,
			interfaceName: "en0",
			expected:      "",
		},
		{
			name: "keeps scanning until requested interface",
			input: `Interface Name: en1
Security: WPA2 Personal
Interface Name: en0
Security: WPA3 Enterprise`,
			interfaceName: "en0",
			expected:      "WPA3 Enterprise",
		},
		{
			name:          "returns empty when security is missing",
			input:         "Interface Name: en0\nPHY Mode: 11ac",
			interfaceName: "en0",
			expected:      "",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			output := extractSecurityValue(tc.input, tc.interfaceName)
			assert.Equal(t, tc.expected, output)
		})
	}
}

func TestGetSecurityLevel(t *testing.T) {
	mockCmdExecutor := happyCommandExecutor()
	result, err := getSecurityLevel(mockCmdExecutor, "en0")
	assert.NoError(t, err)
	assert.Equal(t, "WPA3 Personal", result)
}

func TestGetSecurityLevelReturnsWdutilErrors(t *testing.T) {
	mockCmdExecutor := happyCommandExecutor()
	mockCmdExecutor.errors["/usr/bin/wdutil"] = errors.New("wdutil failed")

	result, err := getSecurityLevel(mockCmdExecutor, "en0")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to run wdutil")
	assert.Empty(t, result)
}

func TestGenerateWithDeps(t *testing.T) {
	mockOsqueryClient := &utils.MockOsqueryClient{
		Data: map[string][]map[string]string{
			"SELECT * FROM wifi_status;": {wifiStatusFixture()},
		},
	}
	mockCmdExecutor := happyCommandExecutor()

	result, err := generateWithDeps(mockOsqueryClient, mockCmdExecutor)

	require.NoError(t, err)
	assert.Equal(t, []map[string]string{
		{
			"ssid":          "MyNetwork",
			"interface":     "en0",
			"rssi":          "-50",
			"noise":         "-90",
			"channel":       "6",
			"channel_width": "20",
			"channel_band":  "2.4 GHz",
			"transmit_rate": "300 Mbps",
			"security_type": "WPA3 Personal",
			"mode":          "Station",
		},
	}, result)
}

func TestGenerateWithDepsReturnsWifiStatusErrors(t *testing.T) {
	expectedErr := errors.New("query failed")

	result, err := generateWithDeps(errorOsqueryClient{err: expectedErr}, happyCommandExecutor())

	require.ErrorIs(t, err, expectedErr)
	assert.Nil(t, result)
}
