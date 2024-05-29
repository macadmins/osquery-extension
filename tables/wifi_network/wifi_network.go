package wifi_network

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/pkg/errors"
)

type CommandExecutor interface {
	ExecCommand(command string, args ...string) ([]byte, error)
}

type CmdExecutor struct{}

func (r CmdExecutor) ExecCommand(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

type OsqueryClient interface {
	QueryRow(query string) (map[string]string, error)
	Close()
}

func WifiNetworkColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
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
}

type WifiNetwork struct {
	SSID         string `json:"ssid"`
	Interface    string `json:"interface"`
	RSSI         string `json:"rssi"`
	Noise        string `json:"noise"`
	Channel      string `json:"channel"`
	ChannelWidth string `json:"channel_width"`
	ChannelBand  string `json:"channel_band"`
	TransmitRate string `json:"transmit_rate"`
	SecurityType string `json:"security_type"`
	Mode         string `json:"mode"`
}

func WifiNetworkGenerate(
	ctx context.Context,
	queryContext table.QueryContext,
	socketPath string,
) ([]map[string]string, error) {
	// get the wifi interface from osquery
	osqueryClient, err := osquery.NewClient(socketPath, 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer osqueryClient.Close()

	wifiStatus, err := getWifiStatus(osqueryClient)
	if err != nil {
		return nil, err
	}

	cmdExecutor := CmdExecutor{}
	wifiNetwork, err := buildWifiNetworkFromResponse(cmdExecutor, wifiStatus)
	if err != nil {
		return nil, err
	}

	return buildWifiNetworkResults(wifiNetwork), nil
}

// getWifiInterface checks the wifi_status table to determine the wifi interface
func getWifiStatus(client OsqueryClient) (map[string]string, error) {
	wifiStatusQuery := "SELECT * FROM wifi_status;"

	resp, err := client.QueryRow(wifiStatusQuery)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// getValueFromResponse extracts the value from the response
func getValueFromResponse(resp map[string]string, key string) (string, error) {
	if value, ok := resp[key]; ok {
		return value, nil
	}
	return "", errors.New("wifi_status table missing '" + key + "' column")
}

// getWifiNetworkName shells out to 'networksetup -getairportnetwork ${wifiInterface}'
func getWifiNetworkName(cmdExecutor CommandExecutor, wifiInterface string) (string, error) {
	out, err := cmdExecutor.ExecCommand("/usr/sbin/networksetup", "-getairportnetwork", wifiInterface)
	if err != nil {
		return "", errors.Wrap(err, "failed to run networksetup")
	}
	outStr := string(out)
	splitOut := strings.Split(outStr, ": ")
	if len(splitOut) != 2 {
		// Wifi may not be on or connected
		return "", nil
	}
	return strings.TrimSpace(splitOut[1]), nil
}

func getSecurityLevel(cmdExecutor CommandExecutor, interfaceName string) (string, error) {
	out, err := getWdutilOutput(cmdExecutor)
	if err != nil {
		return "", err
	}

	return extractSecurityValue(out, interfaceName), nil
}

func getWdutilOutput(cmdExecutor CommandExecutor) (string, error) {
	out, err := cmdExecutor.ExecCommand("/usr/bin/wdutil", "info", "-q")
	if err != nil {
		return "", errors.Wrap(err, "failed to run wdutil")
	}
	return string(out), nil
}

func extractSecurityValue(input string, desiredInterfaceName string) string {
	scanner := bufio.NewScanner(strings.NewReader(input))
	interfaceName := ""
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Interface Name") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				interfaceName = strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(line, "Security") && interfaceName == desiredInterfaceName {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				return strings.TrimSpace(parts[1])
			}
		}
	}

	return ""
}

// buildWifiNetwork
func buildWifiNetworkFromResponse(cmdExecutor CommandExecutor, wifiStatus map[string]string) (*WifiNetwork, error) {
	wifiInterface, err := getValueFromResponse(wifiStatus, "interface")
	if err != nil {
		return nil, err
	}

	rssi, err := getValueFromResponse(wifiStatus, "rssi")
	if err != nil {
		return nil, err
	}

	noise, err := getValueFromResponse(wifiStatus, "noise")
	if err != nil {
		return nil, err
	}

	channel, err := getValueFromResponse(wifiStatus, "channel")
	if err != nil {
		return nil, err
	}

	channelWidth, err := getValueFromResponse(wifiStatus, "channel_width")
	if err != nil {
		return nil, err
	}

	channelBand, err := getValueFromResponse(wifiStatus, "channel_band")
	if err != nil {
		return nil, err
	}

	transmitRate, err := getValueFromResponse(wifiStatus, "transmit_rate")
	if err != nil {
		return nil, err
	}

	mode, err := getValueFromResponse(wifiStatus, "mode")
	if err != nil {
		return nil, err
	}

	// get the wifi network name
	wifiNetworkName, err := getWifiNetworkName(cmdExecutor, wifiInterface)
	if err != nil {
		return nil, err
	}

	// get the security level
	securityType, err := getSecurityLevel(cmdExecutor, wifiInterface)
	if err != nil {
		return nil, err
	}

	return &WifiNetwork{
		SSID:         wifiNetworkName,
		Interface:    wifiInterface,
		RSSI:         rssi,
		Noise:        noise,
		Channel:      channel,
		ChannelWidth: channelWidth,
		ChannelBand:  channelBand,
		TransmitRate: transmitRate,
		SecurityType: securityType,
		Mode:         mode,
	}, nil
}

// buildWifiNetworkResults creates a map of the results
func buildWifiNetworkResults(info *WifiNetwork) []map[string]string {
	var results []map[string]string
	results = append(results, map[string]string{
		"ssid":          info.SSID,
		"interface":     info.Interface,
		"rssi":          info.RSSI,
		"noise":         info.Noise,
		"channel":       info.Channel,
		"channel_width": info.ChannelWidth,
		"channel_band":  info.ChannelBand,
		"transmit_rate": info.TransmitRate,
		"security_type": info.SecurityType,
		"mode":          info.Mode,
	})
	return results
}
