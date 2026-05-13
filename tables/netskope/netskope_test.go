package netskope

import (
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

const sampleNsdiagOutput = `Orgname:: Talkaloid.
Tenant URL :: talkaloid-prod.goskope.com.
AddonHost:: addon-talkaloid-prod.goskope.com.
AddonCheckerHost:: achecker-talkaloid-prod.goskope.com.
Gateway:: gateway-talkaloid-prod.goskope.com.
Gateway IP:: 139.139.39.39.
Config:: All-Talkaloid_Tech.
Steering Config:: Talkaloid.
Email:: natsune.miku@talkaloid.com.
Peruser config:: FALSE.
Tunnel status:: NSTUNNEL_CONNECTED.
Client status:: enable.
Dynamic Steering:: FALSE.
OnPremDetection:: Not Configured.
Explicit Proxy:: false.
Tunnel Protocol:: TLS.
SNI Enable:: FALSE.
Traffic Mode:: All Web Traffic.
`

func TestNetskopeColumns(t *testing.T) {
	columns := NetskopeColumns()
	expected := []table.ColumnDefinition{
		table.TextColumn("orgname"),
		table.TextColumn("tenant_url"),
		table.TextColumn("addon_host"),
		table.TextColumn("addon_checker_host"),
		table.TextColumn("gateway"),
		table.TextColumn("gateway_ip"),
		table.TextColumn("config"),
		table.TextColumn("steering_config"),
		table.TextColumn("email"),
		table.TextColumn("peruser_config"),
		table.TextColumn("tunnel_status"),
		table.TextColumn("client_status"),
		table.TextColumn("dynamic_steering"),
		table.TextColumn("on_prem_detection"),
		table.TextColumn("explicit_proxy"),
		table.TextColumn("tunnel_protocol"),
		table.TextColumn("sni_enable"),
		table.TextColumn("traffic_mode"),
	}
	assert.Equal(t, expected, columns)
}

func TestKeyToColumn(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Orgname", "orgname"},
		{"Tenant URL", "tenant_url"},
		{"AddonHost", "addon_host"},
		{"AddonCheckerHost", "addon_checker_host"},
		{"Gateway IP", "gateway_ip"},
		{"Steering Config", "steering_config"},
		{"Peruser config", "peruser_config"},
		{"Tunnel status", "tunnel_status"},
		{"Client status", "client_status"},
		{"OnPremDetection", "on_prem_detection"},
		{"Dynamic Steering", "dynamic_steering"},
		{"Explicit Proxy", "explicit_proxy"},
		{"Tunnel Protocol", "tunnel_protocol"},
		{"SNI Enable", "sni_enable"},
		{"Traffic Mode", "traffic_mode"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, keyToColumn(tt.input))
		})
	}
}

func TestParseNsdiagOutput(t *testing.T) {
	result := parseNsdiagOutput(sampleNsdiagOutput)

	assert.Equal(t, "Talkaloid", result["orgname"])
	assert.Equal(t, "talkaloid-prod.goskope.com", result["tenant_url"])
	assert.Equal(t, "addon-talkaloid-prod.goskope.com", result["addon_host"])
	assert.Equal(t, "achecker-talkaloid-prod.goskope.com", result["addon_checker_host"])
	assert.Equal(t, "gateway-talkaloid-prod.goskope.com", result["gateway"])
	assert.Equal(t, "139.139.39.39", result["gateway_ip"])
	assert.Equal(t, "TLS", result["tunnel_protocol"])
	assert.Equal(t, "NSTUNNEL_CONNECTED", result["tunnel_status"])
	assert.Equal(t, "enable", result["client_status"])
	assert.Equal(t, "Not Configured", result["on_prem_detection"])
	assert.Equal(t, "All Web Traffic", result["traffic_mode"])
}

func TestRunNsdiag(t *testing.T) {

	tests := []struct {
		name       string
		fileExists bool
		cmdOutput  string
		cmdErr     error
		wantErr    bool
		wantRow    map[string]string
	}{
		{
			name:       "Netskope not installed — returns empty row",
			fileExists: false,
			wantRow: map[string]string{
				"orgname": "", "tenant_url": "", "addon_host": "",
				"addon_checker_host": "", "gateway": "", "gateway_ip": "",
				"config": "", "steering_config": "", "email": "",
				"peruser_config": "", "tunnel_status": "", "client_status": "",
				"dynamic_steering": "", "on_prem_detection": "", "explicit_proxy": "",
				"tunnel_protocol": "", "sni_enable": "", "traffic_mode": "",
			},
		},
		{
			name:       "Netskope installed and healthy — returns parsed values",
			fileExists: true,
			cmdOutput:  sampleNsdiagOutput,
			wantRow: map[string]string{
				"orgname":            "Talkaloid",
				"tenant_url":         "talkaloid-prod.goskope.com",
				"addon_host":         "addon-talkaloid-prod.goskope.com",
				"addon_checker_host": "achecker-talkaloid-prod.goskope.com",
				"gateway":            "gateway-talkaloid-prod.goskope.com",
				"gateway_ip":         "139.139.39.39",
				"config":             "All-Talkaloid_Tech",
				"steering_config":    "Talkaloid",
				"email":              "natsune.miku@talkaloid.com",
				"peruser_config":     "FALSE",
				"tunnel_status":      "NSTUNNEL_CONNECTED",
				"client_status":      "enable",
				"dynamic_steering":   "FALSE",
				"on_prem_detection":  "Not Configured",
				"explicit_proxy":     "false",
				"tunnel_protocol":    "TLS",
				"sni_enable":         "FALSE",
				"traffic_mode":       "All Web Traffic",
			},
		},
		{
			name:       "Netskope installed but nsdiag fails — returns error",
			fileExists: true,
			cmdErr:     errors.New("exit status 1"),
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := utils.Runner{Runner: utils.MockCmdRunner{Output: tt.cmdOutput, Err: tt.cmdErr}}
			fs := utils.MockFileSystem{FileExists: tt.fileExists}

			results, err := runNsdiag(runner, fs)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, results)
			} else {
				assert.NoError(t, err)
				assert.Len(t, results, 1)
				assert.Equal(t, tt.wantRow, results[0])
			}
		})
	}
}
