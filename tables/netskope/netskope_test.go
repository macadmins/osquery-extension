package netskope

import (
	"strings"
	"testing"

	"github.com/macadmins/osquery-extension/pkg/utils"
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

	names := make(map[string]bool)
	for _, col := range columns {
		assert.NotEmpty(t, col.Name, "column name must not be empty")
		assert.Equal(t, strings.ToLower(col.Name), col.Name, "column name must be lowercase")
		assert.False(t, names[col.Name], "duplicate column name: %s", col.Name)
		names[col.Name] = true
	}
}

func TestKeyToColumn(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// CamelCase splitting
		{"AddonHost", "addon_host"},
		{"AddonCheckerHost", "addon_checker_host"},
		{"OnPremDetection", "on_prem_detection"},
		// Space to underscore
		{"Tenant URL", "tenant_url"},
		{"Gateway IP", "gateway_ip"},
		{"Traffic Mode", "traffic_mode"},
		// All-uppercase abbreviation at start
		{"SNI Enable", "sni_enable"},
		// Already lowercase / single word
		{"orgname", "orgname"},
		{"config", "config"},
		// Edge cases
		{"", ""},
		{"multiple  spaces", "multiple__spaces"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, keyToColumn(tt.input))
		})
	}
}

func TestParseNsdiagOutput(t *testing.T) {
	t.Run("well-formed output", func(t *testing.T) {
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
	})

	t.Run("empty input returns empty map", func(t *testing.T) {
		result := parseNsdiagOutput("")
		assert.Empty(t, result)
	})

	t.Run("malformed lines without separator are skipped", func(t *testing.T) {
		input := "this line has no separator\nOrgname:: Talkaloid.\njust text\n"
		result := parseNsdiagOutput(input)
		assert.Equal(t, map[string]string{"orgname": "Talkaloid"}, result)
	})

	t.Run("single-colon lines are skipped", func(t *testing.T) {
		input := "Orgname: Talkaloid\nTenant URL: talkaloid-prod.goskope.com\n"
		result := parseNsdiagOutput(input)
		assert.Empty(t, result)
	})

	t.Run("duplicate keys - last value wins", func(t *testing.T) {
		input := "Orgname:: First.\nOrgname:: Second.\n"
		result := parseNsdiagOutput(input)
		assert.Equal(t, "Second", result["orgname"])
	})

	t.Run("empty value is preserved", func(t *testing.T) {
		input := "Orgname::\n"
		result := parseNsdiagOutput(input)
		assert.Equal(t, "", result["orgname"])
	})

	t.Run("extra whitespace around key and value is trimmed", func(t *testing.T) {
		input := "  Orgname  ::   Talkaloid   \n"
		result := parseNsdiagOutput(input)
		assert.Equal(t, "Talkaloid", result["orgname"])
	})

	t.Run("value containing :: is preserved intact", func(t *testing.T) {
		input := "Config:: foo::bar.\n"
		result := parseNsdiagOutput(input)
		assert.Equal(t, "foo::bar", result["config"])
	})

	t.Run("trailing dot is stripped from value", func(t *testing.T) {
		input := "Orgname:: Talkaloid.\n"
		result := parseNsdiagOutput(input)
		assert.Equal(t, "Talkaloid", result["orgname"])
	})

	t.Run("value without trailing dot is unchanged", func(t *testing.T) {
		input := "Orgname:: Talkaloid\n"
		result := parseNsdiagOutput(input)
		assert.Equal(t, "Talkaloid", result["orgname"])
	})

	t.Run("unknown and future fields are parsed", func(t *testing.T) {
		input := "Orgname:: Talkaloid.\nNewFeatureXyz:: some value.\n"
		result := parseNsdiagOutput(input)
		assert.Equal(t, "Talkaloid", result["orgname"])
		assert.Equal(t, "some value", result["new_feature_xyz"])
	})

	t.Run("partial output with no trailing newline", func(t *testing.T) {
		input := "Orgname:: Talkaloid.\nTenant URL :: talkaloid-prod.goskope.com"
		result := parseNsdiagOutput(input)
		assert.Equal(t, "Talkaloid", result["orgname"])
		assert.Equal(t, "talkaloid-prod.goskope.com", result["tenant_url"])
	})

	t.Run("mixed warning and debug lines are skipped", func(t *testing.T) {
		input := "[WARN] something went wrong\nOrgname:: Talkaloid.\nDEBUG: internal state\n-- separator --\n"
		result := parseNsdiagOutput(input)
		assert.Equal(t, map[string]string{"orgname": "Talkaloid"}, result)
	})
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
