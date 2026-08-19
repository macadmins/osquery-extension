package dot1x

// Tests for the pure-Go WLAN profile XML parsing. These have no build tag, so
// the parsing logic is exercised and coverage-counted on every platform (not
// only Windows).

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const sampleProfileXML = `<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
	<name>Campus</name>
	<MSM>
		<security>
			<authEncryption>
				<authentication>WPA2</authentication>
				<encryption>AES</encryption>
				<useOneX>true</useOneX>
			</authEncryption>
			<OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
				<authMode>machine</authMode>
				<EAPConfig>
					<EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
						<EapMethod>
							<Type xmlns="http://www.microsoft.com/provisioning/EapCommon">13</Type>
							<VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
							<VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
							<AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId>
						</EapMethod>
						<Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
							<Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
								<Type>13</Type>
								<EapType xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1">
									<ServerValidation>
										<DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation>
										<ServerNames></ServerNames>
										<TrustedRootCA>23 a6 b1 0a be 8a 4a 37 72 11 e2 f4 2c 36 67 f1 36 e9 08 bf</TrustedRootCA>
									</ServerValidation>
								</EapType>
							</Eap>
						</Config>
					</EapHostConfig>
				</EAPConfig>
			</OneX>
		</security>
	</MSM>
</WLANProfile>`

const peapProfileXML = `<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
	<name>PEAPNetwork</name>
	<MSM>
		<security>
			<OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
				<authMode>user</authMode>
				<EAPConfig>
					<EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
						<EapMethod>
							<Type xmlns="http://www.microsoft.com/provisioning/EapCommon">25</Type>
						</EapMethod>
						<Config>
							<Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
								<Type>25</Type>
								<EapType xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1">
									<ServerValidation>
										<TrustedRootCA>aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd</TrustedRootCA>
										<TrustedRootCA>11 22 33 44 55 66 77 88 99 00 aa bb cc dd ee ff 11 22 33 44</TrustedRootCA>
									</ServerValidation>
									<InnerEapOptional>false</InnerEapOptional>
									<Eap>
										<Type>26</Type>
										<EapType>
											<EapMethod>
												<Type>26</Type>
											</EapMethod>
										</EapType>
									</Eap>
								</EapType>
							</Eap>
						</Config>
					</EapHostConfig>
				</EAPConfig>
			</OneX>
		</security>
	</MSM>
</WLANProfile>`

func TestParseWLANProfileEAPType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		xml  string
		want int
	}{
		{"EAP-TLS", sampleProfileXML, 13},
		{"PEAP", peapProfileXML, 25},
		{"no EapMethod", `<WLANProfile><name>open</name></WLANProfile>`, -1},
		{"empty", "", -1},
		{"EapMethod but no Type", `<EapMethod></EapMethod>`, -1},
		{"malformed Type value", `<EapMethod><Type>abc</Type></EapMethod>`, -1},
		{"namespace prefixed Type (matched by local name)", `<EapMethod xmlns:eapCommon="urn:example:eapcommon"><eapCommon:Type>13</eapCommon:Type></EapMethod>`, 13},
		{"Type with attributes", `<EapMethod><Type xmlns="foo">21</Type></EapMethod>`, 21},
		{"EapMethod with attributes", `<EapMethod foo="bar"><Type>21</Type></EapMethod>`, 21},
		{"pretty-printed / indented", "<EapMethod>\n\t<Type>\n\t\t25\n\t</Type>\n</EapMethod>", 25},
	}

	for _, tc := range tests {
		tc := tc // Go 1.22+ scopes this per-iteration; explicit for the linter.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseWLANProfile(tc.xml).eapType
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseWLANProfileAuthMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		xml  string
		want int
	}{
		{"machine", sampleProfileXML, 3},
		{"user", peapProfileXML, 1},
		{"machineOrUser", `<OneX><authMode>machineOrUser</authMode></OneX>`, 2},
		{"guest", `<OneX><authMode>guest</authMode></OneX>`, 0},
		{"unknown value", `<OneX><authMode>somethingElse</authMode></OneX>`, -1},
		{"no authMode", `<OneX><EAPConfig></EAPConfig></OneX>`, -1},
		{"empty", "", -1},
		{"whitespace around value", `<authMode>  machine  </authMode>`, 3},
	}

	for _, tc := range tests {
		tc := tc // Go 1.22+ scopes this per-iteration; explicit for the linter.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseWLANProfile(tc.xml).authMode
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseWLANProfileInnerEAPType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		xml  string
		want int
	}{
		{"PEAP with MSCHAPv2 inner", peapProfileXML, 26},
		{"EAP-TLS no inner", sampleProfileXML, -1},
		{"no EapMethod at all", `<WLANProfile></WLANProfile>`, -1},
		{"single EapMethod only", `<EapMethod><Type>13</Type></EapMethod>`, -1},
		{"empty", "", -1},
	}

	for _, tc := range tests {
		tc := tc // Go 1.22+ scopes this per-iteration; explicit for the linter.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseWLANProfile(tc.xml).innerEAPType
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseWLANProfileTrustedRootCA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		xml  string
		want string
	}{
		{
			"single CA with spaces",
			sampleProfileXML,
			"23:a6:b1:0a:be:8a:4a:37:72:11:e2:f4:2c:36:67:f1:36:e9:08:bf",
		},
		{
			"multiple CAs",
			peapProfileXML,
			"aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd," +
				"11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff:11:22:33:44",
		},
		{
			"contiguous hex (no spaces)",
			`<TrustedRootCA>aabbccddeeff00112233445566778899aabbccdd</TrustedRootCA>`,
			"aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd",
		},
		{
			"uppercase hex",
			`<TrustedRootCA>AABBCCDDEEFF00112233445566778899AABBCCDD</TrustedRootCA>`,
			"aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd",
		},
		{"no TrustedRootCA", `<ServerValidation></ServerValidation>`, ""},
		{"empty", "", ""},
		{
			"wrong length ignored",
			`<TrustedRootCA>aabb</TrustedRootCA>`,
			"",
		},
		{
			"whitespace only",
			`<TrustedRootCA>   </TrustedRootCA>`,
			"",
		},
		{
			"40 non-hex chars rejected",
			`<TrustedRootCA>zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz</TrustedRootCA>`,
			"",
		},
		{
			"newlines and tabs in hex (pretty-printed XML)",
			"<TrustedRootCA>\n\t\t\t\t23 a6 b1 0a ff bb cc dd ee 11\n\t\t\t\t22 33 44 55 66 77 88 99 aa bb\n\t\t\t</TrustedRootCA>",
			"23:a6:b1:0a:ff:bb:cc:dd:ee:11:22:33:44:55:66:77:88:99:aa:bb",
		},
	}

	for _, tc := range tests {
		tc := tc // Go 1.22+ scopes this per-iteration; explicit for the linter.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseWLANProfile(tc.xml).trustedRootCASHA1
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestFormatSHA1Hex(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		"aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd",
		formatSHA1Hex("aabbccddeeff00112233445566778899aabbccdd"))
	assert.Equal(t,
		"aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd",
		formatSHA1Hex("AABBCCDDEEFF00112233445566778899AABBCCDD"))

	// Odd-length / short input must not panic on the trailing 2-char slice.
	assert.Equal(t, "", formatSHA1Hex(""))
	assert.Equal(t, "", formatSHA1Hex("a"))
	assert.Equal(t, "", formatSHA1Hex("abc"))
	assert.Equal(t, "aa:bb", formatSHA1Hex("aabb"))
}
