package dot1x

// Tests for the pure-Go WLAN profile XML parsing. These have no build tag, so
// the parsing logic is exercised and coverage-counted on every platform (not
// only Windows).

import (
	"strings"
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
											<UseWinLogonCredentials>false</UseWinLogonCredentials>
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
		// Windows-only: user creds while a user is logged on, machine creds otherwise.
		{"machineOrUser", `<OneX><authMode>machineOrUser</authMode></OneX>`, 4},
		{"guest", `<OneX><authMode>guest</authMode></OneX>`, 0},
		{"unknown value", `<OneX><authMode>somethingElse</authMode></OneX>`, -1},
		// machineOrUser is the documented default when <authMode> is omitted.
		{"no authMode defaults to machineOrUser", `<OneX><EAPConfig></EAPConfig></OneX>`, 4},
		{"no OneX element", `<WLANProfile><name>psk</name></WLANProfile>`, -1},
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
		// Windows' own UI writes bytes without leading zeros.
		{"unpadded bytes", `<TrustedRootCA>8 0 f4 2d 42 8e e5 7 ff ec df fe 4f 9e 31 fd 63 c9 5a bb</TrustedRootCA>`, "08:00:f4:2d:42:8e:e5:07:ff:ec:df:fe:4f:9e:31:fd:63:c9:5a:bb"},
		// EAP-TTLS profiles use TrustedRootCAHash instead of TrustedRootCA.
		{"TTLS TrustedRootCAHash", `<ServerValidation><TrustedRootCAHash>58 34 c1 13 14 9c fc 9b 9f 28 70 6f db e6 81 a4 78 19 a2 0e</TrustedRootCAHash></ServerValidation>`, "58:34:c1:13:14:9c:fc:9b:9f:28:70:6f:db:e6:81:a4:78:19:a2:0e"},
		{"too few bytes", `<TrustedRootCA>8 0 f4</TrustedRootCA>`, ""},
		{"byte too long", `<TrustedRootCA>800 f4 2d 42 8e e5 7 ff ec df fe 4f 9e 31 fd 63 c9 5a bb 01</TrustedRootCA>`, ""},
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

// TestParseWLANProfileRealExports parses profiles exported with
// "netsh wlan export profile" from Windows 11 25H2 after "netsh wlan add
// profile" accepted them. PEAP keeps its inner method at
// Config/Eap/EapType/Eap/Type (no second EapMethod); TTLS with an inner EAP
// method nests a full EapHostConfig (second EapMethod) under
// Phase2Authentication; TTLS with PAP has no inner EAP method at all.
func TestParseWLANProfileRealExports(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		file string
		want wlanProfileInfo
	}{
		{"wlanprofile-peap-mschapv2.xml", wlanProfileInfo{eapType: 25, innerEAPType: 26, authMode: 1, useOneX: true, serverValidation: "prompt"}},
		{"wlanprofile-peap-tls.xml", wlanProfileInfo{eapType: 25, innerEAPType: 13, authMode: 3, useOneX: true, serverValidation: "prompt"}},
		{"wlanprofile-ttls-eapmschapv2.xml", wlanProfileInfo{eapType: 21, innerEAPType: 26, authMode: 1, useOneX: true, serverValidation: "prompt"}},
		{"wlanprofile-ttls-pap.xml", wlanProfileInfo{eapType: 21, innerEAPType: -1, authMode: 1, useOneX: true, serverValidation: "prompt"}},
		// Windows Settings writes TTLS-PAP CA hashes with unpadded bytes.
		{"wlanprofile-ttls-pap-windows-ui.xml", wlanProfileInfo{eapType: 21, innerEAPType: -1, authMode: 1, useOneX: true,
			trustedRootCASHA1: "08:00:f4:2d:42:8e:e5:07:ff:ec:df:fe:4f:9e:31:fd:63:c9:5a:bb", serverValidation: "ca_only"}},
		// Wired profiles use OneXEnabled instead of useOneX.
		{"lanprofile-eap-tls-machine.xml", wlanProfileInfo{eapType: 13, innerEAPType: -1, authMode: 3, useOneX: true,
			trustedRootCASHA1: "58:34:c1:13:14:9c:fc:9b:9f:28:70:6f:db:e6:81:a4:78:19:a2:0e", serverValidation: "ca_only"}},
	} {
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, parseWLANProfile(readTestdata(t, tc.file)))
		})
	}
}

func TestModeNameMachineOrUser(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "MachineOrUser", rowFromStatus(Dot1XStatus{Mode: 4})["mode_name"])
}

// Profile files on disk may be UTF-16 with a matching encoding declaration,
// which encoding/xml rejects unless a CharsetReader is set.
func TestParseWLANProfileEncodingDeclaration(t *testing.T) {
	t.Parallel()

	xml := strings.Replace(readTestdata(t, "lanprofile-eap-tls-machine.xml"),
		`<?xml version="1.0"?>`, `<?xml version="1.0" encoding="UTF-16"?>`, 1)
	info := parseWLANProfile(xml)
	assert.True(t, info.useOneX)
	assert.Equal(t, 13, info.eapType)
}

// useOneX / OneXEnabled are xs:boolean, so "1" is as valid as "true".
func TestParseWLANProfileOneXXSBoolean(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]bool{
		"<useOneX>true</useOneX>":         true,
		"<useOneX>1</useOneX>":            true,
		"<useOneX> 1 </useOneX>":          true,
		"<useOneX>false</useOneX>":        false,
		"<useOneX>0</useOneX>":            false,
		"<OneXEnabled>1</OneXEnabled>":    true,
		"<OneXEnabled>TRUE</OneXEnabled>": false, // xs:boolean is case-sensitive
	} {
		assert.Equal(t, want, parseWLANProfile("<WLANProfile>"+in+"</WLANProfile>").useOneX, in)
	}
}

// peapXML builds a PEAP OneX config whose outer method has the given
// ServerValidation children and PeapExtensions, wrapping an inner EAP-TLS
// method with its own ServerValidation and extra elements (which must be
// ignored: the inner method validates nothing about the outer tunnel).
func peapXML(outerSV, peapExt, innerSV, innerExtra string) string {
	return `<OneX><EAPConfig><EapHostConfig><EapMethod><Type>25</Type></EapMethod><Config>` +
		`<Eap><Type>25</Type><EapType><ServerValidation>` + outerSV + `</ServerValidation>` +
		`<Eap><Type>13</Type><EapType><ServerValidation>` + innerSV + `</ServerValidation>` + innerExtra + `</EapType></Eap>` +
		`<PeapExtensions>` + peapExt + `</PeapExtensions></EapType></Eap></Config></EapHostConfig></EAPConfig></OneX>`
}

const testCA = `<TrustedRootCA>58 34 c1 13 14 9c fc 9b 9f 28 70 6f db e6 81 a4 78 19 a2 0e</TrustedRootCA>`

func TestParseWLANProfileExcludesInnerCAs(t *testing.T) {
	t.Parallel()
	outerNames := `<ServerNames>radius.campus.edu</ServerNames>`
	for name, xml := range map[string]string{
		"PEAP": peapXML(outerNames, "", testCA, ""),
		"TTLS": `<OneX><EapTtls><ServerValidation>` + outerNames +
			`</ServerValidation><Phase2Authentication><EapHostConfig><Config>` +
			`<Eap><Type>13</Type><EapType><ServerValidation>` + testCA +
			`</ServerValidation></EapType></Eap></Config></EapHostConfig></Phase2Authentication></EapTtls></OneX>`,
	} {
		t.Run(name, func(t *testing.T) {
			info := parseWLANProfile(xml)
			assert.Empty(t, info.trustedRootCASHA1)
			assert.Equal(t, "name_only", info.serverValidation)
		})
	}
}

func TestParseProfileOneXDefaults(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, xml string
		want      bool
	}{
		{"LAN omitted", `<LANProfile><MSM><security/></MSM></LANProfile>`, true},
		{"LAN explicitly disabled", `<LANProfile><MSM><security><OneXEnabled>false</OneXEnabled></security></MSM></LANProfile>`, false},
		{"LAN numeric disabled", `<LANProfile><MSM><security><OneXEnabled>0</OneXEnabled></security></MSM></LANProfile>`, false},
		{"WLAN omitted", `<WLANProfile><MSM><security/></MSM></WLANProfile>`, false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseWLANProfile(tc.xml).useOneX)
		})
	}
}

// Server names and the server validation summary come from the OUTER
// method's ServerValidation (PEAP/EAP-TLS) or EapTtls ServerValidation (TTLS),
// plus the V2 PerformServerValidation / AcceptServerName switches.
func TestParseWLANProfileServerValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		xml       string
		wantNames string
		wantSV    string
	}{
		{"sample EAP-TLS", sampleProfileXML, "", "ca_only"},
		{"sample PEAP", peapProfileXML, "", "ca_only"},
		{
			"PEAP pinned; inner names and inner PerformServerValidation ignored",
			peapXML(`<ServerNames>radius1.campus.edu; radius2.campus.edu</ServerNames>`+testCA, "",
				`<ServerNames>inner.campus.edu</ServerNames>`, `<PerformServerValidation>false</PerformServerValidation>`),
			"radius1.campus.edu,radius2.campus.edu", "pinned",
		},
		{
			"PEAP PerformServerValidation true",
			peapXML(`<ServerNames>radius.campus.edu</ServerNames>`+testCA, `<PerformServerValidation>true</PerformServerValidation><AcceptServerName>true</AcceptServerName>`, "", ""),
			"radius.campus.edu", "pinned",
		},
		{
			"PEAP PerformServerValidation false",
			peapXML(`<ServerNames>radius.campus.edu</ServerNames>`+testCA, `<PerformServerValidation>false</PerformServerValidation>`, "", ""),
			"radius.campus.edu", "none",
		},
		{
			"PerformServerValidation xs:boolean 0",
			peapXML("", `<PerformServerValidation> 0 </PerformServerValidation>`, "", ""),
			"", "none",
		},
		{
			"PerformServerValidation attribute",
			`<OneX><Eap><Type>25</Type><EapType><ServerValidation PerformServerValidation="false">` + testCA + `</ServerValidation></EapType></Eap></OneX>`,
			"", "none",
		},
		{
			"EAP-TLS V2 PerformServerValidation false",
			`<OneX><Eap><Type>13</Type><EapType><ServerValidation>` + testCA + `</ServerValidation><PerformServerValidation>false</PerformServerValidation></EapType></Eap></OneX>`,
			"", "none",
		},
		{
			"AcceptServerName false: names configured but not enforced",
			peapXML(`<ServerNames>radius.campus.edu</ServerNames>`+testCA, `<AcceptServerName>false</AcceptServerName>`, "", ""),
			"radius.campus.edu", "ca_only",
		},
		{
			"names only",
			peapXML(`<ServerNames>radius.campus.edu</ServerNames>`, "", "", ""),
			"radius.campus.edu", "name_only",
		},
		{
			"empty name segments dropped",
			peapXML(`<ServerNames> radius.campus.edu ;; </ServerNames>`+testCA, "", "", ""),
			"radius.campus.edu", "pinned",
		},
		{
			"TTLS",
			`<OneX><EapTtls><ServerValidation><ServerNames>a.campus.edu;b.campus.edu</ServerNames>` +
				`<TrustedRootCAHash>58 34 c1 13 14 9c fc 9b 9f 28 70 6f db e6 81 a4 78 19 a2 0e</TrustedRootCAHash>` +
				`<DisablePrompt>true</DisablePrompt></ServerValidation><Phase2Authentication><EapHostConfig>` +
				`<EapMethod><Type>26</Type></EapMethod><Config><Eap><Type>26</Type><EapType/></Eap></Config>` +
				`</EapHostConfig></Phase2Authentication></EapTtls></OneX>`,
			"a.campus.edu,b.campus.edu", "pinned",
		},
		{
			"TTLS inner EAP-TLS validation ignored",
			`<OneX><EapTtls><ServerValidation>` + testCA + `</ServerValidation><Phase2Authentication><EapHostConfig>` +
				`<EapMethod><Type>13</Type></EapMethod><Config><Eap><Type>13</Type><EapType><ServerValidation>` +
				`<ServerNames>inner.campus.edu</ServerNames></ServerValidation><PerformServerValidation>false</PerformServerValidation>` +
				`</EapType></Eap></Config></EapHostConfig></Phase2Authentication></EapTtls></OneX>`,
			"", "ca_only",
		},
		{"not 802.1X", `<WLANProfile><name>psk</name></WLANProfile>`, "", ""},
		{"empty", "", "", ""},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			info := parseWLANProfile(tc.xml)
			assert.Equal(t, tc.wantNames, info.trustedServerNames, "trusted server names")
			assert.Equal(t, tc.wantSV, info.serverValidation, "server validation")
		})
	}
}
