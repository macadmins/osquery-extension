package dot1x

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // sha1 used only for certificate fingerprint display
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeBackend is a deterministic in-memory Dot1XBackend for tests.
type fakeBackend struct {
	statuses map[string]Dot1XStatus
}

func (f fakeBackend) GetStatus(ifname string) (Dot1XStatus, error) {
	s, ok := f.statuses[ifname]
	if ok {
		return s, nil
	}
	return Dot1XStatus{Interface: ifname}, errors.New("not found")
}

// stubLister is a Dot1XBackend that also implements interfaceLister, returning
// a fixed interface list. It keeps interfacesToQuery tests deterministic
// (independent of host WLAN state) when exercising the default-list path.
type stubLister struct {
	names []string
}

func (stubLister) GetStatus(ifname string) (Dot1XStatus, error) {
	return Dot1XStatus{Interface: ifname}, errors.New("not found")
}

func (s stubLister) interfaceNames() []string { return s.names }

func TestDot1XStatusColumns(t *testing.T) {
	t.Parallel()
	want := []string{
		// Interface & network
		"interface", "interface_type", "ssid", "mac_address", "authenticator_mac_address",
		// Status
		"state", "state_name", "supplicant_state", "supplicant_state_name",
		"client_status", "client_status_name", "authenticated_since", "last_status_timestamp",
		// Failure detail
		"failure_reason", "failure_code", "failure_eap_code", "domain_specific_error",
		// Authentication
		"eap_type", "eap_type_name", "inner_eap_type", "inner_eap_type_name", "identity", "mode", "mode_name",
		// Configuration / profile
		"profile_name", "mdm_payload_uuid", "mdm_payload_type", "mdm_profile_name", "mdm_profile_identifier",
		"unique_identifier", "server_validation", "tls_trusted_root_ca_sha1", "tls_trusted_server_names",
		// TLS session
		"tls_negotiated_protocol_version", "tls_negotiated_cipher", "tls_session_was_resumed", "tls_trust_client_status",
		"tls_server_certificate_chain", "tls_server_certificate_sha1", "tls_server_certificate_serials",
		"tls_server_certificate_not_after",
	}
	cols := Dot1XStatusColumns()
	require.Len(t, cols, len(want))
	for i, c := range cols {
		assert.Equal(t, want[i], c.Name)
	}
}

func TestInterfacesToQuery(t *testing.T) {
	t.Parallel()

	t.Run("no constraint uses backend-provided defaults", func(t *testing.T) {
		t.Parallel()
		backend := stubLister{names: []string{"wlan0", "wlan1"}}
		ifaces := interfacesToQuery(backend, table.QueryContext{})
		assert.Equal(t, []string{"wlan0", "wlan1"}, ifaces)
	})

	t.Run("empty backend defaults query nothing", func(t *testing.T) {
		t.Parallel()
		// Non-nil empty (e.g. enumerated, no WLAN adapters) is authoritative.
		backend := stubLister{names: []string{}}
		ifaces := interfacesToQuery(backend, table.QueryContext{})
		assert.Empty(t, ifaces)
	})

	t.Run("nil backend defaults fall back to en0-en9", func(t *testing.T) {
		t.Parallel()
		// nil means defaults unknown -> generic probe list.
		backend := stubLister{names: nil}
		ifaces := interfacesToQuery(backend, table.QueryContext{})
		require.Len(t, ifaces, 10)
		assert.Equal(t, "en0", ifaces[0])
		assert.Equal(t, "en9", ifaces[9])
	})

	t.Run("with equals constraint returns specified interface", func(t *testing.T) {
		t.Parallel()
		qc := constraintFor("en0")
		ifaces := interfacesToQuery(fakeBackend{}, qc)
		assert.Equal(t, []string{"en0"}, ifaces)
	})

	t.Run("with LIKE constraint falls back to defaults", func(t *testing.T) {
		t.Parallel()
		qc := table.QueryContext{
			Constraints: map[string]table.ConstraintList{
				"interface": {
					Constraints: []table.Constraint{
						{Operator: table.OperatorLike, Expression: "en%"},
					},
				},
			},
		}
		// LIKE is not exact-match, so it falls back to the backend defaults an
		// unconstrained query would use.
		backend := stubLister{names: []string{"wlan0"}}
		assert.Equal(t, []string{"wlan0"}, interfacesToQuery(backend, qc))
	})

	t.Run("duplicate constraints deduplicated", func(t *testing.T) {
		t.Parallel()
		qc := constraintFor("en0", "en0", "en1")
		ifaces := interfacesToQuery(fakeBackend{}, qc)
		assert.Equal(t, []string{"en0", "en1"}, ifaces)
	})
}

func TestRowFromStatus(t *testing.T) {
	t.Parallel()

	s := Dot1XStatus{
		Interface:                    "en0",
		InterfaceType:                "wifi",
		SSID:                         "Campus",
		ProfileName:                  "Campus Wi-Fi",
		MDMPayloadUUID:               "ABC",
		MDMPayloadType:               "com.apple.wifi.managed",
		MDMProfileName:               "Corp Wi-Fi",
		MDMProfileIdentifier:         "com.example.wifi.corp",
		State:                        2,
		SupplicantState:              4,
		EAPType:                      13,
		EAPTypeName:                  "EAP-TLS",
		ClientStatus:                 0,
		DomainSpecificError:          intPtr(0),
		AuthenticatorMACAddress:      "aa:bb:cc:dd:ee:ff",
		Mode:                         1,
		TLSSessionWasResumed:         1,
		TLSServerCertificateChain:    "CN=radius.campus.edu,OU=IT,O=Campus,C=US",
		TLSServerCertificateSHA1:     "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd",
		TLSServerCertificateSerials:  "7D3A1F9E2B5C",
		TLSTrustClientStatus:         0,
		TLSNegotiatedProtocolVersion: "1.2",
		TLSNegotiatedCipher:          0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		InnerEAPType:                 26,
		InnerEAPTypeName:             "MSCHAPv2",
		LastStatusTimestamp:          "2026-06-05T12:00:00Z",
		AuthenticatedSince:           "2026-06-05T11:00:00Z",
		MACAddress:                   "2c:9c:58:29:12:75",
		Identity:                     "anonymous@campus.edu",
		UniqueIdentifier:             "abc-123",
		FailureReason:                "Explicit Eap failure received",
		FailureCode:                  "0x50005",
		FailureEAPCode:               "0x80420015",
		TLSServerCertificateNotAfter: "2027-01-02T03:04:05Z",
		TLSTrustedRootCASHA1:         "58:34:c1:13:14:9c:fc:9b:9f:28:70:6f:db:e6:81:a4:78:19:a2:0e",
		TLSTrustedServerNames:        "radius1.campus.edu,radius2.campus.edu",
		ServerValidation:             "pinned",
	}

	row := rowFromStatus(s)
	assert.Equal(t, "wifi", row["interface_type"])
	assert.Equal(t, "Campus", row["ssid"])
	assert.Equal(t, "Campus Wi-Fi", row["profile_name"])
	assert.Equal(t, "ABC", row["mdm_payload_uuid"])
	assert.Equal(t, "com.apple.wifi.managed", row["mdm_payload_type"])
	assert.Equal(t, "Corp Wi-Fi", row["mdm_profile_name"])
	assert.Equal(t, "com.example.wifi.corp", row["mdm_profile_identifier"])
	assert.Equal(t, "0x80420015", row["failure_eap_code"])
	assert.Equal(t, "2027-01-02T03:04:05Z", row["tls_server_certificate_not_after"])
	assert.Equal(t, "58:34:c1:13:14:9c:fc:9b:9f:28:70:6f:db:e6:81:a4:78:19:a2:0e", row["tls_trusted_root_ca_sha1"])
	assert.Equal(t, "radius1.campus.edu,radius2.campus.edu", row["tls_trusted_server_names"])
	assert.Equal(t, "pinned", row["server_validation"])
	assert.Equal(t, "Explicit Eap failure received", row["failure_reason"])
	assert.Equal(t, "0x50005", row["failure_code"])
	assert.Equal(t, "en0", row["interface"])
	assert.Equal(t, "2", row["state"])
	assert.Equal(t, "Running", row["state_name"])
	assert.Equal(t, "4", row["supplicant_state"])
	assert.Equal(t, "Authenticated", row["supplicant_state_name"])
	assert.Equal(t, "13", row["eap_type"])
	assert.Equal(t, "EAP-TLS", row["eap_type_name"])
	assert.Equal(t, "0", row["client_status"])
	assert.Equal(t, "0", row["domain_specific_error"])
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", row["authenticator_mac_address"])
	assert.Equal(t, "1", row["mode"])
	assert.Equal(t, "User", row["mode_name"])
	assert.Equal(t, "1", row["tls_session_was_resumed"])
	assert.Equal(t, "CN=radius.campus.edu,OU=IT,O=Campus,C=US", row["tls_server_certificate_chain"])
	assert.Equal(t, "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd", row["tls_server_certificate_sha1"])
	assert.Equal(t, "7D3A1F9E2B5C", row["tls_server_certificate_serials"])
	assert.Equal(t, "0", row["tls_trust_client_status"])
	assert.Equal(t, "1.2", row["tls_negotiated_protocol_version"])
	assert.Equal(t, "49195", row["tls_negotiated_cipher"])
	assert.Equal(t, "26", row["inner_eap_type"])
	assert.Equal(t, "MSCHAPv2", row["inner_eap_type_name"])
	assert.Equal(t, "2026-06-05T12:00:00Z", row["last_status_timestamp"])
	assert.Equal(t, "2026-06-05T11:00:00Z", row["authenticated_since"])
	assert.Equal(t, "2c:9c:58:29:12:75", row["mac_address"])
	assert.Equal(t, "anonymous@campus.edu", row["identity"])
	assert.Equal(t, "abc-123", row["unique_identifier"])
}

func TestRowFromStatusUnsetFields(t *testing.T) {
	t.Parallel()

	s := Dot1XStatus{
		Interface:            "en0",
		State:                0,
		SupplicantState:      8,
		TLSSessionWasResumed: 0,
	}

	row := rowFromStatus(s)
	assert.Equal(t, "Idle", row["state_name"])
	assert.Equal(t, "No Authenticator", row["supplicant_state_name"])
	assert.Equal(t, "", row["eap_type_name"])
	assert.Equal(t, "0", row["tls_session_was_resumed"])
	assert.Empty(t, row["ssid"])
	assert.Empty(t, row["interface_type"])
	s.EAPType, s.InnerEAPType, s.ClientStatus, s.Mode = -1, -1, -1, -1
	s.TLSTrustClientStatus, s.TLSNegotiatedCipher = -1, -1
	row = rowFromStatus(s)
	for _, key := range []string{"eap_type", "eap_type_name", "inner_eap_type", "inner_eap_type_name", "client_status", "client_status_name", "mode", "mode_name", "tls_trust_client_status", "tls_negotiated_cipher"} {
		assert.Empty(t, row[key], key)
	}
}

// TLSSessionWasResumed is tri-state: -1 means the backend can't know (e.g.
// Windows, or the key is absent on macOS) and must render empty, not "0".
func TestRowFromStatusTLSSessionWasResumedUnknown(t *testing.T) {
	t.Parallel()

	row := rowFromStatus(Dot1XStatus{Interface: "en0", TLSSessionWasResumed: -1})
	assert.Equal(t, "", row["tls_session_was_resumed"])
}

func TestRowFromStatusUnknownEnumValues(t *testing.T) {
	t.Parallel()

	s := Dot1XStatus{
		Interface:       "en0",
		State:           99,
		SupplicantState: 99,
		Mode:            99,
		EAPType:         99,
		InnerEAPType:    99,
	}

	row := rowFromStatus(s)
	assert.Equal(t, "99", row["state"])
	assert.Equal(t, "Unknown(99)", row["state_name"])
	assert.Equal(t, "99", row["supplicant_state"])
	assert.Equal(t, "Unknown(99)", row["supplicant_state_name"])
	assert.Equal(t, "Unknown(99)", row["mode_name"])
	assert.Equal(t, "99", row["eap_type"])
	assert.Equal(t, "Unknown(99)", row["eap_type_name"])
	assert.Equal(t, "Unknown(99)", row["inner_eap_type_name"])
}

func TestLookupNameNegative(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "", lookupName(stateNames, -1))
	assert.Equal(t, "", lookupName(stateNames, -5))
}

func TestGenerateRowsWithConstraint(t *testing.T) {
	t.Parallel()
	backend := fakeBackend{statuses: map[string]Dot1XStatus{
		"en0": {Interface: "en0", State: 2, SupplicantState: 4, EAPType: 13, Mode: 3},
		"en1": {Interface: "en1", State: 2, SupplicantState: 4, EAPType: 25, InnerEAPType: 26, Mode: 2},
	}}
	for _, names := range [][]string{{"en0"}, {"en0", "en1"}} {
		rows, err := generateRows(context.Background(), backend, constraintFor(names...))
		require.NoError(t, err)
		require.Len(t, rows, len(names))
		assert.Equal(t, "en0", rows[0]["interface"])
		assert.Equal(t, "Running", rows[0]["state_name"])
		assert.Equal(t, "Authenticated", rows[0]["supplicant_state_name"])
		assert.Equal(t, "EAP-TLS", rows[0]["eap_type_name"])
		assert.Equal(t, "System", rows[0]["mode_name"])
		if len(rows) == 2 {
			assert.Equal(t, "en1", rows[1]["interface"])
			assert.Equal(t, "PEAP", rows[1]["eap_type_name"])
			assert.Equal(t, "MSCHAPv2", rows[1]["inner_eap_type_name"])
			assert.Equal(t, "LoginWindow", rows[1]["mode_name"])
		}
	}
}

func TestGenerateRowsNoActiveInterface(t *testing.T) {
	t.Parallel()

	backend := fakeBackend{statuses: map[string]Dot1XStatus{}}
	qc := constraintFor("en9")

	rows, err := generateRows(context.Background(), backend, qc)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestGenerateRowsSkipsErrors(t *testing.T) {
	t.Parallel()

	// en0 has a valid status, en1 errors — should return only en0
	backend := fakeBackend{
		statuses: map[string]Dot1XStatus{
			"en0": {
				Interface:       "en0",
				State:           2,
				SupplicantState: 4,
			},
		},
	}

	qc := constraintFor("en0", "en1")
	rows, err := generateRows(context.Background(), backend, qc)
	require.NoError(t, err)
	assert.Len(t, rows, 1)
	assert.Equal(t, "en0", rows[0]["interface"])
}

func TestGenerateRowsBackendUnavailable(t *testing.T) {
	t.Parallel()

	wrapper := errBackend{err: ErrBackendUnavailable}
	rows, err := generateRows(context.Background(), wrapper, constraintFor("en0"))
	assert.ErrorIs(t, err, ErrBackendUnavailable)
	assert.Empty(t, rows)
}

type errBackend struct {
	err error
}

func (e errBackend) GetStatus(ifname string) (Dot1XStatus, error) {
	return Dot1XStatus{Interface: ifname}, e.err
}

func TestMacAddrString(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "aa:bb:cc:dd:ee:ff",
		macAddrString([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}))
	assert.Equal(t, "", macAddrString([]byte{0xaa}))                // too short
	assert.Equal(t, "", macAddrString([]byte{0, 1, 2, 3, 4, 5, 6})) // too long
	assert.Equal(t, "", macAddrString(nil))
}

func TestGenerateRowsContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	rows, err := generateRows(ctx, fakeBackend{}, table.QueryContext{})
	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, rows)
}

func TestItoa(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "42", itoa(42))
	assert.Equal(t, "0", itoa(0))
	assert.Equal(t, "", itoa(-1))
}

func TestRowFromStatusEAPTypeNameFallback(t *testing.T) {
	t.Parallel()

	// When no explicit EAPTypeName is set, fall back to eapTypeNames map
	s := Dot1XStatus{Interface: "en0", EAPType: 13}
	row := rowFromStatus(s)
	assert.Equal(t, "EAP-TLS", row["eap_type_name"])

	// EAPTypeName set explicitly takes precedence
	s2 := Dot1XStatus{Interface: "en0", EAPType: 13, EAPTypeName: "Custom-EAP"}
	row2 := rowFromStatus(s2)
	assert.Equal(t, "Custom-EAP", row2["eap_type_name"])
}

func TestParseTLSCertChain(t *testing.T) {
	t.Parallel()
	der := testCertDER(t, pkix.Name{CommonName: "test.example.com", Organization: []string{"Test Org"}}, 12345, 2027)
	hash := sha1.Sum(der)
	fingerprint := fmt.Sprintf("% x", hash)
	fingerprint = strings.ReplaceAll(fingerprint, " ", ":")
	subject := "CN=test.example.com,O=Test Org"
	for _, tc := range []struct {
		name                            string
		data                            []byte
		subjects, fingerprints, serials string
	}{
		{name: "nil"},
		{name: "empty", data: []byte{}},
		{name: "truncated prefix", data: []byte{0, 0, 0}},
		{name: "length exceeds buffer", data: []byte{0, 0, 0, 255, 0}},
		{name: "invalid DER", data: packCerts([]byte("nope"))},
		{"single cert", packCerts(der), subject, fingerprint, "3039"},
		{"zero length skipped", packCerts(nil, der), subject, fingerprint, "3039"},
		{"invalid between valid certs", packCerts(der, []byte("bad!"), der), subject + "|" + subject, fingerprint + "," + fingerprint, "3039,3039"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			subjects, fingerprints, serials, expiry := parseTLSCertChain(tc.data)
			assert.Equal(t, tc.subjects, subjects)
			assert.Equal(t, tc.fingerprints, fingerprints)
			assert.Equal(t, tc.serials, serials)
			if tc.subjects == "" {
				assert.Empty(t, expiry)
			} else {
				assert.Equal(t, notAfter(t, der), expiry)
			}
		})
	}
}

func TestParseTLSCertChainPreservesSubject(t *testing.T) {
	// Domain components and multi-valued RDNs must survive parsing the DER,
	// not just direct calls to the renderer.
	rawSubject, err := asn1.Marshal(pkix.RDNSequence{
		{{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, Value: "edu"}},
		{{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, Value: "campus"}},
		{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "a"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "b"},
		},
	})
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		RawSubject:   rawSubject,
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	require.NoError(t, err)
	subject, fingerprint, serial, expiry := parseTLSCertChain(packCerts(der))
	assert.Equal(t, "CN=a+O=b,0.9.2342.19200300.100.1.25=campus,0.9.2342.19200300.100.1.25=edu", subject)
	assert.NotEmpty(t, fingerprint)
	assert.Equal(t, "2a", serial)
	assert.Equal(t, "2027-01-01T00:00:00Z", expiry)
}

func TestRenderRDNSequence(t *testing.T) {
	t.Parallel()

	t.Run("nil returns empty", func(t *testing.T) {
		t.Parallel()
		result := renderRDNSequence(nil)
		assert.Equal(t, "", result)
	})

	t.Run("well_known_oids", func(t *testing.T) {
		t.Parallel()
		seq := pkix.RDNSequence{
			{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "radius.campus.edu"},
			},
			{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "CampusGroup"},
			},
			{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "IT"},
			},
			{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"},
			},
		}
		result := renderRDNSequence(seq)
		assert.Equal(t, "CN=radius.campus.edu,O=CampusGroup,OU=IT,C=US", result)
	})

	t.Run("escapes_special_chars", func(t *testing.T) {
		t.Parallel()
		seq := pkix.RDNSequence{
			{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "dot.com, Inc."},
			},
			{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Org + Subsidiary"},
			},
		}
		result := renderRDNSequence(seq)
		assert.Equal(t, "CN=dot.com\\, Inc.,O=Org \\+ Subsidiary", result)
	})

	t.Run("multi_valued_rdn", func(t *testing.T) {
		t.Parallel()
		seq := pkix.RDNSequence{
			{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Org"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "Dept"},
			},
			{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "example.com"},
			},
		}
		result := renderRDNSequence(seq)
		assert.Equal(t, "O=Org+OU=Dept,CN=example.com", result)
	})

	t.Run("additional_rfc4514_escapes", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name     string
			input    string
			expected string
		}{
			{
				name:     "equals_in_value",
				input:    "key=value",
				expected: "key\\=value",
			},
			{
				name:     "leading_space",
				input:    " leading",
				expected: "\\ leading",
			},
			{
				name:     "trailing_space",
				input:    "trailing ",
				expected: "trailing\\ ",
			},
			{
				name:     "leading_hash",
				input:    "#leading",
				expected: "\\#leading",
			},
			{
				name:     "hash_not_first",
				input:    "mid#hash",
				expected: "mid#hash",
			},
			{
				name:     "control_char_null",
				input:    "test\x00null",
				expected: "test\\00null",
			},
			{
				name:     "control_char_del",
				input:    "test\x7fdel",
				expected: "test\\7Fdel",
			},
			{
				name:     "control_char_esc",
				input:    "test\x1besc",
				expected: "test\\1Besc",
			},
			{
				name:     "single_space",
				input:    " ",
				expected: "\\ ",
			},
		}
		for _, tc := range tests {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				result := escapeDN(tc.input)
				assert.Equal(t, tc.expected, result)
			})
		}
	})
}

// DomainSpecificError carries an Apple OSStatus (e.g. errSSLXCertChainInvalid
// = -9807), so negative values are real data and must render; only an absent
// value (nil) renders empty.
func TestRowFromStatusDomainSpecificError(t *testing.T) {
	t.Parallel()

	neg, zero := -9807, 0
	assert.Equal(t, "-9807", rowFromStatus(Dot1XStatus{DomainSpecificError: &neg})["domain_specific_error"])
	assert.Equal(t, "0", rowFromStatus(Dot1XStatus{DomainSpecificError: &zero})["domain_specific_error"])
	assert.Equal(t, "", rowFromStatus(Dot1XStatus{})["domain_specific_error"])
}

func intPtr(v int) *int { return &v }

// client_status_name maps Apple's public EAPClientStatus enum
// (EAPClientTypes.h); values observed live in failure testing included
// 1 (wrong password) and 3 (credential re-prompt / server trust prompt).
func TestRowFromStatusClientStatusName(t *testing.T) {
	t.Parallel()

	for status, want := range map[int]string{
		-1:   "",
		0:    "OK",
		1:    "Failed",
		3:    "UserInputRequired",
		6:    "ServerCertificateNotTrusted",
		10:   "UnknownRootCertificate",
		12:   "CertificateExpired",
		20:   "OtherInputRequired",
		1000: "ErrnoError",
		1001: "SecurityError",
		1002: "PluginSpecificError",
		999:  "Unknown(999)",
	} {
		assert.Equal(t, want, rowFromStatus(Dot1XStatus{ClientStatus: status})["client_status_name"], "status %d", status)
	}
}

func TestMapSCInterfaceType(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"IEEE80211": "wifi",
		"Ethernet":  "ethernet",
		"Bond":      "",
		"":          "",
	} {
		assert.Equal(t, want, mapSCInterfaceType(in), in)
	}
}

// macOS SSID: match the EAPOL authenticator (the AP BSSID) against the
// BSSIDs each known network was associated on. BSSIDs in the plist may be
// unpadded ("2a:b:8b:0:f2:35"); several networks can share a BSSID (one radio,
// multiple SSIDs), in which case the most recent association wins.
func TestKnownNetworkSSID(t *testing.T) {
	t.Parallel()
	b := []byte(readTestdata(t, "known-networks.plist"))

	assert.Equal(t, "CorpWiFi", knownNetworkSSID(b, "2a:0b:8b:00:f2:35"), "shared BSSID: newest association wins")
	assert.Equal(t, "CorpWiFi", knownNetworkSSID(b, "26:0B:8B:00:F2:34"), "case-insensitive, padded vs unpadded")
	assert.Equal(t, "Home", knownNetworkSSID(b, "1c:0b:8b:00:f2:34"))
	assert.Equal(t, "", knownNetworkSSID(b, "de:ad:be:ef:00:01"), "unknown BSSID")
	assert.Equal(t, "", knownNetworkSSID(b, ""), "no authenticator")
	assert.Equal(t, "", knownNetworkSSID([]byte("not a plist"), "2a:0b:8b:00:f2:35"))
	assert.Equal(t, "", knownNetworkSSID(nil, "2a:0b:8b:00:f2:35"), "plist unreadable (no root/FDA)")
}

// The EAPOLClientProfile also names the connection and, when installed by a
// configuration profile, records the com.apple.wifi.managed PayloadUUID.
func TestEAPOLProfileInfo(t *testing.T) {
	t.Parallel()
	b := []byte(readTestdata(t, "eapolclient-configuration.plist"))

	got := eapolProfileInfo(b, "11111111-2222-3333-4444-555555555555")
	assert.Equal(t, eapolProfile{
		ssid: "CorpWiFi", name: "WiFi (CorpWiFi)", payloadUUID: "ABCDEF01-2345-6789-ABCD-EF0123456789",
		identity:           "anonymous@campus.edu",
		trustedServerNames: "radius1.campus.edu,radius2.campus.edu",
		serverValidation:   "pinned",
	}, got, "OuterIdentity wins over UserName; trusted certs + names")

	got = eapolProfileInfo(b, "66666666-7777-8888-9999-000000000000")
	assert.Equal(t, eapolProfile{
		name: "Wired (no WLAN)", identity: "host/wired01.campus.edu", serverValidation: "ca_only",
	}, got, "no WLAN binding, not from MDM; UserName only; trusted certs only")

	got = eapolProfileInfo(b, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	assert.Equal(t, eapolProfile{name: "EAP-TLS (certificate only)", serverValidation: "prompt"}, got, "no UserName/OuterIdentity, nothing pinned")

	got = eapolProfileInfo(b, "bbbbbbbb-cccc-dddd-eeee-ffffffffffff")
	assert.Equal(t, eapolProfile{name: "Names only", trustedServerNames: "*.campus.edu", serverValidation: "name_only"}, got)

	assert.Equal(t, eapolProfile{}, eapolProfileInfo(b, "unknown"))
	assert.Equal(t, eapolProfile{}, eapolProfileInfo(b, ""))
	assert.Equal(t, eapolProfile{}, eapolProfileInfo([]byte("junk"), "11111111-2222-3333-4444-555555555555"))
	assert.Equal(t, eapolProfile{}, eapolProfileInfo(nil, "11111111-2222-3333-4444-555555555555"))
}

func TestServerValidation(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "pinned", serverValidation(true, true, true))
	assert.Equal(t, "ca_only", serverValidation(true, false, true))
	assert.Equal(t, "name_only", serverValidation(false, true, true))
	assert.Equal(t, "prompt", serverValidation(false, false, true))
	assert.Equal(t, "none", serverValidation(true, true, false), "validation disabled overrides pinning")
}

// mdm_payload_uuid is matched against `profiles -C -o stdout-xml` to name the
// payload type and the configuration profile that contains it.
func TestMDMPayloadInfo(t *testing.T) {
	t.Parallel()
	b := []byte(readTestdata(t, "profiles-stdout.plist"))

	for _, tc := range []struct {
		name, uuid, typ, profile, id string
	}{
		{"wifi", "ABCDEF01-2345-6789-ABCD-EF0123456789", "com.apple.wifi.managed", "Corp Wi-Fi", "com.example.wifi.corp"},
		{"case-insensitive", "abcdef01-2345-6789-abcd-ef0123456789", "com.apple.wifi.managed", "Corp Wi-Fi", "com.example.wifi.corp"},
		{"ethernet", "30000000-0000-0000-0000-00000000000A", "com.apple.globalethernet.managed", "Wired 802.1X", "com.example.ethernet"},
		{"per-user scope", "50000000-0000-0000-0000-000000000005", "com.apple.wifi.managed", "User Wi-Fi", "com.example.wifi.user"},
		{"no match", "deadbeef-0000-0000-0000-000000000000", "", "", ""},
		{"empty uuid", "", "", "", ""},
	} {
		typ, profile, id := mdmPayloadInfo(b, tc.uuid)
		assert.Equal(t, []string{tc.typ, tc.profile, tc.id}, []string{typ, profile, id}, tc.name)
	}

	// PayloadContent (which can hold secrets) is never read or returned.
	typ, profile, id := mdmPayloadInfo(b, "40000000-0000-0000-0000-000000000004")
	assert.Equal(t, []string{"com.apple.ManagedClient.preferences", "App Settings", "com.example.app"}, []string{typ, profile, id})
	assert.NotContains(t, typ+profile+id, "FAKE-SECRET")

	for _, bad := range [][]byte{nil, []byte("not a plist"), []byte(`<plist version="1.0"><array/></plist>`)} {
		typ, profile, id := mdmPayloadInfo(bad, "ABCDEF01-2345-6789-ABCD-EF0123456789")
		assert.Equal(t, []string{"", "", ""}, []string{typ, profile, id}, "bad input %q", bad)
	}
}
