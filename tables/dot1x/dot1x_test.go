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
	"encoding/binary"
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
		"interface", "state", "state_name",
		"supplicant_state", "supplicant_state_name",
		"eap_type", "eap_type_name",
		"client_status", "domain_specific_error",
		"authenticator_mac_address",
		"mode", "mode_name",
		"tls_session_was_resumed",
		"tls_server_certificate_chain",
		"tls_server_certificate_sha1",
		"tls_server_certificate_serials",
		"tls_trusted_root_ca_sha1",
		"tls_trust_client_status",
		"tls_negotiated_protocol_version",
		"tls_negotiated_cipher",
		"inner_eap_type",
		"inner_eap_type_name",
		"last_status_timestamp",
		"unique_identifier",
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
		qc := table.QueryContext{
			Constraints: map[string]table.ConstraintList{
				"interface": {
					Constraints: []table.Constraint{
						{Operator: table.OperatorEquals, Expression: "en0"},
					},
				},
			},
		}
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
		qc := table.QueryContext{
			Constraints: map[string]table.ConstraintList{
				"interface": {
					Constraints: []table.Constraint{
						{Operator: table.OperatorEquals, Expression: "en0"},
						{Operator: table.OperatorEquals, Expression: "en0"},
						{Operator: table.OperatorEquals, Expression: "en1"},
					},
				},
			},
		}
		ifaces := interfacesToQuery(fakeBackend{}, qc)
		assert.Equal(t, []string{"en0", "en1"}, ifaces)
	})
}

func TestRowFromStatus(t *testing.T) {
	t.Parallel()

	s := Dot1XStatus{
		Interface:                    "en0",
		State:                        2,
		SupplicantState:              4,
		EAPType:                      13,
		EAPTypeName:                  "EAP-TLS",
		ClientStatus:                 0,
		DomainSpecificError:          0,
		AuthenticatorMACAddress:      "aa:bb:cc:dd:ee:ff",
		Mode:                         1,
		TLSSessionWasResumed:         true,
		TLSServerCertificateChain:    "CN=radius.campus.edu,OU=IT,O=Campus,C=US",
		TLSServerCertificateSHA1:     "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd",
		TLSServerCertificateSerials:  "7D3A1F9E2B5C",
		TLSTrustClientStatus:         0,
		TLSNegotiatedProtocolVersion: "1.2",
		TLSNegotiatedCipher:          0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		InnerEAPType:                 26,
		InnerEAPTypeName:             "MSCHAPv2",
		LastStatusTimestamp:          "2026-06-05T12:00:00Z",
		UniqueIdentifier:             "abc-123",
	}

	row := rowFromStatus(s)
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
	assert.Equal(t, "abc-123", row["unique_identifier"])
}

func TestRowFromStatusUnsetFields(t *testing.T) {
	t.Parallel()

	s := Dot1XStatus{
		Interface:            "en0",
		State:                0,
		SupplicantState:      8,
		TLSSessionWasResumed: false,
	}

	row := rowFromStatus(s)
	assert.Equal(t, "Idle", row["state_name"])
	assert.Equal(t, "No Authenticator", row["supplicant_state_name"])
	assert.Equal(t, "", row["eap_type_name"])
	assert.Equal(t, "0", row["tls_session_was_resumed"])
}

func TestRowFromStatusUnknownEnumValues(t *testing.T) {
	t.Parallel()

	s := Dot1XStatus{
		Interface:       "en0",
		State:           99,
		SupplicantState: 99,
		Mode:            99,
		EAPType:         0,
	}

	row := rowFromStatus(s)
	assert.Equal(t, "99", row["state"])
	assert.Equal(t, "Unknown(99)", row["state_name"])
	assert.Equal(t, "99", row["supplicant_state"])
	assert.Equal(t, "Unknown(99)", row["supplicant_state_name"])
	assert.Equal(t, "Unknown(99)", row["mode_name"])
	assert.Equal(t, "", row["eap_type_name"])
}

func TestLookupNameNegative(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "", lookupName(stateNames, -1))
	assert.Equal(t, "", lookupName(stateNames, -5))
}

func TestGenerateRowsWithConstraint(t *testing.T) {
	t.Parallel()

	backend := fakeBackend{
		statuses: map[string]Dot1XStatus{
			"en0": {
				Interface:       "en0",
				State:           2,
				SupplicantState: 4,
				EAPType:         13,
				EAPTypeName:     "EAP-TLS",
				Mode:            1,
			},
		},
	}

	qc := table.QueryContext{
		Constraints: map[string]table.ConstraintList{
			"interface": {
				Constraints: []table.Constraint{
					{Operator: table.OperatorEquals, Expression: "en0"},
				},
			},
		},
	}

	rows, err := generateRows(context.Background(), backend, qc)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "en0", rows[0]["interface"])
	assert.Equal(t, "Running", rows[0]["state_name"])
	assert.Equal(t, "Authenticated", rows[0]["supplicant_state_name"])
}

func TestGenerateRowsNoActiveInterface(t *testing.T) {
	t.Parallel()

	backend := fakeBackend{statuses: map[string]Dot1XStatus{}}
	qc := table.QueryContext{
		Constraints: map[string]table.ConstraintList{
			"interface": {
				Constraints: []table.Constraint{
					{Operator: table.OperatorEquals, Expression: "en9"},
				},
			},
		},
	}

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

	qc := table.QueryContext{
		Constraints: map[string]table.ConstraintList{
			"interface": {
				Constraints: []table.Constraint{
					{Operator: table.OperatorEquals, Expression: "en0"},
					{Operator: table.OperatorEquals, Expression: "en1"},
				},
			},
		},
	}
	rows, err := generateRows(context.Background(), backend, qc)
	require.NoError(t, err)
	assert.Len(t, rows, 1)
	assert.Equal(t, "en0", rows[0]["interface"])
}

func TestGenerateRowsBackendUnavailable(t *testing.T) {
	t.Parallel()

	wrapper := errBackend{err: ErrBackendUnavailable}
	rows, err := generateRows(context.Background(), wrapper, table.QueryContext{
		Constraints: map[string]table.ConstraintList{
			"interface": {
				Constraints: []table.Constraint{
					{Operator: table.OperatorEquals, Expression: "en0"},
				},
			},
		},
	})
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

func TestDot1XStatusGenerate(t *testing.T) {
	t.Parallel()

	rows, err := generateRows(context.Background(), fakeBackend{statuses: map[string]Dot1XStatus{}}, table.QueryContext{
		Constraints: map[string]table.ConstraintList{
			"interface": {
				Constraints: []table.Constraint{
					{Operator: table.OperatorEquals, Expression: "nonexistent_en999"},
				},
			},
		},
	})
	require.NoError(t, err)
	assert.Empty(t, rows)
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

func TestNameMapsComplete(t *testing.T) {
	t.Parallel()

	for i, name := range stateNames {
		assert.NotEmpty(t, name, "stateNames missing entry for %d", i)
	}

	for i, name := range supplicantStateNames {
		assert.NotEmpty(t, name, "supplicantStateNames missing entry for %d", i)
	}

	// Separately verify expected count matches enum range
	for i := 0; i <= 8; i++ {
		_, ok := supplicantStateNames[i]
		assert.True(t, ok, "supplicantStateNames missing index %d", i)
	}

	for i := 0; i <= 3; i++ {
		_, ok := stateNames[i]
		assert.True(t, ok, "stateNames missing index %d", i)
	}

	for i := 0; i <= 3; i++ {
		_, ok := modeNames[i]
		assert.True(t, ok, "modeNames missing index %d", i)
	}
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

func TestMacAddrStringCaps(t *testing.T) {
	t.Parallel()
	// Just verify mac address strings use lowercase hex (verify).
	addr := macAddrString([]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", addr)
	assert.True(t, strings.Contains(addr, "aa"), "should use lowercase")
}

func TestParseTLSCertChain(t *testing.T) {
	// Subtests that generate keys/certs with crypto/rand are serialized
	// (no t.Parallel); data-only subtests use t.Parallel().

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		subj, sha1s, serials := parseTLSCertChain(nil)
		assert.Equal(t, "", subj)
		assert.Equal(t, "", sha1s)
		assert.Equal(t, "", serials)
		subj, sha1s, serials = parseTLSCertChain([]byte{})
		assert.Equal(t, "", subj)
		assert.Equal(t, "", sha1s)
		assert.Equal(t, "", serials)
	})

	t.Run("truncated length prefix", func(t *testing.T) {
		t.Parallel()
		subj, sha1s, serials := parseTLSCertChain([]byte{0x00, 0x00, 0x00})
		assert.Equal(t, "", subj)
		assert.Equal(t, "", sha1s)
		assert.Equal(t, "", serials)
	})

	t.Run("invalid DER", func(t *testing.T) {
		t.Parallel()
		packed := []byte{0x00, 0x00, 0x00, 0x04, 'n', 'o', 'p', 'e'}
		subj, sha1s, serials := parseTLSCertChain(packed)
		assert.Equal(t, "", subj)
		assert.Equal(t, "", sha1s)
		assert.Equal(t, "", serials)
	})

	t.Run("length exceeds buffer", func(t *testing.T) {
		t.Parallel()
		packed := []byte{0x00, 0x00, 0x00, 0xff, 0x00}
		subj, sha1s, serials := parseTLSCertChain(packed)
		assert.Equal(t, "", subj)
		assert.Equal(t, "", sha1s)
		assert.Equal(t, "", serials)
	})

	t.Run("valid_single_cert", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(12345),
			Subject: pkix.Name{
				CommonName:   "test.example.com",
				Organization: []string{"Test Org"},
			},
			NotBefore: time.Now().Add(-time.Hour),
			NotAfter:  time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		require.NoError(t, err)

		buf := make([]byte, 4+len(der))
		binary.BigEndian.PutUint32(buf, uint32(len(der)))
		copy(buf[4:], der)

		subj, sha1s, serials := parseTLSCertChain(buf)
		assert.Equal(t, "CN=test.example.com,O=Test Org", subj)
		h := sha1.Sum(der)
		expectedSHA1 := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
			h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9],
			h[10], h[11], h[12], h[13], h[14], h[15], h[16], h[17], h[18], h[19],
		)
		assert.Equal(t, expectedSHA1, sha1s)
		assert.Equal(t, "3039", serials) // 12345 in hex
	})

	t.Run("zero_length_entry_skipped", func(t *testing.T) {
		// Two entries: first has length=0, second is a valid cert.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(999),
			Subject: pkix.Name{
				CommonName: "valid.example.com",
			},
			NotBefore: time.Now().Add(-time.Hour),
			NotAfter:  time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		require.NoError(t, err)

		buf := make([]byte, 4+0+4+len(der))
		binary.BigEndian.PutUint32(buf[0:4], 0) // zero-length entry
		binary.BigEndian.PutUint32(buf[4:8], uint32(len(der)))
		copy(buf[8:], der)

		subj, sha1s, serials := parseTLSCertChain(buf)
		assert.Equal(t, "CN=valid.example.com", subj)
		assert.NotEmpty(t, sha1s)
		assert.Equal(t, "3e7", serials) // 999 in hex (lowercase from Text(16))
	})

	t.Run("mixed_valid_and_invalid", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "good.example.com"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		require.NoError(t, err)

		// Layout: valid cert | invalid garbage | valid cert
		invalidBuf := []byte{0x00, 0x00, 0x00, 0x04, 'b', 'a', 'd', '!'}
		buf := make([]byte, 4+len(der)+len(invalidBuf)+4+len(der))
		binary.BigEndian.PutUint32(buf[0:4], uint32(len(der)))
		copy(buf[4:], der)
		copy(buf[4+len(der):], invalidBuf)
		binary.BigEndian.PutUint32(buf[4+len(der)+len(invalidBuf):], uint32(len(der)))
		copy(buf[4+len(der)+len(invalidBuf)+4:], der)

		subj, sha1s, serials := parseTLSCertChain(buf)
		parts := strings.Split(subj, "|")
		assert.Len(t, parts, 2)
		assert.Len(t, strings.Split(sha1s, ","), 2)
		assert.Len(t, strings.Split(serials, ","), 2)
	})
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
