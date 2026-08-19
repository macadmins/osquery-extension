//go:build darwin

package dot1x

import (
	"context"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCgoFrameworkLoading(t *testing.T) {
	// Not parallel: dlopen has global state via the static copy_state_fn.
	backend := newBackend()

	// Verify the framework loads and the symbol resolves.
	// load_dot1x() is called in newBackend via sync.Once, so the
	// framework is loaded before the first GetStatus call.
	_, err := backend.GetStatus("en0")
	// EAP8021X.framework should be loadable on any macOS system.
	// The call should NOT fail with ErrBackendUnavailable.
	assert.NotErrorIs(t, err, ErrBackendUnavailable,
		"EAP8021X.framework should be loadable on darwin")

	// If there's no active EAP session on en0, that's fine — we get a
	// non-nil error but NOT ErrBackendUnavailable.
}

func TestCgoBogusInterface(t *testing.T) {
	backend := newBackend()

	_, err := backend.GetStatus("bogus999999")
	require.Error(t, err)
	// Bogus interface should not trigger framework-unavailable error.
	assert.NotErrorIs(t, err, ErrBackendUnavailable)
	assert.Contains(t, err.Error(), "bogus999999")
}

// --- Mock-based integration tests using the shared Dot1XBackend interface ---
//
// These exercise the full generateRows -> rowFromStatus path with canned
// Dot1XStatus values, so they run deterministically without the EAP8021X
// framework or an active 802.1X session. They focus on the macOS-rich fields
// (TLS server certificate chain, fingerprints, serials, negotiated protocol
// version/cipher, trust status, and last-status timestamp) that the cgo
// backend populates but the Windows backend does not.

func TestDarwinMockBackendSystemEAPTLS(t *testing.T) {
	t.Parallel()

	backend := fakeBackend{
		statuses: map[string]Dot1XStatus{
			"en0": {
				Interface:               "en0",
				State:                   2, // Running
				SupplicantState:         4, // Authenticated
				EAPType:                 13,
				EAPTypeName:             "EAP-TLS",
				ClientStatus:            0,
				DomainSpecificError:     0,
				AuthenticatorMACAddress: "00:11:22:33:44:55",
				Mode:                    3, // System
				TLSSessionWasResumed:    true,
				// Two-cert chain: leaf | issuing CA. DNs are pipe-separated
				// because LDAP DNs themselves use commas as RDN separators.
				TLSServerCertificateChain: "CN=radius.campus.edu,OU=IT,O=CampusGroup,C=US|CN=CampusGroup Root CA,O=CampusGroup,C=US",
				TLSServerCertificateSHA1: "23:a6:b1:0a:be:8a:4a:37:72:11:e2:f4:2c:36:67:f1:36:e9:08:bf," +
					"aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd",
				TLSServerCertificateSerials:  "7d3a1f9e2b5c,3039",
				TLSTrustClientStatus:         0,
				TLSNegotiatedProtocolVersion: "1.2",
				TLSNegotiatedCipher:          0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
				InnerEAPType:                 -1,
				LastStatusTimestamp:          "2026-06-06T12:00:00Z",
				UniqueIdentifier:             "11111111-2222-3333-4444-555555555555",
			},
		},
	}

	rows, err := generateRows(context.Background(), backend, constraintFor("en0"))
	require.NoError(t, err)
	require.Len(t, rows, 1)

	row := rows[0]
	assert.Equal(t, "en0", row["interface"])
	assert.Equal(t, "2", row["state"])
	assert.Equal(t, "Running", row["state_name"])
	assert.Equal(t, "4", row["supplicant_state"])
	assert.Equal(t, "Authenticated", row["supplicant_state_name"])
	assert.Equal(t, "13", row["eap_type"])
	assert.Equal(t, "EAP-TLS", row["eap_type_name"])
	assert.Equal(t, "0", row["client_status"])
	assert.Equal(t, "0", row["domain_specific_error"])
	assert.Equal(t, "00:11:22:33:44:55", row["authenticator_mac_address"])
	assert.Equal(t, "3", row["mode"])
	assert.Equal(t, "System", row["mode_name"])
	assert.Equal(t, "1", row["tls_session_was_resumed"])
	assert.Equal(t, "CN=radius.campus.edu,OU=IT,O=CampusGroup,C=US|CN=CampusGroup Root CA,O=CampusGroup,C=US", row["tls_server_certificate_chain"])
	assert.Equal(t, "23:a6:b1:0a:be:8a:4a:37:72:11:e2:f4:2c:36:67:f1:36:e9:08:bf,"+
		"aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd", row["tls_server_certificate_sha1"])
	assert.Equal(t, "7d3a1f9e2b5c,3039", row["tls_server_certificate_serials"])
	assert.Equal(t, "0", row["tls_trust_client_status"])
	assert.Equal(t, "1.2", row["tls_negotiated_protocol_version"])
	assert.Equal(t, "49195", row["tls_negotiated_cipher"])
	assert.Equal(t, "", row["inner_eap_type"])
	assert.Equal(t, "", row["inner_eap_type_name"])
	assert.Equal(t, "2026-06-06T12:00:00Z", row["last_status_timestamp"])
	assert.Equal(t, "11111111-2222-3333-4444-555555555555", row["unique_identifier"])
}

func TestDarwinMockBackendIdle(t *testing.T) {
	t.Parallel()

	// An interface with no active 802.1X session: state Idle, supplicant
	// Disconnected, and all the optional numeric fields set to the cgo
	// backend's -1 sentinel (which rowFromStatus renders as empty strings).
	backend := fakeBackend{
		statuses: map[string]Dot1XStatus{
			"en0": {
				Interface:            "en0",
				State:                0, // Idle
				SupplicantState:      0, // Disconnected
				EAPType:              -1,
				ClientStatus:         -1,
				DomainSpecificError:  -1,
				Mode:                 -1,
				TLSTrustClientStatus: -1,
				TLSNegotiatedCipher:  -1,
				InnerEAPType:         -1,
			},
		},
	}

	rows, err := generateRows(context.Background(), backend, constraintFor("en0"))
	require.NoError(t, err)
	require.Len(t, rows, 1)

	row := rows[0]
	assert.Equal(t, "en0", row["interface"])
	assert.Equal(t, "0", row["state"])
	assert.Equal(t, "Idle", row["state_name"])
	assert.Equal(t, "0", row["supplicant_state"])
	assert.Equal(t, "Disconnected", row["supplicant_state_name"])
	assert.Equal(t, "", row["eap_type"])
	assert.Equal(t, "", row["eap_type_name"])
	assert.Equal(t, "", row["client_status"])
	assert.Equal(t, "", row["mode"])
	assert.Equal(t, "", row["mode_name"])
	assert.Equal(t, "", row["tls_negotiated_cipher"])
	assert.Equal(t, "0", row["tls_session_was_resumed"])
	assert.Equal(t, "", row["tls_server_certificate_chain"])
}

func TestDarwinMockBackendPEAP(t *testing.T) {
	t.Parallel()

	// PEAP (25) tunneling MSCHAPv2 (26) on a LoginWindow-mode interface,
	// negotiated over TLS 1.3 with a resumed session.
	backend := fakeBackend{
		statuses: map[string]Dot1XStatus{
			"en1": {
				Interface:                    "en1",
				State:                        2, // Running
				SupplicantState:              4, // Authenticated
				EAPType:                      25,
				InnerEAPType:                 26,
				ClientStatus:                 0,
				DomainSpecificError:          0,
				Mode:                         2, // LoginWindow
				AuthenticatorMACAddress:      "aa:bb:cc:dd:ee:ff",
				TLSSessionWasResumed:         true,
				TLSTrustClientStatus:         0,
				TLSNegotiatedProtocolVersion: "1.3",
				TLSNegotiatedCipher:          0x1301, // TLS_AES_128_GCM_SHA256
				UniqueIdentifier:             "22222222-3333-4444-5555-666666666666",
			},
		},
	}

	rows, err := generateRows(context.Background(), backend, constraintFor("en1"))
	require.NoError(t, err)
	require.Len(t, rows, 1)

	row := rows[0]
	assert.Equal(t, "en1", row["interface"])
	assert.Equal(t, "25", row["eap_type"])
	assert.Equal(t, "PEAP", row["eap_type_name"])
	assert.Equal(t, "26", row["inner_eap_type"])
	assert.Equal(t, "MSCHAPv2", row["inner_eap_type_name"])
	assert.Equal(t, "2", row["mode"])
	assert.Equal(t, "LoginWindow", row["mode_name"])
	assert.Equal(t, "1", row["tls_session_was_resumed"])
	assert.Equal(t, "1.3", row["tls_negotiated_protocol_version"])
	assert.Equal(t, "4865", row["tls_negotiated_cipher"]) // 0x1301
}

func TestDarwinMockBackendUnknownEAPType(t *testing.T) {
	t.Parallel()

	// A positive EAP type code missing from eapTypeNames should render as
	// "Unknown(<n>)", consistent with state/supplicant/mode handling.
	backend := fakeBackend{
		statuses: map[string]Dot1XStatus{
			"en0": {
				Interface:       "en0",
				State:           2,
				SupplicantState: 4,
				EAPType:         99,
				InnerEAPType:    -1,
				Mode:            3,
			},
		},
	}

	rows, err := generateRows(context.Background(), backend, constraintFor("en0"))
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "99", rows[0]["eap_type"])
	assert.Equal(t, "Unknown(99)", rows[0]["eap_type_name"])
}

func TestDarwinMockBackendMultipleInterfaces(t *testing.T) {
	t.Parallel()

	// Probing two interfaces where both are active yields one row each.
	backend := fakeBackend{
		statuses: map[string]Dot1XStatus{
			"en0": {Interface: "en0", State: 2, SupplicantState: 4, EAPType: 13, EAPTypeName: "EAP-TLS", Mode: 3, InnerEAPType: -1},
			"en1": {Interface: "en1", State: 2, SupplicantState: 4, EAPType: 25, InnerEAPType: 26, Mode: 1},
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
	require.Len(t, rows, 2)
	assert.Equal(t, "en0", rows[0]["interface"])
	assert.Equal(t, "EAP-TLS", rows[0]["eap_type_name"])
	assert.Equal(t, "en1", rows[1]["interface"])
	assert.Equal(t, "PEAP", rows[1]["eap_type_name"])
}

func TestDarwinMockBackendNotFound(t *testing.T) {
	t.Parallel()

	// An interface the backend doesn't know about errors per-interface, and
	// generateRows skips it, yielding zero rows.
	backend := fakeBackend{statuses: map[string]Dot1XStatus{}}
	rows, err := generateRows(context.Background(), backend, constraintFor("en0"))
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestDarwinMockBackendUnavailable(t *testing.T) {
	t.Parallel()

	// A systemic ErrBackendUnavailable (e.g. EAP8021X.framework failed to
	// load) propagates rather than being swallowed as a per-interface miss.
	backend := errBackend{err: ErrBackendUnavailable}
	rows, err := generateRows(context.Background(), backend, constraintFor("en0"))
	assert.ErrorIs(t, err, ErrBackendUnavailable)
	assert.Empty(t, rows)
}
