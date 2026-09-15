//go:build windows

package dot1x

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- mapWlanState tests ---

func TestMapWlanState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		input          uint32
		wantState      int
		wantSupplicant int
	}{
		{"connected", wlanIfaceStateConnected, 2, 4},
		{"authenticating", wlanIfaceStateAuthenticating, 2, 3},
		{"associating", wlanIfaceStateAssociating, 1, 1},
		{"discovering", wlanIfaceStateDiscovering, 1, 2},
		{"disconnecting", wlanIfaceStateDisconnecting, 3, 6},
		{"disconnected", wlanIfaceStateDisconnected, 0, 0},
		{"not ready", wlanIfaceStateNotReady, 0, 7},
		{"ad hoc formed (default)", wlanIfaceStateAdHocFormed, 0, 0},
		{"unknown value 99", 99, 0, 0},
	}

	for _, tc := range tests {
		tc := tc // Go 1.22+ scopes this per-iteration; explicit for the linter.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotState, gotSupplicant := mapWlanState(tc.input)
			assert.Equal(t, tc.wantState, gotState, "state")
			assert.Equal(t, tc.wantSupplicant, gotSupplicant, "supplicant")
		})
	}
}

// --- GUID formatting ---

func TestWindowsGUIDString(t *testing.T) {
	t.Parallel()

	g := windowsGUID{
		Data1: 0x9A82D898,
		Data2: 0x7B57,
		Data3: 0x40AA,
		Data4: [8]byte{0xA3, 0x30, 0xE2, 0xB9, 0x9D, 0x10, 0xBD, 0x77},
	}
	assert.Equal(t, "{9A82D898-7B57-40AA-A330-E2B99D10BD77}", g.String())
}

func TestWindowsGUIDStringZero(t *testing.T) {
	t.Parallel()

	g := windowsGUID{}
	assert.Equal(t, "{00000000-0000-0000-0000-000000000000}", g.String())
}

// --- UTF-16 helpers ---

func TestUtf16ToString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input []uint16
		want  string
	}{
		{"simple ASCII", []uint16{'H', 'i', 0}, "Hi"},
		{"empty (just null)", []uint16{0}, ""},
		{"no null terminator", []uint16{'A', 'B', 'C'}, "ABC"},
		{"unicode", []uint16{0x00C9, 0x006D, 0x0069, 0x006C, 0x0065, 0}, "Émile"},
	}

	for _, tc := range tests {
		tc := tc // Go 1.22+ scopes this per-iteration; explicit for the linter.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := utf16ToString(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestUtf16PtrToString(t *testing.T) {
	t.Parallel()

	t.Run("nil pointer", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "", utf16PtrToString(nil))
	})

	t.Run("normal string", func(t *testing.T) {
		t.Parallel()
		data := []uint16{'T', 'e', 's', 't', 0}
		assert.Equal(t, "Test", utf16PtrToString(&data[0]))
	})
}

// --- duplicate interface description handling ---

func TestUniqueIfaceKey(t *testing.T) {
	t.Parallel()

	g1 := windowsGUID{Data1: 0x11111111}
	g2 := windowsGUID{Data1: 0x22222222}

	infos := map[string]ifaceInfo{}

	// First adapter keeps its plain description.
	k1 := uniqueIfaceKey(infos, "Intel Wi-Fi 6", g1)
	assert.Equal(t, "Intel Wi-Fi 6", k1)
	infos[k1] = ifaceInfo{guid: g1}

	// A second adapter with the same description is disambiguated by GUID, so
	// it is not dropped and stays individually queryable.
	k2 := uniqueIfaceKey(infos, "Intel Wi-Fi 6", g2)
	assert.Equal(t, "Intel Wi-Fi 6 "+g2.String(), k2)
	assert.NotEqual(t, k1, k2)

	// A distinct description is untouched.
	assert.Equal(t, "Realtek Wi-Fi", uniqueIfaceKey(infos, "Realtek Wi-Fi", g2))
}

// --- unavailableBackend ---

func TestUnavailableBackend(t *testing.T) {
	t.Parallel()

	b := unavailableBackend{}
	s, err := b.GetStatus("wifi0")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendUnavailable)
	assert.Equal(t, "wifi0", s.Interface)
}

// --- Mock-based integration tests using the shared Dot1XBackend interface ---

func TestWindowsMockBackendConnected(t *testing.T) {
	t.Parallel()

	backend := fakeBackend{
		statuses: map[string]Dot1XStatus{
			"RZ616 Wi-Fi 6E 160MHz": {
				Interface:                "RZ616 Wi-Fi 6E 160MHz",
				State:                    2,
				SupplicantState:          4,
				EAPType:                  13,
				ClientStatus:             0,
				AuthenticatorMACAddress: "26:0b:8b:00:f2:34",
				Mode:                    3,
				TLSTrustedRootCASHA1:    "23:a6:b1:0a:be:8a:4a:37:72:11:e2:f4:2c:36:67:f1:36:e9:08:bf",
				UniqueIdentifier:        "{9A82D898-7B57-40AA-A330-E2B99D10BD77}",
				DomainSpecificError:      -1,
				TLSTrustClientStatus:     -1,
				TLSNegotiatedCipher:      -1,
				InnerEAPType:             -1,
			},
		},
	}

	qc := constraintFor("RZ616 Wi-Fi 6E 160MHz")
	rows, err := generateRows(context.Background(), backend, qc)
	require.NoError(t, err)
	require.Len(t, rows, 1)

	row := rows[0]
	assert.Equal(t, "RZ616 Wi-Fi 6E 160MHz", row["interface"])
	assert.Equal(t, "2", row["state"])
	assert.Equal(t, "Running", row["state_name"])
	assert.Equal(t, "4", row["supplicant_state"])
	assert.Equal(t, "Authenticated", row["supplicant_state_name"])
	assert.Equal(t, "13", row["eap_type"])
	assert.Equal(t, "EAP-TLS", row["eap_type_name"])
	assert.Equal(t, "0", row["client_status"])
	assert.Equal(t, "26:0b:8b:00:f2:34", row["authenticator_mac_address"])
	assert.Equal(t, "3", row["mode"])
	assert.Equal(t, "System", row["mode_name"])
	// Windows surfaces the configured trusted-root-CA thumbprints, not the
	// presented server cert fingerprint, so they land in tls_trusted_root_ca_sha1.
	assert.Equal(t, "23:a6:b1:0a:be:8a:4a:37:72:11:e2:f4:2c:36:67:f1:36:e9:08:bf", row["tls_trusted_root_ca_sha1"])
	assert.Equal(t, "", row["tls_server_certificate_sha1"])
	assert.Equal(t, "{9A82D898-7B57-40AA-A330-E2B99D10BD77}", row["unique_identifier"])
	assert.Equal(t, "", row["domain_specific_error"])
	assert.Equal(t, "", row["tls_trust_client_status"])
	assert.Equal(t, "", row["tls_negotiated_cipher"])
	assert.Equal(t, "", row["inner_eap_type"])
	assert.Equal(t, "", row["inner_eap_type_name"])
}

func TestWindowsMockBackendDisconnected(t *testing.T) {
	t.Parallel()

	backend := fakeBackend{
		statuses: map[string]Dot1XStatus{
			"Intel Wi-Fi 6": {
				Interface:            "Intel Wi-Fi 6",
				State:                0,
				SupplicantState:      0,
				EAPType:              -1,
				ClientStatus:         -1,
				Mode:                 -1,
				DomainSpecificError:  -1,
				TLSTrustClientStatus: -1,
				TLSNegotiatedCipher:  -1,
				InnerEAPType:         -1,
				UniqueIdentifier:     "{ABCDEF01-2345-6789-ABCD-EF0123456789}",
			},
		},
	}

	qc := constraintFor("Intel Wi-Fi 6")
	rows, err := generateRows(context.Background(), backend, qc)
	require.NoError(t, err)
	require.Len(t, rows, 1)

	row := rows[0]
	assert.Equal(t, "Intel Wi-Fi 6", row["interface"])
	assert.Equal(t, "0", row["state"])
	assert.Equal(t, "Idle", row["state_name"])
	assert.Equal(t, "0", row["supplicant_state"])
	assert.Equal(t, "Disconnected", row["supplicant_state_name"])
	assert.Equal(t, "", row["eap_type"])
	assert.Equal(t, "", row["eap_type_name"])
	assert.Equal(t, "", row["client_status"])
	assert.Equal(t, "", row["authenticator_mac_address"])
	assert.Equal(t, "", row["mode"])
	assert.Equal(t, "", row["mode_name"])
}

func TestWindowsMockBackendPEAP(t *testing.T) {
	t.Parallel()

	backend := fakeBackend{
		statuses: map[string]Dot1XStatus{
			"Realtek Wi-Fi": {
				Interface:               "Realtek Wi-Fi",
				State:                   2,
				SupplicantState:         4,
				EAPType:                 25,
				InnerEAPType:            26,
				ClientStatus:            0,
				Mode:                    1,
				AuthenticatorMACAddress: "aa:bb:cc:dd:ee:ff",
				UniqueIdentifier:        "{11111111-2222-3333-4444-555555555555}",
				DomainSpecificError:     -1,
				TLSTrustClientStatus:    -1,
				TLSNegotiatedCipher:     -1,
			},
		},
	}

	qc := constraintFor("Realtek Wi-Fi")
	rows, err := generateRows(context.Background(), backend, qc)
	require.NoError(t, err)
	require.Len(t, rows, 1)

	row := rows[0]
	assert.Equal(t, "25", row["eap_type"])
	assert.Equal(t, "PEAP", row["eap_type_name"])
	assert.Equal(t, "26", row["inner_eap_type"])
	assert.Equal(t, "MSCHAPv2", row["inner_eap_type_name"])
	assert.Equal(t, "1", row["mode"])
	assert.Equal(t, "User", row["mode_name"])
}

func TestWindowsMockBackendNotFound(t *testing.T) {
	t.Parallel()

	backend := fakeBackend{statuses: map[string]Dot1XStatus{}}
	qc := constraintFor("nonexistent adapter")
	rows, err := generateRows(context.Background(), backend, qc)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestWindowsMockBackendUnavailable(t *testing.T) {
	t.Parallel()

	backend := errBackend{err: ErrBackendUnavailable}
	qc := constraintFor("any")
	rows, err := generateRows(context.Background(), backend, qc)
	assert.ErrorIs(t, err, ErrBackendUnavailable)
	assert.Empty(t, rows)
}

// --- Live backend smoke test ---

// requireLiveTests gates the live WLAN tests, which depend on host networking
// and the WLAN service and are therefore non-deterministic in CI. They run
// only when DOT1X_LIVE_TESTS is set, keeping the mock-based tests as the
// default coverage.
func requireLiveTests(t *testing.T) {
	t.Helper()
	if os.Getenv("DOT1X_LIVE_TESTS") == "" {
		t.Skip("set DOT1X_LIVE_TESTS=1 to run live WLAN backend tests")
	}
}

func TestWindowsLiveBackend(t *testing.T) {
	requireLiveTests(t)
	backend := newBackend()

	if _, ok := backend.(unavailableBackend); ok {
		t.Skip("wlanapi.dll not available on this system")
	}

	ifaces := enumerateWlanInterfaces()
	if len(ifaces) == 0 {
		t.Skip("no wireless interfaces found")
	}

	for _, ifname := range ifaces {
		s, err := backend.GetStatus(ifname)
		if errors.Is(err, ErrBackendUnavailable) {
			t.Skipf("WLAN service unavailable: %v", err)
		}
		require.NoError(t, err)
		assert.Equal(t, ifname, s.Interface)
		assert.NotEmpty(t, s.UniqueIdentifier, "GUID should always be set")
		assert.GreaterOrEqual(t, s.State, 0)
		assert.LessOrEqual(t, s.State, 3)
	}
}

func TestWindowsLiveBackendBogusInterface(t *testing.T) {
	requireLiveTests(t)
	backend := newBackend()

	if _, ok := backend.(unavailableBackend); ok {
		t.Skip("wlanapi.dll not available on this system")
	}

	_, err := backend.GetStatus("nonexistent_adapter_999")
	if errors.Is(err, ErrBackendUnavailable) {
		t.Skipf("WLAN service unavailable: %v", err)
	}
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent_adapter_999")
}

// --- Real profile XML extraction (end-to-end on live system) ---

func TestWindowsLiveProfileXMLExtraction(t *testing.T) {
	requireLiveTests(t)
	backend := newBackend()

	if _, ok := backend.(unavailableBackend); ok {
		t.Skip("wlanapi.dll not available on this system")
	}

	ifaces := enumerateWlanInterfaces()
	if len(ifaces) == 0 {
		t.Skip("no wireless interfaces found")
	}

	for _, ifname := range ifaces {
		s, err := backend.GetStatus(ifname)
		if err != nil {
			continue
		}
		if s.State != 2 {
			continue
		}
		// Connected interface should have at minimum an EAP type if 802.1X
		if s.EAPType > 0 {
			assert.NotEmpty(t, lookupName(eapTypeNames, s.EAPType),
				"known EAP type %d should have a name", s.EAPType)
		}
		return
	}
	t.Skip("no connected wireless interface found")
}
