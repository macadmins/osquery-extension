//go:build windows

package dot1x

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- UTF-16 helpers ---

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

	ifaces := enumerateWlanInterfaces()
	if len(ifaces) == 0 {
		t.Skip("no wireless interfaces found")
	}

	for _, ifname := range ifaces {
		s, err := backend.GetStatus(ifname)
		if errors.Is(err, ErrBackendUnavailable) {
			t.Skipf("WLAN service unavailable: %v", err)
		}
		if errors.Is(err, errNotDot1X) || errors.Is(err, errNoActiveConnection) {
			continue // idle, or connected but not to an 802.1X network
		}
		require.NoError(t, err)
		assert.Equal(t, ifname, s.Interface)
		assert.NotEmpty(t, s.UniqueIdentifier, "GUID should always be set")
		assert.GreaterOrEqual(t, s.State, 0)
		assert.LessOrEqual(t, s.State, 3)
		assert.Equal(t, -1, s.TLSSessionWasResumed, "wlanapi doesn't expose TLS resumption")
	}
}

func TestWindowsLiveBackendBogusInterface(t *testing.T) {
	requireLiveTests(t)
	backend := newBackend()

	_, err := backend.GetStatus("nonexistent_adapter_999")
	if errors.Is(err, ErrBackendUnavailable) {
		t.Skipf("WLAN service unavailable: %v", err)
	}
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent_adapter_999")
}
