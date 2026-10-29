package dot1x

// Tests for the pure-Go Windows WLAN status logic (dot1x_wlan.go). No build
// tag: a fakeWlanClient stands in for wlanapi.dll so GetStatus's decoding and
// state handling run deterministically on every platform.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testGUID = windowsGUID{
	Data1: 0x9A82D898,
	Data2: 0x7B57,
	Data3: 0x40AA,
	Data4: [8]byte{0xA3, 0x30, 0xE2, 0xB9, 0x9D, 0x10, 0xBD, 0x77},
}

const testIface = "RZ616 Wi-Fi 6E 160MHz"

type fakeWlanClient struct {
	ifaces     map[string]ifaceInfo
	enumErr    error
	conn       []byte
	connErr    error
	profile    string
	profileErr error
	events     []winEvent
	eventsErr  error

	connCalls    int
	profileGUID  windowsGUID
	profileName  string
	profileCalls int
}

func (f *fakeWlanClient) interfaces() (map[string]ifaceInfo, []string, error) {
	names := make([]string, 0, len(f.ifaces))
	for k := range f.ifaces {
		names = append(names, k)
	}
	return f.ifaces, names, f.enumErr
}

func (f *fakeWlanClient) currentConnection(windowsGUID) ([]byte, error) {
	f.connCalls++
	return f.conn, f.connErr
}

func (f *fakeWlanClient) wlanEvents() ([]winEvent, error) {
	return f.events, f.eventsErr
}

func (f *fakeWlanClient) profileXML(guid windowsGUID, name string) (string, error) {
	f.profileCalls++
	f.profileGUID, f.profileName = guid, name
	return f.profile, f.profileErr
}

// connAttrs builds a WLAN_CONNECTION_ATTRIBUTES value for tests.
func connAttrs(state uint32, oneX bool, profile string) wlanConnectionAttributes {
	var a wlanConnectionAttributes
	a.IsState = state
	copy(a.ProfileName[:], utf16.Encode([]rune(profile)))
	a.AssociationAttributes.Dot11Bssid = [6]byte{0x26, 0x0b, 0x8b, 0x00, 0xf2, 0x34}
	a.SecurityAttributes.SecurityEnabled = 1
	if oneX {
		a.SecurityAttributes.OneXEnabled = 1
	}
	return a
}

// connBuf serialises a as wlanapi would return it (little-endian, Windows ABI).
func connBuf(t *testing.T, a wlanConnectionAttributes) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, a))
	return buf.Bytes()
}

func newFake(t *testing.T, enumState uint32, conn wlanConnectionAttributes, profile string) *fakeWlanClient {
	t.Helper()
	return &fakeWlanClient{
		ifaces:  map[string]ifaceInfo{testIface: {guid: testGUID, state: enumState}},
		conn:    connBuf(t, conn),
		profile: profile,
	}
}

// --- ABI layout / decoding ---

func TestWlanConnectionAttributesSize(t *testing.T) {
	t.Parallel()
	// sizeof(WLAN_CONNECTION_ATTRIBUTES) on Windows (x86/amd64/arm64).
	assert.Equal(t, 604, binary.Size(wlanConnectionAttributes{}))
	assert.Equal(t, uintptr(604), unsafe.Sizeof(wlanConnectionAttributes{}))
}

func TestDecodeConnectionAttributesRoundTrip(t *testing.T) {
	t.Parallel()
	want := connAttrs(wlanIfaceStateConnected, true, "Campus")
	want.ConnectionMode = 1
	want.AssociationAttributes.Dot11Ssid.SSIDLength = 6
	copy(want.AssociationAttributes.Dot11Ssid.SSID[:], "Campus")
	want.AssociationAttributes.WlanSignalQuality = 87
	want.SecurityAttributes.AuthAlgorithm = 7
	want.SecurityAttributes.CipherAlgorithm = 4

	got, err := decodeConnectionAttributes(connBuf(t, want))
	require.NoError(t, err)
	assert.Equal(t, want, got)
	assert.Equal(t, "Campus", utf16ToString(got.ProfileName[:]))
}

func TestDecodeConnectionAttributesShort(t *testing.T) {
	t.Parallel()
	b := connBuf(t, connAttrs(wlanIfaceStateConnected, true, "x"))
	for _, n := range []int{0, 1, len(b) - 1} {
		_, err := decodeConnectionAttributes(b[:n])
		assert.Error(t, err, "len %d", n)
	}
	_, err := decodeConnectionAttributes(nil)
	assert.Error(t, err)
}

// --- wlanStatus ---

func TestWlanStatusConnectedEAPTLS(t *testing.T) {
	t.Parallel()
	a := connAttrs(wlanIfaceStateConnected, true, "Corp WiFi (Intune)")
	a.AssociationAttributes.Dot11Ssid.SSIDLength = 6
	copy(a.AssociationAttributes.Dot11Ssid.SSID[:], "Campus")
	c := newFake(t, wlanIfaceStateConnected, a, sampleProfileXML)

	s, err := wlanStatus(c, testIface)
	require.NoError(t, err)
	assert.Equal(t, Dot1XStatus{
		Interface:               testIface,
		InterfaceType:           "wifi",
		ProfileName:             "Corp WiFi (Intune)",
		SSID:                    "Campus",
		State:                   2, // Running
		SupplicantState:         4, // Authenticated
		EAPType:                 13,
		ClientStatus:            0,
		AuthenticatorMACAddress: "26:0b:8b:00:f2:34",
		Mode:                    3, // System
		TLSSessionWasResumed:    -1,
		TLSTrustedRootCASHA1:    "23:a6:b1:0a:be:8a:4a:37:72:11:e2:f4:2c:36:67:f1:36:e9:08:bf",
		ServerValidation:        "ca_only",
		TLSTrustClientStatus:    -1,
		TLSNegotiatedCipher:     -1,
		InnerEAPType:            -1,
		UniqueIdentifier:        "{9A82D898-7B57-40AA-A330-E2B99D10BD77}",
	}, s)
	assert.Equal(t, testGUID, c.profileGUID)
	assert.Equal(t, "Corp WiFi (Intune)", c.profileName)
}

func TestWlanStatusPEAP(t *testing.T) {
	t.Parallel()
	c := newFake(t, wlanIfaceStateConnected, connAttrs(wlanIfaceStateConnected, true, "PEAPNetwork"), peapProfileXML)

	s, err := wlanStatus(c, testIface)
	require.NoError(t, err)
	assert.Equal(t, 25, s.EAPType)
	assert.Equal(t, 26, s.InnerEAPType)
}

func TestWlanStatusNotDot1X(t *testing.T) {
	t.Parallel()
	c := newFake(t, wlanIfaceStateConnected, connAttrs(wlanIfaceStateConnected, false, "Home"), sampleProfileXML)

	_, err := wlanStatus(c, testIface)
	assert.ErrorIs(t, err, errNotDot1X)
	assert.Zero(t, c.profileCalls)
}

func TestWlanStatusIdleSkipsQuery(t *testing.T) {
	t.Parallel()
	c := newFake(t, wlanIfaceStateDisconnected, connAttrs(wlanIfaceStateConnected, true, "Campus"), sampleProfileXML)

	s, err := wlanStatus(c, testIface)
	assert.ErrorIs(t, err, errNoActiveConnection)
	assert.Zero(t, c.connCalls, "idle adapter must not be queried")
	assert.Equal(t, testIface, s.Interface)
}

// Auth can complete between WlanEnumInterfaces and the current_connection
// query; the fresher connection state must win.
func TestWlanStatusUsesConnectionState(t *testing.T) {
	t.Parallel()
	c := newFake(t, wlanIfaceStateAuthenticating, connAttrs(wlanIfaceStateConnected, true, "Campus"), sampleProfileXML)

	s, err := wlanStatus(c, testIface)
	require.NoError(t, err)
	assert.Equal(t, 2, s.State)
	assert.Equal(t, 4, s.SupplicantState)
	assert.Equal(t, 0, s.ClientStatus)
}

func TestWlanStatusConnectionStillAuthenticating(t *testing.T) {
	t.Parallel()
	c := newFake(t, wlanIfaceStateAuthenticating, connAttrs(wlanIfaceStateAuthenticating, true, "Campus"), sampleProfileXML)

	s, err := wlanStatus(c, testIface)
	require.NoError(t, err)
	assert.Equal(t, 2, s.State)
	assert.Equal(t, 3, s.SupplicantState)
	assert.Equal(t, -1, s.ClientStatus)
}

func TestWlanStatusDisconnectedAfterEnum(t *testing.T) {
	t.Parallel()
	c := newFake(t, wlanIfaceStateConnected, connAttrs(wlanIfaceStateDisconnected, true, "Campus"), sampleProfileXML)

	_, err := wlanStatus(c, testIface)
	assert.ErrorIs(t, err, errNoActiveConnection)
}

func TestWlanStatusShortBuffer(t *testing.T) {
	t.Parallel()
	for _, size := range []int{0, 100} {
		c := newFake(t, wlanIfaceStateConnected, connAttrs(wlanIfaceStateConnected, true, "Campus"), sampleProfileXML)
		c.conn = c.conn[:size]
		_, err := wlanStatus(c, testIface)
		require.Error(t, err, "buffer size %d", size)
		assert.Contains(t, err.Error(), testIface)
	}
}

func TestWlanStatusQueryError(t *testing.T) {
	t.Parallel()
	queryErr := errors.New("boom")
	c := newFake(t, wlanIfaceStateConnected, connAttrs(wlanIfaceStateConnected, true, "Campus"), sampleProfileXML)
	c.connErr = queryErr

	_, err := wlanStatus(c, testIface)
	assert.ErrorIs(t, err, queryErr)
	assert.NotErrorIs(t, err, ErrBackendUnavailable)
	assert.Contains(t, err.Error(), testIface)
}

func TestWlanStatusProfileErrorNonFatal(t *testing.T) {
	t.Parallel()
	c := newFake(t, wlanIfaceStateConnected, connAttrs(wlanIfaceStateConnected, true, "Campus"), "")
	c.profileErr = errors.New("profile gone")

	s, err := wlanStatus(c, testIface)
	require.NoError(t, err)
	assert.Equal(t, 4, s.SupplicantState)
	assert.Equal(t, "26:0b:8b:00:f2:34", s.AuthenticatorMACAddress)
	assert.Equal(t, -1, s.EAPType)
	assert.Equal(t, -1, s.Mode)
	assert.Equal(t, -1, s.InnerEAPType)
	assert.Empty(t, s.TLSTrustedRootCASHA1)
}

func TestWlanStatusNoProfileName(t *testing.T) {
	t.Parallel()
	c := newFake(t, wlanIfaceStateConnected, connAttrs(wlanIfaceStateConnected, true, ""), sampleProfileXML)

	s, err := wlanStatus(c, testIface)
	require.NoError(t, err)
	assert.Zero(t, c.profileCalls)
	assert.Equal(t, -1, s.EAPType)
}

func TestWlanStatusUnknownInterface(t *testing.T) {
	t.Parallel()
	c := newFake(t, wlanIfaceStateConnected, connAttrs(wlanIfaceStateConnected, true, "Campus"), sampleProfileXML)

	s, err := wlanStatus(c, "nope")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nope")
	assert.NotErrorIs(t, err, ErrBackendUnavailable)
	assert.Equal(t, "nope", s.Interface)
}

func TestWlanStatusEnumError(t *testing.T) {
	t.Parallel()
	enumErr := errors.New("wlansvc down")
	c := &fakeWlanClient{enumErr: enumErr}

	_, err := wlanStatus(c, testIface)
	assert.ErrorIs(t, err, ErrBackendUnavailable)
	assert.ErrorIs(t, err, enumErr)
	assert.Zero(t, c.connCalls)
}

// --- pure helpers (moved from dot1x_windows_test.go) ---

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

func TestWindowsGUIDString(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "{9A82D898-7B57-40AA-A330-E2B99D10BD77}", testGUID.String())
	assert.Equal(t, "{00000000-0000-0000-0000-000000000000}", windowsGUID{}.String())
}

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
			assert.Equal(t, tc.want, utf16ToString(tc.input))
		})
	}
}

// Idle/transitional adapters have no current connection to inspect for
// 802.1X, so they're skipped (macOS reports nothing for interfaces without
// active EAPOL). Only connected/authenticating adapters proceed.
func TestCheckActiveConnection(t *testing.T) {
	t.Parallel()

	for _, st := range []uint32{wlanIfaceStateConnected, wlanIfaceStateAuthenticating} {
		assert.NoError(t, checkActiveConnection(st), "state %d", st)
	}
	for _, st := range []uint32{
		wlanIfaceStateNotReady, wlanIfaceStateDisconnected, wlanIfaceStateDisconnecting,
		wlanIfaceStateAssociating, wlanIfaceStateDiscovering, wlanIfaceStateAdHocFormed, 99,
	} {
		assert.ErrorIs(t, checkActiveConnection(st), errNoActiveConnection, "state %d", st)
	}
}

// While a connection is authenticating, wlanapi hasn't populated
// SecurityAttributes yet (OneXEnabled=0, observed live on Windows 11 25H2),
// so whether it's 802.1X must come from the profile's <useOneX>.
func TestWlanStatusAuthenticatingOneXFromProfile(t *testing.T) {
	t.Parallel()
	c := newFake(t, wlanIfaceStateAuthenticating, connAttrs(wlanIfaceStateAuthenticating, false, "PEAPNetwork"), readTestdata(t, "wlanprofile-peap-mschapv2.xml"))

	s, err := wlanStatus(c, testIface)
	require.NoError(t, err)
	assert.Equal(t, 2, s.State)
	assert.Equal(t, 3, s.SupplicantState, "Authenticating")
	assert.Equal(t, -1, s.ClientStatus)
	assert.Equal(t, 25, s.EAPType)
	assert.Equal(t, 26, s.InnerEAPType)
}

func TestWlanStatusAuthenticatingNotDot1X(t *testing.T) {
	t.Parallel()
	psk := `<WLANProfile><MSM><security><authEncryption><useOneX>false</useOneX></authEncryption></security></MSM></WLANProfile>`
	c := newFake(t, wlanIfaceStateAuthenticating, connAttrs(wlanIfaceStateAuthenticating, false, "Home"), psk)

	_, err := wlanStatus(c, testIface)
	assert.ErrorIs(t, err, errNotDot1X)
}

func TestWlanStatusAuthenticatingProfileUnavailable(t *testing.T) {
	t.Parallel()
	c := newFake(t, wlanIfaceStateAuthenticating, connAttrs(wlanIfaceStateAuthenticating, false, "PEAPNetwork"), readTestdata(t, "wlanprofile-peap-mschapv2.xml"))
	c.profileErr = errors.New("profile gone")

	_, err := wlanStatus(c, testIface)
	assert.ErrorIs(t, err, errNotDot1X, "can't confirm 802.1X without the flag or the profile")
}

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return string(b)
}

func TestDecodeSSIDClampsLength(t *testing.T) {
	t.Parallel()
	var d dot11SSID
	copy(d.SSID[:], "abc")
	d.SSIDLength = 99 // corrupt: longer than the 32-byte buffer
	assert.Equal(t, "abc"+string(make([]byte, 29)), ssidString(d))
	d.SSIDLength = 3
	assert.Equal(t, "abc", ssidString(d))
}
