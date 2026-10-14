package dot1x

// Tests for the pure-Go Windows event log + LAN profile logic
// (dot1x_winevents.go). No build tag: events are parsed from real exported
// fixtures (testdata/winevents) and fake clients stand in for wevtapi.dll,
// GetAdaptersAddresses and the dot3svc profile store.

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testWiredIface = "Realtek Gaming USB 2.5GbE Family Controller"
	// Adapter GUIDs come uppercase from GetAdaptersAddresses; the event log
	// fixtures carry them lowercase.
	testWiredGUID = "{77B9B334-D6F7-4314-A0B4-9BC86BD8FE97}"
)

func loadEvent(t *testing.T, name string) winEvent {
	t.Helper()
	e, err := parseWinEventXML(readTestdata(t, "winevents/"+name+".xml"))
	require.NoError(t, err)
	return e
}

// at returns e with its time moved to sec seconds past a fixed base, for
// building newest-first sequences independent of the fixtures' real times.
func at(e winEvent, sec int) winEvent {
	e.Time = time.Date(2026, 10, 3, 8, 0, sec, 0, time.UTC)
	return e
}

func wiredEvent(id int) winEvent {
	return winEvent{ID: id, Data: map[string]string{"InterfaceGuid": testWiredGUID}}
}

func testWired(t *testing.T) wiredIface {
	t.Helper()
	return wiredIface{
		guid:        testWiredGUID,
		description: testWiredIface,
		linkUp:      true,
		profileXML:  readTestdata(t, "lanprofile-eap-tls-machine.xml"),
	}
}

// wiredBase is the row every wired test starts from: profile-derived fields
// from lanprofile-eap-tls-machine.xml and unknown sentinels elsewhere.
func wiredBase() Dot1XStatus {
	return Dot1XStatus{
		Interface:            testWiredIface,
		InterfaceType:        "ethernet",
		State:                2,
		SupplicantState:      -1,
		EAPType:              13,
		ClientStatus:         -1,
		Mode:                 3,
		TLSSessionWasResumed: -1,
		TLSTrustedRootCASHA1: "58:34:c1:13:14:9c:fc:9b:9f:28:70:6f:db:e6:81:a4:78:19:a2:0e",
		ServerValidation:     "ca_only",
		TLSTrustClientStatus: -1,
		TLSNegotiatedCipher:  -1,
		InnerEAPType:         -1,
		UniqueIdentifier:     testWiredGUID,
	}
}

// --- parseWinEventXML ---

func TestParseWinEventXMLFixtures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		file string
		id   int
		time string
		data map[string]string
	}{
		{"wired-15502", 15502, "2026-10-03T07:40:42.9842918Z", map[string]string{"InterfaceGuid": "{77b9b334-d6f7-4314-a0b4-9bc86bd8fe97}", "ProfileType": "0"}},
		{"wired-15503", 15503, "2026-10-03T07:40:43.0562062Z", map[string]string{"ConnectionID": "0x3"}},
		{"wired-15505", 15505, "2026-10-03T07:40:43.3950832Z", map[string]string{"SwitchMAC": "8C3066A0FD33", "Identity": "host/host/DESKTOP-TEST01", "ReasonCode": "0x0"}},
		{"wired-15506", 15506, "2026-10-03T07:40:42.7795741Z", map[string]string{"ReasonCode": "Unable to identify a user for 802.1X authentication", "BlockingTime": "1200"}},
		{"wired-15507", 15507, "2026-10-03T07:40:42.9937703Z", map[string]string{"InterfaceDescription": testWiredIface}},
		{"wired-15511", 15511, "2026-10-03T07:40:42.6641646Z", map[string]string{}},
		{"wired-15514", 15514, "2026-10-03T07:40:42.7789247Z", map[string]string{"SwitchMAC": "000000000000", "ReasonCode": "0x50001", "ReasonText": "Unable to identify a user for 802.1X authentication", "ErrorCode": "0x525"}},
		{"wired-15515", 15515, "2026-10-03T07:40:42.6530785Z", map[string]string{}},
		{"wlan-12011", 12011, "2026-10-03T07:13:29.6017233Z", map[string]string{"DeviceGuid": "{9a82d898-7b57-40aa-a330-e2b99d10bd77}", "EapType": "21"}},
		{"wlan-12012", 12012, "2026-10-03T06:52:12.2387869Z", map[string]string{"SSID": "dot1x-test", "Identity": "dot1x-test"}},
		{"wlan-12013", 12013, "2026-10-03T07:08:16.4918452Z", map[string]string{"PeerMac": "2A:0B:8B:00:F2:34", "ReasonText": "Explicit Eap failure received", "ReasonCode": "0x50005", "EAPRootCauseString": ""}},
		{"wlan-12014", 12014, "2026-10-03T07:13:29.6017465Z", map[string]string{"EapType": "21", "RestartReason": "Msm Initiated"}},
		{"wlan-8001", 8001, "2026-10-03T07:14:30.5630059Z", map[string]string{"InterfaceGuid": "{9a82d898-7b57-40aa-a330-e2b99d10bd77}", "OnexEnabled": "0"}},
		{"wlan-8002", 8002, "2026-10-03T07:14:30.2756279Z", map[string]string{"FailureReason": "The specific network is not available.", "ReasonCode": "163851"}},
		{"wlan-8003", 8003, "2026-10-03T07:43:44.8278171Z", map[string]string{"ReasonCode": "5"}},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			e := loadEvent(t, tc.file)
			assert.Equal(t, tc.id, e.ID)
			want, err := time.Parse(time.RFC3339Nano, tc.time)
			require.NoError(t, err)
			assert.True(t, want.Equal(e.Time), "time %v", e.Time)
			assert.Equal(t, time.UTC, e.Time.Location())
			for k, v := range tc.data {
				got, ok := e.Data[k]
				assert.True(t, ok, "missing %s", k)
				assert.Equal(t, v, got, k)
			}
		})
	}
}

func TestParseWinEventXMLMultilineData(t *testing.T) {
	t.Parallel()
	e := loadEvent(t, "wired-15502")
	assert.Contains(t, e.Data["ProfileContent"], "802.1x: Enabled")
}

func TestParseWinEventXMLInvalid(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"",
		"not xml",
		`<Event><System><EventID>15505</EventID></System></Event>`,                                             // no time
		`<Event><System><EventID>x</EventID><TimeCreated SystemTime='2026-10-03T07:40:42Z'/></System></Event>`, // bad id
		`<Event><System><EventID>15505</EventID><TimeCreated SystemTime='yesterday'/></System></Event>`,        // bad time
	} {
		_, err := parseWinEventXML(in)
		assert.Error(t, err, "%q", in)
	}
}

func TestEventMAC(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "8c:30:66:a0:fd:33", eventMAC("8C3066A0FD33"))
	assert.Equal(t, "2a:0b:8b:00:f2:34", eventMAC("2A:0B:8B:00:F2:34"))
	assert.Equal(t, "2a:0b:8b:00:f2:34", eventMAC("2A-0B-8B-00-F2-34"))
	assert.Equal(t, "", eventMAC("000000000000"), "all zeros = unknown")
	assert.Equal(t, "", eventMAC(""))
	assert.Equal(t, "", eventMAC("-"))
	assert.Equal(t, "", eventMAC("8C3066A0FD"))
	assert.Equal(t, "", eventMAC("ZZ3066A0FD33"))
}

func TestDecodeProfileBytes(t *testing.T) {
	t.Parallel()
	const s = "<LANProfile>é</LANProfile>"
	u16 := utf16.Encode([]rune(s))
	le := []byte{0xFF, 0xFE}
	be := []byte{0xFE, 0xFF}
	for _, u := range u16 {
		le = append(le, byte(u), byte(u>>8))
		be = append(be, byte(u>>8), byte(u))
	}
	assert.Equal(t, s, decodeProfileBytes([]byte(s)))
	assert.Equal(t, s, decodeProfileBytes(append([]byte{0xEF, 0xBB, 0xBF}, s...)))
	assert.Equal(t, s, decodeProfileBytes(le))
	assert.Equal(t, s, decodeProfileBytes(be))
	assert.Equal(t, "", decodeProfileBytes(nil))
}

// --- wiredStatus ---

// The real sequence exported from the test box (a failure, the block timer,
// then a successful re-authentication), newest first.
func TestWiredStatusSuccessRealSequence(t *testing.T) {
	t.Parallel()
	events := []winEvent{
		loadEvent(t, "wired-15505"),
		loadEvent(t, "wired-15503"),
		loadEvent(t, "wired-15507"),
		loadEvent(t, "wired-15506"),
		loadEvent(t, "wired-15514"),
	}

	s, err := wiredStatus(testWired(t), events)
	require.NoError(t, err)
	want := wiredBase()
	want.SupplicantState = 4 // Authenticated
	want.ClientStatus = 0
	want.AuthenticatorMACAddress = "8c:30:66:a0:fd:33"
	want.LastStatusTimestamp = "2026-10-03T07:40:43Z"
	want.AuthenticatedSince = "2026-10-03T07:40:43Z"
	want.MACAddress = "9c:bf:0d:00:93:95"
	want.Identity = "host/host/DESKTOP-TEST01"
	assert.Equal(t, want, s)
}

func TestWiredStatusFailure(t *testing.T) {
	t.Parallel()

	s, err := wiredStatus(testWired(t), []winEvent{loadEvent(t, "wired-15514")})
	require.NoError(t, err)
	want := wiredBase()
	want.SupplicantState = 5 // Held
	want.ClientStatus = 1    // Failed
	want.FailureReason = "Unable to identify a user for 802.1X authentication"
	want.FailureCode = "0x50001"
	want.LastStatusTimestamp = "2026-10-03T07:40:42Z"
	want.MACAddress = "9c:bf:0d:00:93:95" // Identity "-" is empty
	assert.Equal(t, want, s, "SwitchMAC 000000000000 is unknown, not a MAC")
}

func TestWiredStatusFailureWithAuthenticator(t *testing.T) {
	t.Parallel()
	e := loadEvent(t, "wired-15514")
	e.Data["SwitchMAC"] = "8C3066A0FD33"

	s, err := wiredStatus(testWired(t), []winEvent{e})
	require.NoError(t, err)
	assert.Equal(t, 5, s.SupplicantState)
	assert.Equal(t, "8c:30:66:a0:fd:33", s.AuthenticatorMACAddress)
}

func TestWiredStatusSuspended(t *testing.T) {
	t.Parallel()

	s, err := wiredStatus(testWired(t), []winEvent{loadEvent(t, "wired-15506"), loadEvent(t, "wired-15514")})
	require.NoError(t, err)
	want := wiredBase()
	want.SupplicantState = 5 // Held
	want.ClientStatus = 1    // Failed
	want.FailureReason = "Unable to identify a user for 802.1X authentication"
	want.FailureCode = "0x50001"
	want.LastStatusTimestamp = "2026-10-03T07:40:42Z"
	want.MACAddress = "9c:bf:0d:00:93:95"
	assert.Equal(t, want, s)
}

func TestWiredStatusSuspendedWithoutFailure(t *testing.T) {
	t.Parallel()

	s, err := wiredStatus(testWired(t), []winEvent{loadEvent(t, "wired-15506")})
	require.NoError(t, err)
	assert.Equal(t, 5, s.SupplicantState)
	assert.Empty(t, s.FailureReason)
	assert.Empty(t, s.FailureCode)
	assert.Equal(t, "2026-10-03T07:40:42Z", s.LastStatusTimestamp)
}

// 15507 (resumed) carries no state of its own: the event before it decides.
func TestWiredStatusResumedUsesPriorEvent(t *testing.T) {
	t.Parallel()

	s, err := wiredStatus(testWired(t), []winEvent{
		loadEvent(t, "wired-15507"), loadEvent(t, "wired-15506"), loadEvent(t, "wired-15514"),
	})
	require.NoError(t, err)
	assert.Equal(t, 5, s.SupplicantState)
	assert.Equal(t, "0x50001", s.FailureCode)

	s, err = wiredStatus(testWired(t), []winEvent{loadEvent(t, "wired-15507")})
	require.NoError(t, err)
	assert.Equal(t, -1, s.SupplicantState, "only 15507: unknown")
}

func TestWiredStatusAuthenticating(t *testing.T) {
	t.Parallel()

	for _, id := range []int{15503, 15504} {
		s, err := wiredStatus(testWired(t), []winEvent{at(wiredEvent(id), 5), at(wiredEvent(15514), 1)})
		require.NoError(t, err)
		assert.Equal(t, 2, s.State)
		assert.Equal(t, 3, s.SupplicantState, "event %d", id)
		assert.Equal(t, -1, s.ClientStatus)
		assert.Empty(t, s.FailureReason)
		assert.Equal(t, "2026-10-03T08:00:05Z", s.LastStatusTimestamp)
		assert.Empty(t, s.AuthenticatedSince, "not authenticated")
	}

	// The start event's client MAC/identity, when it carries them.
	e := at(wiredEvent(15503), 5)
	e.Data["LocalMAC"], e.Data["Identity"] = "9CBF0D009395", "host/DESKTOP-TEST01"
	s, err := wiredStatus(testWired(t), []winEvent{e, at(loadEvent(t, "wired-15505"), 1)})
	require.NoError(t, err)
	assert.Equal(t, "9c:bf:0d:00:93:95", s.MACAddress)
	assert.Equal(t, "host/DESKTOP-TEST01", s.Identity)
	assert.Empty(t, s.AuthenticatedSince)
}

func TestWiredStatusUnplugged(t *testing.T) {
	t.Parallel()

	_, err := wiredStatus(testWired(t), []winEvent{at(wiredEvent(15500), 9), loadEvent(t, "wired-15505")})
	assert.ErrorIs(t, err, errNoActiveConnection)
}

func TestWiredStatusLinkDown(t *testing.T) {
	t.Parallel()
	w := testWired(t)
	w.linkUp = false

	_, err := wiredStatus(w, []winEvent{loadEvent(t, "wired-15505")})
	assert.ErrorIs(t, err, errNoActiveConnection)
}

func TestWiredStatusNoEvents(t *testing.T) {
	t.Parallel()

	s, err := wiredStatus(testWired(t), nil)
	require.NoError(t, err)
	assert.Equal(t, wiredBase(), s)
}

// Events for other adapters are ignored; matching is case-insensitive.
func TestWiredStatusFiltersByGUID(t *testing.T) {
	t.Parallel()
	other := loadEvent(t, "wired-15514")
	other.Data = map[string]string{"InterfaceGuid": "{00000000-0000-0000-0000-000000000001}", "ReasonCode": "0x1"}

	s, err := wiredStatus(testWired(t), []winEvent{other})
	require.NoError(t, err)
	assert.Equal(t, wiredBase(), s)

	w := testWired(t)
	w.guid = "{77b9b334-d6f7-4314-a0b4-9bc86bd8fe97}"
	s, err = wiredStatus(w, []winEvent{other, loadEvent(t, "wired-15505")})
	require.NoError(t, err)
	assert.Equal(t, 4, s.SupplicantState)
	assert.Equal(t, testWiredGUID, s.UniqueIdentifier, "GUID normalised to uppercase like WLAN")
}

func TestWiredStatusNotDot1X(t *testing.T) {
	t.Parallel()

	for _, profile := range []string{
		"",
		`<LANProfile><MSM><security><OneXEnforced>false</OneXEnforced><OneXEnabled>false</OneXEnabled></security></MSM></LANProfile>`,
	} {
		w := testWired(t)
		w.profileXML = profile
		_, err := wiredStatus(w, []winEvent{loadEvent(t, "wired-15505")})
		assert.ErrorIs(t, err, errNotDot1X)
	}
}

func TestWiredStatusDefaultOneXEnabled(t *testing.T) {
	t.Parallel()
	w := testWired(t)
	w.profileXML = strings.Replace(w.profileXML, "<OneXEnabled>true</OneXEnabled>", "", 1)
	require.NotContains(t, w.profileXML, "OneXEnabled")
	s, err := wiredStatus(w, []winEvent{loadEvent(t, "wired-15505")})
	require.NoError(t, err)
	assert.Equal(t, 4, s.SupplicantState)
	assert.Equal(t, 13, s.EAPType)
}

// --- WLAN events ---

func TestWlanStatusIdleFailureRow(t *testing.T) {
	t.Parallel()
	c := newFake(t, wlanIfaceStateDisconnected, connAttrs(wlanIfaceStateDisconnected, true, "Campus"), sampleProfileXML)
	c.events = []winEvent{loadEvent(t, "wlan-12013"), loadEvent(t, "wlan-12011")}

	s, err := wlanStatus(c, testIface)
	require.NoError(t, err)
	assert.Equal(t, Dot1XStatus{
		Interface:               testIface,
		InterfaceType:           "wifi",
		SSID:                    "dot1x-test",
		State:                   0, // Idle
		SupplicantState:         5, // Held
		EAPType:                 -1,
		ClientStatus:            1, // Failed
		AuthenticatorMACAddress: "2a:0b:8b:00:f2:34",
		MACAddress:              "2c:9c:58:29:12:75",
		Identity:                "anonymous",
		Mode:                    -1,
		TLSSessionWasResumed:    -1,
		TLSTrustClientStatus:    -1,
		TLSNegotiatedCipher:     -1,
		InnerEAPType:            -1,
		LastStatusTimestamp:     "2026-10-03T07:08:16Z",
		UniqueIdentifier:        "{9A82D898-7B57-40AA-A330-E2B99D10BD77}",
		FailureReason:           "Explicit Eap failure received",
		FailureCode:             "0x50005",
		FailureEAPCode:          "0x80420015",
	}, s)
	assert.Zero(t, c.connCalls)
}

// The failure is stale once a newer connect/disconnect/auth event exists.
func TestWlanStatusIdleNewerEventClearsFailure(t *testing.T) {
	t.Parallel()

	for _, newer := range []string{"wlan-8001", "wlan-8003", "wlan-12011", "wlan-12012"} {
		e := loadEvent(t, newer)
		e.Time = loadEvent(t, "wlan-12013").Time.Add(time.Minute)
		c := newFake(t, wlanIfaceStateDisconnected, connAttrs(wlanIfaceStateDisconnected, true, "Campus"), sampleProfileXML)
		c.events = []winEvent{e, loadEvent(t, "wlan-12013")}

		_, err := wlanStatus(c, testIface)
		assert.ErrorIs(t, err, errNoActiveConnection, newer)
	}
}

// Irrelevant IDs (8002, 12014) don't count as "newer".
func TestWlanStatusIdleIgnoresOtherIDs(t *testing.T) {
	t.Parallel()
	c := newFake(t, wlanIfaceStateDisconnected, connAttrs(wlanIfaceStateDisconnected, true, "Campus"), sampleProfileXML)
	c.events = []winEvent{loadEvent(t, "wlan-8002"), loadEvent(t, "wlan-12014"), loadEvent(t, "wlan-12013")}

	s, err := wlanStatus(c, testIface)
	require.NoError(t, err)
	assert.Equal(t, 5, s.SupplicantState)
}

func TestWlanStatusIdleOtherAdapterFailure(t *testing.T) {
	t.Parallel()
	e := loadEvent(t, "wlan-12013")
	e.Data["DeviceGuid"] = "{00000000-0000-0000-0000-000000000001}"
	c := newFake(t, wlanIfaceStateDisconnected, connAttrs(wlanIfaceStateDisconnected, true, "Campus"), sampleProfileXML)
	c.events = []winEvent{e}

	_, err := wlanStatus(c, testIface)
	assert.ErrorIs(t, err, errNoActiveConnection)
}

func TestWlanStatusIdleEventsError(t *testing.T) {
	t.Parallel()
	c := newFake(t, wlanIfaceStateDisconnected, connAttrs(wlanIfaceStateDisconnected, true, "Campus"), sampleProfileXML)
	c.events = []winEvent{loadEvent(t, "wlan-12013")}
	c.eventsErr = errors.New("access denied")

	_, err := wlanStatus(c, testIface)
	assert.ErrorIs(t, err, errNoActiveConnection)
}

// The connection query can also report disconnected after enumeration said
// connected; the failure row applies there too.
func TestWlanStatusDisconnectedAfterEnumFailureRow(t *testing.T) {
	t.Parallel()
	c := newFake(t, wlanIfaceStateConnected, connAttrs(wlanIfaceStateDisconnected, true, "Campus"), sampleProfileXML)
	c.events = []winEvent{loadEvent(t, "wlan-12013")}

	s, err := wlanStatus(c, testIface)
	require.NoError(t, err)
	assert.Equal(t, 0, s.State)
	assert.Equal(t, 5, s.SupplicantState)
	assert.Empty(t, s.TLSTrustedRootCASHA1, "no profile fields on a failure row")
}

func TestWlanStatusConnectedTimestamp(t *testing.T) {
	t.Parallel()
	c := newFake(t, wlanIfaceStateConnected, connAttrs(wlanIfaceStateConnected, true, "Campus"), sampleProfileXML)
	c.events = []winEvent{loadEvent(t, "wlan-8001"), loadEvent(t, "wlan-12012"), loadEvent(t, "wlan-12013")}

	s, err := wlanStatus(c, testIface)
	require.NoError(t, err)
	assert.Equal(t, 4, s.SupplicantState)
	assert.Equal(t, "2026-10-03T06:52:12Z", s.LastStatusTimestamp)
	assert.Equal(t, "2026-10-03T06:52:12Z", s.AuthenticatedSince)
	assert.Equal(t, "2c:9c:58:29:12:75", s.MACAddress)
	assert.Equal(t, "dot1x-test", s.Identity)
	assert.Empty(t, s.FailureReason)
}

// Mid-authentication the start event (12011) gives the client MAC; there is
// no success yet, so no authenticated_since.
func TestWlanStatusAuthenticatingClientMAC(t *testing.T) {
	t.Parallel()
	c := newFake(t, wlanIfaceStateAuthenticating, connAttrs(wlanIfaceStateAuthenticating, true, "Campus"), sampleProfileXML)
	start := loadEvent(t, "wlan-12011")
	start.Time = loadEvent(t, "wlan-12012").Time.Add(time.Hour)
	c.events = []winEvent{start, loadEvent(t, "wlan-12012")}

	s, err := wlanStatus(c, testIface)
	require.NoError(t, err)
	assert.Equal(t, 3, s.SupplicantState)
	assert.Equal(t, "2c:9c:58:29:12:75", s.MACAddress)
	assert.Empty(t, s.Identity, "12011 carries no Identity")
	assert.Empty(t, s.AuthenticatedSince)
	assert.Empty(t, s.LastStatusTimestamp)
}

func TestWlanStatusConnectedEventsError(t *testing.T) {
	t.Parallel()
	c := newFake(t, wlanIfaceStateConnected, connAttrs(wlanIfaceStateConnected, true, "Campus"), sampleProfileXML)
	c.eventsErr = errors.New("access denied")

	s, err := wlanStatus(c, testIface)
	require.NoError(t, err)
	assert.Equal(t, 4, s.SupplicantState)
	assert.Empty(t, s.LastStatusTimestamp)
	assert.Empty(t, s.AuthenticatedSince)
	assert.Empty(t, s.MACAddress)
}

// --- routing (WLAN + wired) ---

type fakeWiredClient struct {
	ifaces    []wiredIface
	ifErr     error
	events    []winEvent
	eventsErr error
}

func (f *fakeWiredClient) wiredInterfaces() ([]wiredIface, error) { return f.ifaces, f.ifErr }
func (f *fakeWiredClient) wiredEvents() ([]winEvent, error)       { return f.events, f.eventsErr }

func TestWindowsInterfaceNames(t *testing.T) {
	t.Parallel()
	w := newFake(t, wlanIfaceStateConnected, connAttrs(wlanIfaceStateConnected, true, "Campus"), sampleProfileXML)
	d := &fakeWiredClient{ifaces: []wiredIface{testWired(t)}}

	assert.Equal(t, []string{testIface, testWiredIface}, windowsInterfaceNames(w, d))
}

func TestWindowsInterfaceNamesWlanUnavailable(t *testing.T) {
	t.Parallel()
	w := &fakeWlanClient{enumErr: errors.New("wlansvc stopped")}
	d := &fakeWiredClient{ifaces: []wiredIface{testWired(t)}}

	assert.Equal(t, []string{testWiredIface}, windowsInterfaceNames(w, d))

	d.ifErr, d.ifaces = errors.New("GetAdaptersAddresses failed"), nil
	assert.Nil(t, windowsInterfaceNames(w, d), "both sources failed: defaults unknown")
}

func TestWindowsInterfaceNamesNoAdapters(t *testing.T) {
	t.Parallel()
	w := &fakeWlanClient{ifaces: map[string]ifaceInfo{}}
	d := &fakeWiredClient{}

	names := windowsInterfaceNames(w, d)
	assert.NotNil(t, names, "enumerated, nothing found: authoritative empty")
	assert.Empty(t, names)
}

func TestWindowsStatusRoutes(t *testing.T) {
	t.Parallel()
	w := newFake(t, wlanIfaceStateConnected, connAttrs(wlanIfaceStateConnected, true, "Campus"), sampleProfileXML)
	d := &fakeWiredClient{ifaces: []wiredIface{testWired(t)}, events: []winEvent{loadEvent(t, "wired-15505")}}

	s, err := windowsStatus(w, d, testIface)
	require.NoError(t, err)
	assert.Equal(t, "{9A82D898-7B57-40AA-A330-E2B99D10BD77}", s.UniqueIdentifier)

	s, err = windowsStatus(w, d, testWiredIface)
	require.NoError(t, err)
	assert.Equal(t, testWiredGUID, s.UniqueIdentifier)
	assert.Equal(t, 4, s.SupplicantState)

	s, err = windowsStatus(w, d, "nope")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrBackendUnavailable)
	assert.Contains(t, err.Error(), "nope")
	assert.Equal(t, "nope", s.Interface)
}

func TestWindowsStatusWiredWithoutWlan(t *testing.T) {
	t.Parallel()
	w := &fakeWlanClient{enumErr: errors.New("wlanapi.dll not found")}
	d := &fakeWiredClient{ifaces: []wiredIface{testWired(t)}, events: []winEvent{loadEvent(t, "wired-15505")}}

	s, err := windowsStatus(w, d, testWiredIface)
	require.NoError(t, err)
	assert.Equal(t, 4, s.SupplicantState)

	_, err = windowsStatus(w, d, "nope")
	assert.NotErrorIs(t, err, ErrBackendUnavailable, "wired still works")
}

func TestWindowsStatusBothUnavailable(t *testing.T) {
	t.Parallel()
	wlanErr := errors.New("wlanapi.dll not found")
	wiredErr := errors.New("GetAdaptersAddresses failed")
	w := &fakeWlanClient{enumErr: wlanErr}
	d := &fakeWiredClient{ifErr: wiredErr}

	_, err := windowsStatus(w, d, testWiredIface)
	assert.ErrorIs(t, err, ErrBackendUnavailable)
	assert.ErrorIs(t, err, wlanErr)
	assert.ErrorIs(t, err, wiredErr)
}

func TestWindowsStatusWiredEventsError(t *testing.T) {
	t.Parallel()
	w := &fakeWlanClient{ifaces: map[string]ifaceInfo{}}
	d := &fakeWiredClient{ifaces: []wiredIface{testWired(t)}, eventsErr: errors.New("access denied")}

	s, err := windowsStatus(w, d, testWiredIface)
	require.NoError(t, err)
	assert.Equal(t, wiredBase(), s)
}

// Observed live (wired reject on Windows 11 25H2): ReasonText can contain
// both a literal "\n" and real line breaks. Failures also set client_status
// to Failed (1) so client_status_name = 'Failed' matches on both platforms.
func TestApplyFailureNormalizes(t *testing.T) {
	t.Parallel()

	var s Dot1XStatus
	applyFailure(&s, winEvent{ID: 15514, Data: map[string]string{
		"ReasonText": "Network authentication failed\\nWindows doesn't have the required authentication method to connect to this network.\r\n",
		"ReasonCode": "0x50005",
	}})
	assert.Equal(t, "Network authentication failed; Windows doesn't have the required authentication method to connect to this network.", s.FailureReason)
	assert.Equal(t, "0x50005", s.FailureCode)
	assert.Equal(t, 1, s.ClientStatus)
	assert.Equal(t, "Failed", rowFromStatus(s)["client_status_name"])
}

// A failed Wi-Fi side must not be hidden by a wired side that merely found
// nothing: the query would look like "no 802.1X here" instead of failing.
func TestWindowsWlanErrorNotHiddenByEmptyWired(t *testing.T) {
	t.Parallel()
	w := &fakeWlanClient{enumErr: errors.New("wlansvc stopped")}
	d := &fakeWiredClient{ifaces: []wiredIface{}}

	assert.Nil(t, windowsInterfaceNames(w, d), "defaults unknown, so the caller probes and gets the error")
	_, err := windowsStatus(w, d, "en0")
	assert.ErrorIs(t, err, ErrBackendUnavailable)
}

// Only a disconnected adapter reports its last failure. During a retry
// (associating/discovering) or with Wi-Fi off (not ready), an old 12013
// would be stale.
func TestWlanIdleFailureOnlyWhenDisconnected(t *testing.T) {
	t.Parallel()
	fail := loadEvent(t, "wlan-12013")
	for _, st := range []uint32{wlanIfaceStateAssociating, wlanIfaceStateDiscovering, wlanIfaceStateNotReady, wlanIfaceStateDisconnecting} {
		c := newFake(t, st, connAttrs(st, false, ""), "")
		c.events = []winEvent{fail}
		_, err := wlanStatus(c, testIface)
		assert.ErrorIs(t, err, errNoActiveConnection, "state %d", st)
	}
}

// 12013 (and 15514 on builds that log them) carry the EAP method's own
// result: EAPReasonCode goes to failure_eap_code and a non-empty
// EAPRootCauseString is appended to failure_reason.
func TestApplyFailureEAPRootCause(t *testing.T) {
	t.Parallel()

	var s Dot1XStatus
	applyFailure(&s, loadEvent(t, "wlan-12013"))
	assert.Equal(t, "0x80420015", s.FailureEAPCode)
	assert.Equal(t, "Explicit Eap failure received", s.FailureReason, "empty root cause adds nothing")
	assert.Equal(t, "0x50005", s.FailureCode)

	s = Dot1XStatus{}
	applyFailure(&s, loadEvent(t, "wired-15514"))
	assert.Empty(t, s.FailureEAPCode, "field absent")

	s = Dot1XStatus{}
	applyFailure(&s, winEvent{ID: evWlanAuthFailed, Data: map[string]string{
		"ReasonText":         "Explicit Eap failure received",
		"ReasonCode":         "0x50005",
		"EAPReasonCode":      "0x0",
		"EAPRootCauseString": "The server certificate is not trusted.\nCheck the trusted root CA.\r\n",
	}})
	assert.Empty(t, s.FailureEAPCode, "0x0 means no EAP reason")
	assert.Equal(t, "Explicit Eap failure received; The server certificate is not trusted.; Check the trusted root CA.", s.FailureReason)
}

// A wired adapter whose description matches a WLAN adapter's must not be
// swallowed by the WLAN one: it is renamed "<description> <GUID>" (like
// duplicate adapters from one source) and that name routes to it.
func TestWindowsInterfaceNameCollision(t *testing.T) {
	t.Parallel()
	w := newFake(t, wlanIfaceStateConnected, connAttrs(wlanIfaceStateConnected, true, "Campus"), sampleProfileXML)
	clash := testWired(t)
	clash.description = testIface
	d := &fakeWiredClient{ifaces: []wiredIface{clash}, events: []winEvent{loadEvent(t, "wired-15505")}}
	wiredName := testIface + " " + testWiredGUID

	assert.Equal(t, []string{testIface, wiredName}, windowsInterfaceNames(w, d))

	s, err := windowsStatus(w, d, testIface)
	require.NoError(t, err)
	assert.Equal(t, "wifi", s.InterfaceType)

	s, err = windowsStatus(w, d, wiredName)
	require.NoError(t, err)
	assert.Equal(t, "ethernet", s.InterfaceType)
	assert.Equal(t, wiredName, s.Interface)
	assert.Equal(t, testWiredGUID, s.UniqueIdentifier)

	// Without the WLAN adapter there is no clash: the plain name is kept.
	w = &fakeWlanClient{ifaces: map[string]ifaceInfo{}}
	assert.Equal(t, []string{testIface}, windowsInterfaceNames(w, d))
	_, err = windowsStatus(w, d, testIface)
	require.NoError(t, err)
}
