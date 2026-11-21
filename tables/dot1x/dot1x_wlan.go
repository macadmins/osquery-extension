package dot1x

// Pure-Go Windows WLAN status logic. The wlanapi.dll syscalls live in
// dot1x_windows.go behind the wlanClient interface; everything that decodes
// and interprets their results lives here (no build tag) so it is compiled
// and unit-tested with a fake client on every platform.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

// WLAN_INTERFACE_STATE values.
const (
	wlanIfaceStateNotReady       uint32 = 0
	wlanIfaceStateConnected      uint32 = 1
	wlanIfaceStateAdHocFormed    uint32 = 2
	wlanIfaceStateDisconnecting  uint32 = 3
	wlanIfaceStateDisconnected   uint32 = 4
	wlanIfaceStateAssociating    uint32 = 5
	wlanIfaceStateDiscovering    uint32 = 6
	wlanIfaceStateAuthenticating uint32 = 7
)

type windowsGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

func (g windowsGUID) String() string {
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1],
		g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])
}

// The structs below mirror the Windows ABI layout of WLAN_CONNECTION_ATTRIBUTES
// and its members (all fields 4-byte aligned, explicit padding, no trailing
// padding), so binary.Size == unsafe.Sizeof == 604 bytes.

type dot11SSID struct {
	SSIDLength uint32
	SSID       [32]byte
}

type wlanAssociationAttributes struct {
	Dot11Ssid         dot11SSID
	Dot11BssType      uint32
	Dot11Bssid        [6]byte
	_                 [2]byte // align to 4-byte boundary
	Dot11PhyType      uint32
	Dot11PhyIndex     uint32
	WlanSignalQuality uint32
	RxRate            uint32
	TxRate            uint32
}

type wlanSecurityAttributes struct {
	SecurityEnabled int32
	OneXEnabled     int32
	AuthAlgorithm   uint32
	CipherAlgorithm uint32
}

type wlanConnectionAttributes struct {
	IsState               uint32
	ConnectionMode        uint32
	ProfileName           [256]uint16
	AssociationAttributes wlanAssociationAttributes
	SecurityAttributes    wlanSecurityAttributes
}

// ifaceInfo is the per-interface data captured from a single
// WlanEnumInterfaces call: its GUID (stable) and current state.
type ifaceInfo struct {
	guid  windowsGUID
	state uint32
}

// wlanClient is the wlanapi.dll surface wlanStatus needs. The Windows backend
// implements it with syscalls; tests use a fake.
type wlanClient interface {
	// interfaces returns a description->info map and the descriptions in
	// enumeration order.
	interfaces() (map[string]ifaceInfo, []string, error)
	// currentConnection returns the raw WLAN_CONNECTION_ATTRIBUTES buffer.
	currentConnection(guid windowsGUID) ([]byte, error)
	// profileXML returns the named profile's XML.
	profileXML(guid windowsGUID, name string) (string, error)
	// wlanEvents returns WLAN-AutoConfig/Operational events (wlanEventIDs),
	// newest first. Errors are treated as no events.
	wlanEvents() ([]winEvent, error)
}

// errNoActiveConnection is returned by GetStatus for an adapter that is not
// connected or authenticating; like macOS, idle adapters produce no row.
var errNoActiveConnection = errors.New("no active WLAN connection")

// errNotDot1X is returned by GetStatus for a WLAN connection that is not
// using 802.1X (open/PSK/SAE), so generateRows skips the interface like macOS.
var errNotDot1X = errors.New("802.1X not enabled on current WLAN connection")

// decodeConnectionAttributes decodes a WLAN_CONNECTION_ATTRIBUTES buffer,
// rejecting a short one (version differences / unexpected value type /
// corrupt response).
func decodeConnectionAttributes(b []byte) (wlanConnectionAttributes, error) {
	var a wlanConnectionAttributes
	if want := binary.Size(a); len(b) < want {
		return a, fmt.Errorf("got %d bytes, want >= %d", len(b), want)
	}
	err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &a)
	return a, err
}

// wlanStatus builds the 802.1X status for ifname from c.
func wlanStatus(c wlanClient, ifname string) (Dot1XStatus, error) {
	infos, _, err := c.interfaces()
	if err != nil {
		// Enumeration failing is systemic (affects every interface), so report
		// it as backend-unavailable rather than a per-interface miss. Both are
		// wrapped (%w) so errors.Is(ErrBackendUnavailable) holds and the
		// underlying error stays introspectable.
		return Dot1XStatus{Interface: ifname}, fmt.Errorf("%w: %w", ErrBackendUnavailable, err)
	}
	info, ok := infos[ifname]
	if !ok {
		return Dot1XStatus{Interface: ifname}, fmt.Errorf("wireless interface %q not found", ifname)
	}

	s := Dot1XStatus{
		Interface:            ifname,
		InterfaceType:        "wifi",
		UniqueIdentifier:     info.guid.String(),
		ClientStatus:         -1,
		Mode:                 -1,
		TLSTrustClientStatus: -1,
		TLSNegotiatedCipher:  -1,
		InnerEAPType:         -1,
		EAPType:              -1,
		TLSSessionWasResumed: -1,
	}
	s.State, s.SupplicantState = mapWlanState(info.state)

	// Gate on the enumeration state to avoid querying idle adapters. An idle
	// adapter still gets a row if its last 802.1X attempt failed.
	if checkActiveConnection(info.state) != nil {
		return wlanIdleStatus(c, s, info.state)
	}

	// The interface reports connected/authenticating, so a failed or empty
	// current-connection query would leave a misleading "successful" row
	// missing MAC/EAP/profile data. Return a per-interface error so
	// generateRows skips it rather than emitting a partial row.
	buf, err := c.currentConnection(info.guid)
	if err != nil {
		return s, fmt.Errorf("WlanQueryInterface(current_connection) failed for %q: %w", ifname, err)
	}
	if len(buf) == 0 {
		return s, fmt.Errorf("WlanQueryInterface(current_connection) returned no data for %q", ifname)
	}
	conn, err := decodeConnectionAttributes(buf)
	if err != nil {
		return s, fmt.Errorf("WlanQueryInterface(current_connection) for %q: %w", ifname, err)
	}

	// The connection's own state is fresher than the enumeration snapshot
	// (auth may have completed in between), so it decides from here on.
	s.State, s.SupplicantState = mapWlanState(conn.IsState)
	if checkActiveConnection(conn.IsState) != nil {
		return wlanIdleStatus(c, s, conn.IsState)
	}

	s.AuthenticatorMACAddress = macAddrString(conn.AssociationAttributes.Dot11Bssid[:])
	s.SSID = ssidString(conn.AssociationAttributes.Dot11Ssid)

	// The profile is fetched lazily and at most once. A fetch failure is
	// non-fatal: the row is still valid without the profile-derived fields.
	profileName := utf16ToString(conn.ProfileName[:])
	s.ProfileName = profileName
	var profile wlanProfileInfo
	haveProfile, fetched := false, false
	loadProfile := func() bool {
		if !fetched && profileName != "" {
			fetched = true
			if xmlStr, err := c.profileXML(info.guid, profileName); err == nil {
				profile, haveProfile = parseWLANProfile(xmlStr), true
			}
		}
		return haveProfile
	}

	// wlanapi only fills SecurityAttributes once the connection completes
	// (OneXEnabled is 0 while authenticating), so mid-authentication the
	// profile's <useOneX> decides whether this is an 802.1X connection.
	oneX := conn.SecurityAttributes.OneXEnabled != 0
	if !oneX && conn.IsState == wlanIfaceStateAuthenticating && loadProfile() {
		oneX = profile.useOneX
	}
	if err := applyOneXSecurity(&s, conn.IsState, oneX); err != nil {
		return s, err
	}
	applyWlanEvents(c, &s, conn.IsState)

	if loadProfile() {
		applyProfile(&s, profile)
	}
	return s, nil
}

// applyProfile copies the 802.1X fields of a parsed WLAN/LAN profile into s.
func applyProfile(s *Dot1XStatus, profile wlanProfileInfo) {
	if profile.eapType > 0 {
		s.EAPType = profile.eapType
	}
	if profile.authMode >= 0 {
		s.Mode = profile.authMode
	}
	if profile.innerEAPType > 0 {
		s.InnerEAPType = profile.innerEAPType
	}
	// These are the configured trusted root CA thumbprints (server
	// validation), not the presented server certificate's fingerprint, so they
	// go in TLSTrustedRootCASHA1 rather than TLSServerCertificateSHA1 (which
	// macOS fills with the actual chain).
	if profile.trustedRootCASHA1 != "" {
		s.TLSTrustedRootCASHA1 = profile.trustedRootCASHA1
	}
	s.TLSTrustedServerNames = profile.trustedServerNames
	s.ServerValidation = profile.serverValidation
}

// checkActiveConnection returns errNoActiveConnection unless ifState is
// connected or authenticating.
func checkActiveConnection(ifState uint32) error {
	if ifState != wlanIfaceStateConnected && ifState != wlanIfaceStateAuthenticating {
		return errNoActiveConnection
	}
	return nil
}

// applyOneXSecurity applies the connection's 802.1X security state to s. It
// returns errNotDot1X when 802.1X is not enabled; when connected it marks the
// supplicant Authenticated with ClientStatus success.
func applyOneXSecurity(s *Dot1XStatus, ifState uint32, oneXEnabled bool) error {
	if !oneXEnabled {
		return errNotDot1X
	}
	if ifState == wlanIfaceStateConnected {
		s.SupplicantState = 4 // Authenticated
		s.ClientStatus = 0
	}
	return nil
}

// mapWlanState maps WLAN_INTERFACE_STATE to (EAPOLControlState, SupplicantState).
func mapWlanState(state uint32) (int, int) {
	switch state {
	case wlanIfaceStateConnected:
		return 2, 4 // Running, Authenticated
	case wlanIfaceStateAuthenticating:
		return 2, 3 // Running, Authenticating
	case wlanIfaceStateAssociating:
		return 1, 1 // Starting, Connecting
	case wlanIfaceStateDiscovering:
		return 1, 2 // Starting, Acquired
	case wlanIfaceStateDisconnecting:
		return 3, 6 // Stopping, Logoff
	case wlanIfaceStateDisconnected:
		return 0, 0 // Idle, Disconnected
	case wlanIfaceStateNotReady:
		return 0, 7 // Idle, Inactive
	default:
		return 0, 0
	}
}

// utf16ToString decodes a NUL-terminated (or full-length) UTF-16 buffer.
func utf16ToString(s []uint16) string {
	for i, v := range s {
		if v == 0 {
			s = s[:i]
			break
		}
	}
	return string(utf16.Decode(s))
}

// ssidString returns the SSID bytes, clamping a corrupt length to the buffer.
func ssidString(d dot11SSID) string {
	n := min(int(d.SSIDLength), len(d.SSID))
	return string(d.SSID[:n])
}
