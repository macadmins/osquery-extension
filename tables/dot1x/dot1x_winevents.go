package dot1x

// Pure-Go Windows event log and wired (Ethernet) 802.1X logic. The wevtapi.dll
// queries, adapter enumeration and dot3svc profile reads live in
// dot1x_windows.go behind the wiredClient / wlanClient interfaces; everything
// that interprets their results lives here (no build tag) so it is compiled
// and unit-tested with fakes and real exported events on every platform.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// Wired-AutoConfig (155xx) and WLAN-AutoConfig (80xx/120xx) Operational
// channel event IDs.
const (
	evWiredUnplugged    = 15500
	evWiredAuthStarted  = 15503
	evWiredAuthRestart  = 15504
	evWiredAuthSuccess  = 15505
	evWiredAuthSuspend  = 15506
	evWiredAuthResumed  = 15507
	evWiredAuthFailed   = 15514
	evWlanConnected     = 8001
	evWlanDisconnected  = 8003
	evWlanAuthStarted   = 12011
	evWlanAuthSucceeded = 12012
	evWlanAuthFailed    = 12013
)

// Event IDs each channel is queried for (see dot1x_windows.go).
var (
	wiredEventIDs = []int{evWiredUnplugged, evWiredAuthStarted, evWiredAuthRestart, evWiredAuthSuccess, evWiredAuthSuspend, evWiredAuthResumed, evWiredAuthFailed}
	wlanEventIDs  = []int{evWlanConnected, evWlanDisconnected, evWlanAuthStarted, evWlanAuthSucceeded, evWlanAuthFailed}
)

// winEvent is one event log record as rendered by EvtRender(EvtRenderEventXml).
type winEvent struct {
	ID   int
	Time time.Time         // UTC
	Data map[string]string // EventData/Data@Name -> text
}

// parseWinEventXML parses a single rendered event.
func parseWinEventXML(s string) (winEvent, error) {
	var x struct {
		EventID     string `xml:"System>EventID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"System>TimeCreated"`
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"EventData>Data"`
	}
	if err := xml.Unmarshal([]byte(s), &x); err != nil {
		return winEvent{}, fmt.Errorf("parsing event XML: %w", err)
	}
	id, err := strconv.Atoi(strings.TrimSpace(x.EventID))
	if err != nil {
		return winEvent{}, fmt.Errorf("parsing EventID %q: %w", x.EventID, err)
	}
	t, err := time.Parse(time.RFC3339Nano, x.TimeCreated.SystemTime)
	if err != nil {
		return winEvent{}, fmt.Errorf("parsing TimeCreated %q: %w", x.TimeCreated.SystemTime, err)
	}
	e := winEvent{ID: id, Time: t.UTC(), Data: make(map[string]string, len(x.Data))}
	for _, d := range x.Data {
		e.Data[d.Name] = d.Value
	}
	return e, nil
}

// newestFor returns the first (newest) event in newest-first events that
// belongs to the interface guid (case-insensitive; Wired and 80xx WLAN events
// name it InterfaceGuid, 120xx WLAN events DeviceGuid) and has one of ids.
func newestFor(events []winEvent, guid string, ids ...int) (winEvent, int, bool) {
	for i, e := range events {
		g := e.Data["InterfaceGuid"]
		if g == "" {
			g = e.Data["DeviceGuid"]
		}
		if !strings.EqualFold(g, guid) {
			continue
		}
		for _, id := range ids {
			if e.ID == id {
				return e, i, true
			}
		}
	}
	return winEvent{}, 0, false
}

// bestEffort treats an event log failure (e.g. access denied, channel
// disabled) as no events: events only enrich a row, never fail it.
func bestEffort(events []winEvent, err error) []winEvent {
	if err != nil {
		return nil
	}
	return events
}

// eventTimestamp formats an event time like macOS's LastStatusTimestamp.
func eventTimestamp(e winEvent) string {
	return e.Time.UTC().Format("2006-01-02T15:04:05Z")
}

// eventMAC normalises an event's MAC ("8C3066A0FD33" or "2A:0B:8B:00:F2:34")
// to lowercase colon form; "" for anything else, including all zeros, which
// Wired AutoConfig logs when the switch MAC is unknown.
func eventMAC(s string) string {
	b, err := hex.DecodeString(strings.NewReplacer(":", "", "-", "").Replace(s))
	if err != nil || len(b) != 6 || bytes.Equal(b, make([]byte, 6)) {
		return ""
	}
	return macAddrString(b)
}

// applyClient copies the client side of an 802.1X event into s: the local
// MAC (WLAN "LocalMac", wired "LocalMAC") and the outer EAP identity, which
// Wired AutoConfig logs as "-" when there is none.
func applyClient(s *Dot1XStatus, e winEvent) {
	mac := e.Data["LocalMac"]
	if mac == "" {
		mac = e.Data["LocalMAC"]
	}
	s.MACAddress = eventMAC(mac)
	if s.Identity = e.Data["Identity"]; s.Identity == "-" {
		s.Identity = ""
	}
}

// applyFailure copies an 802.1X failure event (15514 / 12013) into s and
// marks it Failed (EAPClientStatus 1) so client_status_name matches macOS.
// The EAP method's own result, when logged, adds EAPReasonCode
// (failure_eap_code; "0x0" means none) and EAPRootCauseString (appended to
// failure_reason).
func applyFailure(s *Dot1XStatus, e winEvent) {
	s.ClientStatus = 1
	reason := e.Data["ReasonText"]
	if rc := e.Data["EAPRootCauseString"]; strings.TrimSpace(rc) != "" {
		reason += "\n" + rc
	}
	s.FailureReason = oneLine(reason)
	s.FailureCode = e.Data["ReasonCode"]
	if s.FailureEAPCode = e.Data["EAPReasonCode"]; s.FailureEAPCode == "0x0" {
		s.FailureEAPCode = ""
	}
	s.SSID = e.Data["SSID"] // WLAN only; wired events have none
	mac := e.Data["SwitchMAC"]
	if mac == "" {
		mac = e.Data["PeerMac"]
	}
	s.AuthenticatorMACAddress = eventMAC(mac)
	s.LastStatusTimestamp = eventTimestamp(e)
	applyClient(s, e)
}

// wlanIdleStatus is consulted for a WLAN adapter with no active connection
// (s already carries its identity). If the adapter's newest connection event
// is an 802.1X failure, it returns a Held row describing it; otherwise
// errNoActiveConnection (no row). Event log errors count as no events.
func wlanIdleStatus(c wlanClient, s Dot1XStatus, ifState uint32) (Dot1XStatus, error) {
	// Only a disconnected adapter reports its last failure: while it retries
	// (associating/discovering) or with Wi-Fi off (not ready), an earlier
	// failure would be stale.
	if ifState != wlanIfaceStateDisconnected {
		return s, errNoActiveConnection
	}
	e, _, ok := newestFor(bestEffort(c.wlanEvents()), s.UniqueIdentifier, wlanEventIDs...)
	if !ok || e.ID != evWlanAuthFailed {
		return s, errNoActiveConnection
	}
	s.State, s.SupplicantState = 0, 5 // Idle, Held
	applyFailure(&s, e)
	return s, nil
}

// applyWlanEvents fills s from guid's newest 802.1X event matching the
// connection state: when connected, the success (12012) gives the
// timestamps, client MAC and identity; while authenticating, the start
// (12011) gives the client MAC.
func applyWlanEvents(c wlanClient, s *Dot1XStatus, ifState uint32) {
	id := evWlanAuthStarted
	if ifState == wlanIfaceStateConnected {
		id = evWlanAuthSucceeded
	}
	e, _, ok := newestFor(bestEffort(c.wlanEvents()), s.UniqueIdentifier, id)
	if !ok {
		return
	}
	applyClient(s, e)
	if id == evWlanAuthSucceeded {
		s.LastStatusTimestamp = eventTimestamp(e)
		s.AuthenticatedSince = s.LastStatusTimestamp
	}
}

// wiredIface is a wired adapter that has a dot3svc LAN profile.
type wiredIface struct {
	guid        string // "{GUID}" (AdapterName)
	description string // adapter Description; the table's interface name
	linkUp      bool   // OperStatus == IfOperStatusUp
	profileXML  string
}

// wiredClient is the Wired AutoConfig surface the Windows backend needs. The
// Windows backend implements it with syscalls; tests use a fake.
type wiredClient interface {
	// wiredInterfaces returns the wired adapters with a LAN profile.
	wiredInterfaces() ([]wiredIface, error)
	// wiredEvents returns Wired-AutoConfig/Operational events (wiredEventIDs),
	// newest first.
	wiredEvents() ([]winEvent, error)
}

// wiredStatus builds the 802.1X status of a wired adapter from its LAN
// profile and newest-first Wired AutoConfig events. The newest auth event for
// the adapter decides the supplicant state.
func wiredStatus(w wiredIface, events []winEvent) (Dot1XStatus, error) {
	guid := strings.ToUpper(w.guid)
	s := Dot1XStatus{
		Interface:            w.description,
		InterfaceType:        "ethernet",
		UniqueIdentifier:     guid,
		State:                2, // Running
		SupplicantState:      -1,
		ClientStatus:         -1,
		Mode:                 -1,
		TLSTrustClientStatus: -1,
		TLSNegotiatedCipher:  -1,
		InnerEAPType:         -1,
		EAPType:              -1,
		TLSSessionWasResumed: -1,
	}
	profile := parseWLANProfile(w.profileXML)
	if !profile.useOneX {
		return s, errNotDot1X
	}
	if !w.linkUp {
		return s, errNoActiveConnection
	}
	applyProfile(&s, profile)

	rest := events
	for {
		e, i, ok := newestFor(rest, guid, wiredEventIDs...)
		if !ok {
			return s, nil // no auth events: supplicant state unknown
		}
		rest = rest[i+1:]
		switch e.ID {
		case evWiredAuthResumed:
			continue // no state of its own; the event before it decides
		case evWiredUnplugged:
			return s, errNoActiveConnection
		case evWiredAuthStarted, evWiredAuthRestart:
			s.SupplicantState = 3 // Authenticating
			applyClient(&s, e)
		case evWiredAuthSuccess:
			s.SupplicantState, s.ClientStatus = 4, 0 // Authenticated
			s.AuthenticatorMACAddress = eventMAC(e.Data["SwitchMAC"])
			s.AuthenticatedSince = eventTimestamp(e)
			applyClient(&s, e)
		case evWiredAuthFailed:
			s.SupplicantState = 5 // Held
			applyFailure(&s, e)
		case evWiredAuthSuspend:
			s.SupplicantState = 5 // Held (block timer)
			if f, _, ok := newestFor(rest, guid, evWiredAuthSuccess, evWiredAuthFailed); ok && f.ID == evWiredAuthFailed {
				applyFailure(&s, f)
			}
		}
		s.LastStatusTimestamp = eventTimestamp(e)
		return s, nil
	}
}

// wiredInterfaces returns d's wired adapters, renaming any whose description
// is also a WLAN adapter name to "<description> <GUID>" (as duplicates within
// one source are), so both stay listed and individually queryable.
func wiredInterfaces(wlanInfos map[string]ifaceInfo, d wiredClient) ([]wiredIface, error) {
	wired, err := d.wiredInterfaces()
	out := make([]wiredIface, len(wired)) // don't rename in the client's (cached) slice
	for i, w := range wired {
		if _, clash := wlanInfos[w.description]; clash {
			w.description += " " + w.guid
		}
		out[i] = w
	}
	return out, err
}

// windowsInterfaceNames lists WLAN adapters then wired adapters with a LAN
// profile. It returns nil (defaults unknown) only when both enumerations
// fail; one failing source is treated as having no adapters.
func windowsInterfaceNames(w wlanClient, d wiredClient) []string {
	infos, wlanNames, wlanErr := w.interfaces()
	wired, wiredErr := wiredInterfaces(infos, d)
	if wlanErr != nil && (wiredErr != nil || len(wired) == 0) {
		return nil // can't tell "no 802.1X" from "Wi-Fi broken": defaults unknown
	}
	names := []string{}
	if wlanErr == nil {
		names = append(names, wlanNames...)
	}
	for _, i := range wired {
		names = append(names, i.description)
	}
	return names
}

// windowsStatus routes ifname to the WLAN backend if it is a wireless
// adapter, else to the wired one. ErrBackendUnavailable is returned only when
// neither source could enumerate (e.g. no wlanapi.dll and adapter enumeration
// failed), so wired 802.1X works on hosts without the WLAN service.
func windowsStatus(w wlanClient, d wiredClient, ifname string) (Dot1XStatus, error) {
	infos, _, wlanErr := w.interfaces()
	if _, ok := infos[ifname]; ok && wlanErr == nil {
		return wlanStatus(w, ifname)
	}
	wired, wiredErr := wiredInterfaces(infos, d)
	for _, i := range wired {
		if i.description == ifname {
			return wiredStatus(i, bestEffort(d.wiredEvents()))
		}
	}
	if wlanErr != nil && (wiredErr != nil || len(wired) == 0) {
		return Dot1XStatus{Interface: ifname},
			fmt.Errorf("%w: %w", ErrBackendUnavailable, errors.Join(wlanErr, wiredErr))
	}
	return Dot1XStatus{Interface: ifname}, fmt.Errorf("interface %q not found", ifname)
}

// decodeProfileBytes decodes a profile file read from disk: UTF-8 (with or
// without BOM) or UTF-16 with a BOM.
func decodeProfileBytes(b []byte) string {
	var order binary.ByteOrder
	switch {
	case bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}):
		return string(b[3:])
	case bytes.HasPrefix(b, []byte{0xFF, 0xFE}):
		order = binary.LittleEndian
	case bytes.HasPrefix(b, []byte{0xFE, 0xFF}):
		order = binary.BigEndian
	default:
		return string(b)
	}
	u := make([]uint16, (len(b)-2)/2)
	for i := range u {
		u[i] = order.Uint16(b[2+2*i:])
	}
	return string(utf16.Decode(u))
}

// oneLine joins a multi-line event message into one line. Windows ReasonText
// can contain real line breaks and literal "\n" sequences.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, `\n`, "\n")
	var parts []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			parts = append(parts, l)
		}
	}
	return strings.Join(parts, "; ")
}
