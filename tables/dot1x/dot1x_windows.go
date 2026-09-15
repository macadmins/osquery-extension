//go:build windows

package dot1x

import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wlanClientVersion = 2

	wlanIntfOpcodeCurrentConnection uint32 = 7

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

type wlanInterfaceInfo struct {
	InterfaceGuid           windowsGUID
	StrInterfaceDescription [256]uint16
	IsState                 uint32
}

type wlanInterfaceInfoList struct {
	NumberOfItems uint32
	Index         uint32
}

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

var (
	// NewLazySystemDLL (not NewLazyDLL) forces loading from the Windows system
	// directory, avoiding DLL search-order hijacking if the process runs from a
	// writable location.
	modWlanapi = windows.NewLazySystemDLL("wlanapi.dll")

	procWlanOpenHandle     = modWlanapi.NewProc("WlanOpenHandle")
	procWlanEnumInterfaces = modWlanapi.NewProc("WlanEnumInterfaces")
	procWlanQueryInterface = modWlanapi.NewProc("WlanQueryInterface")
	procWlanGetProfile     = modWlanapi.NewProc("WlanGetProfile")
	procWlanFreeMemory     = modWlanapi.NewProc("WlanFreeMemory")
)

var (
	wlanOnce sync.Once
	// wlanAvail reports whether wlanapi.dll loaded and a client handle opened.
	wlanAvail bool
	// wlanInitErr records why initWlan failed (DLL load, missing proc, or
	// WlanOpenHandle), so unavailableBackend can report a specific reason.
	wlanInitErr error
	// wlanHandle is a process-lifetime WLAN client handle opened once in
	// initWlan and reused by every query. Like the darwin framework handle, it
	// is intentionally never closed — the OS reclaims it at process exit, and
	// reusing one handle avoids an open/close round-trip on every GetStatus.
	wlanHandle uintptr
)

func initWlan() {
	if err := modWlanapi.Load(); err != nil {
		wlanInitErr = fmt.Errorf("loading wlanapi.dll: %w", err)
		return
	}
	for _, p := range []*windows.LazyProc{
		procWlanOpenHandle, procWlanEnumInterfaces,
		procWlanQueryInterface, procWlanGetProfile, procWlanFreeMemory,
	} {
		if err := p.Find(); err != nil {
			wlanInitErr = fmt.Errorf("resolving wlanapi.dll proc %s: %w", p.Name, err)
			return
		}
	}
	h, err := openWlanHandle()
	if err != nil {
		wlanInitErr = fmt.Errorf("opening WLAN client handle: %w", err)
		return
	}
	wlanHandle = h
	wlanAvail = true
}

// ifaceInfo is the per-interface data captured from a single
// WlanEnumInterfaces call: its GUID (stable) and current state.
type ifaceInfo struct {
	guid  windowsGUID
	state uint32
}

// windowsBackend reuses the process-lifetime WLAN handle and, on first use,
// snapshots all interfaces (both the description->info map and the ordered
// names) so one table generation enumerates only once — shared between the
// default interface list and every GetStatus.
type windowsBackend struct {
	handle  uintptr
	once    sync.Once
	ifaces  map[string]ifaceInfo
	names   []string
	enumErr error
}

func newBackend() Dot1XBackend {
	wlanOnce.Do(initWlan)
	if !wlanAvail {
		return unavailableBackend{}
	}
	return &windowsBackend{handle: wlanHandle}
}

type unavailableBackend struct{}

func (unavailableBackend) GetStatus(ifname string) (Dot1XStatus, error) {
	if wlanInitErr != nil {
		return Dot1XStatus{Interface: ifname},
			fmt.Errorf("%w: Windows WLAN backend unavailable: %w", ErrBackendUnavailable, wlanInitErr)
	}
	return Dot1XStatus{Interface: ifname},
		fmt.Errorf("%w: Windows WLAN backend unavailable", ErrBackendUnavailable)
}

func openWlanHandle() (uintptr, error) {
	var negotiatedVersion uint32
	var handle uintptr
	ret, _, _ := procWlanOpenHandle.Call(
		uintptr(wlanClientVersion),
		0,
		uintptr(unsafe.Pointer(&negotiatedVersion)),
		uintptr(unsafe.Pointer(&handle)),
	)
	if ret != 0 {
		return 0, fmt.Errorf("WlanOpenHandle failed: %w", syscall.Errno(ret))
	}
	return handle, nil
}

func freeWlanMemory(p uintptr) {
	procWlanFreeMemory.Call(p) //nolint:errcheck
}

// enumerateWlanInterfaceInfos performs one WlanEnumInterfaces call and returns
// a description->info map plus the descriptions in enumeration order.
func enumerateWlanInterfaceInfos(handle uintptr) (map[string]ifaceInfo, []string, error) {
	var listPtr unsafe.Pointer
	ret, _, _ := procWlanEnumInterfaces.Call(handle, 0, uintptr(unsafe.Pointer(&listPtr)))
	if ret != 0 {
		return nil, nil, fmt.Errorf("WlanEnumInterfaces failed: %w", syscall.Errno(ret))
	}
	if listPtr == nil {
		return nil, nil, fmt.Errorf("WlanEnumInterfaces succeeded but returned no interface list")
	}
	defer freeWlanMemory(uintptr(listPtr))

	list := (*wlanInterfaceInfoList)(listPtr)
	infos := make(map[string]ifaceInfo, list.NumberOfItems)
	names := make([]string, 0, list.NumberOfItems)

	headerSize := unsafe.Sizeof(*list)
	itemSize := unsafe.Sizeof(wlanInterfaceInfo{})
	for i := uint32(0); i < list.NumberOfItems; i++ {
		offset := headerSize + uintptr(i)*itemSize
		info := (*wlanInterfaceInfo)(unsafe.Pointer(uintptr(unsafe.Pointer(list)) + offset))
		desc := utf16ToString(info.StrInterfaceDescription[:])
		key := uniqueIfaceKey(infos, desc, info.InterfaceGuid)
		infos[key] = ifaceInfo{guid: info.InterfaceGuid, state: info.IsState}
		names = append(names, key)
	}
	return infos, names, nil
}

// uniqueIfaceKey returns desc, or a GUID-disambiguated key when desc already
// exists in seen. Windows can report two adapters with identical interface
// descriptions (e.g. two identical USB Wi-Fi dongles); without this the later
// one would overwrite the earlier in the snapshot map, dropping it from
// results and making it unqueryable. Suffixing the stable GUID keeps each
// physical adapter individually enumerable and targetable via
// WHERE interface = '...'.
func uniqueIfaceKey(seen map[string]ifaceInfo, desc string, guid windowsGUID) string {
	if _, dup := seen[desc]; !dup {
		return desc
	}
	return desc + " " + guid.String()
}

// enumerateWlanInterfaces returns the descriptions of all wireless interfaces.
func enumerateWlanInterfaces() []string {
	wlanOnce.Do(initWlan)
	if !wlanAvail {
		return nil
	}
	_, names, err := enumerateWlanInterfaceInfos(wlanHandle)
	if err != nil {
		return nil
	}
	return names
}

func defaultInterfaces() []string {
	// Return enumerateWlanInterfaces' result as-is so the nil/empty distinction
	// is preserved: nil means WLAN is unavailable or enumeration failed
	// (defaults unknown -> caller's generic fallback), while a non-nil empty
	// slice means "successfully enumerated, no wireless adapters" (query none).
	return enumerateWlanInterfaces()
}

// snapshot lazily enumerates interfaces once per backend instance (i.e. once
// per table generation) and caches both the info map and ordered names.
func (b *windowsBackend) snapshot() (map[string]ifaceInfo, []string, error) {
	b.once.Do(func() {
		b.ifaces, b.names, b.enumErr = enumerateWlanInterfaceInfos(b.handle)
	})
	return b.ifaces, b.names, b.enumErr
}

// interfaceNames satisfies the shared interfaceLister optional interface so the
// default interface list for an unconstrained query is sourced from the same
// snapshot GetStatus uses, avoiding a second WlanEnumInterfaces call. Returns
// nil when WLAN is unavailable / enumeration failed (caller's generic
// fallback), or a possibly-empty slice of adapter names otherwise.
func (b *windowsBackend) interfaceNames() []string {
	_, names, err := b.snapshot()
	if err != nil {
		return nil
	}
	return names
}

func (b *windowsBackend) GetStatus(ifname string) (Dot1XStatus, error) {
	infos, _, err := b.snapshot()
	if err != nil {
		// Enumeration failing is systemic (affects every interface), so report
		// it as backend-unavailable rather than a per-interface miss. Both are
		// wrapped (%w) so errors.Is(ErrBackendUnavailable) holds and the
		// underlying WlanEnumInterfaces error stays introspectable.
		return Dot1XStatus{Interface: ifname}, fmt.Errorf("%w: %w", ErrBackendUnavailable, err)
	}
	info, ok := infos[ifname]
	if !ok {
		return Dot1XStatus{Interface: ifname}, fmt.Errorf("wireless interface %q not found", ifname)
	}
	guid := info.guid
	ifState := info.state

	s := Dot1XStatus{
		Interface:        ifname,
		UniqueIdentifier: guid.String(),
	}

	s.State, s.SupplicantState = mapWlanState(ifState)
	s.ClientStatus = -1
	s.DomainSpecificError = -1
	s.Mode = -1
	s.TLSTrustClientStatus = -1
	s.TLSNegotiatedCipher = -1
	s.InnerEAPType = -1
	s.EAPType = -1

	if ifState != wlanIfaceStateConnected && ifState != wlanIfaceStateAuthenticating {
		return s, nil
	}

	var dataSize uint32
	var dataPtr unsafe.Pointer
	var opcodeValueType uint32
	ret, _, _ := procWlanQueryInterface.Call(
		b.handle,
		uintptr(unsafe.Pointer(&guid)),
		uintptr(wlanIntfOpcodeCurrentConnection),
		0,
		uintptr(unsafe.Pointer(&dataSize)),
		uintptr(unsafe.Pointer(&dataPtr)),
		uintptr(unsafe.Pointer(&opcodeValueType)),
	)
	if ret != 0 {
		// The interface reports connected/authenticating, so a failed
		// current-connection query would leave a misleading "successful" row
		// missing MAC/EAP/profile data. Return a per-interface error so
		// generateRows skips it rather than emitting a partial row.
		return s, fmt.Errorf("WlanQueryInterface(current_connection) failed for %q: %w", ifname, syscall.Errno(ret))
	}
	if dataPtr == nil {
		return s, fmt.Errorf("WlanQueryInterface(current_connection) returned no data for %q", ifname)
	}
	defer freeWlanMemory(uintptr(dataPtr))

	// Guard against a short buffer (version differences / unexpected value
	// type / corrupt response) before dereferencing, to avoid an OOB read.
	if want := unsafe.Sizeof(wlanConnectionAttributes{}); uintptr(dataSize) < want {
		return s, fmt.Errorf("WlanQueryInterface(current_connection) returned %d bytes for %q, want >= %d", dataSize, ifname, want)
	}

	conn := (*wlanConnectionAttributes)(dataPtr)

	s.AuthenticatorMACAddress = macAddrString(conn.AssociationAttributes.Dot11Bssid[:])

	sec := conn.SecurityAttributes
	if sec.OneXEnabled != 0 {
		if ifState == wlanIfaceStateConnected {
			s.SupplicantState = 4 // Authenticated
			s.ClientStatus = 0
		}
	} else {
		s.SupplicantState = 0 // not an 802.1X network
	}

	profileName := utf16ToString(conn.ProfileName[:])
	if profileName != "" {
		if xmlStr, err := getWlanProfileXML(b.handle, &guid, profileName); err == nil {
			profile := parseWLANProfile(xmlStr) // single pass over the XML
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
			// validation), not the presented server certificate's fingerprint,
			// so they go in TLSTrustedRootCASHA1 rather than
			// TLSServerCertificateSHA1 (which macOS fills with the actual chain).
			if profile.trustedRootCASHA1 != "" {
				s.TLSTrustedRootCASHA1 = profile.trustedRootCASHA1
			}
		}
	}

	return s, nil
}

// getWlanProfileXML calls WlanGetProfile and returns the profile XML string.
func getWlanProfileXML(handle uintptr, guid *windowsGUID, profileName string) (string, error) {
	namePtr, err := syscall.UTF16PtrFromString(profileName)
	if err != nil {
		return "", err
	}
	var xmlPtr *uint16
	var flags uint32
	ret, _, _ := procWlanGetProfile.Call(
		handle,
		uintptr(unsafe.Pointer(guid)),
		uintptr(unsafe.Pointer(namePtr)),
		0,
		uintptr(unsafe.Pointer(&xmlPtr)),
		uintptr(unsafe.Pointer(&flags)),
		0,
	)
	if ret != 0 {
		return "", fmt.Errorf("WlanGetProfile failed: %w", syscall.Errno(ret))
	}
	if xmlPtr == nil {
		return "", fmt.Errorf("WlanGetProfile succeeded but returned no profile XML")
	}
	defer freeWlanMemory(uintptr(unsafe.Pointer(xmlPtr)))
	return utf16PtrToString(xmlPtr), nil
}

func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	return windows.UTF16PtrToString(p)
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

func utf16ToString(s []uint16) string {
	for i, v := range s {
		if v == 0 {
			return syscall.UTF16ToString(s[:i])
		}
	}
	return syscall.UTF16ToString(s)
}
