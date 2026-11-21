//go:build windows

package dot1x

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This file holds only the syscall plumbing: wlanapi.dll (Wi-Fi), wevtapi.dll
// (event log), GetAdaptersAddresses and the dot3svc profile store (wired). The
// status logic it feeds lives in dot1x_wlan.go and dot1x_winevents.go, which
// are tested on every platform.

const (
	wlanClientVersion = 2

	wlanIntfOpcodeCurrentConnection uint32 = 7
)

type wlanInterfaceInfo struct {
	InterfaceGuid           windowsGUID
	StrInterfaceDescription [256]uint16
	IsState                 uint32
}

type wlanInterfaceInfoList struct {
	NumberOfItems uint32
	Index         uint32
}

var (
	// NewLazySystemDLL (not NewLazyDLL) forces loading from the Windows system
	// directory, avoiding DLL search-order hijacking if the process runs from a
	// writable location.
	modWlanapi = windows.NewLazySystemDLL("wlanapi.dll")

	procWlanOpenHandle     = modWlanapi.NewProc("WlanOpenHandle")
	procWlanCloseHandle    = modWlanapi.NewProc("WlanCloseHandle")
	procWlanEnumInterfaces = modWlanapi.NewProc("WlanEnumInterfaces")
	procWlanQueryInterface = modWlanapi.NewProc("WlanQueryInterface")
	procWlanGetProfile     = modWlanapi.NewProc("WlanGetProfile")
	procWlanFreeMemory     = modWlanapi.NewProc("WlanFreeMemory")
)

var (
	wlanOnce sync.Once
	// wlanAvail reports whether wlanapi.dll loaded and every proc resolved.
	// Only DLL/proc resolution is cached for the process lifetime; the client
	// handle is opened per table generation (see windowsBackend) so the
	// extension recovers if wlansvc was down or restarts.
	wlanAvail bool
	// wlanInitErr records why initWlan failed (DLL load or missing proc), so
	// unavailableBackend can report a specific reason.
	wlanInitErr error
)

func initWlan() {
	if err := modWlanapi.Load(); err != nil {
		wlanInitErr = fmt.Errorf("loading wlanapi.dll: %w", err)
		return
	}
	for _, p := range []*windows.LazyProc{
		procWlanOpenHandle, procWlanCloseHandle, procWlanEnumInterfaces,
		procWlanQueryInterface, procWlanGetProfile, procWlanFreeMemory,
	} {
		if err := p.Find(); err != nil {
			wlanInitErr = fmt.Errorf("resolving wlanapi.dll proc %s: %w", p.Name, err)
			return
		}
	}
	wlanAvail = true
}

// windowsBackend implements wlanClient and wiredClient for one table
// generation. On first use it opens a WLAN client handle and snapshots all
// interfaces (both the description->info map and the ordered names) so the
// generation enumerates only once — shared between the default interface list
// and every GetStatus. Wired adapters and each event log channel are likewise
// fetched at most once per generation. Close releases the handle.
type windowsBackend struct {
	handle  uintptr
	once    sync.Once
	ifaces  map[string]ifaceInfo
	names   []string
	enumErr error

	wiredOnce   sync.Once
	wired       []wiredIface
	wiredErr    error
	wiredEvOnce sync.Once
	wiredEv     []winEvent
	wiredEvErr  error
	wlanEvOnce  sync.Once
	wlanEv      []winEvent
	wlanEvErr   error
}

// newBackend always returns a windowsBackend: wired 802.1X needs no optional
// DLL, so a missing wlanapi.dll (e.g. Server without the Wireless LAN
// Service) only makes the WLAN half report an enumeration error.
// ErrBackendUnavailable is returned by GetStatus only when both halves fail.
func newBackend() Dot1XBackend {
	wlanOnce.Do(initWlan)
	return &windowsBackend{}
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

// enumerateWlanInterfaces returns the descriptions of all wireless
// interfaces, or nil when WLAN is unavailable or enumeration failed.
func enumerateWlanInterfaces() []string {
	b := &windowsBackend{}
	defer b.Close() //nolint:errcheck
	_, names, err := b.interfaces()
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

// interfaces lazily opens the client handle and enumerates interfaces once
// per backend instance (i.e. once per table generation), caching both the
// info map and ordered names. A WlanOpenHandle failure is reported like an
// enumeration failure (backend unavailable for this generation); the next
// generation retries with a fresh backend.
func (b *windowsBackend) interfaces() (map[string]ifaceInfo, []string, error) {
	b.once.Do(func() {
		wlanOnce.Do(initWlan)
		if !wlanAvail {
			b.enumErr = fmt.Errorf("windows WLAN backend unavailable: %w", wlanInitErr)
			return
		}
		h, err := openWlanHandle()
		if err != nil {
			b.enumErr = fmt.Errorf("opening WLAN client handle: %w", err)
			return
		}
		b.handle = h
		b.ifaces, b.names, b.enumErr = enumerateWlanInterfaceInfos(h)
	})
	return b.ifaces, b.names, b.enumErr
}

// interfaceNames satisfies the shared interfaceLister optional interface so the
// default interface list for an unconstrained query is sourced from the same
// snapshots GetStatus uses. Returns nil when both WLAN and wired enumeration
// failed (caller's generic fallback), or a possibly-empty slice of WLAN and
// wired adapter names otherwise.
func (b *windowsBackend) interfaceNames() []string {
	return windowsInterfaceNames(b, b)
}

func (b *windowsBackend) GetStatus(ifname string) (Dot1XStatus, error) {
	return windowsStatus(b, b, ifname)
}

func (b *windowsBackend) wlanEvents() ([]winEvent, error) {
	b.wlanEvOnce.Do(func() {
		b.wlanEv, b.wlanEvErr = queryEvents("Microsoft-Windows-WLAN-AutoConfig/Operational", wlanEventIDs)
	})
	return b.wlanEv, b.wlanEvErr
}

func (b *windowsBackend) wiredEvents() ([]winEvent, error) {
	b.wiredEvOnce.Do(func() {
		b.wiredEv, b.wiredEvErr = queryEvents("Microsoft-Windows-Wired-AutoConfig/Operational", wiredEventIDs)
	})
	return b.wiredEv, b.wiredEvErr
}

func (b *windowsBackend) wiredInterfaces() ([]wiredIface, error) {
	b.wiredOnce.Do(func() {
		b.wired, b.wiredErr = enumerateWiredInterfaces()
	})
	return b.wired, b.wiredErr
}

// Close releases the WLAN client handle, if one was opened.
func (b *windowsBackend) Close() error {
	if b.handle == 0 {
		return nil
	}
	ret, _, _ := procWlanCloseHandle.Call(b.handle, 0)
	b.handle = 0
	if ret != 0 {
		return fmt.Errorf("WlanCloseHandle failed: %w", syscall.Errno(ret))
	}
	return nil
}

// currentConnection queries WLAN_CONNECTION_ATTRIBUTES for guid and returns a
// copy of the raw buffer (the wlanapi allocation is freed before returning).
func (b *windowsBackend) currentConnection(guid windowsGUID) ([]byte, error) {
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
		return nil, syscall.Errno(ret)
	}
	if dataPtr == nil {
		return nil, nil
	}
	defer freeWlanMemory(uintptr(dataPtr))
	return append([]byte(nil), unsafe.Slice((*byte)(dataPtr), dataSize)...), nil
}

// profileXML calls WlanGetProfile and returns the profile XML string.
func (b *windowsBackend) profileXML(guid windowsGUID, profileName string) (string, error) {
	namePtr, err := syscall.UTF16PtrFromString(profileName)
	if err != nil {
		return "", err
	}
	var xmlPtr *uint16
	var flags uint32
	ret, _, _ := procWlanGetProfile.Call(
		b.handle,
		uintptr(unsafe.Pointer(&guid)),
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

// --- wired: dot3svc LAN profiles + GetAdaptersAddresses ---

// enumerateWiredInterfaces returns the adapters that have a dot3svc LAN
// profile (%ProgramData%\Microsoft\dot3svc\Profiles\Interfaces\{GUID}\*.xml),
// named by adapter Description like the WLAN adapters.
func enumerateWiredInterfaces() ([]wiredIface, error) {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return nil, fmt.Errorf("locating ProgramData: %w", err)
	}
	root := filepath.Join(programData, "Microsoft", "dot3svc", "Profiles", "Interfaces")
	dirs, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return []wiredIface{}, nil // Wired AutoConfig never configured
	}
	if err != nil {
		// Typically access denied when not admin/SYSTEM; don't report "none".
		return nil, fmt.Errorf("reading Wired AutoConfig profiles: %w", err)
	}
	profiles := make(map[string]string) // upper-case "{GUID}" -> profile XML
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		files, err := filepath.Glob(filepath.Join(root, d.Name(), "*.xml"))
		if err != nil || len(files) == 0 {
			continue
		}
		// Wired AutoConfig keeps one profile per adapter (netsh lan add
		// profile replaces it); if several exist, the newest is the one
		// applied last.
		newest, newestMod := files[0], time.Time{}
		for _, f := range files {
			if fi, err := os.Stat(f); err == nil && fi.ModTime().After(newestMod) {
				newest, newestMod = f, fi.ModTime()
			}
		}
		b, err := os.ReadFile(newest)
		if err != nil {
			return nil, fmt.Errorf("reading Wired AutoConfig profile: %w", err)
		}
		profiles[strings.ToUpper(d.Name())] = decodeProfileBytes(b)
	}
	if len(profiles) == 0 {
		return []wiredIface{}, nil // no wired 802.1X configured; skip adapter enumeration
	}

	head, err := adapterAddresses()
	if err != nil {
		return nil, err
	}
	out := []wiredIface{}
	seen := make(map[string]bool)
	for a := head; a != nil; a = a.Next {
		guid := strings.ToUpper(windows.BytePtrToString(a.AdapterName))
		profile, ok := profiles[guid]
		if !ok {
			continue
		}
		desc := windows.UTF16PtrToString(a.Description)
		if seen[desc] {
			desc += " " + guid // identical adapters stay individually queryable
		}
		seen[desc] = true
		out = append(out, wiredIface{
			guid:        guid,
			description: desc,
			linkUp:      a.OperStatus == windows.IfOperStatusUp,
			profileXML:  profile,
		})
	}
	return out, nil
}

// adapterAddresses calls GetAdaptersAddresses, growing the buffer as needed.
// The returned list points into a Go-allocated buffer kept alive by it.
func adapterAddresses() (*windows.IpAdapterAddresses, error) {
	const flags = windows.GAA_FLAG_SKIP_UNICAST | windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER
	size := uint32(15000)
	for i := 0; i < 3; i++ {
		buf := make([]byte, size)
		p := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, p, &size)
		if err == nil {
			if size == 0 {
				return nil, nil
			}
			return p, nil
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil, fmt.Errorf("GetAdaptersAddresses failed: %w", err)
		}
	}
	return nil, fmt.Errorf("GetAdaptersAddresses: buffer kept growing")
}

// --- event log: wevtapi.dll ---

const (
	evtQueryChannelPath      = 0x1
	evtQueryReverseDirection = 0x200
	evtRenderEventXML        = 1

	maxEvents = 256 // per channel per generation
	evtBatch  = 32
)

var (
	modWevtapi    = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery  = modWevtapi.NewProc("EvtQuery")
	procEvtNext   = modWevtapi.NewProc("EvtNext")
	procEvtRender = modWevtapi.NewProc("EvtRender")
	procEvtClose  = modWevtapi.NewProc("EvtClose")
)

func evtClose(h uintptr) {
	procEvtClose.Call(h) //nolint:errcheck
}

// queryEvents returns up to maxEvents events with the given IDs from channel,
// newest first. Events that fail to render or parse are skipped.
func queryEvents(channel string, ids []int) ([]winEvent, error) {
	for _, p := range []*windows.LazyProc{procEvtQuery, procEvtNext, procEvtRender, procEvtClose} {
		if err := p.Find(); err != nil {
			return nil, fmt.Errorf("resolving wevtapi.dll proc %s: %w", p.Name, err)
		}
	}
	terms := make([]string, len(ids))
	for i, id := range ids {
		terms[i] = "EventID=" + strconv.Itoa(id)
	}
	pathPtr, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return nil, err
	}
	queryPtr, err := windows.UTF16PtrFromString("*[System[(" + strings.Join(terms, " or ") + ")]]")
	if err != nil {
		return nil, err
	}
	h, _, callErr := procEvtQuery.Call(0, uintptr(unsafe.Pointer(pathPtr)), uintptr(unsafe.Pointer(queryPtr)),
		evtQueryChannelPath|evtQueryReverseDirection)
	if h == 0 {
		return nil, fmt.Errorf("EvtQuery(%s) failed: %w", channel, callErr)
	}
	defer evtClose(h)

	var events []winEvent
	var buf []uint16
	handles := make([]uintptr, evtBatch)
	for len(events) < maxEvents {
		var returned uint32
		ok, _, callErr := procEvtNext.Call(h, uintptr(len(handles)), uintptr(unsafe.Pointer(&handles[0])),
			windows.INFINITE, 0, uintptr(unsafe.Pointer(&returned)))
		if ok == 0 {
			if callErr == windows.ERROR_NO_MORE_ITEMS {
				break
			}
			return events, fmt.Errorf("EvtNext(%s) failed: %w", channel, callErr)
		}
		for _, eh := range handles[:returned] {
			if len(events) < maxEvents {
				if x, err := renderEventXML(eh, &buf); err == nil {
					if e, err := parseWinEventXML(x); err == nil {
						events = append(events, e)
					}
				}
			}
			evtClose(eh)
		}
	}
	return events, nil
}

// renderEventXML renders one event handle as XML, reusing/growing *buf.
func renderEventXML(h uintptr, buf *[]uint16) (string, error) {
	for {
		var used, count uint32
		var p uintptr
		if len(*buf) > 0 {
			p = uintptr(unsafe.Pointer(&(*buf)[0]))
		}
		ok, _, callErr := procEvtRender.Call(0, h, evtRenderEventXML, uintptr(len(*buf)*2), p,
			uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&count)))
		if ok != 0 {
			return windows.UTF16ToString((*buf)[:used/2]), nil
		}
		if callErr != windows.ERROR_INSUFFICIENT_BUFFER || int(used) <= len(*buf)*2 {
			return "", fmt.Errorf("EvtRender failed: %w", callErr)
		}
		*buf = make([]uint16, (used+1)/2)
	}
}
