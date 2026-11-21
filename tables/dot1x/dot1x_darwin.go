//go:build darwin

package dot1x

/*
#cgo LDFLAGS: -framework CoreFoundation -framework SystemConfiguration
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// EAPOLControlState enum from EAPOLControlTypes.h
enum {
	kEAPOLControlStateIdle = 0,
	kEAPOLControlStateStarting = 1,
	kEAPOLControlStateRunning = 2,
	kEAPOLControlStateStopping = 3,
};

typedef int (*EAPOLControlCopyStateAndStatusFn)(const char*, uint32_t*, CFDictionaryRef*);

static EAPOLControlCopyStateAndStatusFn copy_state_fn = NULL;

// load_error holds the dlopen/dlsym failure reason (from dlerror) so the Go
// layer can surface it for diagnosis; empty when load succeeded.
static char load_error[256] = {0};

static int load_dot1x(void) {
	if (copy_state_fn) return 1;
	// Handle intentionally held for process lifetime (sync.Once); the
	// framework must stay loaded for copy_state_fn to remain valid.
	void* h = dlopen("/System/Library/PrivateFrameworks/EAP8021X.framework/EAP8021X", RTLD_LAZY);
	if (!h) {
		const char* e = dlerror();
		snprintf(load_error, sizeof(load_error), "dlopen: %s", e ? e : "unknown error");
		return 0;
	}
	copy_state_fn = (EAPOLControlCopyStateAndStatusFn)dlsym(h, "EAPOLControlCopyStateAndStatus");
	if (!copy_state_fn) {
		const char* e = dlerror();
		snprintf(load_error, sizeof(load_error), "dlsym: %s", e ? e : "unknown error");
		dlclose(h);
		return 0;
	}
	return 1;
}

// dot1x_load_error returns the captured load failure reason, or NULL if none.
static const char* dot1x_load_error(void) {
	return load_error[0] ? load_error : NULL;
}

// cfstring_go creates a Go-owned copy of a CFString as a malloc'd C string.
static char* cfstring_go(CFStringRef s) {
	if (!s) return NULL;
	CFIndex len = CFStringGetMaximumSizeForEncoding(CFStringGetLength(s), kCFStringEncodingUTF8) + 1;
	char* buf = (char*)malloc((size_t)len);
	if (buf && CFStringGetCString(s, buf, len, kCFStringEncodingUTF8)) {
		return buf;
	}
	free(buf);
	return NULL;
}

// cfnumber_int returns the int value of a CFNumber, or -1.
static int cfnumber_int(CFTypeRef v) {
	if (!v || CFGetTypeID(v) != CFNumberGetTypeID()) return -1;
	int result = -1;
	if (!CFNumberGetValue((CFNumberRef)v, kCFNumberIntType, &result)) return -1;
	return result;
}

// cfbool_int returns 1 if the value is kCFBooleanTrue, 0 otherwise.
static int cfbool_int(CFTypeRef v) {
	if (!v) return 0;
	return (v == kCFBooleanTrue) ? 1 : 0;
}

// cfdata_bytes copies CFData bytes to a malloc'd buffer. *out_len receives the length.
static uint8_t* cfdata_bytes(CFTypeRef v, CFIndex* out_len) {
	if (!v || CFGetTypeID(v) != CFDataGetTypeID()) {
		*out_len = 0;
		return NULL;
	}
	CFIndex len = CFDataGetLength((CFDataRef)v);
	uint8_t* buf = (uint8_t*)malloc((size_t)len);
	if (buf) {
		CFDataGetBytes((CFDataRef)v, CFRangeMake(0, len), buf);
		*out_len = len;
	} else {
		*out_len = 0;
	}
	return buf;
}

// get_dict_int_v extracts an integer value for a CFString key from the dictionary.
static int get_dict_int_v(CFDictionaryRef d, CFStringRef key) {
	CFTypeRef v = NULL;
	CFDictionaryGetValueIfPresent(d, key, &v);
	return cfnumber_int(v);
}

// get_dict_string_v extracts a string value for a CFString key from the dictionary.
static char* get_dict_string_v(CFDictionaryRef d, CFStringRef key) {
	CFTypeRef v = NULL;
	CFDictionaryGetValueIfPresent(d, key, &v);
	if (!v || CFGetTypeID(v) != CFStringGetTypeID()) return NULL;
	return cfstring_go((CFStringRef)v);
}

// get_dict_data_v extracts raw bytes from a CFData value for a CFString key.
static uint8_t* get_dict_data_v(CFDictionaryRef d, CFStringRef key, CFIndex* out_len) {
	CFTypeRef v = NULL;
	CFDictionaryGetValueIfPresent(d, key, &v);
	return cfdata_bytes(v, out_len);
}

// cfdate_iso8601 converts a CFDate to an ISO 8601 string.
static char* cfdate_iso8601(CFTypeRef v) {
	if (!v || CFGetTypeID(v) != CFDateGetTypeID()) return NULL;
	CFAbsoluteTime abs = CFDateGetAbsoluteTime((CFDateRef)v);
	// CFAbsoluteTime is seconds since 2001-01-01 00:00:00 UTC.
	// Convert to Unix timestamp and format with strftime.
	time_t unix = (time_t)(abs + 978307200.0); // 978307200 = seconds from 1970 to 2001
	struct tm utc;
	if (!gmtime_r(&unix, &utc)) return NULL;
	char buf[32];
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc);
	return strdup(buf);
}

// pack_cert_chain takes a CFArray of CFData (DER-encoded certificates)
// and packs them into a single malloc'd byte buffer as a sequence of
// (4-byte big-endian length || DER bytes) entries. *out_len receives the
// total buffer length. Returns NULL if the array is empty or invalid.
// The caller must free the returned buffer.
static uint8_t* pack_cert_chain(CFArrayRef certs, CFIndex* out_len) {
	*out_len = 0;
	if (!certs || CFGetTypeID(certs) != CFArrayGetTypeID()) return NULL;
	CFIndex count = CFArrayGetCount(certs);
	if (count == 0) return NULL;

	// First pass: calculate total buffer size. Apply the same oversized-entry
	// skip the write pass uses below, so the allocation stays bounded and
	// matches exactly what is written (no oversized malloc, no slack bytes).
	CFIndex total = 0;
	for (CFIndex i = 0; i < count; i++) {
		CFTypeRef item = CFArrayGetValueAtIndex(certs, i);
		if (!item || CFGetTypeID(item) != CFDataGetTypeID()) continue;
		CFIndex len = CFDataGetLength((CFDataRef)item);
		if (len > 0xffffffff) continue; // exceeds 4-byte packed format
		total += 4 + len;
	}
	if (total == 0) return NULL;

	uint8_t* buf = (uint8_t*)malloc((size_t)total);
	if (!buf) return NULL;

	// Second pass: write (len BE || data) for each cert.
	uint8_t* dst = buf;
	CFIndex written = 0;
	for (CFIndex i = 0; i < count; i++) {
		CFTypeRef item = CFArrayGetValueAtIndex(certs, i);
		if (!item || CFGetTypeID(item) != CFDataGetTypeID()) continue;
		CFDataRef data = (CFDataRef)item;
		CFIndex len = CFDataGetLength(data);
		if (len > 0xffffffff) continue; // exceeds 4-byte packed format
		// Big-endian length prefix.
		dst[0] = (uint8_t)((len >> 24) & 0xff);
		dst[1] = (uint8_t)((len >> 16) & 0xff);
		dst[2] = (uint8_t)((len >> 8) & 0xff);
		dst[3] = (uint8_t)(len & 0xff);
		dst += 4;
		CFDataGetBytes(data, CFRangeMake(0, len), dst);
		dst += len;
		written += 4 + len;
	}

	if (written == 0) {
		free(buf);
		*out_len = 0;
		return NULL;
	}
	*out_len = written;
	return buf;
}

// dot1x_query calls EAPOLControlCopyStateAndStatus for the given interface
// and fills the provided Go-accessible fields. Returns 0 on success, -1 if the
// framework/symbol could not be loaded, -2 if the call reported success but
// returned no status dictionary, otherwise the EAPOLControl error code.
// All string/buffer outputs are malloc'd and must be freed by the caller.
int dot1x_query(
	const char* ifname,
	int* out_state,
	int* out_supplicant_state,
	int* out_eap_type,
	char** out_eap_type_name,
	int* out_client_status,
	int* out_domain_specific_error,
	int* out_domain_specific_error_present,
	uint8_t** out_auth_mac,
	CFIndex* out_auth_mac_len,
	int* out_mode,
	int* out_tls_session_was_resumed,
	uint8_t** out_cert_chain_data,
	CFIndex* out_cert_chain_len,
	int* out_tls_trust_client_status,
	int* out_tls_negotiated_cipher,
	char** out_tls_negotiated_protocol_version,
	int* out_inner_eap_type,
	char** out_inner_eap_type_name,
	char** out_last_status_timestamp,
	char** out_authenticated_since,
	char** out_unique_identifier
) {
	// Initialize all outputs before any early return path.
	*out_state = -1;
	*out_supplicant_state = -1;
	*out_eap_type = -1;
	*out_eap_type_name = NULL;
	*out_client_status = -1;
	*out_domain_specific_error = 0;
	*out_domain_specific_error_present = 0;
	*out_auth_mac = NULL;
	*out_auth_mac_len = 0;
	*out_mode = -1;
	*out_tls_session_was_resumed = -1;
	*out_cert_chain_data = NULL;
	*out_cert_chain_len = 0;
	*out_tls_trust_client_status = -1;
	*out_tls_negotiated_cipher = -1;
	*out_tls_negotiated_protocol_version = NULL;
	*out_inner_eap_type = -1;
	*out_inner_eap_type_name = NULL;
	*out_last_status_timestamp = NULL;
	*out_authenticated_since = NULL;
	*out_unique_identifier = NULL;

	if (!copy_state_fn) return -1;

	uint32_t state = 0;
	CFDictionaryRef status = NULL;
	int ret = copy_state_fn(ifname, &state, &status);

	if (ret != 0 || status == NULL) {
		if (status) CFRelease(status);
		// status == NULL with ret == 0 means the call "succeeded" but provided
		// no status dictionary (no usable per-interface data). Return a
		// distinct code (-2) so the Go layer raises a per-interface error and
		// the interface is skipped, rather than emitting a row of sentinels.
		return ret != 0 ? ret : -2;
	}

	*out_state = (int)state;

	// Pre-create CFString keys for all dictionary lookups to avoid
	// per-lookup CFStringCreateWithCString/CFRelease overhead.
	CFStringRef kSupplicantState        = CFSTR("SupplicantState");
	CFStringRef kEAPType                = CFSTR("EAPType");
	CFStringRef kEAPTypeName            = CFSTR("EAPTypeName");
	CFStringRef kClientStatus           = CFSTR("ClientStatus");
	CFStringRef kDomainSpecificError    = CFSTR("DomainSpecificError");
	CFStringRef kAuthenticatorMACAddress = CFSTR("AuthenticatorMACAddress");
	CFStringRef kMode                   = CFSTR("Mode");
	CFStringRef kUniqueIdentifier       = CFSTR("UniqueIdentifier");
	CFStringRef kLastStatusTimestamp    = CFSTR("LastStatusTimestamp");
	CFStringRef kTimestamp              = CFSTR("Timestamp");
	CFStringRef kAdditionalProperties   = CFSTR("AdditionalProperties");
	CFStringRef kTLSSessionWasResumed   = CFSTR("TLSSessionWasResumed");
	CFStringRef kTLSServerCertChain     = CFSTR("TLSServerCertificateChain");
	CFStringRef kTLSTrustClientStatus   = CFSTR("TLSTrustClientStatus");
	CFStringRef kTLSNegotiatedCipher    = CFSTR("TLSNegotiatedCipher");
	CFStringRef kTLSNegProtocolVersion  = CFSTR("TLSNegotiatedProtocolVersion");
	CFStringRef kInnerEAPType           = CFSTR("InnerEAPType");
	CFStringRef kInnerEAPTypeName       = CFSTR("InnerEAPTypeName");

	*out_supplicant_state = get_dict_int_v(status, kSupplicantState);
	*out_eap_type = get_dict_int_v(status, kEAPType);
	*out_eap_type_name = get_dict_string_v(status, kEAPTypeName);
	*out_client_status = get_dict_int_v(status, kClientStatus);
	{
		CFTypeRef v = NULL;
		int32_t n = 0;
		if (CFDictionaryGetValueIfPresent(status, kDomainSpecificError, &v) && v != NULL &&
		    CFGetTypeID(v) == CFNumberGetTypeID() &&
		    CFNumberGetValue((CFNumberRef)v, kCFNumberSInt32Type, &n)) {
			*out_domain_specific_error = (int)n;
			*out_domain_specific_error_present = 1;
		}
	}
	*out_auth_mac = get_dict_data_v(status, kAuthenticatorMACAddress, out_auth_mac_len);
	*out_mode = get_dict_int_v(status, kMode);
	*out_unique_identifier = get_dict_string_v(status, kUniqueIdentifier);

	// LastStatusTimestamp lives in the main status dict as a CFDate.
	{
		CFTypeRef tsVal = NULL;
		CFDictionaryGetValueIfPresent(status, kLastStatusTimestamp, &tsVal);
		*out_last_status_timestamp = cfdate_iso8601(tsVal);
	}

	// Timestamp (kEAPOLControlTimestamp): when the session first became
	// Authenticated; Supplicant.c only includes it while authenticated.
	{
		CFTypeRef tsVal = NULL;
		CFDictionaryGetValueIfPresent(status, kTimestamp, &tsVal);
		*out_authenticated_since = cfdate_iso8601(tsVal);
	}

	// TLSSessionWasResumed, TLSServerCertificateChain,
	// TLSTrustClientStatus, and TLSNegotiatedProtocolVersion live in
	// AdditionalProperties sub-dictionary.
	{
		CFTypeRef apVal = NULL;
		if (CFDictionaryGetValueIfPresent(status, kAdditionalProperties, &apVal) && apVal) {
			if (CFGetTypeID(apVal) == CFDictionaryGetTypeID()) {
				CFDictionaryRef apDict = (CFDictionaryRef)apVal;
				CFTypeRef resumed = NULL;
				if (CFDictionaryGetValueIfPresent(apDict, kTLSSessionWasResumed, &resumed)) {
					*out_tls_session_was_resumed = cfbool_int(resumed);
				}
				CFTypeRef certChain = NULL;
				CFDictionaryGetValueIfPresent(apDict, kTLSServerCertChain, &certChain);
				if (certChain && CFGetTypeID(certChain) == CFArrayGetTypeID()) {
					*out_cert_chain_data = pack_cert_chain((CFArrayRef)certChain,
						out_cert_chain_len);
				}
				*out_tls_trust_client_status = get_dict_int_v(apDict, kTLSTrustClientStatus);
				*out_tls_negotiated_cipher = get_dict_int_v(apDict, kTLSNegotiatedCipher);
				*out_tls_negotiated_protocol_version = get_dict_string_v(apDict,
					kTLSNegProtocolVersion);
				*out_inner_eap_type = get_dict_int_v(apDict, kInnerEAPType);
				*out_inner_eap_type_name = get_dict_string_v(apDict, kInnerEAPTypeName);
			}
		}
	}

	CFRelease(status);
	return 0;
}

// sc_interface_type returns the SystemConfiguration type of the BSD
// interface (e.g. "IEEE80211", "Ethernet") as a malloc'd string, or NULL.
static char* sc_interface_type(const char* bsd) {
	CFArrayRef all = SCNetworkInterfaceCopyAll();
	if (!all) return NULL;
	CFStringRef want = CFStringCreateWithCString(NULL, bsd, kCFStringEncodingUTF8);
	char* out = NULL;
	for (CFIndex i = 0; want && i < CFArrayGetCount(all); i++) {
		SCNetworkInterfaceRef ni = (SCNetworkInterfaceRef)CFArrayGetValueAtIndex(all, i);
		CFStringRef name = SCNetworkInterfaceGetBSDName(ni);
		if (name && CFEqual(name, want)) {
			out = cfstring_go(SCNetworkInterfaceGetInterfaceType(ni));
			break;
		}
	}
	if (want) CFRelease(want);
	CFRelease(all);
	return out;
}
*/
import "C"
import (
	"context"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"time"
	"unsafe"
)

// productionBackend calls EAPOLControlCopyStateAndStatus via cgo. One is
// created per table generation, so profilesXML caches `profiles -C` output
// for that generation only.
type productionBackend struct {
	profilesOnce sync.Once
	profilesXML  []byte
}

var loadOnce sync.Once

func newBackend() Dot1XBackend {
	loadOnce.Do(func() { C.load_dot1x() })
	return &productionBackend{}
}

// profilesTimeout bounds the `profiles` call.
const profilesTimeout = 10 * time.Second

// installedProfiles returns `/usr/bin/profiles -C -o stdout-xml` output (works
// as any user), run at most once per backend and only when a row needs it;
// nil on error.
func (b *productionBackend) installedProfiles() []byte {
	b.profilesOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), profilesTimeout)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "/usr/bin/profiles", "-C", "-o", "stdout-xml").Output(); err == nil {
			b.profilesXML = out
		}
	})
	return b.profilesXML
}

// knownNetworksPlist is where macOS records joined Wi-Fi networks. It is
// root-only and Full Disk Access protected, so it is only readable under
// osqueryd; anywhere else the ssid column stays empty.
const knownNetworksPlist = "/Library/Preferences/com.apple.wifi.known-networks.plist"

// eapolClientConfigPlist is eap8021x's EAPOLClientConfiguration store
// (world-readable).
const eapolClientConfigPlist = "/Library/Preferences/SystemConfiguration/com.apple.network.eapolclient.configuration.plist"

// applyDarwinProfile fills ssid, profile_name, mdm_payload_uuid, identity,
// tls_trusted_server_names and server_validation, which the
// EAPOL status doesn't carry: exactly from the session's EAPOLClientProfile
// when it is profile-based (UniqueIdentifier is the profile ID), with the
// SSID otherwise matched from the BSSID against known networks (root + Full
// Disk Access). When the profile came from MDM, the mdm_payload_type /
// mdm_profile_* columns come from installedProfiles.
func applyDarwinProfile(s *Dot1XStatus, installedProfiles func() []byte) {
	if s.UniqueIdentifier != "" {
		if b, err := os.ReadFile(eapolClientConfigPlist); err == nil {
			p := eapolProfileInfo(b, s.UniqueIdentifier)
			s.ProfileName, s.MDMPayloadUUID, s.Identity = p.name, p.payloadUUID, p.identity
			s.TLSTrustedServerNames, s.ServerValidation = p.trustedServerNames, p.serverValidation
			if s.InterfaceType == "wifi" {
				s.SSID = p.ssid
			}
		}
	}
	if s.MDMPayloadUUID != "" {
		s.MDMPayloadType, s.MDMProfileName, s.MDMProfileIdentifier = mdmPayloadInfo(installedProfiles(), s.MDMPayloadUUID)
	}
	if s.SSID == "" && s.InterfaceType == "wifi" && s.AuthenticatorMACAddress != "" {
		if b, err := os.ReadFile(knownNetworksPlist); err == nil {
			s.SSID = knownNetworkSSID(b, s.AuthenticatorMACAddress)
		}
	}
}

func (b *productionBackend) GetStatus(ifname string) (Dot1XStatus, error) {
	cName := C.CString(ifname)
	defer C.free(unsafe.Pointer(cName))

	var (
		cState            C.int
		cSupplicantState  C.int
		cEAPType          C.int
		cEAPTypeName      *C.char
		cClientStatus     C.int
		cDomainError      C.int
		cDomainErrorSet   C.int
		cAuthMAC          *C.uint8_t
		cAuthMACLen       C.CFIndex
		cMode             C.int
		cTLSResumed       C.int
		cCertChainData    *C.uint8_t
		cCertChainLen     C.CFIndex
		cTLSTrustStatus   C.int
		cTLSCipher        C.int
		cTLSProtoVersion  *C.char
		cInnerEAPType     C.int
		cInnerEAPTypeName *C.char
		cLastTimestamp    *C.char
		cAuthSince        *C.char
		cUniqueID         *C.char
	)

	ret := C.dot1x_query(
		cName,
		&cState,
		&cSupplicantState,
		&cEAPType,
		&cEAPTypeName,
		&cClientStatus,
		&cDomainError,
		&cDomainErrorSet,
		&cAuthMAC,
		&cAuthMACLen,
		&cMode,
		&cTLSResumed,
		&cCertChainData,
		&cCertChainLen,
		&cTLSTrustStatus,
		&cTLSCipher,
		&cTLSProtoVersion,
		&cInnerEAPType,
		&cInnerEAPTypeName,
		&cLastTimestamp,
		&cAuthSince,
		&cUniqueID,
	)

	var ifType string
	if cType := C.sc_interface_type(cName); cType != nil {
		ifType = mapSCInterfaceType(C.GoString(cType))
		C.free(unsafe.Pointer(cType))
	}

	r := eapolRaw{
		ret:                          int(ret),
		interfaceType:                ifType,
		state:                        int(cState),
		supplicantState:              int(cSupplicantState),
		eapType:                      int(cEAPType),
		eapTypeName:                  C.GoString(cEAPTypeName),
		clientStatus:                 int(cClientStatus),
		domainSpecificError:          int(cDomainError),
		domainSpecificErrorPresent:   cDomainErrorSet != 0,
		mode:                         int(cMode),
		tlsSessionWasResumed:         int(cTLSResumed),
		tlsTrustClientStatus:         int(cTLSTrustStatus),
		tlsNegotiatedCipher:          int(cTLSCipher),
		tlsNegotiatedProtocolVersion: C.GoString(cTLSProtoVersion),
		innerEAPType:                 int(cInnerEAPType),
		innerEAPTypeName:             C.GoString(cInnerEAPTypeName),
		lastStatusTimestamp:          C.GoString(cLastTimestamp),
		authenticatedSince:           C.GoString(cAuthSince),
		uniqueIdentifier:             C.GoString(cUniqueID),
	}
	if cAuthMAC != nil && cAuthMACLen > 0 {
		r.authMAC = C.GoBytes(unsafe.Pointer(cAuthMAC), C.int(cAuthMACLen))
	}
	if cCertChainData != nil && cCertChainLen > 0 {
		r.certChain = C.GoBytes(unsafe.Pointer(cCertChainData), C.int(cCertChainLen))
	}
	if ret == -1 {
		r.loadError = C.GoString(C.dot1x_load_error())
	}

	for _, p := range []unsafe.Pointer{
		unsafe.Pointer(cEAPTypeName), unsafe.Pointer(cAuthMAC), unsafe.Pointer(cCertChainData),
		unsafe.Pointer(cTLSProtoVersion), unsafe.Pointer(cInnerEAPTypeName),
		unsafe.Pointer(cLastTimestamp), unsafe.Pointer(cAuthSince), unsafe.Pointer(cUniqueID),
	} {
		C.free(p) // free(NULL) is a no-op
	}

	s, err := statusFromEAPOL(ifname, r)
	if err == nil {
		applyDarwinProfile(&s, b.installedProfiles)
		// The interface's current (possibly private/randomized) address.
		if i, ierr := net.InterfaceByName(ifname); ierr == nil && len(i.HardwareAddr) == 6 {
			s.MACAddress = macAddrString(i.HardwareAddr)
		}
	}
	return s, err
}

// defaultInterfaces returns the real en* interfaces on this host, falling back
// to en0-en9 if enumeration fails or finds none.
func defaultInterfaces() []string {
	if all, err := net.Interfaces(); err == nil {
		names := make([]string, 0, len(all))
		for _, i := range all {
			names = append(names, i.Name)
		}
		if en := enInterfaceNames(names); len(en) > 0 {
			return en
		}
	}
	ifaces := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		ifaces = append(ifaces, "en"+strconv.Itoa(i))
	}
	return ifaces
}

var enIfaceRe = regexp.MustCompile(`^en[0-9]+$`)

// enInterfaceNames returns the names matching ^en[0-9]+$, in input order.
func enInterfaceNames(names []string) []string {
	var out []string
	for _, n := range names {
		if enIfaceRe.MatchString(n) {
			out = append(out, n)
		}
	}
	return out
}
