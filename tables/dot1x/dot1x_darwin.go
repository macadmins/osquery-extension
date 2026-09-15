//go:build darwin

package dot1x

/*
#include <CoreFoundation/CoreFoundation.h>
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

// get_dict_bool_v extracts a boolean value for a CFString key from the dictionary.
static int get_dict_bool_v(CFDictionaryRef d, CFStringRef key) {
	CFTypeRef v = NULL;
	CFDictionaryGetValueIfPresent(d, key, &v);
	return cfbool_int(v);
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
	char** out_unique_identifier
) {
	// Initialize all outputs before any early return path.
	*out_state = -1;
	*out_supplicant_state = -1;
	*out_eap_type = -1;
	*out_eap_type_name = NULL;
	*out_client_status = -1;
	*out_domain_specific_error = -1;
	*out_auth_mac = NULL;
	*out_auth_mac_len = 0;
	*out_mode = -1;
	*out_tls_session_was_resumed = 0;
	*out_cert_chain_data = NULL;
	*out_cert_chain_len = 0;
	*out_tls_trust_client_status = -1;
	*out_tls_negotiated_cipher = -1;
	*out_tls_negotiated_protocol_version = NULL;
	*out_inner_eap_type = -1;
	*out_inner_eap_type_name = NULL;
	*out_last_status_timestamp = NULL;
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
	*out_domain_specific_error = get_dict_int_v(status, kDomainSpecificError);
	*out_auth_mac = get_dict_data_v(status, kAuthenticatorMACAddress, out_auth_mac_len);
	*out_mode = get_dict_int_v(status, kMode);
	*out_unique_identifier = get_dict_string_v(status, kUniqueIdentifier);

	// LastStatusTimestamp lives in the main status dict as a CFDate.
	{
		CFTypeRef tsVal = NULL;
		CFDictionaryGetValueIfPresent(status, kLastStatusTimestamp, &tsVal);
		*out_last_status_timestamp = cfdate_iso8601(tsVal);
	}

	// TLSSessionWasResumed, TLSServerCertificateChain,
	// TLSTrustClientStatus, and TLSNegotiatedProtocolVersion live in
	// AdditionalProperties sub-dictionary.
	{
		CFTypeRef apVal = NULL;
		if (CFDictionaryGetValueIfPresent(status, kAdditionalProperties, &apVal) && apVal) {
			if (CFGetTypeID(apVal) == CFDictionaryGetTypeID()) {
				CFDictionaryRef apDict = (CFDictionaryRef)apVal;
				*out_tls_session_was_resumed = get_dict_bool_v(apDict, kTLSSessionWasResumed);
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
*/
import "C"
import (
	"fmt"
	"strconv"
	"sync"
	"unsafe"
)

// productionBackend calls EAPOLControlCopyStateAndStatus via cgo.
type productionBackend struct{}

var loadOnce sync.Once

func newBackend() Dot1XBackend {
	loadOnce.Do(func() { C.load_dot1x() })
	return productionBackend{}
}

func (productionBackend) GetStatus(ifname string) (Dot1XStatus, error) {
	cName := C.CString(ifname)
	defer C.free(unsafe.Pointer(cName))

	var (
		cState            C.int
		cSupplicantState  C.int
		cEAPType          C.int
		cEAPTypeName      *C.char
		cClientStatus     C.int
		cDomainError      C.int
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
		&cUniqueID,
	)

	s := Dot1XStatus{
		Interface:            ifname,
		State:                int(cState),
		SupplicantState:      int(cSupplicantState),
		EAPType:              int(cEAPType),
		ClientStatus:         int(cClientStatus),
		DomainSpecificError:  int(cDomainError),
		Mode:                 int(cMode),
		TLSSessionWasResumed: cTLSResumed == 1,
	}

	defer func() {
		if cEAPTypeName != nil {
			C.free(unsafe.Pointer(cEAPTypeName))
		}
		if cAuthMAC != nil {
			C.free(unsafe.Pointer(cAuthMAC))
		}
		if cCertChainData != nil {
			C.free(unsafe.Pointer(cCertChainData))
		}
		if cTLSProtoVersion != nil {
			C.free(unsafe.Pointer(cTLSProtoVersion))
		}
		if cInnerEAPTypeName != nil {
			C.free(unsafe.Pointer(cInnerEAPTypeName))
		}
		if cLastTimestamp != nil {
			C.free(unsafe.Pointer(cLastTimestamp))
		}
		if cUniqueID != nil {
			C.free(unsafe.Pointer(cUniqueID))
		}
	}()

	if cEAPTypeName != nil {
		s.EAPTypeName = C.GoString(cEAPTypeName)
	}
	if cAuthMAC != nil && cAuthMACLen == 6 {
		macBytes := unsafe.Slice((*byte)(unsafe.Pointer(cAuthMAC)), 6)
		s.AuthenticatorMACAddress = macAddrString(macBytes)
	}
	if cCertChainData != nil && cCertChainLen > 0 {
		s.TLSServerCertificateChain, s.TLSServerCertificateSHA1, s.TLSServerCertificateSerials = parseTLSCertChain(
			unsafe.Slice((*byte)(unsafe.Pointer(cCertChainData)), int(cCertChainLen)))
	}
	s.TLSTrustClientStatus = int(cTLSTrustStatus)
	s.TLSNegotiatedCipher = int(cTLSCipher)
	if cTLSProtoVersion != nil {
		s.TLSNegotiatedProtocolVersion = C.GoString(cTLSProtoVersion)
	}
	s.InnerEAPType = int(cInnerEAPType)
	if cInnerEAPTypeName != nil {
		s.InnerEAPTypeName = C.GoString(cInnerEAPTypeName)
	}
	if cLastTimestamp != nil {
		s.LastStatusTimestamp = C.GoString(cLastTimestamp)
	}
	if cUniqueID != nil {
		s.UniqueIdentifier = C.GoString(cUniqueID)
	}

	if ret != 0 {
		if ret == -1 {
			reason := "unknown error"
			if cerr := C.dot1x_load_error(); cerr != nil {
				reason = C.GoString(cerr)
			}
			return s, fmt.Errorf("%w: could not load EAPOLControlCopyStateAndStatus for %s: %s", ErrBackendUnavailable, ifname, reason)
		}
		if ret == -2 {
			return s, fmt.Errorf("EAPOLControlCopyStateAndStatus returned no status for %s", ifname)
		}
		return s, fmt.Errorf("EAPOLControlCopyStateAndStatus returned %d for %s", int(ret), ifname)
	}

	return s, nil
}

func defaultInterfaces() []string {
	ifaces := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		ifaces = append(ifaces, "en"+strconv.Itoa(i))
	}
	return ifaces
}
