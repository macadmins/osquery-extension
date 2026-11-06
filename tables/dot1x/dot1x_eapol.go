package dot1x

// Pure-Go macOS EAPOL status conversion. The cgo call to
// EAPOLControlCopyStateAndStatus lives in dot1x_darwin.go, which copies its
// out-params into an eapolRaw; everything that interprets them lives here (no
// build tag) so it is compiled and unit-tested on every platform.

import "fmt"

// eapolRaw holds dot1x_query's out-params as Go values. Numeric fields use -1
// when absent, as set by dot1x_query.
type eapolRaw struct {
	// ret is dot1x_query's return: 0 ok, -1 framework load failure, -2 no
	// status dictionary, otherwise the EAPOLControl error code.
	ret int
	// loadError is the dlopen/dlsym failure reason (only meaningful when ret == -1).
	loadError string

	interfaceType                string // "wifi"/"ethernet" from SystemConfiguration
	state                        int
	supplicantState              int
	eapType                      int
	eapTypeName                  string
	clientStatus                 int
	domainSpecificError          int
	domainSpecificErrorPresent   bool
	authMAC                      []byte
	mode                         int
	tlsSessionWasResumed         int // -1 absent, 0 false, 1 true
	certChain                    []byte
	tlsTrustClientStatus         int
	tlsNegotiatedCipher          int
	tlsNegotiatedProtocolVersion string
	innerEAPType                 int
	innerEAPTypeName             string
	lastStatusTimestamp          string
	authenticatedSince           string // eap8021x "Timestamp": when the session first became Authenticated
	uniqueIdentifier             string
}

// statusFromEAPOL converts dot1x_query output into a Dot1XStatus. The status
// is populated even when an error is returned.
func statusFromEAPOL(ifname string, r eapolRaw) (Dot1XStatus, error) {
	s := Dot1XStatus{
		Interface:                    ifname,
		State:                        r.state,
		SupplicantState:              r.supplicantState,
		InterfaceType:                r.interfaceType,
		EAPType:                      r.eapType,
		EAPTypeName:                  r.eapTypeName,
		ClientStatus:                 r.clientStatus,
		Mode:                         r.mode,
		TLSSessionWasResumed:         r.tlsSessionWasResumed,
		TLSTrustClientStatus:         r.tlsTrustClientStatus,
		TLSNegotiatedCipher:          r.tlsNegotiatedCipher,
		TLSNegotiatedProtocolVersion: r.tlsNegotiatedProtocolVersion,
		InnerEAPType:                 r.innerEAPType,
		InnerEAPTypeName:             r.innerEAPTypeName,
		LastStatusTimestamp:          r.lastStatusTimestamp,
		UniqueIdentifier:             r.uniqueIdentifier,
	}
	if r.supplicantState == 4 { // Authenticated
		s.AuthenticatedSince = r.authenticatedSince
	}
	if r.domainSpecificErrorPresent {
		v := r.domainSpecificError
		s.DomainSpecificError = &v
	}
	if len(r.authMAC) == 6 {
		s.AuthenticatorMACAddress = macAddrString(r.authMAC)
	}
	s.TLSServerCertificateChain, s.TLSServerCertificateSHA1, s.TLSServerCertificateSerials, s.TLSServerCertificateNotAfter = parseTLSCertChain(r.certChain)

	switch r.ret {
	case 0:
		return s, nil
	case -1:
		reason := r.loadError
		if reason == "" {
			reason = "unknown error"
		}
		return s, fmt.Errorf("%w: could not load EAPOLControlCopyStateAndStatus for %s: %s", ErrBackendUnavailable, ifname, reason)
	case -2:
		return s, fmt.Errorf("EAPOLControlCopyStateAndStatus returned no status for %s", ifname)
	default:
		return s, fmt.Errorf("EAPOLControlCopyStateAndStatus returned %d for %s", r.ret, ifname)
	}
}
