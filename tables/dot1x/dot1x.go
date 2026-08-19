package dot1x

import (
	"context"
	"crypto/sha1" //nolint:gosec // sha1 used only for certificate fingerprint display
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/osquery/osquery-go/plugin/table"
)

// Dot1XStatus holds the 802.1X supplicant state and status for a single
// interface. On macOS the values come from the EAPOL (EAP over LAN) layer of
// the EAP8021X framework; on Windows they come from the WLAN/OneX APIs.
type Dot1XStatus struct {
	Interface                    string
	State                        int    // EAPOLControlState: 0=Idle,1=Starting,2=Running,3=Stopping
	SupplicantState              int    // 802.1X supplicant state machine value
	EAPType                      int    // EAP method code (e.g. 13=TLS)
	EAPTypeName                  string // human-readable EAP method (e.g. "EAP-TLS")
	ClientStatus                 int    // 0=ok, nonzero=error code
	DomainSpecificError          int
	AuthenticatorMACAddress      string // colon-separated
	Mode                         int    // 0=None,1=User,2=LoginWindow,3=System
	TLSSessionWasResumed         bool
	TLSServerCertificateChain    string // pipe-separated subject DNs in LDAP notation
	TLSServerCertificateSHA1     string // comma-separated colon-separated SHA-1 fingerprints
	TLSServerCertificateSerials  string // comma-separated hex serial numbers
	TLSTrustedRootCASHA1         string // comma-separated SHA-1 thumbprints of the trusted root CAs configured for server validation (Windows profile)
	TLSTrustClientStatus         int    // trust evaluation error code (0=ok)
	TLSNegotiatedProtocolVersion string // "1.2" or "1.3"
	TLSNegotiatedCipher          int    // TLS cipher suite code
	InnerEAPType                 int    // inner EAP method for tunneled auth (PEAP/TTLS)
	InnerEAPTypeName             string // human-readable inner EAP method
	LastStatusTimestamp          string // ISO 8601
	UniqueIdentifier             string
}

// Dot1XBackend fetches 802.1X status for a named interface. The production
// implementation is platform-specific: macOS calls EAPOLControlCopyStateAndStatus
// from EAP8021X.framework via cgo (dot1x_darwin.go); Windows queries wlanapi.dll
// and parses WLAN profile XML (dot1x_windows.go); other platforms use a noop
// backend that reports ErrBackendUnavailable (dot1x_other.go). Tests inject a fake.
type Dot1XBackend interface {
	GetStatus(ifname string) (Dot1XStatus, error)
}

// ErrBackendUnavailable is returned by GetStatus when a platform's 802.1X
// backend cannot be initialized (e.g. EAP8021X.framework on macOS or
// wlanapi.dll on Windows) — a systemic failure, not a per-interface one.
// Each backend wraps it with platform-specific detail.
var ErrBackendUnavailable = errors.New("802.1X backend unavailable")

// stateNames maps EAPOLControlState to human-readable strings.
var stateNames = map[int]string{
	0: "Idle",
	1: "Starting",
	2: "Running",
	3: "Stopping",
}

// supplicantStateNames maps SupplicantState to human-readable strings.
var supplicantStateNames = map[int]string{
	0: "Disconnected",
	1: "Connecting",
	2: "Acquired",
	3: "Authenticating",
	4: "Authenticated",
	5: "Held",
	6: "Logoff",
	7: "Inactive",
	8: "No Authenticator",
}

// eapTypeNames maps EAPType codes to human-readable strings.
var eapTypeNames = map[int]string{
	1:  "Identity",
	2:  "Notification",
	3:  "Nak",
	4:  "MD5-Challenge",
	5:  "One-Time Password",
	6:  "Generic Token Card",
	13: "EAP-TLS",
	17: "Cisco LEAP",
	18: "EAP-SIM",
	19: "SRP-SHA1",
	21: "EAP-TTLS",
	23: "EAP-AKA",
	25: "PEAP",
	26: "MSCHAPv2",
	33: "Extensions",
	43: "EAP-FAST",
	50: "EAP-AKA-Prime",
}

// modeNames maps EAPOLControlMode to human-readable strings.
var modeNames = map[int]string{
	0: "None",
	1: "User",
	2: "LoginWindow",
	3: "System",
}

// Dot1XStatusColumns returns the column definitions.
func Dot1XStatusColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("interface"),
		table.IntegerColumn("state"),
		table.TextColumn("state_name"),
		table.IntegerColumn("supplicant_state"),
		table.TextColumn("supplicant_state_name"),
		table.IntegerColumn("eap_type"),
		table.TextColumn("eap_type_name"),
		table.IntegerColumn("client_status"),
		table.IntegerColumn("domain_specific_error"),
		table.TextColumn("authenticator_mac_address"),
		table.IntegerColumn("mode"),
		table.TextColumn("mode_name"),
		table.IntegerColumn("tls_session_was_resumed"),
		table.TextColumn("tls_server_certificate_chain"),
		table.TextColumn("tls_server_certificate_sha1"),
		table.TextColumn("tls_server_certificate_serials"),
		table.TextColumn("tls_trusted_root_ca_sha1"),
		table.IntegerColumn("tls_trust_client_status"),
		table.TextColumn("tls_negotiated_protocol_version"),
		table.IntegerColumn("tls_negotiated_cipher"),
		table.IntegerColumn("inner_eap_type"),
		table.TextColumn("inner_eap_type_name"),
		table.TextColumn("last_status_timestamp"),
		table.TextColumn("unique_identifier"),
	}
}

// Dot1XStatusGenerate generates table rows by querying each interface.
func Dot1XStatusGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	return generateRows(ctx, newBackend(), queryContext)
}

// generateRows queries the backend for the requested interfaces. If the
// constraint "interface" is provided, only that interface is queried;
// otherwise en0 through en9 are probed. The context is checked before each
// backend call to support cancellation.
func generateRows(ctx context.Context, backend Dot1XBackend, queryContext table.QueryContext) ([]map[string]string, error) {
	ifaces := interfacesToQuery(backend, queryContext)
	var rows []map[string]string

	for _, ifname := range ifaces {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s, err := backend.GetStatus(ifname)
		if err != nil {
			if errors.Is(err, ErrBackendUnavailable) {
				return nil, err
			}
			continue
		}
		rows = append(rows, rowFromStatus(s))
	}

	return rows, nil
}

// interfaceLister is an optional backend capability: a backend that already
// enumerates interfaces (e.g. the Windows WLAN backend) can supply the default
// interface list from its own cached snapshot, avoiding a second enumeration.
type interfaceLister interface {
	interfaceNames() []string
}

// interfacesToQuery returns the list of interfaces to query. If a WHERE
// constraint "interface" is present, only that interface is returned;
// otherwise the platform-specific default list is used (e.g. real
// wireless adapter names on Windows, en0-en9 on macOS).
func interfacesToQuery(backend Dot1XBackend, queryContext table.QueryContext) []string {
	if constraints, ok := queryContext.Constraints["interface"]; ok {
		seen := make(map[string]struct{})
		var ifaces []string
		for _, c := range constraints.Constraints {
			if c.Operator == table.OperatorEquals && c.Expression != "" {
				if _, ok := seen[c.Expression]; ok {
					continue
				}
				seen[c.Expression] = struct{}{}
				ifaces = append(ifaces, c.Expression)
			}
		}
		if len(ifaces) > 0 {
			return ifaces
		}
	}

	// Prefer the backend's own enumeration when it provides one (the Windows
	// backend shares its per-generation snapshot, so we must NOT also call the
	// package defaultInterfaces() — that would enumerate a second time);
	// otherwise use the package default. A non-nil result is authoritative even
	// when empty: a Windows host with no WLAN adapters returns an empty slice
	// (query nothing) rather than falling through to the macOS-style en0-en9
	// probe list. Only a nil result (defaults unknown) uses that fallback.
	var defaults []string
	if l, ok := backend.(interfaceLister); ok {
		defaults = l.interfaceNames()
	} else {
		defaults = defaultInterfaces()
	}
	if defaults != nil {
		return defaults
	}
	fallback := make([]string, 10)
	for i := range fallback {
		fallback[i] = "en" + strconv.Itoa(i)
	}
	return fallback
}

func rowFromStatus(s Dot1XStatus) map[string]string {
	row := map[string]string{
		"interface":                       s.Interface,
		"state":                           itoa(s.State),
		"state_name":                      lookupName(stateNames, s.State),
		"supplicant_state":                itoa(s.SupplicantState),
		"supplicant_state_name":           lookupName(supplicantStateNames, s.SupplicantState),
		"eap_type":                        itoa(s.EAPType),
		"eap_type_name":                   "",
		"client_status":                   itoa(s.ClientStatus),
		"domain_specific_error":           itoa(s.DomainSpecificError),
		"authenticator_mac_address":       s.AuthenticatorMACAddress,
		"mode":                            itoa(s.Mode),
		"mode_name":                       lookupName(modeNames, s.Mode),
		"tls_server_certificate_chain":    s.TLSServerCertificateChain,
		"tls_server_certificate_sha1":     s.TLSServerCertificateSHA1,
		"tls_server_certificate_serials":  s.TLSServerCertificateSerials,
		"tls_trusted_root_ca_sha1":        s.TLSTrustedRootCASHA1,
		"tls_trust_client_status":         itoa(s.TLSTrustClientStatus),
		"tls_negotiated_protocol_version": s.TLSNegotiatedProtocolVersion,
		"tls_negotiated_cipher":           itoa(s.TLSNegotiatedCipher),
		"inner_eap_type":                  itoa(s.InnerEAPType),
		"inner_eap_type_name":             "",
		"last_status_timestamp":           s.LastStatusTimestamp,
		"unique_identifier":               s.UniqueIdentifier,
	}
	if s.TLSSessionWasResumed {
		row["tls_session_was_resumed"] = "1"
	} else {
		row["tls_session_was_resumed"] = "0"
	}
	if s.EAPTypeName != "" {
		row["eap_type_name"] = s.EAPTypeName
	} else if s.EAPType > 0 {
		row["eap_type_name"] = lookupName(eapTypeNames, s.EAPType)
	}
	if s.InnerEAPTypeName != "" {
		row["inner_eap_type_name"] = s.InnerEAPTypeName
	} else if s.InnerEAPType > 0 {
		row["inner_eap_type_name"] = lookupName(eapTypeNames, s.InnerEAPType)
	}
	return row
}

func itoa(v int) string {
	if v < 0 {
		return ""
	}
	return strconv.Itoa(v)
}

func lookupName(names map[int]string, v int) string {
	if name, ok := names[v]; ok {
		return name
	}
	if v < 0 {
		return ""
	}
	return "Unknown(" + strconv.Itoa(v) + ")"
}

// parseTLSCertChain unpacks a packed buffer of DER certificates (each
// prefixed with a 4-byte big-endian length) and returns (subject DNs in LDAP
// notation, SHA-1 fingerprints, serial numbers). DNs are pipe-separated
// ("|") because LDAP DNs themselves use commas as RDN separators. If the
// input is entirely empty the results are empty strings; if parsing of a
// single cert fails, it is skipped and previously-parsed certs are retained.
func parseTLSCertChain(packed []byte) (subjects, sha1s, serials string) {
	if len(packed) == 0 {
		return "", "", ""
	}
	var dnParts, sha1Parts, serialParts []string
	offset := 0
	for offset+4 <= len(packed) {
		length := binary.BigEndian.Uint32(packed[offset : offset+4])
		offset += 4
		if length == 0 {
			continue
		}
		// Validate with uint32 arithmetic before converting to int,
		// avoiding overflow on 32-bit platforms or malformed input.
		if uint64(offset)+uint64(length) > uint64(len(packed)) {
			break
		}
		intLen := int(length)
		der := packed[offset : offset+intLen]
		offset += intLen
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		dnParts = append(dnParts, renderRDNSequence(reverseRDNSequence(cert.Subject.ToRDNSequence())))
		sha1Parts = append(sha1Parts, sha1String(sha1.Sum(cert.Raw)))
		serialParts = append(serialParts, cert.SerialNumber.Text(16))
	}
	return strings.Join(dnParts, "|"), strings.Join(sha1Parts, ","), strings.Join(serialParts, ",")
}

// renderRDNSequence converts an x509 RDN sequence to LDAP notation
// (e.g. "CN=radius.campus.edu,OU=IT,O=Campus"). The input should be in
// display order (most-specific first). Use reverseRDNSequence to convert
// from cert.Subject.ToRDNSequence() which returns least-specific first.
func renderRDNSequence(rdns pkix.RDNSequence) string {
	var parts []string
	for _, rdn := range rdns {
		var rdnParts []string
		for _, atv := range rdn {
			key := atv.Type.String()
			// Shorten OID strings to common names.
			switch key {
			case "2.5.4.3":
				key = "CN"
			case "2.5.4.6":
				key = "C"
			case "2.5.4.7":
				key = "L"
			case "2.5.4.8":
				key = "ST"
			case "2.5.4.10":
				key = "O"
			case "2.5.4.11":
				key = "OU"
			}
			val, ok := atv.Value.(string)
			if !ok {
				val = fmt.Sprintf("%v", atv.Value)
			}
			rdnParts = append(rdnParts, fmt.Sprintf("%s=%s", key, escapeDN(val)))
		}
		parts = append(parts, strings.Join(rdnParts, "+"))
	}
	return strings.Join(parts, ",")
}

// needsEscape checks whether a character in s at position i needs RFC4514
// escaping. Handles: special chars, leading/trailing space, leading #, and
// control characters.
func needsEscape(s string, i int) bool {
	r := s[i]
	if r == ',' || r == '+' || r == '"' || r == '\\' || r == '<' || r == '>' || r == ';' || r == '=' || r == 0x7f || r < ' ' {
		return true
	}
	if r == ' ' && (i == 0 || i == len(s)-1) {
		return true
	}
	if r == '#' && i == 0 {
		return true
	}
	return false
}

// escapeDN escapes a DN attribute value per RFC4514 section 2.4.
func escapeDN(s string) string {
	if s == "" {
		return s
	}
	needs := false
	for i := range s {
		if needsEscape(s, i) {
			needs = true
			break
		}
	}
	if !needs {
		return s
	}
	var buf strings.Builder
	for i, r := range s {
		switch r {
		case ',':
			buf.WriteString("\\,")
		case '+':
			buf.WriteString("\\+")
		case '"':
			buf.WriteString("\\\"")
		case '\\':
			buf.WriteString("\\\\")
		case '<':
			buf.WriteString("\\<")
		case '>':
			buf.WriteString("\\>")
		case ';':
			buf.WriteString("\\;")
		case '=':
			buf.WriteString("\\=")
		case ' ':
			if i == 0 || i == len(s)-1 {
				buf.WriteString("\\ ")
			} else {
				buf.WriteRune(' ')
			}
		case '#':
			if i == 0 {
				buf.WriteString("\\#")
			} else {
				buf.WriteRune('#')
			}
		default:
			if r < ' ' || r == 0x7f {
				fmt.Fprintf(&buf, "\\%02X", r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	return buf.String()
}

// reverseRDNSequence returns a new RDNSequence in reverse order.
// cert.Subject.ToRDNSequence() returns least-specific-first (C,O,OU,CN);
// this produces display order (CN,OU,O,C).
func reverseRDNSequence(rdns pkix.RDNSequence) pkix.RDNSequence {
	if len(rdns) == 0 {
		return rdns
	}
	reversed := make(pkix.RDNSequence, len(rdns))
	for i, rdn := range rdns {
		reversed[len(rdns)-1-i] = rdn
	}
	return reversed
}

// sha1String formats a 20-byte SHA-1 hash as colon-separated hex pairs.
func sha1String(hash [20]byte) string {
	b := make([]byte, 0, 59) // 19 colons + 40 hex chars
	for i, v := range hash {
		if i > 0 {
			b = append(b, ':')
		}
		b = append(b, hexChar(v>>4), hexChar(v&0x0f))
	}
	return string(b)
}

func hexChar(n byte) byte {
	n &= 0xf
	if n < 10 {
		return '0' + n
	}
	return 'a' + n - 10
}

// macAddrString formats 6 raw bytes as a colon-separated MAC address.
func macAddrString(b []byte) string {
	if len(b) != 6 {
		return ""
	}
	buf := make([]byte, 0, 17) // 5 colons + 12 hex chars
	for i, v := range b {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hexChar(v>>4), hexChar(v&0x0f))
	}
	return string(buf)
}
