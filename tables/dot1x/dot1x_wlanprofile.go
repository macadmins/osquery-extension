package dot1x

// WLAN profile XML parsing for the Windows backend. dot3svc LAN (wired)
// profiles share the OneX/EAPConfig schema and are parsed here too. This logic is pure Go
// (no syscalls), so it lives outside the //go:build windows file and is
// compiled, tested, and coverage-counted on every platform.

import (
	"encoding/xml"
	"io"
	"strconv"
	"strings"
)

// wlanProfileInfo holds the 802.1X-relevant fields parsed from a Windows WLAN
// profile XML. Numeric fields are -1 when absent/invalid.
type wlanProfileInfo struct {
	eapType           int    // outer EAP method type (first <EapMethod><Type>)
	innerEAPType      int    // inner/tunneled EAP method type (see parseWLANProfile)
	authMode          int    // EAPOLControlMode mapped from <authMode>
	trustedRootCASHA1 string // comma-separated colon-delimited SHA-1 thumbprints
	// trustedServerNames is the outer method's <ServerNames> (';'-separated
	// in the profile), comma-joined.
	trustedServerNames string
	serverValidation   string // see serverValidation; "" for a non-802.1X profile
	useOneX            bool   // <useOneX> (WLAN) or <OneXEnabled> (LAN); defaults to true for LAN
}

// parseWLANProfile extracts every 802.1X field from a WLAN profile XML in a
// single token pass. Matching is by local element name, so namespace prefixes
// and attributes on elements are tolerated. The outer EAP type is the <Type>
// inside the first <EapMethod>. The inner type (first found wins) is either the
// <Type> of an <Eap> nested inside another <Eap> (PEAP:
// Config/Eap/EapType/Eap/Type) or the <Type> inside a second <EapMethod>
// (EAP-TTLS nests a full EapHostConfig under Phase2Authentication); authMode is the first
// <authMode>; trusted root CA thumbprints are the outer method's valid
// <TrustedRootCA> / <TrustedRootCAHash> values (comma-joined).
//
// Server validation settings are read from the outer method only (Eap depth
// <= 1: EAP-TLS/PEAP Config/Eap/EapType, or TTLS EapTtls outside
// Phase2Authentication); an inner method's own ServerValidation (PEAP Eap
// depth 2, or TTLS Phase2Authentication) is ignored. They are the outer
// <ServerNames>, and the Windows 7+ switches <PerformServerValidation> (PEAP
// PeapExtensions, EAP-TLS V2 EapType, or a ServerValidation attribute; false
// = no validation at all) and <AcceptServerName> (false = ServerNames is not
// enforced).
func parseWLANProfile(xmlStr string) wlanProfileInfo {
	info := wlanProfileInfo{eapType: -1, innerEAPType: -1, authMode: -1}
	dec := xml.NewDecoder(strings.NewReader(xmlStr))
	// xmlStr is already a Go (UTF-8) string; ignore any encoding="UTF-16"
	// declaration a profile file on disk may carry.
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	eapMethodCount := 0
	eapDepth := 0 // nesting level of <Eap> elements
	gotAuthMode := false
	sawOneX := false
	var caHashes, serverNames []string
	gotServerNames := false
	inPhase2 := false // inside TTLS Phase2Authentication (the inner method)
	validate, acceptNames := true, true
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		if ee, ok := tok.(xml.EndElement); ok {
			switch ee.Name.Local {
			case "Eap":
				eapDepth--
			case "Phase2Authentication":
				inPhase2 = false
			}
			continue
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		outer := eapDepth <= 1 && !inPhase2 // see doc: outer method's settings only
		switch se.Name.Local {
		case "LANProfile":
			// OneXEnabled is optional and defaults to true for LAN profiles.
			// An explicit value below overrides this; WLAN keeps its false default.
			info.useOneX = true
		case "Phase2Authentication":
			inPhase2 = true
		case "Eap":
			eapDepth++
		case "Type":
			// Schema order puts <Type> first in <Eap>, so the first <Type>
			// at Eap depth 2 is the nested Eap's own (inner) method type.
			if eapDepth == 2 && info.innerEAPType == -1 {
				if v, ok := readIntCharData(dec); ok {
					info.innerEAPType = v
				}
			}
		case "EapMethod":
			eapMethodCount++
			if t, ok := readEapMethodType(dec); ok {
				switch {
				case eapMethodCount == 1:
					info.eapType = t
				case eapMethodCount == 2 && info.innerEAPType == -1:
					info.innerEAPType = t
				}
			}
		case "OneX":
			sawOneX = true
		case "useOneX", "OneXEnabled": // WLAN, LAN (dot3svc) profile
			if v, ok := readCharData(dec); ok {
				// xs:boolean: "true" or "1".
				b := strings.TrimSpace(v)
				info.useOneX = b == "true" || b == "1"
			}
		case "authMode":
			if !gotAuthMode {
				if s, ok := readCharData(dec); ok {
					info.authMode = mapAuthMode(strings.TrimSpace(s))
					gotAuthMode = true
				}
			}
		case "ServerValidation":
			for _, a := range se.Attr {
				if outer && a.Name.Local == "PerformServerValidation" && xsFalse(a.Value) {
					validate = false
				}
			}
		case "ServerNames":
			if outer && !gotServerNames {
				if v, ok := readCharData(dec); ok {
					gotServerNames = true
					for _, n := range strings.Split(v, ";") {
						if n = strings.TrimSpace(n); n != "" {
							serverNames = append(serverNames, n)
						}
					}
				}
			}
		case "PerformServerValidation", "AcceptServerName":
			if v, ok := readCharData(dec); ok && outer && xsFalse(v) {
				if se.Name.Local == "AcceptServerName" {
					acceptNames = false
				} else {
					validate = false
				}
			}
		case "TrustedRootCA", "TrustedRootCAHash": // PEAP/EAP-TLS, EAP-TTLS
			if s, ok := readCharData(dec); ok && outer {
				if hex, ok := normalizeThumbprint(s); ok {
					caHashes = append(caHashes, formatSHA1Hex(hex))
				}
			}
		}
	}
	// machineOrUser is the schema default when an 802.1X profile omits it.
	if sawOneX && !gotAuthMode {
		info.authMode = modeMachineOrUser
	}
	info.trustedRootCASHA1 = strings.Join(caHashes, ",")
	info.trustedServerNames = strings.Join(serverNames, ",")
	if sawOneX {
		info.serverValidation = serverValidation(len(caHashes) > 0, len(serverNames) > 0 && acceptNames, validate)
	}
	return info
}

// xsFalse reports whether an xs:boolean value is false ("false" or "0").
func xsFalse(v string) bool {
	v = strings.TrimSpace(v)
	return v == "false" || v == "0"
}

// readEapMethodType reads forward from just after an <EapMethod> StartElement
// and returns the int value of the first <Type> nested within it. It always
// consumes through the matching </EapMethod> before returning, so the caller's
// scan stays aligned and any nested <EapMethod> is swallowed here rather than
// being miscounted as a separate method. Returns (0, false) if no numeric
// <Type> was found.
func readEapMethodType(dec *xml.Decoder) (int, bool) {
	depth := 1 // we are inside the EapMethod element
	value, found := 0, false
	for {
		tok, err := dec.Token()
		if err != nil {
			return value, found
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if !found && t.Name.Local == "Type" {
				if v, ok := readIntCharData(dec); ok {
					value, found = v, true
				}
				// readIntCharData consumed this element through its </Type>,
				// so depth is unchanged; keep scanning to the EapMethod's end.
				continue
			}
			depth++
		case xml.EndElement:
			depth--
			if depth == 0 {
				return value, found // consumed the whole EapMethod
			}
		}
	}
}

// normalizeThumbprint returns a SHA-1 thumbprint as 40 hex chars. Profiles
// carry either 40 contiguous hex chars or 20 space-separated bytes, and
// profiles generated by Windows itself may drop a byte's leading zero
// ("8 0 f4 ..."). Anything else is rejected so malformed content isn't
// emitted as a bogus fingerprint.
func normalizeThumbprint(s string) (string, bool) {
	fields := strings.Fields(s)
	if len(fields) == 1 && len(fields[0]) == 40 && isHexString(fields[0]) {
		return fields[0], true
	}
	if len(fields) != 20 {
		return "", false
	}
	var b strings.Builder
	for _, f := range fields {
		if len(f) > 2 || !isHexString(f) {
			return "", false
		}
		if len(f) == 1 {
			b.WriteByte('0')
		}
		b.WriteString(f)
	}
	return b.String(), true
}

// mapAuthMode maps a WLAN profile <authMode> value to an EAPOLControlMode.
func mapAuthMode(s string) int {
	switch s {
	case "machine":
		return 3 // System
	case "user":
		return 1 // User
	case "machineOrUser":
		return modeMachineOrUser
	case "guest":
		return 0 // None
	default:
		return -1
	}
}

// readCharData consumes tokens until the end of the element the decoder is
// currently positioned inside, returning the concatenated direct character
// data (text in nested child elements is ignored). It must be called
// immediately after reading a StartElement.
func readCharData(dec *xml.Decoder) (string, bool) {
	var sb strings.Builder
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
		case xml.CharData:
			if depth == 0 {
				sb.Write(t)
			}
		case xml.EndElement:
			if depth == 0 {
				return sb.String(), true
			}
			depth--
		}
	}
}

// readIntCharData is readCharData parsed as a base-10 int.
func readIntCharData(dec *xml.Decoder) (int, bool) {
	s, ok := readCharData(dec)
	if !ok {
		return 0, false
	}
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, false
	}
	return v, true
}

// isHexString reports whether s consists solely of hexadecimal digits.
func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// formatSHA1Hex converts an even-length hex string to colon-separated pairs
// (e.g. "aabb..." -> "aa:bb:..."). Returns "" for odd-length input rather than
// panicking on the trailing 2-char slice.
func formatSHA1Hex(hex string) string {
	if len(hex) == 0 || len(hex)%2 != 0 {
		return ""
	}
	hex = strings.ToLower(hex)
	var buf strings.Builder
	buf.Grow(len(hex) + len(hex)/2) // hex chars + colon separators
	for i := 0; i < len(hex); i += 2 {
		if i > 0 {
			buf.WriteByte(':')
		}
		buf.WriteString(hex[i : i+2])
	}
	return buf.String()
}
