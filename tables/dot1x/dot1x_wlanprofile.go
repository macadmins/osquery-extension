package dot1x

// WLAN profile XML parsing for the Windows backend. This logic is pure Go
// (no syscalls), so it lives outside the //go:build windows file and is
// compiled, tested, and coverage-counted on every platform.

import (
	"encoding/xml"
	"strconv"
	"strings"
)

// wlanProfileInfo holds the 802.1X-relevant fields parsed from a Windows WLAN
// profile XML. Numeric fields are -1 when absent/invalid.
type wlanProfileInfo struct {
	eapType           int    // outer EAP method type (first <EapMethod><Type>)
	innerEAPType      int    // inner/tunneled EAP method type (second <EapMethod><Type>)
	authMode          int    // EAPOLControlMode mapped from <authMode>
	trustedRootCASHA1 string // comma-separated colon-delimited SHA-1 thumbprints
}

// parseWLANProfile extracts every 802.1X field from a WLAN profile XML in a
// single token pass. Matching is by local element name, so namespace prefixes
// and attributes on elements are tolerated. The outer EAP type is the <Type>
// inside the first <EapMethod>; the inner type is the <Type> inside the second
// <EapMethod> (tunneled methods like PEAP/EAP-TTLS); authMode is the first
// <authMode>; trusted root CA thumbprints are every valid 40-hex-char
// <TrustedRootCA> (comma-joined).
func parseWLANProfile(xmlStr string) wlanProfileInfo {
	info := wlanProfileInfo{eapType: -1, innerEAPType: -1, authMode: -1}
	dec := xml.NewDecoder(strings.NewReader(xmlStr))
	eapMethodCount := 0
	gotAuthMode := false
	var caHashes []string
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "EapMethod":
			eapMethodCount++
			if t, ok := readEapMethodType(dec); ok {
				switch eapMethodCount {
				case 1:
					info.eapType = t
				case 2:
					info.innerEAPType = t
				}
			}
		case "authMode":
			if !gotAuthMode {
				if s, ok := readCharData(dec); ok {
					info.authMode = mapAuthMode(strings.TrimSpace(s))
					gotAuthMode = true
				}
			}
		case "TrustedRootCA":
			if s, ok := readCharData(dec); ok {
				// A SHA-1 thumbprint is exactly 40 hex chars; require valid hex
				// so malformed content isn't emitted as a bogus fingerprint.
				hex := strings.Join(strings.Fields(s), "")
				if len(hex) == 40 && isHexString(hex) {
					caHashes = append(caHashes, formatSHA1Hex(hex))
				}
			}
		}
	}
	info.trustedRootCASHA1 = strings.Join(caHashes, ",")
	return info
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

// mapAuthMode maps a WLAN profile <authMode> value to an EAPOLControlMode.
func mapAuthMode(s string) int {
	switch s {
	case "machine":
		return 3 // System
	case "user":
		return 1 // User
	case "machineOrUser":
		return 2 // LoginWindow
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
