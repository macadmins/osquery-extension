package dot1x

import (
	"net"
	"strings"
	"time"

	"github.com/micromdm/plist"
)

// knownNetworkSSID returns the SSID of the known network that was associated
// on bssid, the AP the 802.1X session authenticated against. Several networks
// can share a BSSID (one radio, multiple SSIDs); the most recent association
// wins. Only SSID/BSSID/LastAssociatedAt are read; the plist also holds AP
// locations, which are deliberately ignored. Returns "" if nothing matches or
// the plist can't be parsed.
func knownNetworkSSID(plistData []byte, bssid string) string {
	want, err := net.ParseMAC(padMAC(bssid))
	if err != nil || len(plistData) == 0 {
		return ""
	}
	// Decode loosely: the file also holds non-network keys of other types,
	// which would make a typed map fail as a whole.
	var top map[string]any
	if plist.Unmarshal(plistData, &top) != nil {
		return ""
	}
	var best string
	var bestAt time.Time
	for key, v := range top {
		n, ok := v.(map[string]any)
		if !strings.HasPrefix(key, "wifi.network.ssid.") || !ok {
			continue
		}
		ssid, _ := n["SSID"].([]byte)
		list, _ := n["BSSList"].([]any)
		for _, e := range list {
			b, _ := e.(map[string]any)
			bssid, _ := b["BSSID"].(string)
			at, _ := b["LastAssociatedAt"].(time.Time)
			if mac, err := net.ParseMAC(padMAC(bssid)); err == nil && len(ssid) > 0 &&
				mac.String() == want.String() && (best == "" || at.After(bestAt)) {
				best, bestAt = string(ssid), at
			}
		}
	}
	return best
}

// padMAC zero-pads each octet of a colon MAC ("2a:b:8b:0:f2:35" ->
// "2a:0b:8b:00:f2:35"), the form macOS uses in the known-networks plist.
func padMAC(s string) string {
	parts := strings.Split(s, ":")
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":")
}

// eapolProfile is what eap8021x's client configuration records for one
// EAPOLClientProfile.
type eapolProfile struct {
	ssid        string // WLAN binding
	name        string // UserDefinedName
	payloadUUID string // PayloadUUID of the Wi-Fi/Ethernet 802.1X payload that installed it, if any
	identity    string // outer EAP identity: AuthenticationProperties OuterIdentity, else UserName

	trustedServerNames string // comma-joined AuthenticationProperties TLSTrustedServerNames
	serverValidation   string // see serverValidation; macOS has no "validation off" setting
}

// eapolProfileInfo looks up profileID in eap8021x's client configuration
// (Profiles -> <ProfileID>). A profile-based session (typically
// MDM-deployed) reports that ProfileID as its UniqueIdentifier, so this
// identifies the network exactly; the file is world-readable. Zero value
// for unknown profiles or bad input.
func eapolProfileInfo(plistData []byte, profileID string) eapolProfile {
	var out eapolProfile
	if profileID == "" || len(plistData) == 0 {
		return out
	}
	var cfg map[string]any
	if plist.Unmarshal(plistData, &cfg) != nil {
		return out
	}
	profiles, _ := cfg["Profiles"].(map[string]any)
	profile, ok := profiles[profileID].(map[string]any)
	if !ok {
		return out
	}
	out.name, _ = profile["UserDefinedName"].(string)
	wlan, _ := profile["WLAN"].(map[string]any)
	switch ssid := wlan["SSID"].(type) {
	case []byte:
		out.ssid = string(ssid)
	case string:
		out.ssid = ssid
	}
	info, _ := profile["Information"].(map[string]any)
	mcx, _ := info["com.apple.mcx.configurationprofiles.8021X"].(map[string]any)
	out.payloadUUID, _ = mcx["PayloadUUID"].(string)
	// Only the identity and trust keys are read; AuthenticationProperties can
	// also hold UserPassword and other secrets.
	auth, _ := profile["AuthenticationProperties"].(map[string]any)
	if out.identity, _ = auth["OuterIdentity"].(string); out.identity == "" {
		out.identity, _ = auth["UserName"].(string)
	}
	var names []string
	list, _ := auth["TLSTrustedServerNames"].([]any)
	for _, v := range list {
		if n, _ := v.(string); n != "" {
			names = append(names, n)
		}
	}
	out.trustedServerNames = strings.Join(names, ",")
	certs, _ := auth["TLSTrustedCertificates"].([]any)
	out.serverValidation = serverValidation(len(certs) > 0, len(names) > 0, true)
	return out
}

// mdmPayloadInfo finds the payload whose PayloadUUID matches payloadUUID
// (case-insensitive) in `profiles -C -o stdout-xml` output (scope, e.g.
// "_computerlevel" or a user name -> profiles -> ProfileItems) and returns its
// PayloadType plus the containing profile's display name and identifier.
// Decoded loosely so unrelated keys don't break it; PayloadContent, which can
// hold secrets, is never read. Empty strings when nothing matches.
func mdmPayloadInfo(profilesXML []byte, payloadUUID string) (payloadType, profileName, profileIdentifier string) {
	var scopes map[string]any
	if payloadUUID == "" || plist.Unmarshal(profilesXML, &scopes) != nil {
		return "", "", ""
	}
	for _, v := range scopes {
		profiles, _ := v.([]any)
		for _, p := range profiles {
			profile, _ := p.(map[string]any)
			items, _ := profile["ProfileItems"].([]any)
			for _, it := range items {
				item, _ := it.(map[string]any)
				if uuid, _ := item["PayloadUUID"].(string); strings.EqualFold(uuid, payloadUUID) {
					payloadType, _ = item["PayloadType"].(string)
					profileName, _ = profile["ProfileDisplayName"].(string)
					profileIdentifier, _ = profile["ProfileIdentifier"].(string)
					return payloadType, profileName, profileIdentifier
				}
			}
		}
	}
	return "", "", ""
}
