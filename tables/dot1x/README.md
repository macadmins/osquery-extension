# `dot1x`

Per-interface 802.1X (EAPOL) supplicant state for **macOS** and **Windows**, covering Wi-Fi and wired Ethernet. Use it to see across a fleet which machines are authenticated, how (EAP method, mode, certificates), against which network or switch port, and why an attempt failed, without remoting into each device.

```sql
-- Who isn't authenticated, and why?
SELECT interface, interface_type, ssid, supplicant_state_name,
       client_status_name, failure_reason, failure_code
FROM dot1x
WHERE supplicant_state_name != 'Authenticated';
```

## Columns

### Interface & network

| Column | Type | Description | macOS | Windows |
|---|---|---|---|---|
| `interface` | TEXT | Interface name: BSD name on macOS (`en0`), adapter description on Windows | ✓ | ✓ |
| `interface_type` | TEXT | `wifi` or `ethernet` | ✓ | ✓ |
| `ssid` | TEXT | Wi-Fi network name (see [SSID on macOS](#ssid-on-macos)) | ✓ Wi-Fi | ✓ Wi-Fi |
| `mac_address` | TEXT | Client MAC address on this link (RADIUS `Calling-Station-Id`), including private/randomized Wi-Fi addresses. macOS: the interface's current address. Windows: from the newest 802.1X event, so also set on failure rows | ✓ | ✓ |
| `authenticator_mac_address` | TEXT | Authenticator MAC: the AP's BSSID for Wi-Fi, the switch port's MAC for wired | ✓ | ✓ |

### Status

| Column | Type | Description | macOS | Windows |
|---|---|---|---|---|
| `state` / `state_name` | INTEGER / TEXT | EAPOL control state ([values](#state)) | ✓ | ✓ |
| `supplicant_state` / `supplicant_state_name` | INTEGER / TEXT | 802.1X supplicant state machine ([values](#supplicant_state)) | ✓ | ✓ |
| `client_status` / `client_status_name` | INTEGER / TEXT | EAP client status ([values](#client_status)). Windows reports `OK`, or `Failed` for failure rows | ✓ | ✓ |
| `authenticated_since` | TEXT | ISO 8601 time the current session became `Authenticated`; empty otherwise. macOS: eap8021x's session `Timestamp`. Windows: the newest 802.1X success event (12012 / 15505) | ✓ | ✓ |
| `last_status_timestamp` | TEXT | ISO 8601 time of the last status change (Windows: time of the last 802.1X event) | ✓ | ✓ |

### Failure detail

| Column | Type | Description | macOS | Windows |
|---|---|---|---|---|
| `failure_reason` / `failure_code` | TEXT | Last 802.1X failure from the Windows event log (`ReasonText` / `ReasonCode`, e.g. `Explicit Eap failure received` / `0x50005`). When the event names an EAP root cause (`EAPRootCauseString`), it is appended: `<ReasonText>; <root cause>` | — | ✓ |
| `failure_eap_code` | TEXT | The EAP method's own error for that failure (`EAPReasonCode`, e.g. `0x80420015`); empty when absent or `0x0` | — | ✓ |
| `domain_specific_error` | INTEGER | EAP client domain-specific error; an Apple OSStatus, may be negative (e.g. `-9807`) | ✓ | — |

### Authentication

| Column | Type | Description | macOS | Windows |
|---|---|---|---|---|
| `eap_type` / `eap_type_name` | INTEGER / TEXT | Outer EAP method ([values](#eap_type--inner_eap_type)) | ✓ | ✓ |
| `inner_eap_type` / `inner_eap_type_name` | INTEGER / TEXT | Inner EAP method for tunneled auth ([values](#eap_type--inner_eap_type)). Empty when the inner method isn't EAP (e.g. TTLS-PAP) | ✓ | ✓ |
| `identity` | TEXT | Outer EAP identity sent to the RADIUS server (`User-Name`), e.g. `anonymous@campus.edu` or `host/PC01`. macOS: profile-based sessions only (the profile's `OuterIdentity`, else `UserName`); empty for hand-joined networks and certificate-only EAP-TLS. Windows: from the newest 802.1X event | ✓ profile-based | ✓ |
| `mode` / `mode_name` | INTEGER / TEXT | Whose credentials authenticate the session ([values](#mode)) | ✓ | ✓ |

### Configuration / profile

| Column | Type | Description | macOS | Windows |
|---|---|---|---|---|
| `profile_name` | TEXT | Name of the configuration behind the connection. macOS: the EAPOLClientProfile name, i.e. the 802.1X payload's `PayloadDisplayName`, or `WiFi (<SSID>)` when the payload has none (not the configuration profile's own name; see `mdm_profile_name`). Windows: the WLAN profile name (MDM-pushed or hand-joined, usually the SSID) | ✓ profile-based | ✓ Wi-Fi |
| `mdm_payload_uuid` | TEXT | `PayloadUUID` of the configuration-profile 802.1X payload (Wi-Fi or Ethernet) that installed the profile (see [Which MDM profile?](#which-mdm-profile-is-controlling-the-connection)) | ✓ | — |
| `mdm_payload_type` | TEXT | `PayloadType` of that payload: `com.apple.wifi.managed` for Wi-Fi, or an Ethernet scope such as `com.apple.globalethernet.managed`, `com.apple.firstethernet.managed` or `com.apple.firstactiveethernet.managed`. Needs no special privileges; from `profiles -C` | ✓ | — |
| `mdm_profile_name` | TEXT | Display name (`ProfileDisplayName`) of the configuration profile containing that payload. Needs no special privileges; from `profiles -C` | ✓ | — |
| `mdm_profile_identifier` | TEXT | Identifier (`ProfileIdentifier`) of that configuration profile. Needs no special privileges; from `profiles -C` | ✓ | — |
| `unique_identifier` | TEXT | macOS: eap8021x's EAPOLClientProfile ID (profile-based sessions only; a local ID, **not** an MDM UUID). Windows: interface GUID | ✓ | ✓ |
| `server_validation` | TEXT | How the profile has the client validate the RADIUS server: `pinned`, `ca_only`, `name_only`, `prompt` or `none` (see [Auditing server validation](#auditing-server-validation)); empty for macOS sessions without a profile | ✓ profile-based | ✓ |
| `tls_trusted_root_ca_sha1` | TEXT | SHA-1 thumbprints of the trusted root CA(s) pinned in the profile | — | ✓ |
| `tls_trusted_server_names` | TEXT | Comma-separated server names the RADIUS certificate must match. macOS: the profile's `TLSTrustedServerNames`. Windows: the outer method's `ServerNames` | ✓ profile-based | ✓ |

### TLS session

| Column | Type | Description | macOS | Windows |
|---|---|---|---|---|
| `tls_negotiated_protocol_version` | TEXT | `1.2` / `1.3` (EAP-TLS only, see [TLS details on macOS](#tls-details-on-macos)) | ✓ | — |
| `tls_negotiated_cipher` | INTEGER | TLS cipher suite code (PEAP / TTLS / EAP-FAST only) | ✓ | — |
| `tls_session_was_resumed` | INTEGER | 1/0; empty when unknown (always on Windows) | ✓ | — |
| `tls_trust_client_status` | INTEGER | Trust evaluation status while a trust decision is pending | ✓ | — |
| `tls_server_certificate_chain` | TEXT | Pipe-separated subject DNs (RFC 4514) of the server certificate chain | ✓ | — |
| `tls_server_certificate_sha1` / `tls_server_certificate_serials` | TEXT | Comma-separated SHA-1 fingerprints / hex serials of that chain | ✓ | — |
| `tls_server_certificate_not_after` | TEXT | ISO 8601 (UTC) expiry of the leaf (first) server certificate; empty without a chain | ✓ | — |

Query a single interface with `WHERE interface = 'en0'` (macOS) or `WHERE interface = '<adapter description>'` (Windows). Otherwise every 802.1X-capable interface is checked: all `en*` interfaces on macOS, and Wi-Fi adapters plus wired adapters with a Wired AutoConfig profile on Windows.

## When is there a row?

An interface returns a row only when it has an 802.1X session. Interfaces on open/PSK networks, and disconnected adapters, return no row. There's one exception: on Windows, a **disconnected Wi-Fi adapter whose last 802.1X attempt failed** returns a `Held` row with `failure_reason`/`failure_code`, so failed attempts are visible.

While macOS is still trying, failures show directly in the row:

| Situation | Typical row |
|---|---|
| Wrong password | `Held`, `client_status_name = Failed`, then `Acquired` / `UserInputRequired` while it re-prompts |
| Untrusted server certificate | `Authenticating`, `UserInputRequired`; `tls_server_certificate_chain` shows the certificate the user is being asked to trust |
| RADIUS server unreachable | `Acquired` → `Connecting` → `No Authenticator` (wired) |

Once macOS gives up (or the user cancels), the interface stops 802.1X and the row disappears. Scheduled queries every few minutes catch persistent failures.

## Matching RADIUS logs

The RADIUS `Acct-Session-Id` is generated by the AP or switch and never reaches the client, so match a row to RADIUS / NAC logs on the attributes both sides see:

| RADIUS attribute | `dot1x` column |
|---|---|
| `Calling-Station-Id` | `mac_address` |
| `Called-Station-Id` | `authenticator_mac_address` (plus `ssid`; many APs send `<BSSID>:<SSID>`) |
| `User-Name` | `identity` |
| Session start time | `authenticated_since` |

```sql
-- How long has each interface been authenticated?
SELECT interface, ssid, mac_address, identity, authenticated_since,
       strftime('%s','now') - strftime('%s', authenticated_since) AS connected_seconds
FROM dot1x
WHERE authenticated_since != '';
```

## How it works

### macOS

`EAPOLControlCopyStateAndStatus()` from `/System/Library/PrivateFrameworks/EAP8021X.framework` (Apple's open-source [eap8021x](https://github.com/apple-oss-distributions/eap8021x)), loaded with `dlopen`, so no root is required for the core columns. Wi-Fi and Ethernet use the same API. `interface_type` comes from SystemConfiguration (`SCNetworkInterfaceGetInterfaceType`).

#### SSID on macOS

The EAPOL status has no SSID, and every public macOS source (CoreWLAN, `networksetup`, `wdutil`, `ipconfig`, the SystemConfiguration dynamic store) hides it without Location Services, even for root. `ssid` is filled in this order:

1. **Profile-based sessions (e.g. MDM-deployed networks):** exactly, from the session's EAPOLClientProfile in `/Library/Preferences/SystemConfiguration/com.apple.network.eapolclient.configuration.plist` (world-readable; `unique_identifier` is the profile ID).
2. **Otherwise:** the session's BSSID (`authenticator_mac_address`) is matched against the BSSIDs each network was associated on in `/Library/Preferences/com.apple.wifi.known-networks.plist`. This needs **root + Full Disk Access** (osqueryd). If several networks share a BSSID, the most recent association wins. Only SSID/BSSID/association times are read; the AP location data in that file is ignored.
3. If neither applies, `ssid` is empty. `authenticator_mac_address` still identifies the AP, and the built-in `wifi_status` table can be joined on `interface`.

#### Which MDM profile is controlling the connection?

`unique_identifier` is eap8021x's own profile ID, generated locally. The link to MDM is `mdm_payload_uuid`, the `PayloadUUID` of the payload that installed the 802.1X profile; it is empty for networks configured by hand. When it is set, the table looks that payload up in `profiles -C` (no special privileges needed) and fills:

- `mdm_payload_type`: which payload it is, and so which interfaces it scopes: `com.apple.wifi.managed` for Wi-Fi, or for wired `com.apple.globalethernet.managed` (any Ethernet interface), `com.apple.firstethernet.managed` (the first Ethernet interface) or `com.apple.firstactiveethernet.managed` (the first active one).
- `mdm_profile_name` / `mdm_profile_identifier`: the configuration profile it came from, as shown in System Settings and your MDM.

```sql
SELECT interface, ssid, mdm_payload_type, mdm_profile_name, mdm_profile_identifier
FROM dot1x
WHERE mdm_payload_uuid != '';
```

If `mdm_payload_uuid` is set but the other three are empty, the payload wasn't found in `profiles -C` output, or the command failed or timed out (10 s); search for the UUID in your MDM.

#### TLS details on macOS

Which TLS fields appear depends on the EAP method:

| EAP method | `tls_negotiated_protocol_version` | `tls_negotiated_cipher` |
|---|---|---|
| EAP-TLS | ✓ | empty: eap8021x's default BoringSSL path doesn't publish it ([`/* TBD */`](https://github.com/apple-oss-distributions/eap8021x/blob/eap8021x-368.120.2.0.1/EAP8021X.fproj/EAPTLSSession.c)) |
| PEAP / TTLS / EAP-FAST | empty | ✓ (Secure Transport `SSLGetNegotiatedCipher`) |

Only the EAP-TLS plugin records the protocol version. The PEAP, TTLS and EAP-FAST plugins run on Secure Transport and never publish it. For those methods the cipher usually implies it:

- TLS 1.3 suites (`4865`–`4869`, i.e. `0x1301`–`0x1305`) exist only in TLS 1.3.
- AEAD suites (AES-GCM and ChaCha20-Poly1305, e.g. `49199`/`49200` = `0xC02F`/`0xC030` ECDHE-RSA-AES-GCM) exist only in TLS 1.2.
- CBC suites are valid in TLS 1.0–1.2, so the version can't be told from them.

```sql
SELECT interface, eap_type_name, tls_negotiated_cipher,
       CASE
         WHEN tls_negotiated_protocol_version != '' THEN tls_negotiated_protocol_version
         WHEN tls_negotiated_cipher BETWEEN 4865 AND 4869 THEN '1.3 (from cipher)'
         WHEN tls_negotiated_cipher IN (156, 157, 158, 159, 49195, 49196, 49199, 49200, 52392, 52393, 52394) THEN '1.2 (from cipher)'
       END AS tls_version
FROM dot1x;
```

### Auditing server validation

`server_validation` summarizes, from the profile, how the client decides whether the RADIUS server is genuine:

| Value | Meaning |
|---|---|
| `pinned` | Trusted root CA(s) **and** server names configured: only a certificate from that CA with a matching name is accepted |
| `ca_only` | Trusted CA(s), no server names: **any** certificate that CA issues is accepted |
| `name_only` | Server names, no trusted CA: any certificate with a matching name that chains to a system-trusted CA is accepted |
| `prompt` | Nothing pinned: any system-trusted certificate is accepted, and the user may be asked to trust an unknown one |
| `none` | Windows only: validation switched off (`PerformServerValidation` = `false`); any certificate is accepted |

Anything but `pinned` is risky. With `ca_only`, a rogue access point holding any certificate from the same CA (often a public or broadly used internal CA) passes. With `name_only` and `prompt`, an attacker with a certificate from any public CA, or a user who taps "Trust", hands their credentials (e.g. a PEAP/MSCHAPv2 hash) to a rogue AP. `none` accepts anyone.

Sources: macOS reads the profile's `TLSTrustedCertificates` and `TLSTrustedServerNames` (it has no "no validation" setting; `TLSAllowTrustExceptions` only allows the prompt). Windows reads the outer EAP method's `ServerValidation` (`TrustedRootCA` / TTLS `TrustedRootCAHash`, and `ServerNames`), plus the Windows 7+ switches `PerformServerValidation` (PEAP `PeapExtensions`, EAP-TLS `EapType`, or a `ServerValidation` attribute; `false` gives `none`) and `AcceptServerName` (`false` means `ServerNames` isn't enforced, so it doesn't count). `DisableUserPromptForServerValidation` / TTLS `DisablePrompt` only stops the prompt (validation then fails instead of asking), so it doesn't change the value.

```sql
-- Profiles that don't pin the RADIUS server.
SELECT interface, ssid, profile_name, server_validation FROM dot1x WHERE server_validation IN ('ca_only','name_only','prompt','none');

-- RADIUS server certificates expiring within 30 days (macOS).
SELECT interface, ssid, tls_server_certificate_chain, tls_server_certificate_not_after
FROM dot1x
WHERE tls_server_certificate_not_after != ''
  AND tls_server_certificate_not_after < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '+30 days');
```

### Windows

Pure Go (no cgo):

- **Wi-Fi:** the Native Wifi API (`wlanapi.dll`) for live state, BSSID, SSID and profile name, plus the WLAN profile XML for EAP type, inner type, mode and server validation settings.
- **Wired:** Windows has no documented wired equivalent of wlanapi, so wired uses the Wired AutoConfig LAN profile (`%ProgramData%\Microsoft\dot3svc\Profiles\Interfaces\{GUID}\*.xml`, same schema) for EAP settings, and the `Microsoft-Windows-Wired-AutoConfig/Operational` event log for state, switch-port MAC, timestamp and failure reason (15505 succeeded, 15514 failed, 15503/15504 started, 15506 suspended, 15500 unplugged).
- **Failures, timestamps, client MAC and identity:** from the `Microsoft-Windows-WLAN-AutoConfig/Operational` (12011 started, 12012 succeeded, 12013 failed) and Wired-AutoConfig event logs, read with `wevtapi.dll`.

## Privileges

| Columns | macOS | Windows |
|---|---|---|
| Live state, EAP method, authenticator, profile settings (`profile_name`, `server_validation`, trusted CA/names, `mdm_*`) | any user | any user (Wi-Fi live state via wlanapi; wired profile settings) |
| Event-log columns: `authenticated_since`, `last_status_timestamp`, `mac_address`, `identity`, failure rows, **wired `supplicant_state`** | — | admin / SYSTEM. As a standard user they're empty and wired rows show an unknown state |
| `ssid` for networks without a profile | root + Full Disk Access | — |

Verified on Windows 11 as a standard (non-admin) user: Wi-Fi rows are complete apart from the event-log columns, and wired rows appear with their profile settings but no state. osqueryd runs as root/SYSTEM, and Fleet and most MDM setups grant osquery Full Disk Access, so in production every column is available.

## Limitations

- **Windows wired state** comes from the most recent Wired AutoConfig event, not a live query. The event logs are about 1 MB, so only recent history is kept.
- **Windows user-credential profiles** (wired or Wi-Fi) fail with "Unable to identify a user" when nobody is logged in at the console. That's Windows behavior, and it shows up as a failure row.
- **Hard failures on macOS** leave no row once the supplicant gives up (see above).

## Testing

```sh
bazel test //tables/dot1x:dot1x_test
```

Most tests are platform-neutral and run on Linux CI. They exercise both backends' `GetStatus` logic against fakes and real fixtures exported from macOS and Windows (WLAN/LAN profiles, event-log XML, plist structures). Set `DOT1X_LIVE_TESTS=1` to also run the live smoke tests against the host's real 802.1X stack.

## Value reference

### `state`

- `0` Idle
- `1` Starting
- `2` Running
- `3` Stopping

### `supplicant_state`

- `0` Disconnected
- `1` Connecting
- `2` Acquired: an authenticator responded; waiting for identity or credentials
- `3` Authenticating
- `4` Authenticated
- `5` Held: the last attempt failed; waiting before retrying
- `6` Logoff
- `7` Inactive
- `8` No Authenticator: nothing answered 802.1X on this link (e.g. the RADIUS server is unreachable, or the switch port isn't enforcing 802.1X)

### `eap_type` / `inner_eap_type`

- `1` Identity
- `2` Notification
- `3` Nak
- `4` MD5-Challenge
- `5` One-Time Password
- `6` Generic Token Card
- `13` EAP-TLS
- `17` Cisco LEAP
- `18` EAP-SIM
- `19` SRP-SHA1
- `21` EAP-TTLS
- `23` EAP-AKA
- `25` PEAP
- `26` MSCHAPv2
- `33` Extensions
- `43` EAP-FAST
- `50` EAP-AKA-Prime

On macOS, `eap_type_name` / `inner_eap_type_name` are taken from macOS itself when it supplies them (e.g. `EAP-PEAP`, `EAP-TTLS`), so they can differ slightly from this list. Unlisted numbers show as `Unknown(<n>)`.

### `client_status`

These are eap8021x's `EAPClientStatus` values ([EAPClientTypes.h](https://github.com/apple-oss-distributions/eap8021x/blob/eap8021x-368.120.2.0.1/EAP8021X.fproj/EAPClientTypes.h)):

- `0` OK
- `1` Failed
- `2` AllocationFailed
- `3` UserInputRequired: waiting for credentials or a certificate-trust decision
- `4` ConfigurationInvalid
- `5` ProtocolNotSupported
- `6` ServerCertificateNotTrusted
- `7` InnerProtocolNotSupported
- `8` InternalError
- `9` UserCancelledAuthentication
- `10` UnknownRootCertificate
- `11` NoRootCertificate
- `12` CertificateExpired
- `13` CertificateNotYetValid
- `14` CertificateRequiresConfirmation
- `15` UserInputNotPossible
- `16` ResourceUnavailable
- `17` ProtocolError
- `18` AuthenticationStalled
- `19` IdentityDecryptionError
- `20` OtherInputRequired
- `1000` ErrnoError: see `domain_specific_error`
- `1001` SecurityError: see `domain_specific_error` (an OSStatus)
- `1002` PluginSpecificError

### `mode`

- `0` None
- `1` User: the logged-in user's credentials
- `2` LoginWindow: credentials entered at the login window
- `3` System: machine credentials (e.g. a device certificate), no user needed
- `4` MachineOrUser (Windows only): user credentials while a user is logged on, machine credentials otherwise. This is also Windows' default when a profile omits `authMode`.
