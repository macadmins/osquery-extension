package dot1x

// Tests for the pure-Go macOS EAPOL status conversion (dot1x_eapol.go). No
// build tag: eapolRaw values stand in for the cgo out-params of
// EAPOLControlCopyStateAndStatus, so GetStatus's conversion and error mapping
// run deterministically on every platform.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // sha1 used only for certificate fingerprint display
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCertDER returns a self-signed DER certificate with the given subject
// and serial, expiring at the start of expiryYear.
func testCertDER(t *testing.T, subject pkix.Name, serial int64, expiryYear int) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      subject,
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(expiryYear, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}

// packCerts mirrors the C pack_cert_chain format: (4-byte BE len || DER)*.
func packCerts(ders ...[]byte) []byte {
	var out []byte
	for _, d := range ders {
		out = binary.BigEndian.AppendUint32(out, uint32(len(d)))
		out = append(out, d...)
	}
	return out
}

// sentinelRaw is what dot1x_query leaves in its out-params before (or
// without) reading a status dictionary.
func sentinelRaw() eapolRaw {
	return eapolRaw{
		state:                -1,
		supplicantState:      -1,
		eapType:              -1,
		clientStatus:         -1,
		mode:                 -1,
		tlsSessionWasResumed: -1,
		tlsTrustClientStatus: -1,
		tlsNegotiatedCipher:  -1,
		innerEAPType:         -1,
	}
}

func TestStatusFromEAPOLSystemEAPTLS(t *testing.T) {
	leaf := testCertDER(t, pkix.Name{CommonName: "radius.campus.edu", OrganizationalUnit: []string{"IT"}, Organization: []string{"CampusGroup"}}, 0x7d3a1f9e2b5c, 2027)
	ca := testCertDER(t, pkix.Name{CommonName: "CampusGroup Root CA", Organization: []string{"CampusGroup"}}, 12345, 2028)

	r := eapolRaw{
		interfaceType:                "ethernet",
		state:                        2,
		supplicantState:              4,
		eapType:                      13,
		eapTypeName:                  "EAP-TLS",
		clientStatus:                 0,
		domainSpecificError:          0,
		domainSpecificErrorPresent:   true,
		authMAC:                      []byte{0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc},
		mode:                         3,
		tlsSessionWasResumed:         0,
		certChain:                    packCerts(leaf, ca),
		tlsTrustClientStatus:         0,
		tlsNegotiatedCipher:          0xC02B,
		tlsNegotiatedProtocolVersion: "1.2",
		innerEAPType:                 -1,
		lastStatusTimestamp:          "2026-06-06T12:00:00Z",
		authenticatedSince:           "2026-06-06T11:59:58Z",
		uniqueIdentifier:             "11111111-2222-3333-4444-555555555555",
	}

	s, err := statusFromEAPOL("en0", r)
	require.NoError(t, err)

	assert.Equal(t, Dot1XStatus{
		Interface:                    "en0",
		InterfaceType:                "ethernet",
		State:                        2,
		SupplicantState:              4,
		EAPType:                      13,
		EAPTypeName:                  "EAP-TLS",
		ClientStatus:                 0,
		DomainSpecificError:          intPtr(0),
		AuthenticatorMACAddress:      "00:11:22:aa:bb:cc",
		Mode:                         3,
		TLSSessionWasResumed:         0,
		TLSServerCertificateChain:    "CN=radius.campus.edu,OU=IT,O=CampusGroup|CN=CampusGroup Root CA,O=CampusGroup",
		TLSServerCertificateSHA1:     sha1String(sha1.Sum(leaf)) + "," + sha1String(sha1.Sum(ca)),
		TLSServerCertificateSerials:  "7d3a1f9e2b5c,3039",
		TLSServerCertificateNotAfter: notAfter(t, leaf),
		TLSTrustClientStatus:         0,
		TLSNegotiatedCipher:          0xC02B,
		TLSNegotiatedProtocolVersion: "1.2",
		InnerEAPType:                 -1,
		LastStatusTimestamp:          "2026-06-06T12:00:00Z",
		AuthenticatedSince:           "2026-06-06T11:59:58Z",
		UniqueIdentifier:             "11111111-2222-3333-4444-555555555555",
	}, s)
}

func TestStatusFromEAPOLPEAP(t *testing.T) {
	t.Parallel()
	r := sentinelRaw()
	r.state, r.supplicantState, r.mode = 2, 4, 2
	r.eapType, r.eapTypeName = 25, "PEAP"
	r.innerEAPType, r.innerEAPTypeName = 26, "MSCHAPv2"
	r.tlsNegotiatedProtocolVersion = "1.3"

	s, err := statusFromEAPOL("en1", r)
	require.NoError(t, err)
	assert.Equal(t, "en1", s.Interface)
	assert.Equal(t, 25, s.EAPType)
	assert.Equal(t, "PEAP", s.EAPTypeName)
	assert.Equal(t, 26, s.InnerEAPType)
	assert.Equal(t, "MSCHAPv2", s.InnerEAPTypeName)
	assert.Equal(t, 2, s.Mode)
	assert.Equal(t, "1.3", s.TLSNegotiatedProtocolVersion)
}

func TestStatusFromEAPOLDomainSpecificError(t *testing.T) {
	t.Parallel()

	r := sentinelRaw()
	r.domainSpecificError, r.domainSpecificErrorPresent = -9807, true
	s, err := statusFromEAPOL("en0", r)
	require.NoError(t, err)
	require.NotNil(t, s.DomainSpecificError)
	assert.Equal(t, -9807, *s.DomainSpecificError)
	assert.Equal(t, "-9807", rowFromStatus(s)["domain_specific_error"])

	// Absent: the value is ignored even if nonzero.
	r.domainSpecificErrorPresent = false
	s, err = statusFromEAPOL("en0", r)
	require.NoError(t, err)
	assert.Nil(t, s.DomainSpecificError)
	assert.Equal(t, "", rowFromStatus(s)["domain_specific_error"])
}

func TestStatusFromEAPOLTLSSessionWasResumed(t *testing.T) {
	t.Parallel()
	for _, v := range []int{-1, 0, 1} {
		r := sentinelRaw()
		r.tlsSessionWasResumed = v
		s, err := statusFromEAPOL("en0", r)
		require.NoError(t, err)
		assert.Equal(t, v, s.TLSSessionWasResumed)
	}
}

func TestStatusFromEAPOLSentinels(t *testing.T) {
	t.Parallel()
	s, err := statusFromEAPOL("en0", sentinelRaw())
	require.NoError(t, err)
	assert.Equal(t, Dot1XStatus{
		Interface:            "en0",
		State:                -1,
		SupplicantState:      -1,
		EAPType:              -1,
		ClientStatus:         -1,
		Mode:                 -1,
		TLSSessionWasResumed: -1,
		TLSTrustClientStatus: -1,
		TLSNegotiatedCipher:  -1,
		InnerEAPType:         -1,
	}, s)
}

func TestStatusFromEAPOLMalformedInput(t *testing.T) {
	t.Parallel()
	r := sentinelRaw()
	r.authMAC = []byte{0, 1, 2}
	r.certChain = packCerts([]byte("not DER"))
	s, err := statusFromEAPOL("en0", r)
	require.NoError(t, err)
	assert.Empty(t, s.AuthenticatorMACAddress)
	assert.Empty(t, s.TLSServerCertificateChain)
	assert.Empty(t, s.TLSServerCertificateSHA1)
	assert.Empty(t, s.TLSServerCertificateSerials)
	assert.Empty(t, s.TLSServerCertificateNotAfter)
}

// notAfter is der's NotAfter in the not_after column format.
func notAfter(t *testing.T, der []byte) string {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return c.NotAfter.UTC().Format("2006-01-02T15:04:05Z")
}

func TestStatusFromEAPOLNoStatus(t *testing.T) {
	t.Parallel()
	r := sentinelRaw()
	r.ret = -2
	s, err := statusFromEAPOL("en7", r)
	require.EqualError(t, err, "EAPOLControlCopyStateAndStatus returned no status for en7")
	assert.NotErrorIs(t, err, ErrBackendUnavailable)
	assert.Equal(t, "en7", s.Interface)
}

func TestStatusFromEAPOLLoadFailure(t *testing.T) {
	t.Parallel()
	r := sentinelRaw()
	r.ret = -1
	r.loadError = "dlopen: image not found"
	_, err := statusFromEAPOL("en0", r)
	require.ErrorIs(t, err, ErrBackendUnavailable)
	assert.EqualError(t, err, "802.1X backend unavailable: could not load EAPOLControlCopyStateAndStatus for en0: dlopen: image not found")

	r.loadError = ""
	_, err = statusFromEAPOL("en0", r)
	require.ErrorIs(t, err, ErrBackendUnavailable)
	assert.Contains(t, err.Error(), ": unknown error")
}

func TestStatusFromEAPOLOtherError(t *testing.T) {
	t.Parallel()
	r := sentinelRaw()
	r.ret = 5
	_, err := statusFromEAPOL("bogus0", r)
	require.EqualError(t, err, "EAPOLControlCopyStateAndStatus returned 5 for bogus0")
	assert.NotErrorIs(t, err, ErrBackendUnavailable)
}

// eap8021x's "Timestamp" (kEAPOLControlTimestamp) is when the session first
// became Authenticated; it only applies to an Authenticated row.
func TestStatusFromEAPOLAuthenticatedSince(t *testing.T) {
	t.Parallel()
	r := sentinelRaw()
	r.state, r.supplicantState = 2, 4
	r.authenticatedSince = "2026-06-06T11:59:58Z"

	s, err := statusFromEAPOL("en0", r)
	require.NoError(t, err)
	assert.Equal(t, "2026-06-06T11:59:58Z", s.AuthenticatedSince)

	r.supplicantState = 3 // Authenticating
	s, err = statusFromEAPOL("en0", r)
	require.NoError(t, err)
	assert.Empty(t, s.AuthenticatedSince)
}
