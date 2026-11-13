package smtp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The DANE acceptance matrix (med-shard2-001). Every test here runs with a
// scripted exchangeTLSA seam — NO live DNS. The matrix under test:
//
//	TLSA RRset state                      | required delivery behavior
//	--------------------------------------+------------------------------------------
//	no RRset (NODATA/NXDOMAIN, any AD)    | opportunistic non-DANE delivery;
//	                                      | absence never defers or rejects
//	unsigned-zone RRset (any records)     | records ignored — non-DANE behavior
//	                                      | retained, matching AND mismatching
//	lookup failure (SERVFAIL/timeout/     | defer with retry; never degrade to
//	bogus DNSSEC)                         | plaintext, never masquerade as absence
//	"secure" usable record + cert match   | deliver (DANE authenticated)
//	"secure" usable record + cert MISMATCH| reject even against a CA-valid certificate
//	"secure" RRset, rollover either order | match on ANY record authenticates
//	"secure" RRset, all records unusable  | DANESecureUnusable — never a mismatch

// newSelfSignedCert generates a self-signed ECDSA certificate (with its private
// key) for the tests in this package (DANE matrix + submission STARTTLS gate).
// dnsNames populate the SAN extension so DANE-TA(2) hostname checks can be
// exercised.
func newSelfSignedCert(t *testing.T, cn string, dnsNames ...string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert, key
}

// writeCertPEMFiles writes a cert/key PEM pair into a temp dir for tests that
// need files on disk (the submission STARTTLS loader reads paths, not bytes).
func writeCertPEMFiles(t *testing.T, cert *x509.Certificate, key *ecdsa.PrivateKey) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPath = dir + "/cert.pem"
	keyPath = dir + "/key.pem"
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// fakeExchangeTLSA installs a scripted exchangeTLSA seam for the duration of
// the test (restored via t.Cleanup). resp may be nil when err is non-nil.
func fakeExchangeTLSA(t *testing.T, resp *dns.Msg, err error) {
	t.Helper()
	prev := exchangeTLSA
	t.Cleanup(func() { exchangeTLSA = prev })
	exchangeTLSA = func(string) (*dns.Msg, error) { return resp, err }
}

// dnsResponse builds a scripted TLSA DNS response with the given header state.
func dnsResponse(authenticated bool, rcode int, answers ...dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.Rcode = rcode
	m.MsgHdr.AuthenticatedData = authenticated
	m.Answer = answers
	return m
}

// tlsaRR builds one scripted TLSA answer. assoc is the RAW certificate
// association bytes; the wire format (and miekg/dns) carries them hex-encoded.
func tlsaRR(usage, selector, matchingType uint8, assoc []byte) *dns.TLSA {
	return &dns.TLSA{
		Hdr:          dns.RR_Header{Name: "_25._tcp.mx.example.test.", Rrtype: dns.TypeTLSA, Class: dns.ClassINET},
		Usage:        usage,
		Selector:     selector,
		MatchingType: matchingType,
		Certificate:  hex.EncodeToString(assoc),
	}
}

// tlsaRRHex builds one scripted TLSA answer whose association is the given
// literal hex TEXT (valid or not) — for undecodable-association records.
func tlsaRRHex(usage, selector, matchingType uint8, hexAssoc string) *dns.TLSA {
	return &dns.TLSA{
		Hdr:          dns.RR_Header{Name: "_25._tcp.mx.example.test.", Rrtype: dns.TypeTLSA, Class: dns.ClassINET},
		Usage:        usage,
		Selector:     selector,
		MatchingType: matchingType,
		Certificate:  hexAssoc,
	}
}

// sha256Assoc is the certificate association for a full-certificate (selector
// 0), SHA-256 (matching type 1) TLSA record.
func sha256Assoc(cert *x509.Certificate) []byte {
	h := sha256.Sum256(cert.Raw)
	return h[:]
}

func TestLookupTLSA_AbsenceVsFailureDistinction(t *testing.T) {
	assoc := []byte("deadbeef")
	tests := []struct {
		name        string
		resp        *dns.Msg
		exchangeErr error
		wantRecords int
		wantSec     DANESecurityLevel
		wantErrSub  string // empty = no error expected
	}{
		{
			name:        "authenticated NODATA (secure empty answer) is absence, not failure",
			resp:        dnsResponse(true, dns.RcodeSuccess),
			wantRecords: 0, wantSec: DANESecureSecurity,
		},
		{
			name:        "NXDOMAIN without AD is absence (insecure), not failure",
			resp:        dnsResponse(false, dns.RcodeNameError),
			wantRecords: 0, wantSec: DANEInsecureSecurity,
		},
		{
			name:        "unsigned-zone NODATA is absence (insecure), not failure",
			resp:        dnsResponse(false, dns.RcodeSuccess),
			wantRecords: 0, wantSec: DANEInsecureSecurity,
		},
		{
			name:        "SERVFAIL is bogus → lookup failure",
			resp:        dnsResponse(false, dns.RcodeServerFailure),
			wantRecords: 0, wantSec: DANEBogusSecurity, wantErrSub: "bogus",
		},
		{
			name:        "other rcode is indeterminate → lookup failure",
			resp:        dnsResponse(false, dns.RcodeRefused),
			wantRecords: 0, wantSec: DANEIndeterminateSecurity, wantErrSub: "indeterminate",
		},
		{
			name:        "network error is a lookup failure, never absence",
			exchangeErr: errTLSANetwork,
			wantRecords: 0, wantErrSub: "i/o timeout",
		},
		{
			name:        "secure RRset yields decoded record",
			resp:        dnsResponse(true, dns.RcodeSuccess, tlsaRR(3, 1, 1, assoc)),
			wantRecords: 1, wantSec: DANESecureSecurity,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeExchangeTLSA(t, tc.resp, tc.exchangeErr)
			records, secLevel, err := LookupTLSA("mx.example.test")
			if tc.wantErrSub == "" {
				if err != nil {
					t.Fatalf("LookupTLSA returned error %v, want absence/records with nil error", err)
				}
			} else {
				if err == nil {
					t.Fatalf("LookupTLSA returned nil error, want lookup failure containing %q", tc.wantErrSub)
				}
				if !strings.Contains(err.Error(), tc.wantErrSub) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErrSub)
				}
			}
			if len(records) != tc.wantRecords {
				t.Fatalf("LookupTLSA returned %d records, want %d", len(records), tc.wantRecords)
			}
			if secLevel != tc.wantSec {
				t.Errorf("secLevel = %q, want %q", secLevel, tc.wantSec)
			}
			if len(records) > 0 && string(records[0].CertAssoc) != string(assoc) {
				t.Errorf("CertAssoc = %q, want hex-DECODED association %q", records[0].CertAssoc, assoc)
			}
		})
	}
}

// TestLookupTLSA_ReturnsCompleteRRsetInOrder pins the item-3 repair: the WHOLE
// RRset comes back in answer order (rollover publishes old+new records side by
// side), and an undecodable association is KEPT as an unusable record (empty
// association) — never dropped into a fake absence or a fake lookup failure.
func TestLookupTLSA_ReturnsCompleteRRsetInOrder(t *testing.T) {
	assocA := []byte("aaaa")
	assocB := []byte("bbbb")
	resp := dnsResponse(true, dns.RcodeSuccess,
		tlsaRR(3, 1, 1, assocA),
		tlsaRRHex(3, 0, 1, "zz-not-hex"),
		tlsaRR(2, 1, 2, assocB),
	)
	fakeExchangeTLSA(t, resp, nil)
	records, secLevel, err := LookupTLSA("mx.example.test")
	if err != nil {
		t.Fatalf("LookupTLSA returned error %v, want the RRset", err)
	}
	if secLevel != DANESecureSecurity {
		t.Errorf("secLevel = %q, want %q", secLevel, DANESecureSecurity)
	}
	if len(records) != 3 {
		t.Fatalf("LookupTLSA returned %d records, want the COMPLETE RRset of 3", len(records))
	}
	if string(records[0].CertAssoc) != string(assocA) || records[0].Usage != 3 || records[0].Selector != 1 || records[0].MatchingType != 1 {
		t.Errorf("record[0] = %+v, want decoded assoc %q (usage 3, selector 1, matching 1)", records[0], assocA)
	}
	if len(records[1].CertAssoc) != 0 {
		t.Errorf("record[1] CertAssoc = %q, want EMPTY (undecodable → unusable, kept)", records[1].CertAssoc)
	}
	if string(records[2].CertAssoc) != string(assocB) || records[2].Usage != 2 || records[2].Selector != 1 || records[2].MatchingType != 2 {
		t.Errorf("record[2] = %+v, want decoded assoc %q (usage 2, selector 1, matching 2)", records[2], assocB)
	}
	if !usableTLSA(records[0]) {
		t.Error("record[0] must classify usable")
	}
	if usableTLSA(records[1]) {
		t.Error("record[1] (undecodable association) must classify UNUSABLE")
	}
	if !usableTLSA(records[2]) {
		t.Error("record[2] must classify usable")
	}
}

// errTLSANetwork simulates a resolver timeout / unreachable resolver.
var errTLSANetwork = errNetwork{}

type errNetwork struct{}

func (errNetwork) Error() string { return "i/o timeout" }

func TestValidateDANEConnection_AcceptanceMatrix(t *testing.T) {
	certEE, _ := newSelfSignedCert(t, "ee", "mx.example.test") // presented leaf, name matches TLSA base domain
	certBad, _ := newSelfSignedCert(t, "other")                // CA-valid-but-different leaf (VerifiedChains simulate PKIX OK)
	certTA, _ := newSelfSignedCert(t, "trust-anchor")          // DANE-TA(2) trust anchor in the presented chain
	certWrongTA, _ := newSelfSignedCert(t, "wrong-anchor")     // anchor the record asserts but the chain lacks
	logger := testLogger()

	caValidChain := [][]*x509.Certificate{{certBad, certEE}}

	tests := []struct {
		name  string
		resp  *dns.Msg
		state tls.ConnectionState
		want  DANEResult
	}{
		{
			name:  "no TLSA RRset keeps legitimate non-DANE delivery (opportunistic, no deferral)",
			resp:  dnsResponse(false, dns.RcodeSuccess),
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{certEE}},
			want:  DANEInsecure,
		},
		{
			name:  "authenticated denial (secure NODATA) also never defers or rejects",
			resp:  dnsResponse(true, dns.RcodeSuccess),
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{certEE}},
			want:  DANEInsecure,
		},
		{
			name:  "SERVFAIL defers with retry (lookup failure, never absence)",
			resp:  dnsResponse(false, dns.RcodeServerFailure),
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{certEE}},
			want:  DANELookupFailed,
		},
		{
			name:  "DANE-EE(3) match authenticates delivery",
			resp:  dnsResponse(true, dns.RcodeSuccess, tlsaRR(3, 0, 1, sha256Assoc(certEE))),
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{certEE}},
			want:  DANESecure,
		},
		{
			name:  "DANE-EE(3) mismatch rejects even against a CA-valid certificate",
			resp:  dnsResponse(true, dns.RcodeSuccess, tlsaRR(3, 0, 1, sha256Assoc(certEE))),
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{certBad}, VerifiedChains: caValidChain},
			want:  DANECertMismatch,
		},
		// DNSSEC security level (item 2): only an authenticated RRset drives
		// DANE. Unsigned records — matching or mismatching — retain non-DANE
		// behavior.
		{
			name:  "unsigned-zone MATCHING record retains non-DANE behavior",
			resp:  dnsResponse(false, dns.RcodeSuccess, tlsaRR(3, 0, 1, sha256Assoc(certEE))),
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{certEE}},
			want:  DANEInsecure,
		},
		{
			name:  "unsigned-zone MISMATCHING record never rejects a CA-valid certificate",
			resp:  dnsResponse(false, dns.RcodeSuccess, tlsaRR(3, 0, 1, sha256Assoc(certEE))),
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{certBad}, VerifiedChains: caValidChain},
			want:  DANEInsecure,
		},
		// Complete RRset (item 3): rollover in BOTH orders, unusable records
		// ignored.
		{
			name: "rollover: stale record first, matching record second authenticates",
			resp: dnsResponse(true, dns.RcodeSuccess,
				tlsaRR(3, 0, 1, sha256Assoc(certBad)), // old cert (rolled out)
				tlsaRR(3, 0, 1, sha256Assoc(certEE))), // new cert (presented)
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{certEE}},
			want:  DANESecure,
		},
		{
			name: "rollover: matching record first, stale record second authenticates",
			resp: dnsResponse(true, dns.RcodeSuccess,
				tlsaRR(3, 0, 1, sha256Assoc(certEE)), // new cert (presented)
				tlsaRR(3, 0, 1, sha256Assoc(certBad))),
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{certEE}},
			want:  DANESecure,
		},
		{
			name: "unsupported record before the matching record is ignored, not a mismatch",
			resp: dnsResponse(true, dns.RcodeSuccess,
				tlsaRR(5, 0, 1, sha256Assoc(certEE)), // unusable usage
				tlsaRR(3, 0, 1, sha256Assoc(certEE))),
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{certEE}},
			want:  DANESecure,
		},
		{
			name: "undecodable association plus matching record authenticates",
			resp: dnsResponse(true, dns.RcodeSuccess,
				tlsaRRHex(3, 0, 1, "zz-not-hex"), // unusable association
				tlsaRR(3, 0, 1, sha256Assoc(certEE))),
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{certEE}},
			want:  DANESecure,
		},
		{
			name: "usable record mismatching PLUS unusable record still rejects",
			resp: dnsResponse(true, dns.RcodeSuccess,
				tlsaRR(3, 0, 1, sha256Assoc(certBad)),
				tlsaRRHex(3, 0, 1, "zz-not-hex")),
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{certEE}, VerifiedChains: caValidChain},
			want:  DANECertMismatch,
		},
		{
			name: "every record unusable (unknown usage + undecodable) is SecureUnusable, not a mismatch",
			resp: dnsResponse(true, dns.RcodeSuccess,
				tlsaRR(5, 0, 1, sha256Assoc(certEE)),
				tlsaRRHex(3, 0, 1, "zz-not-hex")),
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{certEE}},
			want:  DANESecureUnusable,
		},
		{
			name:  "PKIX-EE(1) CA-valid chain with no TLSA match rejects",
			resp:  dnsResponse(true, dns.RcodeSuccess, tlsaRR(1, 0, 1, sha256Assoc(certEE))),
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{certBad}, VerifiedChains: caValidChain},
			want:  DANECertMismatch,
		},
		{
			name:  "DANE-TA(2) chain match + hostname match authenticates",
			resp:  dnsResponse(true, dns.RcodeSuccess, tlsaRR(2, 0, 1, sha256Assoc(certTA))),
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{certEE, certTA}},
			want:  DANESecure,
		},
		{
			name:  "DANE-TA(2) chain without the asserted anchor rejects",
			resp:  dnsResponse(true, dns.RcodeSuccess, tlsaRR(2, 0, 1, sha256Assoc(certWrongTA))),
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{certEE, certTA}},
			want:  DANECertMismatch,
		},
		{
			name:  "PKIX-TA(0) without a verified chain stays SecureUnusable (no chain to mismatch)",
			resp:  dnsResponse(true, dns.RcodeSuccess, tlsaRR(0, 0, 1, sha256Assoc(certEE))),
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{certEE}},
			want:  DANESecureUnusable,
		},
		{
			name:  "unknown TLSA usage is unusable, not a mismatch",
			resp:  dnsResponse(true, dns.RcodeSuccess, tlsaRR(5, 0, 1, sha256Assoc(certEE))),
			state: tls.ConnectionState{PeerCertificates: []*x509.Certificate{certEE}},
			want:  DANESecureUnusable,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeExchangeTLSA(t, tc.resp, nil)
			if got := ValidateDANEConnection(tc.state, "mx.example.test", logger); got != tc.want {
				t.Fatalf("ValidateDANEConnection = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestDANEPrecheckMX pins the complete pre-connection outcome (item 1): the
// three states are distinct — records published (authenticated) REQUIRE TLS, a
// failed/bogus lookup makes the server UNREACHABLE (defer), and everything
// else (absence, authenticated denial, unsigned-zone records) keeps plain
// opportunistic behavior.
func TestDANEPrecheckMX(t *testing.T) {
	assoc := []byte("deadbeef")
	tests := []struct {
		name        string
		resp        *dns.Msg
		exchangeErr error
		want        DANEPrecheck
	}{
		{
			name: "authenticated records → TLS required",
			resp: dnsResponse(true, dns.RcodeSuccess, tlsaRR(3, 1, 1, assoc)),
			want: DANEPrecheckRequired,
		},
		{
			name: "authenticated denial (secure NODATA) → no DANE",
			resp: dnsResponse(true, dns.RcodeSuccess),
			want: DANEPrecheckNone,
		},
		{
			name: "unsigned-zone records are ignored → no DANE",
			resp: dnsResponse(false, dns.RcodeSuccess, tlsaRR(3, 1, 1, assoc)),
			want: DANEPrecheckNone,
		},
		{
			name: "unsigned NODATA → no DANE",
			resp: dnsResponse(false, dns.RcodeSuccess),
			want: DANEPrecheckNone,
		},
		{
			name: "SERVFAIL (bogus DNSSEC) → unavailable, defer",
			resp: dnsResponse(false, dns.RcodeServerFailure),
			want: DANEPrecheckUnavailable,
		},
		{
			name: "refused rcode (indeterminate) → unavailable, defer",
			resp: dnsResponse(false, dns.RcodeRefused),
			want: DANEPrecheckUnavailable,
		},
		{
			name:        "network error → unavailable, defer",
			exchangeErr: errTLSANetwork,
			want:        DANEPrecheckUnavailable,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeExchangeTLSA(t, tc.resp, tc.exchangeErr)
			if got := DANEPrecheckMX("mx.example.test"); got != tc.want {
				t.Fatalf("DANEPrecheckMX = %v, want %v", got, tc.want)
			}
		})
	}
}
