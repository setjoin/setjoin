package smtp

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DANEResult represents the outcome of a DANE TLSA lookup and validation.
// Per RFC 7672 §2.2, there are four distinct outcomes.
type DANEResult int

const (
	// DANESecure — "secure" RRset with usable TLSA records.
	// TLS MUST be used, server MUST be authenticated via DANE.
	DANESecure DANEResult = iota

	// DANESecureUnusable — "secure" non-empty RRset where all records are unusable.
	// TLS MUST be used, but authentication is NOT required.
	DANESecureUnusable

	// DANEInsecure — "insecure" result or authenticated denial of existence.
	// Opportunistic TLS SHOULD be used (pre-DANE behavior).
	DANEInsecure

	// DANELookupFailed — TLSA lookup error or "bogus"/"indeterminate" DNSSEC.
	// Server MUST be treated as unreachable. Delivery MUST be delayed.
	DANELookupFailed

	// DANECertMismatch — "secure" RRset with usable TLSA records exists, but
	// NONE matches the presented certificate. Per RFC 7672 §2.2 the server
	// must be treated as unreachable: the caller rejects the delivery (even
	// when the presented certificate is CA-valid) and never falls back to
	// plaintext or to "no DANE" opportunistic handling.
	DANECertMismatch
)

// DANESecurityLevel classifies the DNSSEC validation state per RFC 4035 §4.3.
type DANESecurityLevel string

const (
	DANESecureSecurity        DANESecurityLevel = "secure"        // DNSSEC validated (AD bit)
	DANEInsecureSecurity      DANESecurityLevel = "insecure"      // zone unsigned, no trust anchor
	DANEBogusSecurity         DANESecurityLevel = "bogus"         // DNSSEC validation failed
	DANEIndeterminateSecurity DANESecurityLevel = "indeterminate" // transient resolver failure
)

// TLSARecord holds a parsed TLSA DNS record (RFC 6698 / RFC 7672).
type TLSARecord struct {
	Usage        uint8 // 0=PKIX-TA, 1=PKIX-EE, 2=DANE-TA, 3=DANE-EE
	Selector     uint8 // 0=full cert, 1=SubjectPublicKeyInfo
	MatchingType uint8 // 0=exact, 1=SHA-256, 2=SHA-512
	CertAssoc    []byte
}

// exchangeTLSA performs one DNSSEC-aware TLSA query for name (an FQDN) and
// returns the raw response so classifyDNSSEC — not the transport — owns the
// DNSSEC verdict. It is a package variable so tests script exact DNS answers
// (NODATA / NXDOMAIN / SERVFAIL / AD-bit responses) with no live DNS, mirroring
// the LookupTXT/LookupMX seams in helpers.go.
var exchangeTLSA = defaultExchangeTLSA

// tlsaUpstreamAddr resolves the "host:port" the default exchange queries. The
// previous implementation passed the EMPTY address to dns.Client.Exchange,
// which net.Dial resolves to ":53" — every TLSA lookup failed with a network
// error and DANE treated every domain as a lookup failure (or, via the
// precheck's false "no DANE" result, never saw records at all). The system
// resolver configuration is read once per process; when it is unavailable the
// repo's documented default DNSSEC upstream (the address dnsresolver.New uses
// for an empty config) is used.
var (
	tlsaResolverOnce sync.Once
	tlsaResolverAddr string
)

func tlsaUpstreamAddr() string {
	tlsaResolverOnce.Do(func() {
		tlsaResolverAddr = "1.1.1.1:53"
		if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cfg.Servers) > 0 {
			port := cfg.Port
			if port == "" {
				port = "53"
			}
			tlsaResolverAddr = net.JoinHostPort(cfg.Servers[0], port)
		}
	})
	return tlsaResolverAddr
}

func defaultExchangeTLSA(name string) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeTLSA)
	msg.SetEdns0(1232, true) // DO bit = DNSSEC OK (RFC 3225)
	msg.RecursionDesired = true

	client := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := client.Exchange(msg, tlsaUpstreamAddr())
	if err != nil {
		return nil, fmt.Errorf("TLSA lookup network error: %w", err)
	}
	return resp, nil
}

// LookupTLSA performs a DNSSEC-aware TLSA record lookup for _25._tcp.{mxHost}.
// Returns EVERY TLSA record of the RRset in answer order, the security level,
// and any error. Per RFC 7672 §2.1: security-oblivious stub resolvers MUST NOT
// be used.
//
// The complete RRset is load-bearing for the DANE acceptance matrix: certificate
// rollover publishes the old AND new associations side by side, so only a match
// across ALL records (not the first one) decides authentication, and a
// "secure" RRset made only of unusable records must stay distinguishable from
// authenticated absence (usableTLSA classifies records; an undecodable
// association is returned with an empty CertAssoc — an UNUSABLE record, never
// silently dropped into a fake absence).
//
// The ABSENT-vs-FAILURE distinction is equally load-bearing: (nil records, nil
// error) means "no TLSA RRset published" (NODATA or NXDOMAIN on the TLSA query)
// and MUST keep legitimate non-DANE opportunistic delivery — absence never
// defers or rejects. A non-nil error means a genuine lookup or DNSSEC failure
// (SERVFAIL, timeout, bogus) and MUST defer with retry, never degrade to
// plaintext and never masquerade as absence.
func LookupTLSA(mxHost string) ([]*TLSARecord, DANESecurityLevel, error) {
	mxHost = strings.TrimSuffix(mxHost, ".")
	name := "_25._tcp." + mxHost + "."

	resp, err := exchangeTLSA(name)
	if err != nil {
		return nil, "", err
	}
	if resp == nil {
		return nil, "", fmt.Errorf("TLSA lookup: nil response")
	}

	secLevel := classifyDNSSEC(resp)

	switch secLevel {
	case DANEBogusSecurity:
		// RFC 4035 §4.3: bogus = DNSSEC validation failed.
		// RFC 7672 §2.1: treat as unreachable.
		return nil, secLevel, fmt.Errorf("DANE: DNSSEC bogus for %s (rcode=%d)", mxHost, resp.Rcode)
	case DANEIndeterminateSecurity:
		// RFC 4035 §4.3: indeterminate = transient resolver failure.
		// RFC 7672 §2.1: "MUST be treated as lookup failure."
		return nil, secLevel, fmt.Errorf("DANE: DNSSEC indeterminate for %s — resolver cannot validate", mxHost)
	}

	// No TLSA records at all — authenticated denial (secure NXDOMAIN/NODATA)
	// or insecure zone with no records. Both are "insecure" outcomes.
	if len(resp.Answer) == 0 {
		return nil, secLevel, nil // nil records + no error = no DANE
	}

	var records []*TLSARecord
	for _, ans := range resp.Answer {
		tlsa, ok := ans.(*dns.TLSA)
		if !ok {
			continue
		}
		// RFC 7672 §3: PKIX-TA(0) and PKIX-EE(1) SHOULD NOT be published for SMTP port 25.
		if tlsa.Usage == 0 || tlsa.Usage == 1 {
			slog.Warn("DANE: PKIX-TA/PKIX-EE usage published for SMTP — per RFC 7672 §3, use DANE-EE(3) or DANE-TA(2) instead",
				"mx_host", mxHost, "usage", tlsa.Usage)
		}
		// The DNS wire carries the certificate association as hex text
		// (miekg/dns keeps tlsa.Certificate as the hex string); the association
		// must be DECODED to raw bytes or ValidateTLSA's length comparison can
		// never match a computed hash. An undecodable record is kept with an
		// empty association — an UNUSABLE record, classified by usableTLSA —
		// rather than dropped into a fake absence or a fake lookup failure.
		certAssoc, decErr := hex.DecodeString(tlsa.Certificate)
		if decErr != nil {
			slog.Warn("DANE: undecodable TLSA certificate association — record kept as unusable",
				"mx_host", mxHost, "error", decErr)
			records = append(records, &TLSARecord{
				Usage:        tlsa.Usage,
				Selector:     tlsa.Selector,
				MatchingType: tlsa.MatchingType,
			})
			continue
		}
		records = append(records, &TLSARecord{
			Usage:        tlsa.Usage,
			Selector:     tlsa.Selector,
			MatchingType: tlsa.MatchingType,
			CertAssoc:    certAssoc,
		})
	}
	return records, secLevel, nil // every record of the RRset, in answer order
}

// usableTLSA reports whether a decoded TLSA record is usable per RFC 6698
// §2.1.1: a supported usage (0–3), selector (0–1), matching type (0–2) and a
// non-empty decodable certificate association. Unusable records never
// authenticate and never become mismatches — they are ignored; a "secure"
// RRset made only of unusable records is the DANESecureUnusable outcome.
func usableTLSA(rec *TLSARecord) bool {
	return rec != nil && len(rec.CertAssoc) > 0 &&
		rec.Usage <= 3 && rec.Selector <= 1 && rec.MatchingType <= 2
}

// classifyDNSSEC determines the DNSSEC validation state per RFC 4035 §4.3.
func classifyDNSSEC(resp *dns.Msg) DANESecurityLevel {
	if resp.MsgHdr.AuthenticatedData {
		return DANESecureSecurity
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		// Valid response but not authenticated — zone is unsigned (insecure)
		return DANEInsecureSecurity
	case dns.RcodeNameError:
		// NXDOMAIN — could be secure or insecure
		if resp.MsgHdr.AuthenticatedData {
			return DANESecureSecurity
		}
		return DANEInsecureSecurity
	case dns.RcodeServerFailure:
		// SERVFAIL = bogus (validation failure)
		return DANEBogusSecurity
	default:
		// Other error codes = indeterminate
		return DANEIndeterminateSecurity
	}
}

// ValidateTLSA validates a TLS peer certificate against a TLSA record.
// Returns nil on match, error on mismatch.
func ValidateTLSA(cert *x509.Certificate, record *TLSARecord) error {
	if record == nil || cert == nil {
		return fmt.Errorf("DANE: nil cert or record")
	}

	var data []byte
	switch record.Selector {
	case 0: // Full certificate
		data = cert.Raw
	case 1: // SubjectPublicKeyInfo
		data = cert.RawSubjectPublicKeyInfo
	default:
		return fmt.Errorf("DANE: unknown selector %d", record.Selector)
	}

	var expected []byte
	switch record.MatchingType {
	case 0: // Exact match
		expected = make([]byte, len(data))
		copy(expected, data)
	case 1: // SHA-256
		h := sha256.Sum256(data)
		expected = h[:]
	case 2: // SHA-512
		h := sha512.Sum512(data)
		expected = h[:]
	default:
		return fmt.Errorf("DANE: unknown matching type %d", record.MatchingType)
	}

	if len(expected) != len(record.CertAssoc) {
		return fmt.Errorf("DANE: hash size mismatch (expected %d, got %d)", len(expected), len(record.CertAssoc))
	}
	for i := range expected {
		if expected[i] != record.CertAssoc[i] {
			return fmt.Errorf("DANE: TLSA validation failed — certificate does not match TLSA record")
		}
	}
	return nil
}

// hasPKIXChain reports whether the TLS connection state includes at least one
// PKIX-validated certificate chain.  PKIX usage modes (0 and 1) require this
// per RFC 6698 §2.1.1; DANE usage modes (2 and 3) do not.
func hasPKIXChain(cs tls.ConnectionState) bool {
	return len(cs.VerifiedChains) > 0 && len(cs.VerifiedChains[0]) > 0
}

// ValidateDANEConnection validates a TLS connection against DANE TLSA records
// per RFC 7672 §2.2 and §3.
//
// Returns a DANEResult indicating the outcome. The caller must:
//   - On DANESecure: authentication passed, proceed with delivery.
//   - On DANESecureUnusable: the "secure" RRset contains no usable records;
//     TLS is active but DANE authentication is not possible; proceed but log.
//   - On DANEInsecure: no authenticated TLSA records apply; use opportunistic
//     TLS. Absence never defers or rejects — non-DANE delivery under the
//     existing opportunistic/MTA-STS policy is preserved. This is ALSO the
//     outcome for records published in an UNSIGNED zone: without the AD-bit
//     security level they MUST NOT authenticate DANE nor trigger mismatch
//     rejections, matching or not (RFC 7672 §2.1/§2.3).
//   - On DANECertMismatch: authenticated usable TLSA records exist and the
//     presented certificate matches none of them; reject the delivery even
//     when the certificate is CA-valid (RFC 7672 §2.2 — server treated as
//     unreachable).
//   - On DANELookupFailed: server is unreachable; defer with retry. Never
//     degrade to plaintext, never treat as absence.
func ValidateDANEConnection(cs tls.ConnectionState, mxHost string, logger *slog.Logger) DANEResult {
	records, secLevel, err := LookupTLSA(mxHost)
	if err != nil {
		logger.Warn("DANE: TLSA lookup failed — server unreachable per RFC 7672 §2.1",
			"mx_host", mxHost, "error", err, "sec_level", secLevel)
		return DANELookupFailed
	}

	// The DNSSEC security level returned with the records is authoritative:
	// only an authenticated ("secure", AD-bit) RRset may drive DANE. Unsigned
	// records — matching or mismatching — are ignored, retaining non-DANE
	// opportunistic behavior (previously the level was discarded, so unsigned
	// records could authenticate DANE or trigger mismatch rejections).
	if secLevel != DANESecureSecurity {
		return DANEInsecure
	}

	// Classify the COMPLETE RRset. Unusable records (unsupported usage /
	// selector / matching type, undecodable association) never authenticate
	// and never become mismatches; a match on ANY usable record authenticates
	// (certificate rollover publishes old and new associations side by side).
	var usable []*TLSARecord
	for _, rec := range records {
		if usableTLSA(rec) {
			usable = append(usable, rec)
		} else {
			logger.Warn("DANE: unusable TLSA record ignored — unsupported usage/selector/matching type or undecodable association",
				"mx_host", mxHost, "usage", rec.Usage, "selector", rec.Selector, "matching_type", rec.MatchingType)
		}
	}
	switch {
	case len(records) == 0:
		// Authenticated denial (secure NODATA/NXDOMAIN) — no DANE.
		return DANEInsecure
	case len(usable) == 0:
		// "Secure" non-empty RRset with no USABLE records — TLS is active and
		// required, but DANE authentication is not possible (RFC 7672 §2.2).
		logger.Warn("DANE: secure TLSA RRset contains no usable records — TLS active, authentication not required per RFC 7672 §2.2",
			"mx_host", mxHost)
		return DANESecureUnusable
	}

	if len(cs.PeerCertificates) == 0 {
		logger.Warn("DANE: no peer certificates in TLS handshake", "mx_host", mxHost)
		return DANESecureUnusable
	}

	// Try EVERY usable record in the RRset: the first matching one
	// authenticates, so a rollover RRset is accepted in either order.
	matched, evaluated := false, false
	for _, rec := range usable {
		if (rec.Usage == 0 || rec.Usage == 1) && !hasPKIXChain(cs) {
			// PKIX usage records cannot be evaluated without a PKIX-validated
			// chain — the record is skipped (not a mismatch); the
			// DANESecureUnusable outcome is preserved when nothing else
			// matches either.
			continue
		}
		evaluated = true
		if daneRecordMatches(cs, rec, mxHost, logger) {
			matched = true
			break
		}
	}
	switch {
	case matched:
		return DANESecure
	case evaluated:
		// Usable authenticated records exist and NONE matches the presented
		// certificate — reject per RFC 7672 §2.2 even against a CA-valid
		// certificate.
		return DANECertMismatch
	default:
		// Nothing was actually evaluated against the certificate (every PKIX
		// usage record lacked its required validated chain).
		return DANESecureUnusable
	}
}

// daneRecordMatches reports whether the TLS connection state satisfies ONE
// usable TLSA record per its usage mode (RFC 6698 §2.1.1, RFC 7672 §3).
// Prerequisite checks (PKIX chain availability) belong to the caller so a
// skipped record stays distinct from an evaluated mismatch.
func daneRecordMatches(cs tls.ConnectionState, rec *TLSARecord, mxHost string, logger *slog.Logger) bool {
	leafCert := cs.PeerCertificates[0]
	switch rec.Usage {
	case 0: // PKIX-TA — CA constraint; PKIX-validated chain required (checked by caller).
		for _, chainCert := range cs.PeerCertificates {
			if ValidateTLSA(chainCert, rec) == nil {
				return true
			}
		}
		return false

	case 1: // PKIX-EE — service certificate constraint; PKIX chain required (checked by caller).
		return ValidateTLSA(leafCert, rec) == nil

	case 2: // DANE-TA — trust anchor assertion.
		// PKIX validation is NOT required. The TLSA record binds a trust anchor
		// to the domain. Name checks against the TLSA base domain are required
		// per RFC 7672 §3.
		for _, chainCert := range cs.PeerCertificates[1:] {
			if ValidateTLSA(chainCert, rec) == nil {
				if err := leafCert.VerifyHostname(mxHost); err != nil {
					logger.Warn("DANE: DANE-TA name check failed — cert CN/SAN does not match TLSA base domain",
						"mx_host", mxHost, "error", err)
					continue
				}
				return true
			}
		}
		return false

	default: // 3: DANE-EE — domain-issued certificate.
		// PKIX validation and name checks are NOT required. The TLSA record
		// itself authenticates the server certificate (RFC 7672 §3).
		return ValidateTLSA(leafCert, rec) == nil
	}
}

// DANEPrecheck is the pre-connection DANE requirement for an MX host — the
// complete outcome the outbound path must evaluate BEFORE choosing a pooled or
// fresh connection and BEFORE any MAIL/DATA command.
type DANEPrecheck int

const (
	// DANEPrecheckNone — no authenticated TLSA records apply (absence incl.
	// authenticated denial, or an unsigned zone whose records MUST be
	// ignored). Opportunistic behavior: plaintext permitted, no DANE
	// validation.
	DANEPrecheckNone DANEPrecheck = iota

	// DANEPrecheckRequired — authenticated TLSA records exist. TLS is
	// mandatory for this attempt: STARTTLS must be offered and used (admin
	// skipTLS MUST NOT bypass this), the attempt must never ride a pooled
	// plaintext session, and after the handshake the certificate must satisfy
	// the records (ValidateDANEConnection).
	DANEPrecheckRequired

	// DANEPrecheckUnavailable — the TLSA lookup failed (network error,
	// SERVFAIL, bogus or indeterminate DNSSEC). The server MUST be treated as
	// unreachable: delivery deferred with retry (RFC 7672 §2.1). Never
	// plaintext, never treated as "no DANE".
	DANEPrecheckUnavailable
)

// DANEPrecheckMX classifies the CURRENT DANE requirement for mxHost. It
// replaces the former IsDANEAvailable boolean, which collapsed lookup
// failures (and unsigned-zone records) into "no DANE" — permitting plaintext
// exactly when STARTTLS stripping or a skipTLS opt-out removed the only TLS
// path. Here the three outcomes are distinct and callers fail closed.
func DANEPrecheckMX(mxHost string) DANEPrecheck {
	records, secLevel, err := LookupTLSA(mxHost)
	if err != nil {
		return DANEPrecheckUnavailable
	}
	// Only an authenticated ("secure") RRset applies; unsigned records are
	// ignored, and an authenticated empty answer is plain absence.
	if secLevel != DANESecureSecurity || len(records) == 0 {
		return DANEPrecheckNone
	}
	return DANEPrecheckRequired
}

// DANEVerificationResult holds structured DANE verification info for logging/TLS-RPT.
type DANEVerificationResult struct {
	MXHost      string            `json:"mx_host"`
	Result      string            `json:"result"`
	Security    DANESecurityLevel `json:"security_level"`
	TLSAUsage   *uint8            `json:"tlsa_usage,omitempty"`
	IsAvailable bool              `json:"is_available"`
}
