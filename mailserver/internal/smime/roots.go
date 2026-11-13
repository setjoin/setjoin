package smime

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"sync"
	"time"
)

//go:embed cacert.pem
var bundledCABytes []byte

// LoadBundledRoots returns an x509.CertPool of the embedded Mozilla CA bundle.
// No network needed (compiled in) — works air-gapped.
func LoadBundledRoots() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundledCABytes) {
		return nil, errors.New("smime: failed to parse embedded CA bundle")
	}
	return pool, nil
}

// AnchorPEM pairs a stored admin-imported PEM with the fingerprint row that
// authorizes it. Round 6 (Astra HOLD, D-MAILSERVER-INTERNAL-CALDAV-004
// reopened): a stored PEM may contain SEVERAL certificates while its row
// carries one fingerprint — BuildTrustPool therefore loads ONLY the
// certificates whose SHA-256 DER fingerprint equals the authorizing row, so an
// unfingerprinted certificate riding inside a stored bundle can never enter a
// trust pool.
type AnchorPEM struct {
	PEM         string
	Fingerprint string
}

// BuildTrustPool returns LoadBundledRoots() augmented with each admin-imported
// anchor cert that its stored fingerprint row authorizes: every PEM block of
// every entry is parsed and only the certs whose DER fingerprint matches the
// entry's Fingerprint are added — an unparseable or unfingerprinted cert is
// skipped (a bad row never breaks the pool, and it never grants trust either).
// The CALLER selects which rows to pass (e.g. deployment-wide + a recipient
// domain's anchors — per-tenant scoping lives in the DB query, not here).
func BuildTrustPool(anchors []AnchorPEM) (*x509.CertPool, error) {
	pool, err := LoadBundledRoots()
	if err != nil {
		return nil, err
	}
	for _, a := range anchors {
		certs, perr := ParseAllCerts([]byte(a.PEM))
		if perr != nil {
			continue
		}
		for _, c := range certs {
			if a.Fingerprint != "" && FingerprintCert(c) == a.Fingerprint {
				pool.AddCert(c)
			}
		}
	}
	return pool, nil
}

// ParsedAnchorCert is ONE certificate of an imported anchor PEM: its
// re-encoded single-cert PEM, DER fingerprint, and display/validity metadata —
// the unit the admin trust-store import persists (one row per certificate, so
// the stored fingerprint list covers EVERY certificate of the uploaded bundle).
type ParsedAnchorCert struct {
	PEM         string
	Fingerprint string
	SubjectCN   string
	NotBefore   time.Time
	NotAfter    time.Time
}

// ParseAllCerts parses EVERY PEM certificate block of pemBytes. It fails when
// no block parses as a certificate, when any block fails to parse, or when
// non-whitespace content remains after the last certificate (fail closed: an
// import that is not entirely certificates must not be stored).
func ParseAllCerts(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		block, remain := pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		rest = remain
	}
	if len(certs) == 0 {
		return nil, errors.New("smime: failed to decode PEM certificate")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("smime: trailing non-certificate content after PEM block")
	}
	return certs, nil
}

// ParseAnchorChain splits a PEM (possibly a multi-cert bundle) into
// per-certificate ParsedAnchorCert records — the fingerprint list the import
// stores alongside the anchor.
func ParseAnchorChain(certPEM string) ([]ParsedAnchorCert, error) {
	certs, err := ParseAllCerts([]byte(certPEM))
	if err != nil {
		return nil, err
	}
	out := make([]ParsedAnchorCert, 0, len(certs))
	for _, c := range certs {
		out = append(out, ParsedAnchorCert{
			PEM:         string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})),
			Fingerprint: FingerprintCert(c),
			SubjectCN:   c.Subject.CommonName,
			NotBefore:   c.NotBefore,
			NotAfter:    c.NotAfter,
		})
	}
	return out, nil
}

// Fingerprint returns a cert PEM's lowercase-hex SHA-256 DER fingerprint plus
// display/validity metadata of the FIRST certificate, for admin display +
// dedupe. For multi-cert PEMs the import path must use ParseAnchorChain —
// Fingerprint alone deliberately covers only the first block.
func Fingerprint(certPEM string) (fp, subjectCN string, notBefore, notAfter time.Time, err error) {
	cert, err := ParseCert([]byte(certPEM))
	if err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	return FingerprintCert(cert), cert.Subject.CommonName, cert.NotBefore, cert.NotAfter, nil
}

// FingerprintCert returns the lowercase-hex SHA-256 fingerprint of a parsed
// certificate's DER bytes.
func FingerprintCert(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

var (
	bundledFPOnce sync.Once
	bundledFPs    map[string]struct{}
)

// IsBundledRoot reports whether the fingerprint belongs to a root of the
// embedded Mozilla CA bundle — the public trust that needs no
// smime_trust_anchors row. Callers use it to separate "bundled public root ⇒
// unrestricted" from "unknown cert ⇒ fail closed" when resolving which tenant
// domains a validated chain's anchor grants.
func IsBundledRoot(fp string) bool {
	bundledFPOnce.Do(func() {
		bundledFPs = make(map[string]struct{})
		rest := bundledCABytes
		for {
			block, remain := pem.Decode(rest)
			if block == nil {
				break
			}
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				bundledFPs[FingerprintCert(cert)] = struct{}{}
			}
			rest = remain
		}
	})
	if fp == "" {
		return false
	}
	_, ok := bundledFPs[fp]
	return ok
}
