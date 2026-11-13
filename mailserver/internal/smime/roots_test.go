package smime

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestLoadBundledRoots(t *testing.T) {
	pool, err := LoadBundledRoots()
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil {
		t.Fatal("nil pool")
	}
	if len(pool.Subjects()) < 50 { //nolint:staticcheck
		t.Fatalf("expected a populated CA pool, got %d", len(pool.Subjects())) //nolint:staticcheck
	}
}

// selfSignedPEM generates a minimal self-signed root CA certificate and returns its PEM.
func selfSignedPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestBuildTrustPoolAddsAdminRoots(t *testing.T) {
	adminPEM := selfSignedPEM(t, "Test Admin CA")

	bundlePool, err := LoadBundledRoots()
	if err != nil {
		t.Fatal(err)
	}
	bundleCount := len(bundlePool.Subjects()) //nolint:staticcheck

	pool, err := BuildTrustPool([]AnchorPEM{{PEM: adminPEM, Fingerprint: mustPEMFingerprint(t, adminPEM)}})
	if err != nil {
		t.Fatal(err)
	}
	got := len(pool.Subjects()) //nolint:staticcheck
	want := bundleCount + 1
	if got != want {
		t.Fatalf("BuildTrustPool: expected %d subjects, got %d", want, got)
	}
}

func TestBuildTrustPoolSkipsUnparseable(t *testing.T) {
	validPEM := selfSignedPEM(t, "Good CA")

	pool, err := BuildTrustPool([]AnchorPEM{
		{PEM: "not a pem", Fingerprint: "00"},
		{PEM: validPEM, Fingerprint: mustPEMFingerprint(t, validPEM)},
	})
	if err != nil {
		t.Fatal(err)
	}
	bundlePool, err := LoadBundledRoots()
	if err != nil {
		t.Fatal(err)
	}
	// bad row skipped, good one added — net +1
	got := len(pool.Subjects())        //nolint:staticcheck
	base := len(bundlePool.Subjects()) //nolint:staticcheck
	if got != base+1 {
		t.Fatalf("BuildTrustPool: expected %d subjects (bad PEM skipped), got %d", base+1, got)
	}
}

// TestBuildTrustPool_LoadsOnlyFingerprintedCerts — round 6 (Astra HOLD): a
// stored PEM may contain several certificates, but its row authorizes exactly
// one fingerprint. Only the fingerprinted cert may enter the pool; an extra
// cert riding in the same PEM (no row of its own) and a row with an empty
// fingerprint must both be excluded.
func TestBuildTrustPool_LoadsOnlyFingerprintedCerts(t *testing.T) {
	first, second := selfSignedPEM(t, "Bundle CA One"), selfSignedPEM(t, "Bundle CA Two")
	firstFP, secondFP := mustPEMFingerprint(t, first), mustPEMFingerprint(t, second)
	completeBundle := first + second

	bundlePool, err := LoadBundledRoots()
	if err != nil {
		t.Fatal(err)
	}
	base := len(bundlePool.Subjects()) //nolint:staticcheck

	t.Run("only the row-fingerprinted cert enters the pool", func(t *testing.T) {
		pool, err := BuildTrustPool([]AnchorPEM{{PEM: completeBundle, Fingerprint: secondFP}})
		if err != nil {
			t.Fatal(err)
		}
		if got := len(pool.Subjects()); got != base+1 { //nolint:staticcheck
			t.Fatalf("expected bundle+1 subjects (only the fingerprinted cert), got +%d", got-base)
		}
		if !poolContains(t, pool, second) {
			t.Error("fingerprinted cert (Bundle CA Two) must be in the pool")
		}
		if poolContains(t, pool, first) {
			securityFail(t, "unfingerprinted cert (Bundle CA One) entered the trust pool — pre-round-6 smuggling")
		}
	})

	t.Run("empty fingerprint row grants nothing", func(t *testing.T) {
		pool, err := BuildTrustPool([]AnchorPEM{{PEM: completeBundle, Fingerprint: ""}})
		if err != nil {
			t.Fatal(err)
		}
		if got := len(pool.Subjects()); got != base { //nolint:staticcheck
			t.Fatalf("expected bundle-only subjects, got +%d", got-base)
		}
		if poolContains(t, pool, first) || poolContains(t, pool, second) {
			securityFail(t, "a row with no fingerprint granted trust")
		}
	})

	t.Run("mismatched fingerprint grants nothing", func(t *testing.T) {
		pool, err := BuildTrustPool([]AnchorPEM{{PEM: completeBundle, Fingerprint: firstFP + "deadbeef"}})
		if err != nil {
			t.Fatal(err)
		}
		if got := len(pool.Subjects()); got != base { //nolint:staticcheck
			t.Fatalf("expected bundle-only subjects, got +%d", got-base)
		}
	})
}

// TestParseAnchorChain_EveryCertFingerprinted — round 6: the import path must
// produce one fingerprinted record per certificate of a multi-cert PEM, in
// order, each re-encoded as its own single-cert PEM.
func TestParseAnchorChain_EveryCertFingerprinted(t *testing.T) {
	first, second := selfSignedPEM(t, "Chain CA One"), selfSignedPEM(t, "Chain CA Two")
	certs, err := ParseAnchorChain(first + second)
	if err != nil {
		t.Fatalf("ParseAnchorChain: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 parsed certs, got %d", len(certs))
	}
	if certs[0].Fingerprint != mustPEMFingerprint(t, first) || certs[0].SubjectCN != "Chain CA One" {
		t.Errorf("cert 0 = (%s, %s), want (Chain CA One fingerprint, CN)", certs[0].Fingerprint, certs[0].SubjectCN)
	}
	if certs[1].Fingerprint != mustPEMFingerprint(t, second) || certs[1].SubjectCN != "Chain CA Two" {
		t.Errorf("cert 1 = (%s, %s), want (Chain CA Two fingerprint, CN)", certs[1].Fingerprint, certs[1].SubjectCN)
	}
	for i, c := range certs {
		if c.Fingerprint != mustPEMFingerprint(t, c.PEM) {
			t.Errorf("cert %d: re-encoded PEM does not match its stored fingerprint", i)
		}
	}
	if _, err := ParseAnchorChain(first + "garbage"); err == nil {
		t.Error("trailing non-PEM garbage must fail the parse (fail closed)")
	}
	if _, err := ParseAnchorChain("not a pem"); err == nil {
		t.Error("expected error for PEM-less input")
	}
}

// TestIsBundledRoot distinguishes bundled public roots from unknown certs —
// the boundary the round-6 fail-closed anchor resolver relies on.
func TestIsBundledRoot(t *testing.T) {
	// A real bundled root: fingerprint every cert of the embedded bundle and
	// require at least one hit through IsBundledRoot.
	rest := bundledCABytes
	found := 0
	for {
		block, remain := pem.Decode(rest)
		if block == nil {
			break
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil && IsBundledRoot(FingerprintCert(cert)) {
			found++
		}
		rest = remain
	}
	if found == 0 {
		t.Fatal("IsBundledRoot recognized none of the embedded bundle roots")
	}
	if IsBundledRoot(mustPEMFingerprint(t, selfSignedPEM(t, "Not Bundled"))) {
		t.Error("a self-signed test CA must not be classified as a bundled root")
	}
	if IsBundledRoot("") {
		t.Error("empty fingerprint must not be a bundled root")
	}
}

func mustPEMFingerprint(t *testing.T, certPEM string) string {
	t.Helper()
	fp, _, _, _, err := Fingerprint(certPEM)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	return fp
}

// poolContains reports whether the pool accepts cert as a root (Subject-based
// comparison like the other pool assertions in this file).
func poolContains(t *testing.T, pool *x509.CertPool, certPEM string) bool {
	t.Helper()
	cert, err := ParseCert([]byte(certPEM))
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}
	for _, subj := range pool.Subjects() { //nolint:staticcheck
		if bytes.Equal(subj, cert.RawSubject) {
			return true
		}
	}
	return false
}

func securityFail(t *testing.T, msg string) {
	t.Helper()
	t.Fatal("SECURITY: " + msg)
}

func TestFingerprint(t *testing.T) {
	const cn = "Test Fingerprint CA"
	certPEM := selfSignedPEM(t, cn)

	fp, subjectCN, notBefore, notAfter, err := Fingerprint(certPEM)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if len(fp) != 64 {
		t.Fatalf("Fingerprint: expected 64-char hex, got %d chars: %q", len(fp), fp)
	}
	if subjectCN != cn {
		t.Fatalf("Fingerprint: expected CN=%q, got %q", cn, subjectCN)
	}
	if notBefore.IsZero() || notAfter.IsZero() {
		t.Fatal("Fingerprint: notBefore/notAfter must not be zero")
	}
	if !notAfter.After(notBefore) {
		t.Fatalf("Fingerprint: notAfter %v not after notBefore %v", notAfter, notBefore)
	}
}

func TestFingerprintErrorOnBadPEM(t *testing.T) {
	_, _, _, _, err := Fingerprint("not a cert")
	if err == nil {
		t.Fatal("Fingerprint: expected error on bad PEM, got nil")
	}
}
