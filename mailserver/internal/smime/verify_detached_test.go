package smime

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	cms "github.com/github/smimesign/ietf-cms"
)

// testCA builds a self-signed root CA and a leaf cert signed by it.
// The leaf has ExtKeyUsage EmailProtection and the given email SAN(s).
// notAfter controls the leaf validity window.
// Returns root, leaf, leafKey.
func testCA(t *testing.T, leafEmails []string, notAfter time.Time) (*x509.Certificate, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	// Root CA key + cert (self-signed, CA:true)
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root cert: %v", err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root cert: %v", err)
	}

	// Leaf key + cert (signed by root)
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	cn := ""
	if len(leafEmails) > 0 {
		cn = leafEmails[0]
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(2),
		Subject:        pkix.Name{CommonName: cn},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       notAfter,
		EmailAddresses: leafEmails,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	return root, leaf, leafKey
}

// signDetachedForTest produces a DER detached CMS signature using the ietf-cms library.
// Note: smime.Sign uses a hand-rolled CMS format that is incompatible with
// ietf-cms.ParseSignedData's certificate extraction (it stores cert Bytes, not FullBytes).
// Tests use cms.SignDetached directly so the library can roundtrip its own format.
func signDetachedForTest(t *testing.T, content []byte, leaf *x509.Certificate, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := cms.SignDetached(content, []*x509.Certificate{leaf}, key)
	if err != nil {
		t.Fatalf("cms.SignDetached: %v", err)
	}
	return der
}

// TestVerifyDetachedValid asserts the happy path: trusted root, From matches cert email.
// Also asserts that SignerCN, IssuerCN, and SignerEmail are populated.
func TestVerifyDetachedValid(t *testing.T) {
	email := "alice@corp.example"
	root, leaf, key := testCA(t, []string{email}, time.Now().Add(time.Hour))

	content := []byte("hello, S/MIME")
	sigDER := signDetachedForTest(t, content, leaf, key)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	res := VerifyDetached(content, sigDER, email, roots)
	if res.Status != StatusValid {
		t.Errorf("expected %q, got %q", StatusValid, res.Status)
	}
	if res.SignerEmail == "" {
		t.Error("SignerEmail should be populated on StatusValid")
	}
	if res.SignerCN == "" {
		t.Error("SignerCN should be populated on StatusValid")
	}
	if res.IssuerCN == "" {
		t.Error("IssuerCN should be populated on StatusValid")
	}
	t.Logf("SignerEmail=%s SignerCN=%s IssuerCN=%s", res.SignerEmail, res.SignerCN, res.IssuerCN)
}

// TestVerifyDetachedValidPopulatesLeafPEM asserts that a StatusValid verdict exposes
// the verified signer leaf as a PEM block, and that the PEM re-parses to a cert whose
// CommonName matches res.SignerCN. This is the harvest input (Phase 2): without the
// leaf PEM on the result, the inbound harvest hook would have nothing to store.
func TestVerifyDetachedValidPopulatesLeafPEM(t *testing.T) {
	email := "alice@corp.example"
	root, leaf, key := testCA(t, []string{email}, time.Now().Add(time.Hour))

	content := []byte("hello, S/MIME")
	sigDER := signDetachedForTest(t, content, leaf, key)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	res := VerifyDetached(content, sigDER, email, roots)
	if res.Status != StatusValid {
		t.Fatalf("expected %q, got %q", StatusValid, res.Status)
	}
	if !strings.HasPrefix(res.LeafPEM, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("LeafPEM should start with the PEM cert header, got %q", res.LeafPEM)
	}
	block, _ := pem.Decode([]byte(res.LeafPEM))
	if block == nil {
		t.Fatal("LeafPEM did not decode as a PEM block")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("LeafPEM did not parse as an x509 cert: %v", err)
	}
	if parsed.Subject.CommonName != res.SignerCN {
		t.Errorf("LeafPEM CN %q != res.SignerCN %q", parsed.Subject.CommonName, res.SignerCN)
	}
}

// TestVerifyDetachedValidPopulatesTrustAnchorPEM — round 5 (Astra HOLD): a
// StatusValid verdict must expose the VALIDATED chain's trust anchor so the
// caller can bind the signer email's domain to the trust that actually
// validated the chain (the anchor's tenant grant), not to the claimed email.
func TestVerifyDetachedValidPopulatesTrustAnchorPEM(t *testing.T) {
	email := "alice@corp.example"
	root, leaf, key := testCA(t, []string{email}, time.Now().Add(time.Hour))

	content := []byte("hello, S/MIME")
	sigDER := signDetachedForTest(t, content, leaf, key)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	res := VerifyDetached(content, sigDER, email, roots)
	if res.Status != StatusValid {
		t.Fatalf("expected %q, got %q", StatusValid, res.Status)
	}
	if !strings.HasPrefix(res.TrustAnchorPEM, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("TrustAnchorPEM should start with the PEM cert header, got %q", res.TrustAnchorPEM)
	}
	block, _ := pem.Decode([]byte(res.TrustAnchorPEM))
	if block == nil {
		t.Fatal("TrustAnchorPEM did not decode as a PEM block")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("TrustAnchorPEM did not parse as an x509 cert: %v", err)
	}
	if !parsed.Equal(root) {
		t.Error("TrustAnchorPEM must be the validated chain's anchor (the fixture root)")
	}
}

// TestVerifyDetachedUntrustedRoot asserts StatusUntrusted when root is not in pool.
func TestVerifyDetachedUntrustedRoot(t *testing.T) {
	email := "bob@corp.example"
	_, leaf, key := testCA(t, []string{email}, time.Now().Add(time.Hour))

	content := []byte("hello, untrusted")
	sigDER := signDetachedForTest(t, content, leaf, key)

	emptyRoots := x509.NewCertPool() // root not added

	res := VerifyDetached(content, sigDER, email, emptyRoots)
	if res.Status != StatusUntrusted {
		t.Errorf("expected %q, got %q", StatusUntrusted, res.Status)
	}
	// LeafPEM is harvest input and must be set ONLY on a fully-valid verdict — an
	// untrusted signer must never be harvested, so the field stays empty here.
	if res.LeafPEM != "" {
		t.Errorf("LeafPEM must be empty for %q, got %q", StatusUntrusted, res.LeafPEM)
	}
	// TrustAnchorPEM carries anchor-derived authority (round 5) and must be
	// empty for every non-valid verdict, same fail-closed rule as LeafPEM.
	if res.TrustAnchorPEM != "" {
		t.Errorf("TrustAnchorPEM must be empty for %q, got %q", StatusUntrusted, res.TrustAnchorPEM)
	}
}

// TestVerifyDetachedFromMismatch asserts StatusUntrusted when From doesn't match cert email.
func TestVerifyDetachedFromMismatch(t *testing.T) {
	email := "carol@corp.example"
	root, leaf, key := testCA(t, []string{email}, time.Now().Add(time.Hour))

	content := []byte("hello, mismatch")
	sigDER := signDetachedForTest(t, content, leaf, key)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	res := VerifyDetached(content, sigDER, "someone-else@x", roots)
	if res.Status != StatusUntrusted {
		t.Errorf("expected %q, got %q", StatusUntrusted, res.Status)
	}
}

// TestVerifyDetachedExpired asserts StatusUntrusted for an expired leaf cert.
func TestVerifyDetachedExpired(t *testing.T) {
	email := "expired@corp.example"
	// notAfter in the past — leaf was valid in the past but is now expired.
	// testCA sets NotBefore to time.Now()-1h; we set NotAfter to time.Now()-30min
	// so there IS a real validity window in the past (NotBefore < NotAfter < now).
	root, leaf, key := testCA(t, []string{email}, time.Now().Add(-30*time.Minute))

	content := []byte("hello, expired")
	sigDER := signDetachedForTest(t, content, leaf, key)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	res := VerifyDetached(content, sigDER, email, roots)
	if res.Status != StatusUntrusted {
		t.Errorf("expected %q, got %q (expired cert should be untrusted, not invalid)", StatusUntrusted, res.Status)
	}
}

// TestVerifyDetachedTampered asserts StatusInvalid when content differs from what was signed.
func TestVerifyDetachedTampered(t *testing.T) {
	email := "dave@corp.example"
	root, leaf, key := testCA(t, []string{email}, time.Now().Add(time.Hour))

	content := []byte("original content")
	sigDER := signDetachedForTest(t, content, leaf, key)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	// Verify with tampered content — must be StatusInvalid
	res := VerifyDetached([]byte("TAMPERED"), sigDER, email, roots)
	if res.Status != StatusInvalid {
		t.Errorf("expected %q, got %q (tampered content should be invalid)", StatusInvalid, res.Status)
	}
}

// TestVerifyDetachedMultiSAN proves certMatchesEmail checks all SANs, not just the first.
// leaf has two email SANs; From matches the second one.
func TestVerifyDetachedMultiSAN(t *testing.T) {
	emails := []string{"other@corp.example", "alice@corp.example"}
	root, leaf, key := testCA(t, emails, time.Now().Add(time.Hour))

	content := []byte("hello, multi-SAN")
	sigDER := signDetachedForTest(t, content, leaf, key)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	// From = second email — all SANs must be checked → StatusValid
	res := VerifyDetached(content, sigDER, "alice@corp.example", roots)
	if res.Status != StatusValid {
		t.Errorf("expected %q, got %q (second SAN should match)", StatusValid, res.Status)
	}
}

// TestVerifyDetachedNilRootsIsUntrusted asserts that passing roots==nil results in
// StatusUntrusted (NOT StatusValid), proving that VerifyDetached never falls back to
// the OS system trust store. A cryptographically valid signature whose chain is otherwise
// correct must not be trusted when the caller provides no trust anchors.
func TestVerifyDetachedNilRootsIsUntrusted(t *testing.T) {
	email := "nilroots@corp.example"
	_, leaf, key := testCA(t, []string{email}, time.Now().Add(time.Hour))

	content := []byte("nil roots must not hit system store")
	sigDER := signDetachedForTest(t, content, leaf, key)

	// Pass nil — must never fall back to the system store.
	res := VerifyDetached(content, sigDER, email, nil)
	if res.Status != StatusUntrusted {
		t.Errorf("nil roots: expected %q, got %q (system-store fallback detected!)", StatusUntrusted, res.Status)
	}
}

// TestVerifyDetachedOpenSSLFixture tests against a pre-built signature produced by openssl(1).
// The artifacts in testdata/ were generated once with OpenSSL 3.6.2 and committed so that
// this test runs everywhere with no openssl dependency at test time.
//
// Fixture generation (for reference; do not re-run unless regenerating):
//
//	openssl genrsa -out ca.key 2048
//	openssl req -new -x509 -key ca.key -out ca.crt -days 3650 -subj "/CN=Test OpenSSL CA"
//	openssl genrsa -out leaf.key 2048
//	openssl req -new -key leaf.key -out leaf.csr -subj "/CN=openssl-fixture@corp.example"
//	echo "subjectAltName=email:openssl-fixture@corp.example" > leaf.ext
//	echo "extendedKeyUsage=emailProtection" >> leaf.ext
//	openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
//	    -out leaf.crt -days 3650 -extfile leaf.ext
//	printf "openssl fixture body\r\n" > testdata/openssl_body.txt
//	openssl smime -sign -signer leaf.crt -inkey leaf.key \
//	    -in testdata/openssl_body.txt -outform DER -out testdata/openssl_detached.der -binary
//	cp ca.crt testdata/openssl_ca.crt
func TestVerifyDetachedOpenSSLFixture(t *testing.T) {
	const leafEmail = "openssl-fixture@corp.example"

	body, err := os.ReadFile("testdata/openssl_body.txt")
	if err != nil {
		t.Fatalf("read testdata/openssl_body.txt: %v", err)
	}
	sigDER, err := os.ReadFile("testdata/openssl_detached.der")
	if err != nil {
		t.Fatalf("read testdata/openssl_detached.der: %v", err)
	}
	caCertPEM, err := os.ReadFile("testdata/openssl_ca.crt")
	if err != nil {
		t.Fatalf("read testdata/openssl_ca.crt: %v", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caCertPEM) {
		t.Fatal("AppendCertsFromPEM: failed to add CA cert")
	}

	res := VerifyDetached(body, sigDER, leafEmail, roots)
	if res.Status != StatusValid {
		t.Errorf("openssl fixture: expected %q, got %q", StatusValid, res.Status)
	}
	t.Logf("openssl fixture result: %+v", res)
}

// TestVerifyDetachedGarbageSignatureIsInvalid pins the parse-fail arms: a
// signature that is not parseable CMS SignedData (and a garbage cert block)
// yield StatusInvalid with unknown revocation, never a panic.
func TestVerifyDetachedGarbageSignatureIsInvalid(t *testing.T) {
	res := VerifyDetached([]byte("content"), []byte("not-a-der-signed-data"), "a@x.test", nil)
	if res == nil || res.Status != StatusInvalid {
		t.Fatalf("garbage signature status = %+v, want StatusInvalid", res)
	}
	if res.Revocation != RevocationUnknown {
		t.Fatalf("revocation = %v, want unknown for an unparseable signature", res.Revocation)
	}
}
