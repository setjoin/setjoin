package smime

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func generateTestCert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		Subject:        pkix.Name{CommonName: "test@example.com"},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(time.Hour),
		EmailAddresses: []string{"test@example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestParseCert(t *testing.T) {
	cert, _ := generateTestCert(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	parsed, err := ParseCert(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Error("serial mismatch")
	}
}

func TestParsePrivateKey(t *testing.T) {
	_, key := generateTestCert(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	parsed, err := ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if parsed == nil {
		t.Fatal("nil key")
	}
}

func TestSignAndVerify(t *testing.T) {
	cert, key := generateTestCert(t)
	content := []byte("Hello, world! This is a test message for S/MIME signing.\r\n")

	sig, err := Sign(content, cert, key)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}

	verified, err := Verify(content, sig)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if verified.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Error("signer mismatch")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plaintext := []byte("This is a secret message encrypted with S/MIME.\r\n")

	recipientCert, recipientKey := generateTestCert(t)

	encrypted, err := Encrypt(plaintext, []*x509.Certificate{recipientCert})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if len(encrypted) == 0 {
		t.Fatal("empty ciphertext")
	}

	// Extract DER from the base64-encoded MIME wrapper
	// The encrypted output is: Content-Type: ...\r\n\r\n<base64>
	base64Part := string(encrypted[strings.Index(string(encrypted), "\r\n\r\n")+4:])
	der, err := base64Decode(stripCR(base64Part))
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}

	decrypted, err := Decrypt(der, recipientCert, recipientKey)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("decryption mismatch: got %q, want %q", string(decrypted), string(plaintext))
	}
}

func stripCR(s string) string {
	n := len(s)
	for n > 0 && s[n-1] == '\r' || s[n-1] == '\n' {
		n--
	}
	return s[:n]
}

// mustBuildSignedDataWithCert builds a CMS SignedData DER with the given cert DER
// embedded in Certificates, and one SignerInfo using oidSHA256 with a junk signature
// and NO signed attributes. Used to test non-RSA key handling in Verify.
func mustBuildSignedDataWithCert(t *testing.T, certDER []byte) []byte {
	t.Helper()

	// Include a contentType signed attribute so Verify reaches the key-type check
	// (if attrs were empty the new "no signed attributes" guard fires first).
	signerInfo := cmsSignerInfo{
		Version:         1,
		DigestAlgorithm: algorithmIdentifier{Algorithm: oidSHA256},
		Sid: cmsIssuerAndSerial{
			Issuer: asn1.RawValue{FullBytes: []byte{0x30, 0x00}},
			Serial: big.NewInt(1),
		},
		SignatureAlgorithm: algorithmIdentifier{Algorithm: oidRSAEncryption},
		Signature:          []byte("junk"),
		// contentType attr + a fake messageDigest so the digest-binding check is passed
		// before we hit the RSA type assertion.  We want to exercise the key-type path.
		SignedAttributes: []cmsAttribute{
			{Type: oidContentType, Values: []asn1.RawValue{{Bytes: mustMarshal(oidData)}}},
			{Type: oidMessageDigest, Values: []asn1.RawValue{{Bytes: func() []byte {
				// sha256("content") marshalled as OCTET STRING
				h := sha256.Sum256([]byte("content"))
				b, _ := asn1.Marshal(h[:])
				return b
			}()}}},
		},
	}

	sd := cmsSignedData{
		Version:          1,
		DigestAlgorithms: []algorithmIdentifier{{Algorithm: oidSHA256}},
		EncapContent: encapsulatedContentInfo{
			ContentType: oidData,
		},
		Certificates: rawCertificates{
			{Class: 0, Bytes: certDER},
		},
		SignerInfos: []cmsSignerInfo{signerInfo},
	}

	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatalf("mustBuildSignedDataWithCert: marshal SignedData: %v", err)
	}

	ci := cmsContentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: sdDER, IsCompound: true},
	}
	der, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatalf("mustBuildSignedDataWithCert: marshal ContentInfo: %v", err)
	}
	return der
}

// TestVerifyNonRSADoesNotPanic asserts that Verify returns an error (not panics)
// when the signer cert contains a non-RSA (ECDSA) public key.
func TestVerifyNonRSADoesNotPanic(t *testing.T) {
	// Detect panic via defer/recover
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Verify panicked on non-RSA cert: %v", r)
		}
	}()

	// Build an ECDSA self-signed cert
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "ecdsa@example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ecKey.PublicKey, ecKey)
	if err != nil {
		t.Fatal(err)
	}

	sig := mustBuildSignedDataWithCert(t, certDER)

	gotCert, verifyErr := Verify([]byte("content"), sig)
	if verifyErr == nil {
		t.Fatalf("Verify should have returned an error for non-RSA cert, got cert=%v", gotCert)
	}
	// verifyErr != nil: good — no panic, proper error
}

// mustBuildSignedAttrsNoMessageDigest builds a CMS SignedData whose SignerInfo has
// SignedAttributes (contentType only — no messageDigest) properly signed with key.
// Used to assert Verify rejects content whose digest binding is absent.
func mustBuildSignedAttrsNoMessageDigest(t *testing.T, leaf *x509.Certificate, key *rsa.PrivateKey, content []byte) []byte {
	t.Helper()

	// SignedAttributes: contentType present, messageDigest intentionally absent.
	signedAttrs := []cmsAttribute{
		{Type: oidContentType, Values: []asn1.RawValue{{Bytes: mustMarshal(oidData)}}},
	}

	attrDER, err := asn1.Marshal(struct {
		Attrs []cmsAttribute `asn1:"set"`
	}{Attrs: signedAttrs})
	if err != nil {
		t.Fatalf("mustBuildSignedAttrsNoMessageDigest: marshal attrs: %v", err)
	}

	// Sign the attributes
	attrHash := sha256.Sum256(attrDER)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, attrHash[:])
	if err != nil {
		t.Fatalf("mustBuildSignedAttrsNoMessageDigest: sign: %v", err)
	}

	signerInfo := cmsSignerInfo{
		Version: 1,
		Sid: cmsIssuerAndSerial{
			Issuer: asn1.RawValue{FullBytes: leaf.RawIssuer},
			Serial: leaf.SerialNumber,
		},
		DigestAlgorithm:    algorithmIdentifier{Algorithm: oidSHA256},
		SignedAttributes:   signedAttrs,
		SignatureAlgorithm: algorithmIdentifier{Algorithm: oidRSAEncryption},
		Signature:          signature,
	}

	sd := cmsSignedData{
		Version:          1,
		DigestAlgorithms: []algorithmIdentifier{{Algorithm: oidSHA256}},
		EncapContent: encapsulatedContentInfo{
			ContentType: oidData,
		},
		Certificates: rawCertificates{
			{Class: 0, Bytes: leaf.Raw},
		},
		SignerInfos: []cmsSignerInfo{signerInfo},
	}

	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatalf("mustBuildSignedAttrsNoMessageDigest: marshal SignedData: %v", err)
	}

	ci := cmsContentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: sdDER, IsCompound: true},
	}
	der, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatalf("mustBuildSignedAttrsNoMessageDigest: marshal ContentInfo: %v", err)
	}
	return der
}

// TestVerifyRequiresMessageDigest asserts:
//  1. A properly Sign-produced signature (with messageDigest) verifies OK.
//  2. A hand-built CMS with SignedAttributes but NO messageDigest is rejected.
func TestVerifyRequiresMessageDigest(t *testing.T) {
	cert, key := generateTestCert(t)
	content := []byte("BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nEND:VCALENDAR\r\n")

	// Case 1: Sign-produced signature should still pass.
	sig, err := Sign(content, cert, key)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if _, err := Verify(content, sig); err != nil {
		t.Fatalf("Verify of Sign-produced sig failed: %v", err)
	}

	// Case 2: SignedAttributes present, messageDigest absent — must be rejected.
	sigNoDigest := mustBuildSignedAttrsNoMessageDigest(t, cert, key, content)
	_, err = Verify(content, sigNoDigest)
	if err == nil {
		t.Fatal("Verify must reject SignedData with no messageDigest attribute, but returned nil error")
	}
}

// TestVerifyStillAcceptsSignedContent is the iMIP regression: after hardening,
// Verify must still return the signer cert for a Sign-produced detached signature
// over an iCalendar-like body.
func TestVerifyStillAcceptsSignedContent(t *testing.T) {
	cert, key := generateTestCert(t)
	iMIPBody := []byte("BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nSUMMARY:Team sync\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")

	sig, err := Sign(iMIPBody, cert, key)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	verified, err := Verify(iMIPBody, sig)
	if err != nil {
		t.Fatalf("Verify failed after hardening (iMIP regression): %v", err)
	}
	if verified.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Error("signer cert mismatch after hardening")
	}
}

// base64Decode decodes a MIME base64 string (padded, optionally line-wrapped).
// Lines are joined before decoding so both the old single-line unpadded form and
// the new MIME-compliant padded+CRLF-wrapped form are accepted.
func base64Decode(s string) ([]byte, error) {
	// Strip all whitespace (CRLF line wraps) before decoding.
	s = strings.ReplaceAll(s, "\r\n", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.TrimRight(s, "\r\n")
	return base64.StdEncoding.DecodeString(s)
}
