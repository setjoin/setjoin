package smtp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	cms "github.com/github/smimesign/ietf-cms"
	"setjoin.com/mailserver/internal/smime"
)

// testSMIMECA builds a self-signed root CA and a leaf cert signed by it.
// The leaf has ExtKeyUsage EmailProtection and the given email SAN(s).
func testSMIMECA(t *testing.T, leafEmails []string) (*x509.Certificate, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

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
		NotAfter:       time.Now().Add(24 * time.Hour),
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

// buildMultipartSigned assembles a complete multipart/signed MIME message.
// contentPart must be a full MIME part (e.g. "Content-Type: text/plain\r\n\r\nSigned body\r\n").
// sigDER is the detached signature bytes which will be base64-encoded.
// boundary is the MIME boundary string (without "--").
func buildMultipartSigned(t *testing.T, contentPart string, sigDER []byte, boundary string) string {
	t.Helper()
	b64Sig := base64.StdEncoding.EncodeToString(sigDER)
	// Wrap b64 at 76 chars per line (MIME convention)
	var sigLines strings.Builder
	for i := 0; i < len(b64Sig); i += 76 {
		end := i + 76
		if end > len(b64Sig) {
			end = len(b64Sig)
		}
		sigLines.WriteString(b64Sig[i:end])
		sigLines.WriteString("\r\n")
	}

	var sb strings.Builder
	// Top-level headers
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256; boundary=\"" + boundary + "\"\r\n")
	sb.WriteString("\r\n")
	// Opening boundary
	sb.WriteString("--" + boundary + "\r\n")
	// Content part (already includes its own MIME headers + CRLF + body)
	sb.WriteString(contentPart)
	// Closing boundary before sig
	sb.WriteString("\r\n--" + boundary + "\r\n")
	// Signature part
	sb.WriteString("Content-Type: application/pkcs7-signature; name=smime.p7s\r\n")
	sb.WriteString("Content-Transfer-Encoding: base64\r\n")
	sb.WriteString("Content-Disposition: attachment; filename=smime.p7s\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(sigLines.String())
	// Closing boundary
	sb.WriteString("--" + boundary + "--\r\n")
	return sb.String()
}

// TestVerifyInboundSMIME_NotSigned: a plain text/plain message must return nil.
func TestVerifyInboundSMIME_NotSigned(t *testing.T) {
	msg := "MIME-Version: 1.0\r\nContent-Type: text/plain\r\nFrom: alice@example.com\r\n\r\nHello world\r\n"
	result := verifyInboundSMIME(context.Background(), msg, "alice@example.com", x509.NewCertPool(), nil)
	if result != nil {
		t.Errorf("expected nil for unsigned message, got %+v", result)
	}
}

// TestVerifyInboundSMIME_ValidRoundTrip: builds a real detached CMS signature and
// verifies that extractSignedParts pulls the EXACT bytes that were signed, so
// verifyInboundSMIME returns StatusValid.
//
// This is the oracle test — if it fails, fix canonicalSignedContent, not this test.
func TestVerifyInboundSMIME_ValidRoundTrip(t *testing.T) {
	const leafEmail = "alice@corp.example"
	const boundary = "bnd"

	root, leaf, key := testSMIMECA(t, []string{leafEmail})

	// The content part that will be signed — must be a complete MIME part
	contentPart := "Content-Type: text/plain\r\n\r\nSigned body\r\n"

	// The signed bytes are exactly what extractSignedParts must return:
	// the content part as it appears between the boundary markers.
	// Per RFC 2015 / RFC 5751: the signed content is the body part bytes
	// as transmitted — from the first byte of the part's headers through
	// the last byte of the part's body, NOT including the trailing CRLF
	// that precedes the next boundary line.
	signedBytes := []byte(contentPart)

	sigDER, err := cms.SignDetached(signedBytes, []*x509.Certificate{leaf}, key)
	if err != nil {
		t.Fatalf("cms.SignDetached: %v", err)
	}

	msg := buildMultipartSigned(t, contentPart, sigDER, boundary)
	t.Logf("assembled message:\n%s", msg)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	res := verifyInboundSMIME(context.Background(), msg, leafEmail, roots, nil)
	if res == nil {
		t.Fatal("expected non-nil VerifyResult, got nil")
	}
	if res.Status != smime.StatusValid {
		t.Errorf("expected %q, got %q", smime.StatusValid, res.Status)
	}
	t.Logf("result: %+v", res)
}

// TestExtractSignedParts_MissingSignature: a message that looks multipart/signed but
// has no pkcs7-signature part must return an error.
func TestExtractSignedParts_MissingSignature(t *testing.T) {
	msg := "MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=\"bnd\"\r\n" +
		"\r\n" +
		"--bnd\r\n" +
		"Content-Type: text/plain\r\n\r\nHello\r\n" +
		"\r\n--bnd--\r\n"

	_, _, err := extractSignedParts(msg)
	if err == nil {
		t.Error("expected error for message missing signature part, got nil")
	}
}

// TestExtractSignedParts_XPkcs7Variant: x-pkcs7-signature variant is also accepted.
func TestExtractSignedParts_XPkcs7Variant(t *testing.T) {
	const leafEmail = "bob@corp.example"
	const boundary = "xbnd"

	root, leaf, key := testSMIMECA(t, []string{leafEmail})

	contentPart := "Content-Type: text/plain\r\n\r\nHello x-variant\r\n"
	signedBytes := []byte(contentPart)

	sigDER, err := cms.SignDetached(signedBytes, []*x509.Certificate{leaf}, key)
	if err != nil {
		t.Fatalf("cms.SignDetached: %v", err)
	}

	b64Sig := base64.StdEncoding.EncodeToString(sigDER)
	var sb strings.Builder
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: multipart/signed; protocol=\"application/x-pkcs7-signature\"; boundary=\"" + boundary + "\"\r\n")
	sb.WriteString("\r\n")
	sb.WriteString("--" + boundary + "\r\n")
	sb.WriteString(contentPart)
	sb.WriteString("\r\n--" + boundary + "\r\n")
	sb.WriteString("Content-Type: application/x-pkcs7-signature; name=smime.p7s\r\n")
	sb.WriteString("Content-Transfer-Encoding: base64\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(b64Sig + "\r\n")
	sb.WriteString("--" + boundary + "--\r\n")
	msg := sb.String()

	content, gotSigDER, err := extractSignedParts(msg)
	if err != nil {
		t.Fatalf("extractSignedParts: %v", err)
	}
	if string(content) != string(signedBytes) {
		t.Errorf("content mismatch:\ngot:  %q\nwant: %q", content, signedBytes)
	}

	// Verify the signature round-trips
	roots := x509.NewCertPool()
	roots.AddCert(root)
	res := smime.VerifyDetached(content, gotSigDER, leafEmail, roots)
	if res.Status != smime.StatusValid {
		t.Errorf("x-variant round-trip: expected %q, got %q", smime.StatusValid, res.Status)
	}
}
