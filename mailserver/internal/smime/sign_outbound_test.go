package smime

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// genCandidate builds a SignCandidate (cleartext cert PEM + decrypted RSA key PEM)
// whose cert binds the given SAN email. Mirrors the on-disk shape of a row in
// user_smime_certs after pgp_sym_decrypt of the private key.
func genCandidate(t *testing.T, email string, isDefault bool) SignCandidate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(time.Now().UnixNano()),
		Subject:        pkix.Name{CommonName: email},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(time.Hour),
		EmailAddresses: []string{email},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return SignCandidate{CertPEM: certPEM, KeyPEM: keyPEM, IsDefault: isDefault}
}

// genECCandidate builds a candidate whose cert binds the email but whose private
// key is EC (PKCS#8). SignMessage rejects non-RSA keys, so ResolveAndSign must
// classify a matched-but-EC candidate as smime_sign_failed.
func genECCandidate(t *testing.T, email string, isDefault bool) SignCandidate {
	t.Helper()
	eckey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(time.Now().UnixNano()),
		Subject:        pkix.Name{CommonName: email},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(time.Hour),
		EmailAddresses: []string{email},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &eckey.PublicKey, eckey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(eckey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return SignCandidate{CertPEM: certPEM, KeyPEM: keyPEM, IsDefault: isDefault}
}

// genCandidateWithSerial builds a candidate that binds email, with an explicit
// serial + CN so two tie candidates are DISTINGUISHABLE. It also returns the
// parsed leaf cert, so a test can assert which cert ended up as the signer.
func genCandidateWithSerial(t *testing.T, email, cn string, serial int64, isDefault bool) (SignCandidate, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(serial),
		Subject:        pkix.Name{CommonName: cn},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(time.Hour),
		EmailAddresses: []string{email},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return SignCandidate{CertPEM: certPEM, KeyPEM: keyPEM, IsDefault: isDefault}, cert
}

// signatureDERFromOutput parses the multipart/signed output produced by
// ResolveAndSign and returns the raw DER bytes of the PKCS#7 signature part. The
// hand-rolled smime.Sign embeds exactly the chosen signer cert's full DER
// (cert.Raw) into the SignedData.certificates field, so a caller can prove WHICH
// cert signed by checking the embedded DER for that cert's bytes. (We avoid the
// ietf-cms library here: smime.Sign's hand-rolled CMS is not roundtrippable by
// cms.ParseSignedData's GetCertificates — see verify_detached_test.go.)
func signatureDERFromOutput(t *testing.T, signed []byte) []byte {
	t.Helper()
	s := string(signed)
	// The pkcs7-signature part is the base64 block after the
	// Content-Transfer-Encoding: base64 line and its blank line, up to the next
	// boundary line (a line starting with "--").
	marker := "Content-Transfer-Encoding: base64\r\n\r\n"
	idx := strings.Index(s, marker)
	if idx < 0 {
		t.Fatalf("could not find base64 signature part in output:\n%s", s)
	}
	rest := s[idx+len(marker):]
	// Collect base64 lines (MIME-wrapped) up to the boundary. Strip CRLF so we
	// get a continuous base64 string (StdEncoding requires no embedded whitespace).
	var b64 strings.Builder
	for _, line := range strings.Split(rest, "\r\n") {
		if strings.HasPrefix(line, "--") { // boundary → end of the signature part
			break
		}
		b64.WriteString(line)
	}
	// smime.base64Encode now emits padded, MIME-line-wrapped base64 (RFC 2045).
	// After stripping CRLF above, the concatenated string is valid StdEncoding.
	der, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil {
		t.Fatalf("decode signature base64: %v", err)
	}
	return der
}

const testRawDraft = "Content-Type: text/plain\r\nFrom: a@example.com\r\nSubject: hi\r\n\r\nhello body\r\n"

func TestResolveAndSign_MatchAndUsableRSAKey(t *testing.T) {
	cands := []SignCandidate{genCandidate(t, "a@example.com", true)}
	signed, reason := ResolveAndSign(cands, "a@example.com", []byte(testRawDraft))
	if reason != "" {
		t.Fatalf("reason = %q, want empty (success)", reason)
	}
	if len(signed) == 0 {
		t.Fatal("signed bytes empty")
	}
	if !strings.HasPrefix(string(signed), "Content-Type: multipart/signed") {
		t.Errorf("signed output must start with a multipart/signed Content-Type, got: %.80q", string(signed))
	}
	// The signed output must be recognized as already-signed by IsSignedMessage.
	if !IsSignedMessage(signed) {
		t.Error("IsSignedMessage returned false for freshly signed output")
	}
}

func TestResolveAndSign_FromMatchWinsOverDefault(t *testing.T) {
	// Two candidates: the DEFAULT one binds someone else; the From matches a
	// NON-default candidate. From-match must win over is_default.
	def := genCandidate(t, "other@example.com", true)
	match := genCandidate(t, "a@example.com", false)
	cands := []SignCandidate{def, match}
	signed, reason := ResolveAndSign(cands, "a@example.com", []byte(testRawDraft))
	if reason != "" {
		t.Fatalf("reason = %q, want empty (success): From-match must select the non-default cert", reason)
	}
	if len(signed) == 0 {
		t.Fatal("signed bytes empty")
	}
}

func TestResolveAndSign_PreferDefaultOnTie(t *testing.T) {
	// Two candidates BOTH bind the From address; the default must be preferred.
	// The candidates are DISTINGUISHABLE (different serial + CN) and we assert the
	// cert that actually SIGNED the output is the default one. This makes the test
	// non-vacuous: deleting the prefer-default block in ResolveAndSign (which would
	// leave it on the first/non-default candidate) MUST make this fail.
	nonDefault, nonDefaultCert := genCandidateWithSerial(t, "a@example.com", "non-default", 111, false)
	def, defCert := genCandidateWithSerial(t, "a@example.com", "the-default", 222, true)
	// Non-default listed FIRST so "take the first match" would pick the wrong cert.
	cands := []SignCandidate{nonDefault, def}
	signed, reason := ResolveAndSign(cands, "a@example.com", []byte(testRawDraft))
	if reason != "" {
		t.Fatalf("reason = %q, want empty (success)", reason)
	}
	if len(signed) == 0 {
		t.Fatal("signed bytes empty")
	}

	// smime.Sign embeds exactly the chosen signer cert's full DER. The DEFAULT
	// cert's bytes MUST be present, and the NON-default cert's must NOT — this is
	// what makes the test non-vacuous: drop the prefer-default block and signing
	// stays on the first (non-default) candidate, flipping both assertions.
	sigDER := signatureDERFromOutput(t, signed)
	if !bytes.Contains(sigDER, defCert.Raw) {
		t.Errorf("signer cert is NOT the default (CN %q, serial %s): "+
			"prefer-default tie-break did not select the default cert",
			defCert.Subject.CommonName, defCert.SerialNumber)
	}
	if bytes.Contains(sigDER, nonDefaultCert.Raw) {
		t.Errorf("signer cert IS the non-default (CN %q, serial %s): "+
			"tie-break chose the wrong candidate",
			nonDefaultCert.Subject.CommonName, nonDefaultCert.SerialNumber)
	}
}

func TestResolveAndSign_NoCandidates(t *testing.T) {
	signed, reason := ResolveAndSign(nil, "a@example.com", []byte(testRawDraft))
	if reason != "smime_no_cert" {
		t.Errorf("reason = %q, want smime_no_cert", reason)
	}
	if signed != nil {
		t.Errorf("signed = %v, want nil", signed)
	}
}

func TestResolveAndSign_NoMatchingCert(t *testing.T) {
	cands := []SignCandidate{genCandidate(t, "other@example.com", true)}
	signed, reason := ResolveAndSign(cands, "a@example.com", []byte(testRawDraft))
	if reason != "smime_no_matching_cert" {
		t.Errorf("reason = %q, want smime_no_matching_cert", reason)
	}
	if signed != nil {
		t.Errorf("signed = %v, want nil", signed)
	}
}

func TestResolveAndSign_MatchButECKeyFails(t *testing.T) {
	cands := []SignCandidate{genECCandidate(t, "a@example.com", true)}
	signed, reason := ResolveAndSign(cands, "a@example.com", []byte(testRawDraft))
	if reason != "smime_sign_failed" {
		t.Errorf("reason = %q, want smime_sign_failed (EC key is not signable)", reason)
	}
	if signed != nil {
		t.Errorf("signed = %v, want nil", signed)
	}
}

func TestResolveAndSign_MatchButUnparseableKeyFails(t *testing.T) {
	c := genCandidate(t, "a@example.com", true)
	c.KeyPEM = []byte("not a pem key")
	signed, reason := ResolveAndSign([]SignCandidate{c}, "a@example.com", []byte(testRawDraft))
	if reason != "smime_sign_failed" {
		t.Errorf("reason = %q, want smime_sign_failed (unparseable key)", reason)
	}
	if signed != nil {
		t.Errorf("signed = %v, want nil", signed)
	}
}

func TestResolveAndSign_MatchButUnparseableCertSkipped(t *testing.T) {
	// A garbage cert among the candidates must not match (and must not panic);
	// with only a garbage cert present it reduces to no-matching-cert.
	bad := SignCandidate{CertPEM: []byte("garbage"), KeyPEM: []byte("garbage"), IsDefault: true}
	signed, reason := ResolveAndSign([]SignCandidate{bad}, "a@example.com", []byte(testRawDraft))
	if reason != "smime_no_matching_cert" {
		t.Errorf("reason = %q, want smime_no_matching_cert (unparseable cert cannot match)", reason)
	}
	if signed != nil {
		t.Errorf("signed = %v, want nil", signed)
	}
}

func TestResolveAndSign_BodySplitMirrorsWorker(t *testing.T) {
	// The worker splits headers at the first \r\n\r\n and passes only the BODY to
	// SignMessage; the signed output's protected part must therefore be the body,
	// not the original headers. Assert the original Subject header is NOT inside
	// the protected (first) MIME part (which carries the body that was signed).
	cands := []SignCandidate{genCandidate(t, "a@example.com", true)}
	signed, reason := ResolveAndSign(cands, "a@example.com", []byte(testRawDraft))
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
	// SignMessage uses the body as the protected content; the body here is
	// "hello body\r\n". Confirm it is present in the signed output.
	if !strings.Contains(string(signed), "hello body") {
		t.Error("signed output should contain the original body")
	}
}

func TestIsSignedMessage(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{
			name: "multipart/signed pkcs7-signature",
			raw:  "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256; boundary=\"b\"\r\n\r\nbody",
			want: true,
		},
		{
			name: "pkcs7-mime signed-data",
			raw:  "Content-Type: application/pkcs7-mime; smime-type=signed-data; name=\"smime.p7m\"\r\n\r\nbody",
			want: true,
		},
		{
			name: "case-insensitive header name",
			raw:  "content-type: multipart/signed; protocol=\"application/pkcs7-signature\"\r\n\r\nbody",
			want: true,
		},
		{
			name: "plain text message",
			raw:  "Content-Type: text/plain\r\nSubject: hi\r\n\r\nbody",
			want: false,
		},
		{
			name: "encrypted (enveloped) is not signed",
			raw:  "Content-Type: application/pkcs7-mime; smime-type=enveloped-data\r\n\r\nbody",
			want: false,
		},
		{
			name: "empty",
			raw:  "",
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsSignedMessage([]byte(c.raw)); got != c.want {
				t.Errorf("IsSignedMessage(%q) = %v, want %v", c.raw, got, c.want)
			}
		})
	}
}
