//go:build gofree_record

package smtp

// Fixture generation only: the listener recorder supplies every verdict/effect.
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cms "github.com/github/smimesign/ietf-cms"
)

type smtp6Signer struct {
	root, leaf *x509.Certificate
	key        *ecdsa.PrivateKey
}

func smtp6NewSigner(t *testing.T, emails []string, eku []x509.ExtKeyUsage, before, after int) smtp6Signer {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(526), Subject: pkix.Name{CommonName: "SMTP6 Test Root"}, NotBefore: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(527), Subject: pkix.Name{CommonName: "SMTP6 Signer"}, NotBefore: time.Date(before, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(after, 1, 1, 0, 0, 0, 0, time.UTC), EmailAddresses: emails, ExtKeyUsage: eku, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return smtp6Signer{root, leaf, key}
}
func smtp6PEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}
func smtp6Quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
func smtp6Anchor(s smtp6Signer, domain string) string {
	return fmt.Sprintf("INSERT INTO smime_trust_anchors(label,cert_pem,fingerprint,domain_id) VALUES('smtp6-fixture',%s,'%x',%s);", smtp6Quote(smtp6PEM(s.root)), sha256.Sum256(s.root.Raw), domain)
}
func smtp6Detached(t *testing.T, s smtp6Signer, content string) string {
	t.Helper()
	der, err := cms.SignDetached([]byte(content), []*x509.Certificate{s.leaf, s.root}, s.key)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(der)
	var lines strings.Builder
	for len(b64) > 0 {
		n := 64
		if len(b64) < n {
			n = len(b64)
		}
		lines.WriteString(b64[:n])
		lines.WriteString("\r\n")
		b64 = b64[n:]
	}
	return "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=\"smtp6-signed\"\r\n\r\n--smtp6-signed\r\n" + content + "\r\n--smtp6-signed\r\nContent-Type: application/pkcs7-signature\r\nContent-Transfer-Encoding: base64\r\n\r\n" + lines.String() + "--smtp6-signed--\r\n"
}
func smtp6Session(name, sender, recipient, display, body, setup, teardown string, flags map[string]bool, pipeline *smtpOraclePipeline) smtpOracleSession {
	return smtpOracleSession{Name: name, MailAuth: flags, ObserveEffects: true, CaptureBlobs: true, Pipeline: pipeline, SetupSQL: setup, TeardownSQL: teardown, Steps: []smtpOracleStep{
		{Send: "", Lines: 1}, {Send: "EHLO smtp6.test\r\n", Lines: 5}, {Send: fmt.Sprintf("MAIL FROM:<%s>\r\nRCPT TO:<%s>\r\nDATA\r\n", sender, recipient), Lines: 3},
		{Send: fmt.Sprintf("From: %s <%s>\r\nTo: %s\r\nMessage-ID: <%s@smtp6.test>\r\nSubject: S/MIME fixture\r\n", display, sender, recipient, name) + body + ".\r\n", Lines: 1}, {Send: "QUIT\r\n", Lines: 1}}}
}
func TestGenerateSMTP6SMIMERequests(t *testing.T) {
	root := os.Getenv("SMTP_ORACLE_DIR")
	if root == "" {
		t.Skip("recording only")
	}
	path := filepath.Join(root, "security-smime-requests.json")
	if _, err := os.Stat(path); err == nil {
		t.Fatal("refusing existing stimuli")
	}
	normal := smtp6NewSigner(t, []string{"visitor@external.test", "second@external.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}, 2020, 2099)
	expired := smtp6NewSigner(t, []string{"visitor@external.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}, 2010, 2020)
	future := smtp6NewSigner(t, []string{"visitor@external.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}, 2080, 2099)
	wrongEKU := smtp6NewSigner(t, []string{"visitor@external.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, 2020, 2099)
	noEKU := smtp6NewSigner(t, []string{"visitor@external.test"}, nil, 2020, 2099)
	content := "Content-Type: text/plain; charset=utf-8\r\n\r\nhello https://external.test/action\r\n"
	cleanup := "DELETE FROM smime_trust_anchors WHERE label='smtp6-fixture'; DELETE FROM smime_revocation_blocklist WHERE reason='smtp6-fixture'; DELETE FROM recipient_smime_certs WHERE owner_user_id BETWEEN 9348011 AND 9348013;"
	var cases []smtpOracleSession
	add := func(name string, s smtp6Signer, domain, sender, recipient, display, kind string) {
		setup := cleanup
		if domain != "none" {
			setup += smtp6Anchor(s, domain)
		}
		body := smtp6Detached(t, s, content)
		flags := map[string]bool{"feature.smime_verify": true}
		var pipeline *smtpOraclePipeline
		switch kind {
		case "tamper":
			body = strings.Replace(body, "hello https", "TAMPERED https", 1)
		case "bad-b64":
			body = "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=\"smtp6-signed\"\r\n\r\n--smtp6-signed\r\n" + content + "\r\n--smtp6-signed\r\nContent-Type: application/pkcs7-signature\r\n\r\n!!!\r\n--smtp6-signed--\r\n"
		case "opaque":
			body = "Content-Type: application/pkcs7-mime; smime-type=signed-data\r\n\r\nnot-detached\r\n"
		case "unsigned":
			body = "Content-Type: text/plain\r\n\r\nhello\r\n"
		case "x-protocol":
			body = strings.ReplaceAll(body, "application/pkcs7-signature", "application/x-pkcs7-signature")
		case "fingerprint":
			setup += "UPDATE smime_trust_anchors SET fingerprint='wrong' WHERE label='smtp6-fixture';"
		case "revoked":
			setup += fmt.Sprintf("INSERT INTO smime_revocation_blocklist(fingerprint,reason) VALUES('%x','smtp6-fixture');", sha256.Sum256(s.leaf.Raw))
		case "warn", "reject":
			flags["feature.antiphish_display_name"] = true
			pipeline = &smtpOraclePipeline{AntiPhish: true, InternalDomains: []string{"smtp1.test"}}
		}
		if kind == "bad-der" {
			body = "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=\"smtp6-signed\"\r\n\r\n--smtp6-signed\r\n" + content + "\r\n--smtp6-signed\r\nContent-Type: application/pkcs7-signature\r\n\r\nbm90LWRlcg==\r\n--smtp6-signed--\r\n"
		}
		cases = append(cases, smtp6Session(name, sender, recipient, display, body, setup, cleanup, flags, pipeline))
	}
	for _, tc := range []struct {
		name, domain, from, rcpt, display, kind string
		signer                                  smtp6Signer
	}{
		{"smime-valid-global", "NULL", "visitor@external.test", "alias@smtp1.test", "Visitor", "", normal},
		{"smime-valid-domain", "9348001", "visitor@external.test", "alias@smtp1.test", "Visitor", "", normal},
		{"smime-foreign-domain-untrusted", "9348002", "visitor@external.test", "alias@smtp1.test", "Visitor", "", normal},
		{"smime-no-anchor-untrusted", "none", "visitor@external.test", "alias@smtp1.test", "Visitor", "", normal},
		{"smime-wrong-fingerprint-untrusted", "NULL", "visitor@external.test", "alias@smtp1.test", "Visitor", "fingerprint", normal},
		{"smime-expired-untrusted", "NULL", "visitor@external.test", "alias@smtp1.test", "Visitor", "", expired},
		{"smime-future-untrusted", "NULL", "visitor@external.test", "alias@smtp1.test", "Visitor", "", future},
		{"smime-wrong-eku-untrusted", "NULL", "visitor@external.test", "alias@smtp1.test", "Visitor", "", wrongEKU},
		{"smime-absent-eku", "NULL", "visitor@external.test", "alias@smtp1.test", "Visitor", "", noEKU},
		{"smime-from-mismatch", "NULL", "different@external.test", "alias@smtp1.test", "Visitor", "", normal},
		{"smime-second-san-harvest", "NULL", "second@external.test", "alias@smtp1.test", "Visitor", "", normal},
		{"smime-direct-skips-harvest", "NULL", "visitor@external.test", "alice@smtp1.test", "Visitor", "", normal},
		{"smime-tampered-invalid", "NULL", "visitor@external.test", "alias@smtp1.test", "Visitor", "tamper", normal},
		{"smime-bad-der-invalid", "NULL", "visitor@external.test", "alias@smtp1.test", "Visitor", "bad-der", normal},
		{"smime-bad-base64-nil", "NULL", "visitor@external.test", "alias@smtp1.test", "Visitor", "bad-b64", normal},
		{"smime-opaque-not-verified", "NULL", "visitor@external.test", "alias@smtp1.test", "Visitor", "opaque", normal},
		{"smime-unsigned-nil", "NULL", "visitor@external.test", "alias@smtp1.test", "Visitor", "unsigned", normal},
		{"smime-x-protocol", "NULL", "visitor@external.test", "alias@smtp1.test", "Visitor", "x-protocol", normal},
		{"smime-revoked-untrusted", "NULL", "visitor@external.test", "alias@smtp1.test", "Visitor", "revoked", normal},
		{"smime-valid-skips-warning", "NULL", "visitor@external.test", "alias@smtp1.test", "Alic3", "warn", normal},
		{"smime-untrusted-still-warns", "none", "visitor@external.test", "alias@smtp1.test", "Alic3", "warn", normal},
		{"smime-valid-policy-reject-harvests", "NULL", "visitor@external.test", "alias@smtp1.test", "Alice", "reject", normal},
	} {
		add(tc.name, tc.signer, tc.domain, tc.from, tc.rcpt, tc.display, tc.kind)
	}
	raw, err := json.MarshalIndent(cases, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, append(raw, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}
