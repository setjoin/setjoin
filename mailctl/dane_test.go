package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// generateTestCert creates a self-signed ECDSA P-256 certificate, writes it to a temp PEM file,
// and returns the file path, the parsed certificate, and a cleanup function.
func generateTestCert(t *testing.T) (string, *x509.Certificate, func()) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "mail.example.com",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"mail.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}
	pemData := pem.EncodeToMemory(pemBlock)

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	if err := os.WriteFile(certPath, pemData, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	return certPath, cert, func() {}
}

// expectedSPKIHash computes the expected SHA-256 hash of the cert's SubjectPublicKeyInfo.
func expectedSPKIHash(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h[:])
}

// expectedFullCertHash computes the expected SHA-256 hash of the full cert DER.
func expectedFullCertHash(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(h[:])
}

func TestGenerateTLSA_DANE_EE_SPKI_SHA256(t *testing.T) {
	// DANE-EE (3 1 1) — the most common configuration for SMTP
	certPath, cert, cleanup := generateTestCert(t)
	defer cleanup()

	record, err := GenerateTLSAFromCert(certPath, "mail.example.com", 3, 1, 1)
	if err != nil {
		t.Fatalf("GenerateTLSAFromCert: %v", err)
	}

	wantHash := expectedSPKIHash(cert)
	if !strings.Contains(record, wantHash) {
		t.Errorf("record %q does not contain expected hash %s", record, wantHash)
	}
	if !strings.Contains(record, "3 1 1") {
		t.Errorf("record %q does not contain '3 1 1'", record)
	}
	if !strings.Contains(record, "_25._tcp.mail.example.com") {
		t.Errorf("record %q does not contain '_25._tcp.mail.example.com'", record)
	}
}

func TestGenerateTLSA_DANE_TA_SPKI_SHA256(t *testing.T) {
	// DANE-TA (2 1 1) — pin the trust anchor
	certPath, cert, cleanup := generateTestCert(t)
	defer cleanup()

	record, err := GenerateTLSAFromCert(certPath, "mail.example.com", 2, 1, 1)
	if err != nil {
		t.Fatalf("GenerateTLSAFromCert: %v", err)
	}

	wantHash := expectedSPKIHash(cert)
	if !strings.Contains(record, wantHash) {
		t.Errorf("record %q does not contain expected hash %s", record, wantHash)
	}
	if !strings.Contains(record, "2 1 1") {
		t.Errorf("record %q does not contain '2 1 1'", record)
	}
}

func TestGenerateTLSA_DANE_EE_FullCert_SHA256(t *testing.T) {
	// DANE-EE (3 0 1) — full certificate, SHA-256
	certPath, cert, cleanup := generateTestCert(t)
	defer cleanup()

	record, err := GenerateTLSAFromCert(certPath, "mail.example.com", 3, 0, 1)
	if err != nil {
		t.Fatalf("GenerateTLSAFromCert: %v", err)
	}

	wantHash := expectedFullCertHash(cert)
	if !strings.Contains(record, wantHash) {
		t.Errorf("record %q does not contain expected hash %s", record, wantHash)
	}
	if !strings.Contains(record, "3 0 1") {
		t.Errorf("record %q does not contain '3 0 1'", record)
	}
}

func TestGenerateTLSA_SHA512(t *testing.T) {
	// DANE-EE (3 1 2) — SPKI, SHA-512
	certPath, _, cleanup := generateTestCert(t)
	defer cleanup()

	record, err := GenerateTLSAFromCert(certPath, "mail.example.com", 3, 1, 2)
	if err != nil {
		t.Fatalf("GenerateTLSAFromCert: %v", err)
	}

	if !strings.Contains(record, "3 1 2") {
		t.Errorf("record %q does not contain '3 1 2'", record)
	}
}

func TestGenerateTLSA_FileNotFound(t *testing.T) {
	_, err := GenerateTLSAFromCert("/nonexistent/cert.pem", "mail.example.com", 3, 1, 1)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestGenerateTLSA_InvalidCertFile(t *testing.T) {
	tmpDir := t.TempDir()
	badPath := filepath.Join(tmpDir, "bad.pem")
	if err := os.WriteFile(badPath, []byte("not a certificate"), 0644); err != nil {
		t.Fatalf("write bad file: %v", err)
	}

	_, err := GenerateTLSAFromCert(badPath, "mail.example.com", 3, 1, 1)
	if err == nil {
		t.Error("expected error for invalid certificate file")
	}
}

func TestGenerateTLSA_InvalidUsage(t *testing.T) {
	certPath, _, cleanup := generateTestCert(t)
	defer cleanup()

	// Usage 5 is invalid
	_, err := GenerateTLSAFromCert(certPath, "mail.example.com", 5, 1, 1)
	if err == nil {
		t.Error("expected error for invalid usage")
	}
}

func TestGenerateTLSA_InvalidSelector(t *testing.T) {
	certPath, _, cleanup := generateTestCert(t)
	defer cleanup()

	// Selector 3 is invalid
	_, err := GenerateTLSAFromCert(certPath, "mail.example.com", 3, 3, 1)
	if err == nil {
		t.Error("expected error for invalid selector")
	}
}

func TestGenerateTLSA_InvalidMatchingType(t *testing.T) {
	certPath, _, cleanup := generateTestCert(t)
	defer cleanup()

	// Matching type 3 is invalid
	_, err := GenerateTLSAFromCert(certPath, "mail.example.com", 3, 1, 3)
	if err == nil {
		t.Error("expected error for invalid matching type")
	}
}

func TestGenerateTLSA_Format(t *testing.T) {
	// Verify the output format matches zone file conventions
	certPath, _, cleanup := generateTestCert(t)
	defer cleanup()

	record, err := GenerateTLSAFromCert(certPath, "mail.example.com", 3, 1, 1)
	if err != nil {
		t.Fatalf("GenerateTLSAFromCert: %v", err)
	}

	// Expected format: _25._tcp.<hostname>. IN TLSA <usage> <selector> <matching> <hex>
	if !strings.HasPrefix(record, "_25._tcp.") {
		t.Errorf("record should start with '_25._tcp.': %s", record)
	}
	if !strings.Contains(record, " IN TLSA ") {
		t.Errorf("record should contain ' IN TLSA ': %s", record)
	}

	parts := strings.Fields(record)
	if len(parts) < 7 {
		t.Errorf("record should have at least 7 space-separated fields: %s", record)
	}
}

func TestGenerateTLSA_HostnameTrailingDot(t *testing.T) {
	// Hostname with trailing dot should not produce double dot
	certPath, _, cleanup := generateTestCert(t)
	defer cleanup()

	record, err := GenerateTLSAFromCert(certPath, "mail.example.com.", 3, 1, 1)
	if err != nil {
		t.Fatalf("GenerateTLSAFromCert: %v", err)
	}

	if strings.Contains(record, "._25._tcp.") {
		t.Errorf("record should not have double dot: %s", record)
	}
}

// TestGenerateTLSA_HostnameGrammarRejectsInjection pins the D-MAILCTL-004
// remediation: the hostname is a structured DNS name, not display text. Every
// input outside the RFC 1035 preferred grammar — including the record-injection
// payloads from the finding — must be rejected instead of reaching the zone
// record format string. Well-formed names (and the documented trailing-dot
// normalization) stay accepted.
func TestGenerateTLSA_HostnameGrammarRejectsInjection(t *testing.T) {
	certPath, _, cleanup := generateTestCert(t)
	defer cleanup()

	for _, name := range []string{
		`mail.example.com. IN TXT "pwned" mail2`, // record injection from the finding
		"mail.example.com\n_evil.example.",       // embedded newline (multiline injection)
		"mail.example.com (comment)",             // zone-file parens
		`mail".example.com`,                      // quote metacharacter
		"mail exam ple.com",                      // spaces
		"-leading-hyphen.example.com",            // label starts with hyphen
		"trailing-.example.com",                  // label ends with hyphen
		"under_score.example.com",                // underscore is not an RFC 1035 host char
		"",                                       // empty
		strings.Repeat("a.", 127) + "com",        // total length > 253
	} {
		if _, err := GenerateTLSAFromCert(certPath, name, 3, 1, 1); err == nil {
			t.Errorf("GenerateTLSAFromCert(%q) accepted an invalid hostname", name)
		}
	}

	// Single-label and multi-label well-formed names still generate records.
	for _, name := range []string{"mail.example.com", "mail", "a-b.example.com", "mail.example.com."} {
		if _, err := GenerateTLSAFromCert(certPath, name, 3, 1, 1); err != nil {
			t.Errorf("GenerateTLSAFromCert(%q) rejected a valid hostname: %v", name, err)
		}
	}
}

func TestValidateDNSHostname_LabelAndLengthBounds(t *testing.T) {
	if err := validateDNSHostname("mail.example.com"); err != nil {
		t.Errorf("valid hostname rejected: %v", err)
	}
	if err := validateDNSHostname(strings.Repeat("a", 63) + ".example.com"); err != nil {
		t.Errorf("63-octet label rejected: %v", err)
	}
	if err := validateDNSHostname(strings.Repeat("a", 64) + ".example.com"); err == nil {
		t.Error("64-octet label accepted")
	}
	if err := validateDNSHostname(strings.Repeat("ab.", 84) + "com"); err == nil {
		t.Error("254-octet hostname accepted")
	}
}

func TestReadCertificate_PEM(t *testing.T) {
	certPath, _, cleanup := generateTestCert(t)
	defer cleanup()

	cert, err := ReadCertificateFile(certPath)
	if err != nil {
		t.Fatalf("ReadCertificateFile: %v", err)
	}
	if cert.Subject.CommonName != "mail.example.com" {
		t.Errorf("CN = %q, want mail.example.com", cert.Subject.CommonName)
	}
}

func TestComputeCertAssociation(t *testing.T) {
	_, cert, cleanup := generateTestCert(t)
	defer cleanup()

	// Selector 1 (SPKI), Matching 1 (SHA-256)
	data, err := ComputeCertAssociation(cert, 1, 1)
	if err != nil {
		t.Fatalf("ComputeCertAssociation: %v", err)
	}

	want := expectedSPKIHash(cert)
	got := fmt.Sprintf("%x", data)
	if got != want {
		t.Errorf("cert association = %s, want %s", got, want)
	}

	// Verify length: SHA-256 = 32 bytes
	if len(data) != 32 {
		t.Errorf("SHA-256 association length = %d, want 32", len(data))
	}
}

func TestComputeCertAssociation_SHA512(t *testing.T) {
	_, cert, cleanup := generateTestCert(t)
	defer cleanup()

	data, err := ComputeCertAssociation(cert, 1, 2)
	if err != nil {
		t.Fatalf("ComputeCertAssociation: %v", err)
	}

	// SHA-512 = 64 bytes
	if len(data) != 64 {
		t.Errorf("SHA-512 association length = %d, want 64", len(data))
	}
}

func TestComputeCertAssociation_FullCert(t *testing.T) {
	_, cert, cleanup := generateTestCert(t)
	defer cleanup()

	data, err := ComputeCertAssociation(cert, 0, 1)
	if err != nil {
		t.Fatalf("ComputeCertAssociation: %v", err)
	}

	want := expectedFullCertHash(cert)
	got := fmt.Sprintf("%x", data)
	if got != want {
		t.Errorf("full cert association = %s, want %s", got, want)
	}
}

func TestDaneCmdGenerate(t *testing.T) {
	// Integration test: runs daneCmd with a real cert file
	certPath, _, cleanup := generateTestCert(t)
	defer cleanup()

	err := runDane(nil, "generate", []string{"--cert", certPath, "--hostname", "mail.example.com"})
	if err != nil {
		t.Fatalf("daneCmd generate: %v", err)
	}
}

func TestDaneCmdGenerateMissingCert(t *testing.T) {
	err := runDane(nil, "generate", []string{"--hostname", "mail.example.com"})
	if err == nil {
		t.Error("expected error when --cert is missing")
	}
}

func TestDaneCmdGenerateMissingHostname(t *testing.T) {
	certPath, _, cleanup := generateTestCert(t)
	defer cleanup()

	err := runDane(nil, "generate", []string{"--cert", certPath})
	if err == nil {
		t.Error("expected error when --hostname is missing")
	}
}

func TestDaneCmdInvalidAction(t *testing.T) {
	err := runDane(nil, "invalid-action", nil)
	if err == nil {
		t.Error("expected error for invalid action")
	}
	if !strings.Contains(err.Error(), "unknown dane action") {
		t.Errorf("error should mention 'unknown dane action': %v", err)
	}
}

func TestComputeCertAssociation_ExactMatch(t *testing.T) {
	_, cert, cleanup := generateTestCert(t)
	defer cleanup()

	// Selector 1 (SPKI), Matching 0 (exact)
	data, err := ComputeCertAssociation(cert, 1, 0)
	if err != nil {
		t.Fatalf("ComputeCertAssociation: %v", err)
	}

	if len(data) != len(cert.RawSubjectPublicKeyInfo) {
		t.Errorf("exact match length = %d, want %d", len(data), len(cert.RawSubjectPublicKeyInfo))
	}
}
