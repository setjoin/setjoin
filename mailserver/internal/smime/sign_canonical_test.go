package smime

import (
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestEncryptReasonConstants locks the stable, wire-facing values of the three
// encrypt-failure markers. The compose UX switch statement and the plan docs
// reference these exact strings verbatim — a value drift here silently breaks
// the marker→human-copy mapping (the user would see the generic send-failed copy
// instead of the address-naming / settings / admin guidance). Fail loud on drift.
func TestEncryptReasonConstants(t *testing.T) {
	if ReasonEncryptNoCert != "smime_encrypt_no_cert" {
		t.Fatalf("ReasonEncryptNoCert = %q, want smime_encrypt_no_cert", ReasonEncryptNoCert)
	}
	if ReasonEncryptNoSenderCert != "smime_encrypt_no_sender_cert" {
		t.Fatalf("ReasonEncryptNoSenderCert = %q, want smime_encrypt_no_sender_cert", ReasonEncryptNoSenderCert)
	}
	if ReasonEncryptNoJournalCert != "smime_encrypt_no_journal_cert" {
		t.Fatalf("ReasonEncryptNoJournalCert = %q, want smime_encrypt_no_journal_cert", ReasonEncryptNoJournalCert)
	}
}

// TestSignMessage_Canonical proves that SignMessage output is a well-formed
// multipart/signed message AND that openssl can cryptographically verify it
// (the automated proxy for the "does Outlook/Thunderbird accept our signature"
// go-live gate). Canonicalization regressions (CRLF/boundary/digest) are caught
// before the feature toggle flips.
//
// We do NOT use smime.VerifyDetached to verify our own Sign output — doc.go
// documents that our hand-rolled Sign emits CMS that ietf-cms cannot fully
// re-parse, so self-verify would falsely fail.
func TestSignMessage_Canonical(t *testing.T) {
	// Mint a signing identity with an RSA 2048 key and EmailProtection EKU,
	// using the shared genCandidate helper (mirrors sign_outbound_test.go).
	cand := genCandidate(t, "signer@example.com", true)
	cert, err := ParseCert(cand.CertPEM)
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}
	key, err := ParsePrivateKey(cand.KeyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}

	// Build a realistic RFC 5322 message with CRLF line endings.
	rawMsg := "From: signer@example.com\r\n" +
		"To: r@example.com\r\n" +
		"Subject: Canonical test\r\n" +
		"\r\n" +
		"This is the signed body.\r\n"

	// Mirror the handler's exact header/body split (ResolveAndSign / the old worker):
	// split at the first \r\n\r\n and pass only the body to SignMessage.
	body := []byte(rawMsg)
	if idx := strings.Index(rawMsg, "\r\n\r\n"); idx >= 0 {
		body = []byte(rawMsg[idx+4:])
	}

	signed, err := SignMessage(body, cert, key)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	if len(signed) == 0 {
		t.Fatal("SignMessage returned empty output")
	}

	t.Run("A_structural", func(t *testing.T) {
		testStructural(t, signed, body)
	})

	t.Run("B_openssl_verify", func(t *testing.T) {
		testOpensslVerify(t, signed, body, cand.CertPEM)
	})
}

// testStructural asserts that the SignMessage output is a well-formed
// multipart/signed message with exactly two parts: signed content and a valid
// DER PKCS#7 signature. This subtest always runs (no openssl required).
func testStructural(t *testing.T, signed, expectedBody []byte) {
	t.Helper()
	s := string(signed)

	// Top must be Content-Type: multipart/signed with the right protocol + micalg.
	if !strings.HasPrefix(s, "Content-Type: multipart/signed") {
		t.Fatalf("output must start with Content-Type: multipart/signed, got: %.120q", s)
	}
	if !strings.Contains(s, `protocol="application/pkcs7-signature"`) {
		t.Error("missing protocol=\"application/pkcs7-signature\" in Content-Type")
	}
	if !strings.Contains(strings.ToLower(s), "micalg=sha-256") {
		t.Error("missing micalg=sha-256 in Content-Type")
	}

	// Extract the boundary from the Content-Type header line.
	boundary := extractBoundary(t, s)
	if boundary == "" {
		t.Fatal("could not extract boundary from Content-Type")
	}

	// Split the body (everything after the first blank line) on the boundary.
	bodyStart := strings.Index(s, "\r\n\r\n")
	if bodyStart < 0 {
		t.Fatal("no blank line found separating headers from body")
	}
	mimeBody := s[bodyStart+4:]

	parts := extractMultipartParts(t, mimeBody, boundary)
	if len(parts) != 2 {
		t.Fatalf("expected exactly 2 MIME parts, got %d", len(parts))
	}

	// Part 1: the signed content. It must round-trip the original body bytes.
	part1 := parts[0]
	if !strings.Contains(part1, string(expectedBody)) {
		t.Errorf("part 1 (signed content) does not contain the original body.\npart1: %.200q\nbody: %.200q",
			part1, expectedBody)
	}

	// Part 2: the pkcs7-signature part. Must have the right Content-Type and
	// must contain valid DER (non-empty asn1.Unmarshal succeeds).
	part2 := parts[1]
	ctLower := strings.ToLower(part2)
	if !strings.Contains(ctLower, "application/pkcs7-signature") &&
		!strings.Contains(ctLower, "application/x-pkcs7-signature") {
		t.Errorf("part 2 Content-Type must be application/pkcs7-signature, got: %.200q", part2)
	}

	// Extract the base64 payload from part 2. Our base64Encode is unpadded, so
	// decode with RawStdEncoding (same trick used in signatureDERFromOutput).
	b64Payload := extractBase64Payload(t, part2)
	if b64Payload == "" {
		t.Fatal("could not find base64 payload in part 2")
	}
	// base64Encode now emits padded, MIME-wrapped base64; extractBase64Payload
	// strips the CRLF line wraps so the concatenated string is standard base64.
	der, err := base64.StdEncoding.DecodeString(b64Payload)
	if err != nil {
		t.Fatalf("base64 decode of signature part: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("decoded DER signature is empty")
	}
	var rv asn1.RawValue
	rest, err := asn1.Unmarshal(der, &rv)
	if err != nil {
		t.Fatalf("DER in signature part is not valid ASN.1: %v", err)
	}
	if len(rest) != 0 {
		t.Errorf("unexpected trailing bytes after DER: %d bytes", len(rest))
	}
}

// buildFullRFC5322 takes the SignMessage output (which starts with a
// Content-Type header) and constructs a complete RFC 5322 message that openssl
// smime -verify can parse. SignMessage emits:
//
//	Content-Type: multipart/signed; ...\r\n\r\n<multipart body>
//
// openssl smime -verify (SMIME format) expects the Content-Type header to
// appear in the RFC 5322 header block, preceded by standard message headers and
// MIME-Version. We splice them together here to produce a verifiable message.
func buildFullRFC5322(t *testing.T, signed []byte) []byte {
	t.Helper()
	s := string(signed)

	// SignMessage output: first line is the Content-Type header, then \r\n, then body.
	// Find the blank line that separates the Content-Type header from the MIME body.
	sep := strings.Index(s, "\r\n\r\n")
	if sep < 0 {
		t.Fatalf("no \\r\\n\\r\\n found in SignMessage output")
	}
	ctHeader := s[:sep]   // "Content-Type: multipart/signed; ..."
	mimeBody := s[sep+4:] // the multipart body starting at --boundary

	// Assemble: RFC 5322 envelope headers + MIME-Version + our Content-Type + blank + body.
	// These envelope headers are not signed (only mimeBody content is protected).
	full := "From: signer@example.com\r\n" +
		"To: r@example.com\r\n" +
		"MIME-Version: 1.0\r\n" +
		ctHeader + "\r\n" +
		"\r\n" +
		mimeBody
	return []byte(full)
}

// testOpensslVerify uses openssl smime -verify as the cryptographic oracle.
// It skips if openssl is not on PATH.
func testOpensslVerify(t *testing.T, signed, expectedBody, certPEM []byte) {
	t.Helper()

	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available")
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "signer.pem")
	signedFile := filepath.Join(dir, "signed.eml")
	recoveredFile := filepath.Join(dir, "recovered.txt")

	// Build the complete RFC 5322 message that openssl expects.
	fullMsg := buildFullRFC5322(t, signed)

	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert file: %v", err)
	}
	if err := os.WriteFile(signedFile, fullMsg, 0o600); err != nil {
		t.Fatalf("write signed file: %v", err)
	}

	// -noverify: skip chain verification (self-signed cert).
	// -certfile + -CAfile: provide the signer cert as both the trust anchor
	// and the lookup cert so openssl can locate the signer.
	cmd := exec.Command(opensslPath,
		"smime", "-verify",
		"-in", signedFile,
		"-inform", "SMIME",
		"-noverify",
		"-certfile", certFile,
		"-CAfile", certFile,
		"-out", recoveredFile,
	)
	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		// Try cms -verify as a fallback in case smime rejects the structure.
		cmd2 := exec.Command(opensslPath,
			"cms", "-verify",
			"-in", signedFile,
			"-inform", "SMIME",
			"-noverify",
			"-certfile", certFile,
			"-CAfile", certFile,
			"-out", recoveredFile,
		)
		out2, runErr2 := cmd2.CombinedOutput()
		if runErr2 != nil {
			t.Fatalf("openssl smime/cms -verify FAILED (canonicalization error):\n"+
				"smime stderr: %s\ncms stderr: %s", out, out2)
		}
		// cms succeeded; fall through to content check.
		out = out2
	}
	// openssl prints "Verification successful" on stderr on success.
	if !strings.Contains(string(out), "Verification successful") &&
		!strings.Contains(string(out), "verification successful") {
		// Some openssl builds print it differently; exit-0 is the real gate.
		t.Logf("openssl verification note (stderr): %s", out)
	}

	// The recovered content should match the original signed body.
	recovered, readErr := os.ReadFile(recoveredFile)
	if readErr != nil {
		t.Fatalf("read recovered file: %v", readErr)
	}
	// Normalize CRLF→LF for comparison (openssl may emit either).
	normalRecovered := strings.ReplaceAll(string(recovered), "\r\n", "\n")
	normalExpected := strings.ReplaceAll(string(expectedBody), "\r\n", "\n")
	if normalRecovered != normalExpected {
		t.Errorf("recovered content mismatch.\ngot:  %q\nwant: %q", normalRecovered, normalExpected)
	}
}

// extractBoundary finds the boundary="…" value in the Content-Type line.
func extractBoundary(t *testing.T, s string) string {
	t.Helper()
	const marker = `boundary="`
	idx := strings.Index(s, marker)
	if idx < 0 {
		return ""
	}
	rest := s[idx+len(marker):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// extractMultipartParts splits the multipart body on the boundary delimiter and
// returns the non-empty part strings (each including their own headers + blank
// line + body, but trimmed of leading/trailing whitespace).
func extractMultipartParts(t *testing.T, body, boundary string) []string {
	t.Helper()
	delim := "--" + boundary
	sections := strings.Split(body, delim)
	var parts []string
	for _, sec := range sections {
		sec = strings.TrimLeft(sec, "\r\n")
		// Skip the preamble (empty or just newlines before the first delimiter)
		// and the closing "--\r\n" epilogue.
		if strings.TrimSpace(sec) == "" || strings.HasPrefix(sec, "--") {
			continue
		}
		parts = append(parts, sec)
	}
	return parts
}

// extractBase64Payload returns the concatenated base64 lines from a MIME part
// that contains "Content-Transfer-Encoding: base64".
func extractBase64Payload(t *testing.T, part string) string {
	t.Helper()
	const marker = "Content-Transfer-Encoding: base64\r\n\r\n"
	idx := strings.Index(part, marker)
	if idx < 0 {
		// Try LF-only variant.
		const markerLF = "Content-Transfer-Encoding: base64\n\n"
		idx = strings.Index(part, markerLF)
		if idx < 0 {
			t.Log("no Content-Transfer-Encoding: base64 found in part")
			return ""
		}
		idx += len(markerLF)
	} else {
		idx += len(marker)
	}
	rest := part[idx:]
	var b64 strings.Builder
	for _, line := range strings.Split(rest, "\r\n") {
		if line == "" || strings.HasPrefix(line, "--") {
			break
		}
		b64.WriteString(line)
	}
	return b64.String()
}

// TestSignMessage_CanonicalOracleBites is the Step-3 sanity check: it proves
// that the openssl oracle is not vacuous by corrupting a byte in the signed
// content and asserting that openssl FAILS. This is not committed as a
// permanent test — it's an oracle-bites proof run during D4 verification.
func TestSignMessage_CanonicalOracleBites(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}

	cand := genCandidate(t, "signer@example.com", true)
	cert, err := ParseCert(cand.CertPEM)
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}
	key, err := ParsePrivateKey(cand.KeyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}

	rawMsg := "From: signer@example.com\r\nTo: r@example.com\r\nSubject: Oracle bites\r\n\r\nOracle bites body.\r\n"
	body := []byte(rawMsg)
	if idx := strings.Index(rawMsg, "\r\n\r\n"); idx >= 0 {
		body = []byte(rawMsg[idx+4:])
	}

	signed, err := SignMessage(body, cert, key)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}

	// Corrupt a byte in the signed content (part 1, first byte of the body area).
	corrupted := make([]byte, len(signed))
	copy(corrupted, signed)

	// Find the first occurrence of "Oracle" in the signed output (the signed body)
	// and flip one byte.
	targetStr := "Oracle bites body"
	idx := strings.Index(string(corrupted), targetStr)
	if idx < 0 {
		t.Fatalf("could not find %q in signed output", targetStr)
	}
	corrupted[idx] ^= 0xFF // flip all bits in that byte

	dir := t.TempDir()
	certFile := filepath.Join(dir, "signer.pem")
	corruptedFile := filepath.Join(dir, "corrupted.eml")
	recoveredFile := filepath.Join(dir, "recovered.txt")

	// Build proper RFC 5322 message from the corrupted signed output.
	fullCorrupted := buildFullRFC5322(t, corrupted)

	if err := os.WriteFile(certFile, cand.CertPEM, 0o600); err != nil {
		t.Fatalf("write cert file: %v", err)
	}
	if err := os.WriteFile(corruptedFile, fullCorrupted, 0o600); err != nil {
		t.Fatalf("write corrupted file: %v", err)
	}

	opensslPath, _ := exec.LookPath("openssl")
	cmd := exec.Command(opensslPath,
		"smime", "-verify",
		"-in", corruptedFile,
		"-inform", "SMIME",
		"-noverify",
		"-certfile", certFile,
		"-CAfile", certFile,
		"-out", recoveredFile,
	)
	out, runErr := cmd.CombinedOutput()
	if runErr == nil {
		// Try cms as well.
		cmd2 := exec.Command(opensslPath,
			"cms", "-verify",
			"-in", corruptedFile,
			"-inform", "SMIME",
			"-noverify",
			"-certfile", certFile,
			"-CAfile", certFile,
			"-out", recoveredFile,
		)
		out2, runErr2 := cmd2.CombinedOutput()
		if runErr2 == nil {
			t.Fatalf("ORACLE IS VACUOUS: openssl accepted a corrupted signed message — "+
				"the oracle is not detecting forgeries.\nsmime out: %s\ncms out: %s", out, out2)
		}
		t.Logf("cms correctly rejected corrupted message: %s", out2)
		return
	}
	// Correct: openssl rejected the corrupted message.
	t.Logf("oracle bites: openssl correctly FAILED on corrupted content (exit: %v):\n%s", runErr, out)

	// Confirm the error message indicates a verification/digest failure.
	combined := strings.ToLower(string(out))
	if !strings.Contains(combined, "error") && !strings.Contains(combined, "fail") &&
		!strings.Contains(combined, "digest") && !strings.Contains(combined, "invalid") {
		t.Logf("openssl error output (for reference): %s", out)
	}
	fmt.Printf("\n=== ORACLE BITES PROOF ===\nopenssl correctly REJECTED a byte-corrupted signed message.\nstderr: %s\n=========================\n", out)
}
