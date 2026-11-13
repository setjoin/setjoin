package jmap

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/smime"
)

// smime_attach_oracle_test.go — W0/#4 crypto-oracle matrix for the S/MIME ×
// attachments submission pipeline (buildSMIMEWire, the single owner of the
// assemble→sign→encrypt order).
//
// The repo's crypto-oracle rule (sign_canonical_test.go precedent): self
// round-trip is NOT acceptance. Signed cells are verified with
// `openssl smime -verify`; encrypted cells with `openssl smime -decrypt`
// (+ -verify for the inner signature) — and the attachment bytes must appear
// BYTE-IDENTICAL in the verified/decrypted output.
//
// Matrix: {sign, encrypt, sign+encrypt} × {regular attachment, inline-cid
// image, none} = 9 cells. The no-attachment cells pin the pre-fix behavior
// (they must pass before AND after the fix); the attachment cells are the
// red-first proof of the data-loss bug (signed/encrypted sends silently
// shipped without their attachments).

const oracleDraftBody = "Hello oracle matrix body.\r\n"

const oracleDraftRaw = "Message-ID: <matrix@test>\r\n" +
	"From: signer@example.com\r\n" +
	"To: rcpt@example.com\r\n" +
	"Subject: oracle matrix\r\n" +
	"Date: Thu, 02 Jul 2026 12:00:00 +0000\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"\r\n" +
	oracleDraftBody

// oracleAttachmentBytes builds a deliberately binary payload (every byte value)
// so "byte-identical" is a meaningful assertion, not an ASCII coincidence.
func oracleAttachmentBytes(seed byte) []byte {
	out := make([]byte, 0, 512)
	out = append(out, []byte("%PDF-1.4\n%")...)
	for i := 0; i < 256; i++ {
		out = append(out, byte(i)^seed)
	}
	out = append(out, []byte("\n%%EOF\n")...)
	return out
}

// genOracleIdentity mints a self-signed RSA identity bound to email, usable for
// BOTH signing (digitalSignature) and encryption (keyEncipherment). Returns the
// cert PEM and the PKCS#8 key PEM (the forms openssl -certfile/-recip/-inkey and
// smime.SignCandidate expect).
func genOracleIdentity(t *testing.T, email string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(time.Now().UnixNano()),
		Subject:        pkix.Name{CommonName: email},
		EmailAddresses: []string{email},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// requireOpenssl locates the openssl binary or skips — LOUDLY, because a skip
// means the crypto oracle did not run and the matrix proved nothing.
func requireOpenssl(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("openssl")
	if err != nil {
		t.Log("!!!!! OPENSSL NOT FOUND — the S/MIME crypto-oracle matrix DID NOT RUN. " +
			"Self-round-trip is NOT acceptance (repo crypto-oracle rule); install openssl and re-run. !!!!!")
		t.Skip("openssl not available — ORACLE MATRIX SKIPPED (see loud log above)")
	}
	return p
}

// spliceEnvelope turns SignMessage output (which starts at its Content-Type
// header) into a full RFC 5322 message openssl smime -verify can parse — the
// sign_canonical_test.go buildFullRFC5322 precedent.
func spliceEnvelope(t *testing.T, signed []byte) []byte {
	t.Helper()
	s := string(signed)
	sep := strings.Index(s, "\r\n\r\n")
	if sep < 0 {
		t.Fatalf("no header/body separator in signed output: %.120q", s)
	}
	return []byte("From: signer@example.com\r\n" +
		"To: rcpt@example.com\r\n" +
		"MIME-Version: 1.0\r\n" +
		s[:sep] + "\r\n" +
		"\r\n" +
		s[sep+4:])
}

// opensslVerify runs `openssl smime -verify` (cms fallback) on a full signed
// message and returns the recovered (verified) content bytes.
func opensslVerify(t *testing.T, opensslPath string, fullMsg, signerCertPEM []byte) []byte {
	t.Helper()
	dir := t.TempDir()
	certFile := filepath.Join(dir, "signer.pem")
	inFile := filepath.Join(dir, "signed.eml")
	outFile := filepath.Join(dir, "recovered.bin")
	if err := os.WriteFile(certFile, signerCertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inFile, fullMsg, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(opensslPath, "smime", "-verify", "-in", inFile, "-inform", "SMIME",
		"-noverify", "-certfile", certFile, "-CAfile", certFile, "-out", outFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		cmd2 := exec.Command(opensslPath, "cms", "-verify", "-in", inFile, "-inform", "SMIME",
			"-noverify", "-certfile", certFile, "-CAfile", certFile, "-out", outFile)
		if out2, err2 := cmd2.CombinedOutput(); err2 != nil {
			t.Fatalf("openssl smime/cms -verify FAILED:\nsmime: %s\ncms: %s", out, out2)
		}
	}
	recovered, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	return recovered
}

// opensslDecrypt decrypts an application/pkcs7-mime wire entity with the
// recipient's cert+key and returns the plaintext bytes. Since A5 the outbound
// default is AES-GCM CMS AuthEnvelopedData, which the legacy PKCS#7 `openssl
// smime` app cannot parse — so this runs `openssl smime -decrypt` first (still
// exercised by the explicit-CBC fallback) and falls back to the RFC 5652/8551
// `openssl cms -decrypt` codepath, mirroring opensslVerify's cms fallback.
func opensslDecrypt(t *testing.T, opensslPath string, encWire, certPEM, keyPEM []byte) []byte {
	t.Helper()
	dir := t.TempDir()
	certFile := filepath.Join(dir, "rcpt.pem")
	keyFile := filepath.Join(dir, "rcpt.key")
	inFile := filepath.Join(dir, "enc.eml")
	outFile := filepath.Join(dir, "dec.bin")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inFile, encWire, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(opensslPath, "smime", "-decrypt", "-in", inFile, "-inform", "SMIME",
		"-recip", certFile, "-inkey", keyFile, "-out", outFile)
	out, smimeErr := cmd.CombinedOutput()
	if smimeErr != nil {
		// Fallback: cms decrypt (handles AuthEnvelopedData AES-GCM).
		cmd2 := exec.Command(opensslPath, "cms", "-decrypt", "-in", inFile, "-inform", "SMIME",
			"-recip", certFile, "-inkey", keyFile, "-out", outFile)
		out2, cmsErr := cmd2.CombinedOutput()
		if cmsErr != nil {
			t.Fatalf("openssl smime/cms -decrypt FAILED:\nsmime: %v\n%s\ncms: %v\n%s", smimeErr, out, cmsErr, out2)
		}
	}
	dec, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	return dec
}

// oraclePart is one decoded MIME part of the recovered content.
type oraclePart struct {
	contentType string
	disposition string
	contentID   string
	data        []byte
}

// parseMixedParts parses recovered content (a MIME entity or full message whose
// Content-Type must be multipart/mixed) and returns its decoded parts.
func parseMixedParts(t *testing.T, content []byte) []oraclePart {
	t.Helper()
	msg, err := mail.ReadMessage(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("recovered content is not a parseable MIME message: %v\ncontent: %.300q", err, content)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("recovered Content-Type unparseable: %v", err)
	}
	if mediaType != "multipart/mixed" {
		t.Fatalf("recovered content is %q, want multipart/mixed — the attachments did not survive the S/MIME pipeline", mediaType)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	var parts []oraclePart
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read multipart: %v", err)
		}
		raw, err := io.ReadAll(p)
		if err != nil {
			t.Fatalf("read part: %v", err)
		}
		data := raw
		if strings.EqualFold(p.Header.Get("Content-Transfer-Encoding"), "base64") {
			clean := strings.NewReplacer("\r", "", "\n", "").Replace(string(raw))
			data, err = base64.StdEncoding.DecodeString(clean)
			if err != nil {
				t.Fatalf("base64 decode part: %v", err)
			}
		}
		parts = append(parts, oraclePart{
			contentType: p.Header.Get("Content-Type"),
			disposition: p.Header.Get("Content-Disposition"),
			contentID:   p.Header.Get("Content-ID"),
			data:        data,
		})
	}
	return parts
}

// TestSMIMEAttachmentOracleMatrix is the 9-cell matrix:
// {sign, encrypt, sign+encrypt} × {regular attachment, inline-cid image, none}.
func TestSMIMEAttachmentOracleMatrix(t *testing.T) {
	opensslPath := requireOpenssl(t)

	signerCert, signerKey := genOracleIdentity(t, "signer@example.com")
	rcptCert, rcptKey := genOracleIdentity(t, "rcpt@example.com")
	rcptX509, err := smime.ParseCert(rcptCert)
	if err != nil {
		t.Fatal(err)
	}
	candidates := []smime.SignCandidate{{CertPEM: signerCert, KeyPEM: signerKey, IsDefault: true}}

	pdfBytes := oracleAttachmentBytes(0x00)
	pngBytes := append([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, oracleAttachmentBytes(0x5A)...)

	modes := []struct {
		name    string
		sign    bool
		encrypt bool
	}{
		{"sign", true, false},
		{"encrypt", false, true},
		{"sign+encrypt", true, true},
	}
	attachKinds := []string{"regular", "inline-cid", "none"}

	for _, m := range modes {
		for _, kind := range attachKinds {
			t.Run(m.name+"/"+kind, func(t *testing.T) {
				var parts []attachmentPart
				switch kind {
				case "regular":
					parts = []attachmentPart{{
						Filename: "report.pdf", ContentType: "application/pdf",
						Disposition: "attachment", Data: pdfBytes,
					}}
				case "inline-cid":
					parts = []attachmentPart{{
						Filename: "logo.png", ContentType: "image/png",
						Disposition: "inline", ContentID: "logo123", Data: pngBytes,
					}}
				}

				var encCerts []*x509.Certificate
				if m.encrypt {
					encCerts = []*x509.Certificate{rcptX509}
				}
				var cands []smime.SignCandidate
				if m.sign {
					cands = candidates
				}

				wire, reason, err := buildSMIMEWire([]byte(oracleDraftRaw), parts, cands, "signer@example.com", m.sign, encCerts)
				if reason != "" || err != nil {
					t.Fatalf("buildSMIMEWire: reason=%q err=%v", reason, err)
				}
				if len(wire) == 0 {
					t.Fatal("buildSMIMEWire returned empty wire")
				}

				// Oracle chain: decrypt (outer) first when encrypted, then verify
				// the (inner) signature when signed.
				content := wire
				if m.encrypt {
					content = opensslDecrypt(t, opensslPath, content, rcptCert, rcptKey)
				}
				if m.sign {
					content = opensslVerify(t, opensslPath, spliceEnvelope(t, content), signerCert)
				}

				switch kind {
				case "none":
					// Pins current behavior: signed cells recover the body-only
					// content; encrypt-only recovers the full draft.
					got := strings.ReplaceAll(string(content), "\r\n", "\n")
					want := strings.ReplaceAll(oracleDraftBody, "\r\n", "\n")
					if !m.sign {
						want = strings.ReplaceAll(oracleDraftRaw, "\r\n", "\n")
					}
					if got != want {
						t.Fatalf("recovered content mismatch.\ngot:  %q\nwant: %q", got, want)
					}
				case "regular":
					ps := parseMixedParts(t, content)
					found := false
					for _, p := range ps {
						if strings.Contains(p.disposition, "report.pdf") {
							found = true
							if !bytes.Equal(p.data, pdfBytes) {
								t.Fatalf("attachment bytes NOT byte-identical after %s: got %d bytes, want %d", m.name, len(p.data), len(pdfBytes))
							}
						}
					}
					if !found {
						t.Fatalf("attachment report.pdf MISSING from the recovered %s output (data loss)", m.name)
					}
					// The body must survive alongside the attachment.
					if !strings.Contains(string(content), strings.TrimSpace(oracleDraftBody)) {
						t.Fatalf("draft body missing from recovered %s output", m.name)
					}
				case "inline-cid":
					ps := parseMixedParts(t, content)
					found := false
					for _, p := range ps {
						if p.contentID == "<logo123>" {
							found = true
							if !bytes.Equal(p.data, pngBytes) {
								t.Fatalf("inline-cid image bytes NOT byte-identical after %s", m.name)
							}
							if !strings.HasPrefix(p.disposition, "inline") {
								t.Errorf("inline-cid part disposition = %q, want inline", p.disposition)
							}
						}
					}
					if !found {
						t.Fatalf("inline-cid part <logo123> MISSING from the recovered %s output (data loss)", m.name)
					}
				}
			})
		}
	}
}

// TestSMIMEOracleInlineRawRefSign is the 10th matrix cell (W5 raw_ref
// convention fix): a reducer-built draft stores messages.raw_ref as the INLINE
// RFC 5322 text itself (jmap_email.sql v_raw_msg) — not a MinIO key. The sign
// path's raw resolution (rawFromRef) must return those bytes verbatim WITHOUT
// touching MinIO (h.minio is nil here: any fetch attempt panics the test —
// which is exactly what the pre-fix code did, routing every no-attachment
// draft to fetchBlob and failing the sign). The resolved bytes must then
// produce an openssl-VERIFIABLE signature whose recovered content is the body.
func TestSMIMEOracleInlineRawRefSign(t *testing.T) {
	opensslPath := requireOpenssl(t)

	signerCert, signerKey := genOracleIdentity(t, "signer@example.com")
	candidates := []smime.SignCandidate{{CertPEM: signerCert, KeyPEM: signerKey, IsDefault: true}}

	h := &JMAPHandler{} // nil minio + nil pool: inline resolution needs neither
	raw, err := h.rawFromRef(context.Background(), oracleDraftRaw)
	if err != nil {
		t.Fatalf("rawFromRef on an inline raw_ref: %v", err)
	}
	if string(raw) != oracleDraftRaw {
		t.Fatalf("rawFromRef mutated the inline message:\ngot:  %q\nwant: %q", raw, oracleDraftRaw)
	}

	wire, reason, err := buildSMIMEWire(raw, nil, candidates, "signer@example.com", true, nil)
	if reason != "" || err != nil {
		t.Fatalf("buildSMIMEWire: reason=%q err=%v", reason, err)
	}

	content := opensslVerify(t, opensslPath, spliceEnvelope(t, wire), signerCert)
	got := strings.ReplaceAll(string(content), "\r\n", "\n")
	want := strings.ReplaceAll(oracleDraftBody, "\r\n", "\n")
	if got != want {
		t.Fatalf("recovered content mismatch after inline-raw_ref sign.\ngot:  %q\nwant: %q", got, want)
	}
}

// TestSignedAttachmentWireNeverSmaller is the size regression: a signed
// (+attachment) wire blob can never be smaller than the attachment itself —
// if it is, the attachment bytes were dropped. Runs without openssl.
func TestSignedAttachmentWireNeverSmaller(t *testing.T) {
	signerCert, signerKey := genOracleIdentity(t, "signer@example.com")
	candidates := []smime.SignCandidate{{CertPEM: signerCert, KeyPEM: signerKey, IsDefault: true}}

	big := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF, 0x01}, 16*1024) // 64 KiB
	wire, reason, err := buildSMIMEWire([]byte(oracleDraftRaw), []attachmentPart{{
		Filename: "big.bin", ContentType: "application/octet-stream",
		Disposition: "attachment", Data: big,
	}}, candidates, "signer@example.com", true, nil)
	if reason != "" || err != nil {
		t.Fatalf("buildSMIMEWire: reason=%q err=%v", reason, err)
	}
	if len(wire) < len(big) {
		t.Fatalf("signed+attachment wire (%d bytes) is SMALLER than the attachment itself (%d bytes) — the attachment was dropped from the signed artifact", len(wire), len(big))
	}
}
