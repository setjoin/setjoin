package smime

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// encrypt_gcm_test.go — owner decision A5 (S/MIME 4.0 / RFC 8551): outbound
// content encryption defaults to AES-256-GCM wrapped as CMS AuthEnvelopedData
// (RFC 5083), with the S/MIME 3.2 AES-256-CBC EnvelopedData fallback selectable
// by config. Coverage here:
//
//   - GCM round-trip through BOTH receive primitives (Decrypt, DecryptMulti);
//   - explicit-CBC fallback round-trip (the receive side must keep accepting
//     CBC forever — backward-compat mandate);
//   - tamper detection: GCM MUST fail closed on a flipped ciphertext byte
//     (auth failure collapses to ErrNoMatchingKey like a CBC padding failure);
//   - algorithm selection: default is GCM, SetDefaultEncryptAlgorithm validates
//     and the setter is what the smime.encrypt_algorithm config key feeds;
//   - bidirectional openssl oracle for GCM: openssl decrypts our
//     AuthEnvelopedData, and openssl-produced AuthEnvelopedData opens via our
//     DecryptMulti (skip, never silently pass, when the local openssl predates
//     CMS GCM support).

// setEncryptAlgorithmForTest pins the process-wide default algorithm for the
// duration of one test and restores the previous value afterwards, so the
// package-level default never leaks across tests.
func setEncryptAlgorithmForTest(t *testing.T, alg EncryptAlgorithm) (restore func()) {
	t.Helper()
	prev := DefaultEncryptAlgorithm()
	t.Cleanup(func() {
		if err := SetDefaultEncryptAlgorithm(prev); err != nil {
			t.Errorf("restore default encrypt algorithm: %v", err)
		}
	})
	if err := SetDefaultEncryptAlgorithm(alg); err != nil {
		t.Fatalf("SetDefaultEncryptAlgorithm(%q): %v", alg, err)
	}
	return func() { _ = SetDefaultEncryptAlgorithm(prev) }
}

// wireToDER strips Encrypt's MIME wrapper (headers + base64) into the bare DER
// ContentInfo Decrypt consumes.
func wireToDER(t *testing.T, wire []byte) []byte {
	t.Helper()
	b64 := string(wire[strings.Index(string(wire), "\r\n\r\n")+4:])
	der, err := base64Decode(stripCR(b64))
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	return der
}

// TestEncrypt_DefaultIsGCM_AuthEnvelopedData pins the owner decision: the
// no-argument Encrypt path emits RFC 5083 AuthEnvelopedData with AES-256-GCM,
// and the explicit CBC selection emits RFC 5652 EnvelopedData with AES-256-CBC.
func TestEncrypt_DefaultIsGCM_AuthEnvelopedData(t *testing.T) {
	cand := genCandidate(t, "algcheck@example.com", true)
	cert, err := ParseCert(cand.CertPEM)
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}

	// Default (no explicit algorithm): GCM AuthEnvelopedData.
	gcmWire, err := Encrypt([]byte("body\r\n"), []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	gcmDER := wireToDER(t, gcmWire)
	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(gcmDER, &ci); err != nil {
		t.Fatalf("GCM default DER: %v", err)
	}
	if !ci.ContentType.Equal(oidAuthEnvelopedData) {
		t.Errorf("default Encrypt ContentInfo OID = %v, want AuthEnvelopedData %v", ci.ContentType, oidAuthEnvelopedData)
	}
	if !strings.Contains(string(gcmWire), "smime-type=authEnveloped-data") {
		t.Error("default Encrypt wire header must carry smime-type=authEnveloped-data")
	}

	// Inside: aes-256-gcm algorithm identifier with GCMParameters{nonce, ICVLen=16}.
	var aed cmsAuthEnvelopedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &aed); err != nil {
		t.Fatalf("parse AuthEnvelopedData: %v", err)
	}
	if !aed.AuthEncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm.Equal(oidAES256GCM) {
		t.Errorf("content encryption = %v, want aes-256-GCM %v",
			aed.AuthEncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm, oidAES256GCM)
	}
	var params cmsGCMParameters
	paramsDER := aed.AuthEncryptedContentInfo.ContentEncryptionAlgorithm.Parameters.FullBytes
	if _, err := asn1.Unmarshal(paramsDER, &params); err != nil {
		t.Fatalf("parse GCMParameters: %v", err)
	}
	if len(params.Nonce) != gcmNonceLen {
		t.Errorf("GCM nonce length = %d, want %d", len(params.Nonce), gcmNonceLen)
	}
	if params.ICVLen != gcmICVLen {
		t.Errorf("GCM ICVLen = %d, want %d (16 is not the RFC 5084 DEFAULT, it must be explicit)", params.ICVLen, gcmICVLen)
	}
	if len(aed.MAC) != gcmICVLen {
		t.Errorf("mac field length = %d, want %d", len(aed.MAC), gcmICVLen)
	}
	// authAttrs absent (id-data content type ⇒ optional) — our AAD is empty.
	if len(aed.AuthAttrs.FullBytes) != 0 {
		t.Error("we must not emit authAttrs (would change the AAD contract)")
	}

	// Explicit CBC selection: legacy EnvelopedData.
	cbcWire, err := EncryptWithAlgorithm(AlgorithmAES256CBC, []byte("body\r\n"), []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("EncryptWithAlgorithm(CBC): %v", err)
	}
	if !strings.Contains(string(cbcWire), "smime-type=enveloped-data") {
		t.Error("CBC fallback wire header must carry smime-type=enveloped-data")
	}
	var cbcCI cmsContentInfo
	if _, err := asn1.Unmarshal(wireToDER(t, cbcWire), &cbcCI); err != nil {
		t.Fatalf("CBC DER: %v", err)
	}
	if !cbcCI.ContentType.Equal(oidEnvelopedData) {
		t.Errorf("CBC ContentInfo OID = %v, want EnvelopedData %v", cbcCI.ContentType, oidEnvelopedData)
	}
}

// TestEncrypt_GCM_RoundTrip: default Encrypt output decrypts through BOTH
// receive primitives — the single-key Decrypt and the keystore-facing
// DecryptMulti (encrypt-to-self / rollover shape).
func TestEncrypt_GCM_RoundTrip(t *testing.T) {
	cand := genCandidate(t, "gcmrt@example.com", true)
	cert, err := ParseCert(cand.CertPEM)
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}
	keyAny, err := ParsePrivateKey(cand.KeyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	rsaKey, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", keyAny)
	}

	// Empty and non-block-aligned plaintexts — GCM is a stream mode, so no
	// padding-driven length constraints apply (contrast with CBC).
	plaintexts := [][]byte{
		[]byte(""),
		[]byte("x"),
		[]byte("Subject: gcm\r\n\r\nbody exactly 16ch\r\n"),
		bytes.Repeat([]byte("long body without alignment.\r\n"), 7),
	}

	for i, plaintext := range plaintexts {
		wire, err := Encrypt(plaintext, []*x509.Certificate{cert})
		if err != nil {
			t.Fatalf("case %d Encrypt: %v", i, err)
		}
		der := wireToDER(t, wire)

		got, err := Decrypt(der, cert, rsaKey)
		if err != nil {
			t.Fatalf("case %d Decrypt: %v", i, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("case %d Decrypt mismatch: got %d bytes, want %d", i, len(got), len(plaintext))
		}

		got, err = DecryptMulti(der, []DecryptKey{{Cert: cert, Key: rsaKey}})
		if err != nil {
			t.Fatalf("case %d DecryptMulti: %v", i, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("case %d DecryptMulti mismatch: got %d bytes, want %d", i, len(got), len(plaintext))
		}
	}
}

// TestEncrypt_CBC_FallbackRoundTrip pins the receive-backward-compat mandate
// from the OTHER side: messages encrypted with the explicit CBC fallback must
// still open via Decrypt/DecryptMulti, forever.
func TestEncrypt_CBC_FallbackRoundTrip(t *testing.T) {
	cand := genCandidate(t, "cbcrt@example.com", true)
	cert, err := ParseCert(cand.CertPEM)
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}
	keyAny, err := ParsePrivateKey(cand.KeyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	rsaKey := keyAny.(*rsa.PrivateKey)

	plaintext := []byte("Subject: cbc compat\r\n\r\nlegacy body.\r\n")
	wire, err := EncryptWithAlgorithm(AlgorithmAES256CBC, plaintext, []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("EncryptWithAlgorithm(CBC): %v", err)
	}
	der := wireToDER(t, wire)

	got, err := Decrypt(der, cert, rsaKey)
	if err != nil {
		t.Fatalf("Decrypt of CBC fallback: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("CBC Decrypt mismatch: got %q", got)
	}

	got, err = DecryptMulti(der, []DecryptKey{{Cert: cert, Key: rsaKey}})
	if err != nil {
		t.Fatalf("DecryptMulti of CBC fallback: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("CBC DecryptMulti mismatch: got %q", got)
	}
}

// TestEncrypt_GCM_TamperDetection: a single flipped ciphertext byte must make
// the GCM open FAIL (tag verification), surfacing as ErrNoMatchingKey — the
// same collapsed outcome a CBC padding failure gives, so the padding-oracle
// indistinguishability contract extends to auth failures. The CBC contrast
// case documents WHY GCM is the upgrade: CBC has no authentication, so the
// same flip decrypts "successfully" to garbage (bit-flip malleability) or
// errors on a broken padding block — either way the caller gets no integrity
// verdict, only GCM fails closed deterministically.
func TestEncrypt_GCM_TamperDetection(t *testing.T) {
	cand := genCandidate(t, "tamper@example.com", true)
	cert, err := ParseCert(cand.CertPEM)
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}
	keyAny, err := ParsePrivateKey(cand.KeyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	rsaKey := keyAny.(*rsa.PrivateKey)

	plaintext := []byte("tamper target body with some length to it\r\n")

	flippedBody := func(t *testing.T, alg EncryptAlgorithm) []byte {
		t.Helper()
		wire, err := EncryptWithAlgorithm(alg, plaintext, []*x509.Certificate{cert})
		if err != nil {
			t.Fatalf("EncryptWithAlgorithm(%q): %v", alg, err)
		}
		view := parseEnvelopeAny(t, wireToDER(t, wire))
		body := *view.body
		if len(body) == 0 {
			t.Fatal("empty body cannot be tampered")
		}
		body[len(body)/2] ^= 0x01
		*view.body = body
		return view.encode(t)
	}

	// GCM: MUST fail closed — a flipped byte can never pass tag verification.
	got, err := DecryptMulti(flippedBody(t, AlgorithmAES256GCM), []DecryptKey{{Cert: cert, Key: rsaKey}})
	if !errors.Is(err, ErrNoMatchingKey) {
		t.Errorf("GCM: flipped body byte: got (pt=%q, err=%v), want ErrNoMatchingKey (tag must fail)", got, err)
	}

	// CBC (contrast): the same flip yields an error OR garbage, NEVER the
	// plaintext — but unlike GCM there is no deterministic integrity verdict.
	got, err = DecryptMulti(flippedBody(t, AlgorithmAES256CBC), []DecryptKey{{Cert: cert, Key: rsaKey}})
	if err == nil && bytes.Equal(got, plaintext) {
		t.Errorf("CBC: flipped body byte decrypted to the exact plaintext (impossible bit-flip)")
	}
}

// TestSetDefaultEncryptAlgorithm covers the config-selection seam: GCM default,
// CBC selectable, empty resets to GCM, unknown values rejected WITHOUT changing
// the previous setting (a bad config key must never silently break or downgrade
// outbound encryption).
func TestSetDefaultEncryptAlgorithm(t *testing.T) {
	// Package default is GCM (owner decision A5).
	if got := DefaultEncryptAlgorithm(); got != AlgorithmAES256GCM {
		t.Fatalf("package default = %q, want %q", got, AlgorithmAES256GCM)
	}

	if err := SetDefaultEncryptAlgorithm(AlgorithmAES256CBC); err != nil {
		t.Fatalf("SetDefaultEncryptAlgorithm(CBC): %v", err)
	}
	if got := DefaultEncryptAlgorithm(); got != AlgorithmAES256CBC {
		t.Fatalf("after CBC set, default = %q", got)
	}

	// CBC default actually steers Encrypt (structural proof via content OID).
	cand := genCandidate(t, "cfgsel@example.com", true)
	cert, err := ParseCert(cand.CertPEM)
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}
	wire, err := Encrypt([]byte("steered body\r\n"), []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("Encrypt under CBC default: %v", err)
	}
	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(wireToDER(t, wire), &ci); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !ci.ContentType.Equal(oidEnvelopedData) {
		t.Errorf("Encrypt under CBC default produced OID %v, want EnvelopedData", ci.ContentType)
	}

	// Unknown value: rejected, previous (CBC) selection retained.
	if err := SetDefaultEncryptAlgorithm("rot13"); err == nil {
		t.Fatal("unknown algorithm must be rejected")
	}
	if got := DefaultEncryptAlgorithm(); got != AlgorithmAES256CBC {
		t.Fatalf("after rejected set, default must stay %q, got %q", AlgorithmAES256CBC, got)
	}

	// Empty: resets to the GCM default.
	if err := SetDefaultEncryptAlgorithm(""); err != nil {
		t.Fatalf("SetDefaultEncryptAlgorithm(empty): %v", err)
	}
	if got := DefaultEncryptAlgorithm(); got != AlgorithmAES256GCM {
		t.Fatalf("empty must reset to GCM, got %q", got)
	}
}

// TestEncrypt_GCM_OpensslDecrypts proves our AuthEnvelopedData is
// interoperable: openssl cms -decrypt recovers the exact plaintext. Skips (with
// a loud SKIP, never a silent pass) when the local openssl predates CMS GCM.
func TestEncrypt_GCM_OpensslDecrypts(t *testing.T) {
	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available")
	}
	if !opensslSupportsGCMCMS(t) {
		t.Skip("installed openssl cms cannot decrypt AES-GCM AuthEnvelopedData")
	}

	cand := genCandidate(t, "gcmoracle@example.com", true)
	cert, err := ParseCert(cand.CertPEM)
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}

	plaintext := []byte("Subject: gcm interop\r\n\r\nA5 body through the openssl oracle.\r\n")
	wire, err := Encrypt(plaintext, []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	dir := t.TempDir()
	encFile := filepath.Join(dir, "enc.eml")
	outFile := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(filepath.Join(dir, "c.pem"), []byte(cand.CertPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "k.pem"), []byte(cand.KeyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(encFile, []byte("MIME-Version: 1.0\r\n"+string(wire)), 0o600); err != nil {
		t.Fatal(err)
	}

	// cms ONLY — AuthEnvelopedData has no pkcs7 smime fallback.
	cmd := exec.Command(opensslPath, "cms", "-decrypt",
		"-in", encFile, "-inform", "SMIME",
		"-recip", filepath.Join(dir, "c.pem"), "-inkey", filepath.Join(dir, "k.pem"),
		"-out", outFile)
	if out, runErr := cmd.CombinedOutput(); runErr != nil {
		t.Fatalf("openssl cms -decrypt of our GCM AuthEnvelopedData FAILED:\n%s", out)
	}
	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read recovered: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("openssl recovered mismatch.\ngot:  %q\nwant: %q", got, plaintext)
	}
}

// TestReverseOracle_OpensslGCMEncryptThenOurDecrypt is the inverse GCM oracle:
// an AuthEnvelopedData produced by an external S/MIME 4.0 sender's openssl must
// open via our DecryptMulti — the hosted decrypt-on-read property for GCM mail.
func TestReverseOracle_OpensslGCMEncryptThenOurDecrypt(t *testing.T) {
	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available")
	}
	if !opensslSupportsGCMCMS(t) {
		t.Skip("installed openssl cms cannot encrypt with AES-GCM AuthEnvelopedData")
	}

	cand := genCandidate(t, "gcmreader@example.com", true)
	cert, err := ParseCert(cand.CertPEM)
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}
	keyAny, err := ParsePrivateKey(cand.KeyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	rsaKey := keyAny.(*rsa.PrivateKey)

	plaintext := []byte("External S/MIME 4.0 GCM sender body.\r\n")
	dir := t.TempDir()
	certFile := filepath.Join(dir, "r.pem")
	plainFile := filepath.Join(dir, "p.txt")
	envFile := filepath.Join(dir, "e.der")
	for path, data := range map[string][]byte{
		certFile:  []byte(cand.CertPEM),
		plainFile: plaintext,
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cmd := exec.Command(opensslPath, "cms", "-encrypt", "-aes-256-gcm",
		"-in", plainFile, "-outform", "DER", "-out", envFile, certFile)
	if out, runErr := cmd.CombinedOutput(); runErr != nil {
		t.Fatalf("openssl cms -encrypt -aes-256-gcm failed:\n%s", out)
	}
	envDER, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read openssl env: %v", err)
	}

	der, err := DecodeEnvelopedDER(envDER) // bare DER passthrough
	if err != nil {
		t.Fatalf("DecodeEnvelopedDER: %v", err)
	}
	got, err := DecryptMulti(der, []DecryptKey{{Cert: cert, Key: rsaKey}})
	if err != nil {
		t.Fatalf("DecryptMulti of openssl GCM AuthEnvelopedData FAILED (reverse interop bug): %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("reverse GCM oracle mismatch.\ngot:  %q\nwant: %q", got, plaintext)
	}
}
