package smime

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestEncrypt_Canonical proves that smime.Encrypt emits interoperable CMS —
// i.e. that openssl can DECRYPT our output. This is the recipient-encryption
// analogue of the D4 SignMessage oracle: our prior coverage was only a self
// round-trip (our Encrypt → our Decrypt), the exact pattern that hid 5 ASN.1
// bugs in Sign(). A self-test can pass while being non-interoperable, so the
// real gate here is openssl, NOT smime.Decrypt.
//
// Since owner decision A5 the DEFAULT Encrypt output is AES-256-GCM CMS
// AuthEnvelopedData (RFC 5083, smime-type=authEnveloped-data); the S/MIME 3.2
// AES-256-CBC EnvelopedData fallback carries the same oracle coverage in
// TestEncrypt_CBC_Canonical below.
func TestEncrypt_Canonical(t *testing.T) {
	cand := genCandidate(t, "recipient@example.com", true)
	recipCert, err := ParseCert(cand.CertPEM)
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}

	plaintext := []byte("Secret body\r\nLine two.\r\n")

	enc, err := Encrypt(plaintext, []*x509.Certificate{recipCert})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(enc) == 0 {
		t.Fatal("Encrypt returned empty output")
	}

	t.Run("A_structural", func(t *testing.T) {
		testEncryptStructural(t, enc, "authEnveloped-data", oidAuthEnvelopedData)
	})

	t.Run("B_openssl_decrypt", func(t *testing.T) {
		if !opensslSupportsGCMCMS(t) {
			t.Skip("installed openssl cms cannot decrypt AES-GCM AuthEnvelopedData")
		}
		testOpensslDecrypt(t, enc, cand.CertPEM, cand.KeyPEM, plaintext)
	})

	t.Run("C_multi_recipient", func(t *testing.T) {
		if !opensslSupportsGCMCMS(t) {
			t.Skip("installed openssl cms cannot decrypt AES-GCM AuthEnvelopedData")
		}
		testMultiRecipientDecrypt(t, plaintext)
	})
}

// TestEncrypt_CBC_Canonical carries the original E1 oracle (openssl decrypts our
// EnvelopedData) over the S/MIME 3.2 AES-256-CBC fallback selected explicitly via
// EncryptWithAlgorithm — the CBC receive-compat mandate means external S/MIME 3.2
// peers stay interoperable with our fallback output too.
func TestEncrypt_CBC_Canonical(t *testing.T) {
	cand := genCandidate(t, "recipient@example.com", true)
	recipCert, err := ParseCert(cand.CertPEM)
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}

	plaintext := []byte("Secret CBC body\r\nLine two.\r\n")

	enc, err := EncryptWithAlgorithm(AlgorithmAES256CBC, plaintext, []*x509.Certificate{recipCert})
	if err != nil {
		t.Fatalf("EncryptWithAlgorithm(CBC): %v", err)
	}

	t.Run("A_structural", func(t *testing.T) {
		testEncryptStructural(t, enc, "enveloped-data", oidEnvelopedData)
	})

	t.Run("B_openssl_decrypt", func(t *testing.T) {
		testOpensslDecrypt(t, enc, cand.CertPEM, cand.KeyPEM, plaintext)
	})
}

// opensslSupportsGCMCMS reports whether the installed openssl `cms` app supports
// AES-GCM CMS AuthEnvelopedData (OpenSSL >= 3.0 does; LibreSSL and OpenSSL 1.x
// do not). Probed once by actually running `cms -encrypt -aes-256-gcm`, cached
// for the package's tests. The GCM oracle tests skip when it reports false —
// never a silent pass: the CBC oracle tests keep running regardless.
var opensslGCMStatus struct {
	mu        sync.Mutex
	probed    bool
	supported bool
}

func opensslSupportsGCMCMS(t *testing.T) bool {
	t.Helper()
	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available")
		return false
	}
	opensslGCMStatus.mu.Lock()
	defer opensslGCMStatus.mu.Unlock()
	if !opensslGCMStatus.probed {
		opensslGCMStatus.probed = true
		dir := t.TempDir()
		plain := filepath.Join(dir, "p.txt")
		out := filepath.Join(dir, "p.enc")
		if werr := os.WriteFile(plain, []byte("gcm probe\n"), 0o600); werr == nil {
			// Reuse the checked-in test CA cert so the probe needs no key material
			// beyond a recipient cert; only the encrypt side must succeed.
			cmd := exec.Command(opensslPath, "cms", "-encrypt", "-aes-256-gcm",
				"-in", plain, "-outform", "DER", "-out", out,
				filepath.Join("testdata", "openssl_ca.crt"))
			opensslGCMStatus.supported = cmd.Run() == nil
		}
	}
	return opensslGCMStatus.supported
}

// testEncryptStructural asserts the Encrypt output is a well-formed
// application/pkcs7-mime part with the expected smime-type whose base64 body
// decodes to valid DER (no trailing bytes) with the expected CMS content OID:
// authEnveloped-data/oidAuthEnvelopedData for the GCM default,
// enveloped-data/oidEnvelopedData for the CBC fallback. Always runs (no openssl
// required).
func testEncryptStructural(t *testing.T, enc []byte, wantSMIMEType string, wantOID asn1.ObjectIdentifier) {
	t.Helper()
	s := string(enc)

	if !strings.HasPrefix(s, "Content-Type: application/pkcs7-mime") {
		t.Fatalf("output must start with Content-Type: application/pkcs7-mime, got: %.120q", s)
	}
	if !strings.Contains(s, "smime-type="+wantSMIMEType) {
		t.Errorf("missing smime-type=%s in Content-Type", wantSMIMEType)
	}
	if !strings.Contains(s, "Content-Transfer-Encoding: base64") {
		t.Error("missing Content-Transfer-Encoding: base64")
	}

	// Decode the base64 body → DER.
	bodyStart := strings.Index(s, "\r\n\r\n")
	if bodyStart < 0 {
		t.Fatal("no blank line separating headers from body")
	}
	b64 := strings.ReplaceAll(s[bodyStart+4:], "\r\n", "")
	b64 = strings.TrimSpace(b64)
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode of body: %v", err)
	}
	if len(der) == 0 {
		t.Fatal("decoded DER is empty")
	}

	// DER must parse as a single ASN.1 value with no trailing bytes.
	var ci cmsContentInfo
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil {
		t.Fatalf("DER body is not valid ASN.1 ContentInfo: %v", err)
	}
	if len(rest) != 0 {
		t.Errorf("unexpected trailing bytes after DER ContentInfo: %d", len(rest))
	}

	// The outer ContentInfo OID must match the expected CMS content type.
	if !ci.ContentType.Equal(wantOID) {
		t.Errorf("ContentInfo OID = %v, want %v", ci.ContentType, wantOID)
	}
}

// testOpensslDecrypt uses openssl as the interop oracle: it writes the recipient
// cert+key and our encrypted message to temp files and runs `openssl cms/smime
// -decrypt`, asserting exit 0 AND that the recovered plaintext matches. Skips if
// openssl is absent. This is the real go-live gate — NOT smime.Decrypt.
func testOpensslDecrypt(t *testing.T, enc, certPEM, keyPEM, expected []byte) {
	t.Helper()

	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available")
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "recip.pem")
	keyFile := filepath.Join(dir, "recipkey.pem")
	encFile := filepath.Join(dir, "enc.eml")
	outFile := filepath.Join(dir, "recovered.txt")

	// openssl cms/smime -decrypt expects a full MIME message in SMIME inform.
	// Our Encrypt output already carries the Content-Type + CTE headers, so we
	// just need a MIME-Version line above it.
	fullMsg := "MIME-Version: 1.0\r\n" + string(enc)

	mustWrite(t, certFile, certPEM)
	mustWrite(t, keyFile, keyPEM)
	mustWrite(t, encFile, []byte(fullMsg))

	recovered, used, out, runErr := runOpensslDecrypt(t, opensslPath, encFile, certFile, keyFile, outFile)
	if runErr != nil {
		t.Fatalf("openssl decrypt FAILED (CMS interop error):\n%s", out)
	}
	t.Logf("openssl decrypt succeeded via `%s`:\n%s", used, out)

	if string(recovered) != string(expected) {
		t.Errorf("recovered plaintext mismatch.\ngot:  %q\nwant: %q", recovered, expected)
	}
}

// testMultiRecipientDecrypt encrypts to TWO recipient certs and proves the
// SECOND recipient's key also decrypts via openssl. RecipientInfos is a SET OF
// KeyTransRecipientInfo, so this exercises that both entries are well-formed.
func testMultiRecipientDecrypt(t *testing.T, plaintext []byte) {
	t.Helper()

	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available")
	}

	candA := genCandidate(t, "alice@example.com", true)
	candB := genCandidate(t, "bob@example.com", false)
	certA, err := ParseCert(candA.CertPEM)
	if err != nil {
		t.Fatalf("ParseCert A: %v", err)
	}
	certB, err := ParseCert(candB.CertPEM)
	if err != nil {
		t.Fatalf("ParseCert B: %v", err)
	}

	enc, err := Encrypt(plaintext, []*x509.Certificate{certA, certB})
	if err != nil {
		t.Fatalf("Encrypt (multi): %v", err)
	}

	dir := t.TempDir()
	certFileB := filepath.Join(dir, "bob.pem")
	keyFileB := filepath.Join(dir, "bobkey.pem")
	encFile := filepath.Join(dir, "enc.eml")
	outFile := filepath.Join(dir, "recovered.txt")

	fullMsg := "MIME-Version: 1.0\r\n" + string(enc)
	mustWrite(t, certFileB, candB.CertPEM)
	mustWrite(t, keyFileB, candB.KeyPEM)
	mustWrite(t, encFile, []byte(fullMsg))

	// Decrypt with recipient #2's (Bob's) key.
	recovered, used, out, runErr := runOpensslDecrypt(t, opensslPath, encFile, certFileB, keyFileB, outFile)
	if runErr != nil {
		t.Fatalf("openssl decrypt with recipient #2 FAILED (RecipientInfos SET malformed?):\n%s", out)
	}
	t.Logf("openssl decrypt (recipient #2) succeeded via `%s`", used)
	if string(recovered) != string(plaintext) {
		t.Errorf("recipient #2 recovered mismatch.\ngot:  %q\nwant: %q", recovered, plaintext)
	}
}

// runOpensslDecrypt runs `openssl cms -decrypt` and falls back to
// `openssl smime -decrypt` if cms rejects the structure. Returns the recovered
// content, which command succeeded, the combined output, and the run error.
func runOpensslDecrypt(t *testing.T, opensslPath, encFile, certFile, keyFile, outFile string) (recovered []byte, used string, combinedOut []byte, err error) {
	t.Helper()

	// Prefer `cms` (the modern RFC 5652 codepath). Some openssl builds gate
	// `smime -decrypt` differently, so cms is the more faithful CMS oracle.
	cmd := exec.Command(opensslPath,
		"cms", "-decrypt",
		"-in", encFile,
		"-inform", "SMIME",
		"-recip", certFile,
		"-inkey", keyFile,
		"-out", outFile,
	)
	out, runErr := cmd.CombinedOutput()
	if runErr == nil {
		rec, rerr := os.ReadFile(outFile)
		if rerr != nil {
			return nil, "cms", out, fmt.Errorf("read recovered: %w", rerr)
		}
		return rec, "openssl cms -decrypt", out, nil
	}

	// Fallback: smime -decrypt.
	cmd2 := exec.Command(opensslPath,
		"smime", "-decrypt",
		"-in", encFile,
		"-inform", "SMIME",
		"-recip", certFile,
		"-inkey", keyFile,
		"-out", outFile,
	)
	out2, runErr2 := cmd2.CombinedOutput()
	if runErr2 == nil {
		rec, rerr := os.ReadFile(outFile)
		if rerr != nil {
			return nil, "smime", out2, fmt.Errorf("read recovered: %w", rerr)
		}
		return rec, "openssl smime -decrypt", out2, nil
	}

	combined := []byte(fmt.Sprintf("cms stderr:\n%s\nsmime stderr:\n%s", out, out2))
	return nil, "", combined, fmt.Errorf("both cms and smime decrypt failed")
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestReverseOracle_OpensslEncryptThenOurDecrypt is the inverse of
// TestEncrypt_Canonical: E1 proved openssl can DECRYPT our Encrypt output; this
// proves the inverse — an EnvelopedData produced by an EXTERNAL sender's openssl
// opens via OUR DecryptMulti. Decrypt-on-read depends on this (external encrypted
// mail must decrypt with the reader's key). Skips if openssl is absent.
//
// `openssl cms -encrypt -outform DER` emits a bare EnvelopedData ContentInfo (no
// MIME headers), so we feed the DER straight to DecodeEnvelopedDER (bare-DER
// passthrough) → DecryptMulti.
func TestReverseOracle_OpensslEncryptThenOurDecrypt(t *testing.T) {
	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available")
	}

	cand := genCandidate(t, "reader@example.com", true)
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

	plaintext := []byte("External sender body.\r\nThe reverse oracle proves our DecryptMulti opens it.\r\n")

	dir := t.TempDir()
	certFile := filepath.Join(dir, "reader.pem")
	plainFile := filepath.Join(dir, "plain.txt")
	envFile := filepath.Join(dir, "env.der")
	mustWrite(t, certFile, cand.CertPEM)
	mustWrite(t, plainFile, plaintext)

	envDER, used := runOpensslEncrypt(t, opensslPath, plainFile, envFile, certFile)
	t.Logf("openssl encrypt succeeded via `%s`", used)

	der, err := DecodeEnvelopedDER(envDER)
	if err != nil {
		t.Fatalf("DecodeEnvelopedDER of openssl output: %v", err)
	}
	got, err := DecryptMulti(der, []DecryptKey{{Cert: cert, Key: rsaKey}})
	if err != nil {
		t.Fatalf("DecryptMulti of openssl-encrypted EnvelopedData FAILED (reverse interop bug): %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("reverse-oracle recovered mismatch.\ngot:  %q\nwant: %q", got, plaintext)
	}
}

// runOpensslEncrypt runs `openssl cms -encrypt -outform DER` (RFC 5652 codepath)
// and falls back to `openssl smime -encrypt` if cms is unavailable. Returns the
// EnvelopedData artifact bytes and which command succeeded.
func runOpensslEncrypt(t *testing.T, opensslPath, inFile, outFile, certFile string) (artifact []byte, used string) {
	t.Helper()

	cmd := exec.Command(opensslPath,
		"cms", "-encrypt",
		"-aes-256-cbc",
		"-in", inFile,
		"-outform", "DER",
		"-out", outFile,
		certFile,
	)
	out, runErr := cmd.CombinedOutput()
	if runErr == nil {
		data, rerr := os.ReadFile(outFile)
		if rerr != nil {
			t.Fatalf("read openssl cms env: %v", rerr)
		}
		return data, "openssl cms -encrypt -outform DER"
	}

	// Fallback: smime -encrypt (PEM/MIME); DecodeEnvelopedDER handles the wrapper.
	cmd2 := exec.Command(opensslPath,
		"smime", "-encrypt",
		"-aes-256-cbc",
		"-in", inFile,
		"-out", outFile,
		certFile,
	)
	out2, runErr2 := cmd2.CombinedOutput()
	if runErr2 == nil {
		data, rerr := os.ReadFile(outFile)
		if rerr != nil {
			t.Fatalf("read openssl smime env: %v", rerr)
		}
		return data, "openssl smime -encrypt"
	}

	t.Fatalf("both `openssl cms -encrypt` and `openssl smime -encrypt` failed:\ncms:\n%s\nsmime:\n%s", out, out2)
	return nil, ""
}

// TestEncrypt_CanonicalOracleBites proves the openssl decrypt oracle is not
// vacuous: it corrupts a byte of the encrypted content and asserts openssl
// FAILS (or recovers something other than the plaintext). Skips if openssl
// absent. This mirrors the D4 oracle-bites sanity check.
func TestEncrypt_CanonicalOracleBites(t *testing.T) {
	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available")
	}

	cand := genCandidate(t, "recipient@example.com", true)
	recipCert, err := ParseCert(cand.CertPEM)
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}

	plaintext := []byte("Oracle bites body. The quick brown fox jumps.\r\n")
	enc, err := Encrypt(plaintext, []*x509.Certificate{recipCert})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Decode the base64 body to raw DER, corrupt a byte deep in the structure
	// (the encrypted content / session key region), re-encode.
	s := string(enc)
	bodyStart := strings.Index(s, "\r\n\r\n")
	if bodyStart < 0 {
		t.Fatal("no header/body separator")
	}
	header := s[:bodyStart+4]
	b64 := strings.ReplaceAll(s[bodyStart+4:], "\r\n", "")
	b64 = strings.TrimSpace(b64)
	der, derr := base64.StdEncoding.DecodeString(b64)
	if derr != nil {
		t.Fatalf("base64 decode: %v", derr)
	}
	if len(der) < 40 {
		t.Fatalf("DER too short to corrupt: %d", len(der))
	}
	// Flip a byte near the tail (inside the EncryptedContent OCTET STRING).
	corrupted := make([]byte, len(der))
	copy(corrupted, der)
	corrupted[len(corrupted)-5] ^= 0xFF

	corruptedMsg := header + base64Encode(corrupted)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "recip.pem")
	keyFile := filepath.Join(dir, "recipkey.pem")
	encFile := filepath.Join(dir, "enc.eml")
	outFile := filepath.Join(dir, "recovered.txt")

	mustWrite(t, certFile, cand.CertPEM)
	mustWrite(t, keyFile, cand.KeyPEM)
	mustWrite(t, encFile, []byte("MIME-Version: 1.0\r\n"+corruptedMsg))

	recovered, _, out, runErr := runOpensslDecrypt(t, opensslPath, encFile, certFile, keyFile, outFile)
	if runErr == nil && string(recovered) == string(plaintext) {
		t.Fatalf("ORACLE IS VACUOUS: openssl recovered the exact plaintext from a "+
			"byte-corrupted message.\nout: %s", out)
	}
	if runErr != nil {
		fmt.Printf("\n=== ENCRYPT ORACLE BITES PROOF ===\nopenssl correctly REJECTED a byte-corrupted enveloped message.\nstderr: %s\n==================================\n", out)
		t.Logf("oracle bites: openssl correctly FAILED on corrupted ciphertext:\n%s", out)
		return
	}
	// runErr == nil but recovered != plaintext: openssl decrypted but got garbage
	// (CBC bit-flip), which still proves the oracle distinguishes the true content.
	fmt.Printf("\n=== ENCRYPT ORACLE BITES PROOF ===\nopenssl decrypted corrupted ciphertext to NON-matching plaintext (CBC corruption detected).\n==================================\n")
	t.Logf("oracle bites: openssl recovered non-matching content from corrupted ciphertext")
}

// TestEncrypt_SubmissionCertSet_OpensslOracle proves the SP1 submission-shaped
// cert set {recipient, sender, journal} produces an EnvelopedData decryptable by
// EACH party's key — the encrypt-to-self + encrypt-to-journal invariant. openssl
// is the interop oracle (skips if absent), exactly like the E1 pattern.
func TestEncrypt_SubmissionCertSet_OpensslOracle(t *testing.T) {
	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available")
	}

	recip := genCandidate(t, "rcpt@x.test", false)
	sender := genCandidate(t, "u@x.test", true)
	journal := genCandidate(t, "journal@x.test", false)

	parse := func(c SignCandidate) *x509.Certificate {
		cert, perr := ParseCert(c.CertPEM)
		if perr != nil {
			t.Fatalf("ParseCert: %v", perr)
		}
		return cert
	}
	certs := []*x509.Certificate{parse(recip), parse(sender), parse(journal)}

	plaintext := []byte("Subject: secret\r\n\r\nencrypt-to-{recipient,sender,journal}\r\n")
	enc, err := Encrypt(plaintext, certs)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// EACH key must decrypt to the exact plaintext.
	for _, party := range []struct {
		name string
		cand SignCandidate
	}{
		{"recipient", recip},
		{"sender", sender},
		{"journal", journal},
	} {
		dir := t.TempDir()
		certFile := filepath.Join(dir, "c.pem")
		keyFile := filepath.Join(dir, "k.pem")
		encFile := filepath.Join(dir, "enc.eml")
		outFile := filepath.Join(dir, "out.txt")
		mustWrite(t, certFile, party.cand.CertPEM)
		mustWrite(t, keyFile, party.cand.KeyPEM)
		mustWrite(t, encFile, []byte("MIME-Version: 1.0\r\n"+string(enc)))

		recovered, used, out, runErr := runOpensslDecrypt(t, opensslPath, encFile, certFile, keyFile, outFile)
		if runErr != nil {
			t.Fatalf("%s key failed to decrypt the submission cert-set envelope:\n%s", party.name, out)
		}
		if string(recovered) != string(plaintext) {
			t.Errorf("%s recovered mismatch via %s.\ngot:  %q\nwant: %q", party.name, used, recovered, plaintext)
		}
	}
}

// TestSignThenEncrypt_OpensslDecryptsThenVerifies proves sign-inner/encrypt-outer
// nesting: openssl decrypts the outer envelope to recover the INNER signed message,
// which is a multipart/signed S/MIME part (so a client can then verify it). Skips
// if openssl absent.
func TestSignThenEncrypt_OpensslDecryptsThenVerifies(t *testing.T) {
	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available")
	}

	signer := genCandidate(t, "u@x.test", true)
	recip := genCandidate(t, "rcpt@x.test", false)

	// Inner SIGN: mirror the submission path's ResolveAndSign (body split + sign).
	rawMessage := []byte("Subject: hi\r\n\r\nthe signed-then-encrypted body\r\n")
	signed, reason := ResolveAndSign([]SignCandidate{signer}, "u@x.test", rawMessage)
	if reason != "" {
		t.Fatalf("ResolveAndSign: %s", reason)
	}
	if !IsSignedMessage(signed) {
		t.Fatal("inner blob is not a signed S/MIME message")
	}

	// Outer ENCRYPT to the recipient.
	recipCert, err := ParseCert(recip.CertPEM)
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}
	enc, err := Encrypt(signed, []*x509.Certificate{recipCert})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// openssl decrypt → the recovered content must be the inner SIGNED message.
	dir := t.TempDir()
	certFile := filepath.Join(dir, "c.pem")
	keyFile := filepath.Join(dir, "k.pem")
	encFile := filepath.Join(dir, "enc.eml")
	outFile := filepath.Join(dir, "out.txt")
	mustWrite(t, certFile, recip.CertPEM)
	mustWrite(t, keyFile, recip.KeyPEM)
	mustWrite(t, encFile, []byte("MIME-Version: 1.0\r\n"+string(enc)))

	recovered, used, out, runErr := runOpensslDecrypt(t, opensslPath, encFile, certFile, keyFile, outFile)
	if runErr != nil {
		t.Fatalf("openssl decrypt of sign-then-encrypt failed:\n%s", out)
	}
	if !IsSignedMessage(recovered) {
		t.Fatalf("decrypted inner content is NOT a signed message (sign-inner/encrypt-outer broken), via %s:\n%.200q", used, recovered)
	}
	t.Logf("sign-inner/encrypt-outer: openssl decrypted to a signed inner part via %s", used)
}
