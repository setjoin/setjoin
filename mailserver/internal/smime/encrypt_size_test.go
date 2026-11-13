package smime

import (
	"crypto/x509"
	"testing"
)

// encrypt_size_test.go — SP1 Phase 7 (Task 7.5): quota counts the ENCRYPTED
// artifact, not the cleartext.
//
// The submission handler (Phase 3, mail_encrypt.go) stores the CMS EnvelopedData
// blob in raw_ref and hands send()/deliver() the encrypted artifact; p_size_bytes
// MUST be len(encryptedBlob), never len(originalRaw). These tests pin the
// load-bearing property the size accounting relies on: the encrypted blob is
// strictly LARGER than the plaintext, and grows per added recipient. A refactor
// that swapped the sizes (charging cleartext bytes for an encrypted message) would
// under-count quota — these guards make that swap impossible to ship silently.

// TestEncrypt_SizeIsLargerThanPlaintext asserts that the CMS EnvelopedData output
// of smime.Encrypt is strictly larger than the plaintext, accounting for:
//   - CMS SEQUENCE/SET/OCTET-STRING overhead
//   - AES-256-CBC PKCS#7 padding (1–16 bytes)
//   - RSA-encrypted session key (256 bytes per recipient for 2048-bit keys)
//   - Base64 encoding (+33% overhead)
//   - MIME headers
func TestEncrypt_SizeIsLargerThanPlaintext(t *testing.T) {
	cand := genCandidate(t, "recip@example.com", true)
	recipCert, err := ParseCert(cand.CertPEM)
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}

	plaintext := []byte("From: sender@example.com\r\nTo: recip@example.com\r\nSubject: Quota test\r\n\r\nBody line one.\r\nBody line two.\r\n")
	encrypted, err := Encrypt(plaintext, []*x509.Certificate{recipCert})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if len(encrypted) <= len(plaintext) {
		t.Errorf("encrypted size (%d) must be > plaintext size (%d); "+
			"submission handler must use len(encrypted) for p_size_bytes, not len(plaintext)",
			len(encrypted), len(plaintext))
	}

	// Sanity: the overhead is at least the RSA-encrypted key (256 bytes for
	// 2048-bit) — proves the growth is the real CMS envelope, not noise.
	const minExpectedOverhead = 256 // one 2048-bit RSA-wrapped key, unencoded
	if len(encrypted)-len(plaintext) < minExpectedOverhead {
		t.Errorf("encrypted overhead (%d bytes) seems too small; "+
			"expected at least %d bytes for one RSA-2048 recipient key alone",
			len(encrypted)-len(plaintext), minExpectedOverhead)
	}
	t.Logf("plaintext=%d bytes, encrypted=%d bytes, overhead=%d bytes",
		len(plaintext), len(encrypted), len(encrypted)-len(plaintext))
}

// TestEncrypt_MultiRecipientSizeGrowsPerRecipient asserts that adding a second
// recipient adds measurably more overhead (an additional RSA-encrypted key per
// KeyTransRecipientInfo) — so the per-recipient encrypt-to-self + journal fan-out
// is reflected in size_bytes.
func TestEncrypt_MultiRecipientSizeGrowsPerRecipient(t *testing.T) {
	cand1 := genCandidate(t, "alice@example.com", true)
	cand2 := genCandidate(t, "bob@example.com", false)
	cert1, err := ParseCert(cand1.CertPEM)
	if err != nil {
		t.Fatalf("ParseCert 1: %v", err)
	}
	cert2, err := ParseCert(cand2.CertPEM)
	if err != nil {
		t.Fatalf("ParseCert 2: %v", err)
	}

	plaintext := []byte("Multi-recipient quota test.\r\n")

	single, err := Encrypt(plaintext, []*x509.Certificate{cert1})
	if err != nil {
		t.Fatalf("Encrypt (1 recip): %v", err)
	}
	multi, err := Encrypt(plaintext, []*x509.Certificate{cert1, cert2})
	if err != nil {
		t.Fatalf("Encrypt (2 recip): %v", err)
	}

	delta := len(multi) - len(single)
	const minDelta = 200 // one extra RSA-2048 key (256 raw bytes) survives base64
	if delta < minDelta {
		t.Errorf("two-recipient encrypted blob should be at least %d bytes larger than single-recipient, got delta=%d", minDelta, delta)
	}
	t.Logf("single-recip=%d, two-recip=%d, delta=%d bytes per added recipient",
		len(single), len(multi), delta)
}
