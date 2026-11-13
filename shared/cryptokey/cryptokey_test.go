package cryptokey

import (
	"bytes"
	"testing"
)

func TestDeriveCookieKey_Deterministic(t *testing.T) {
	secret := []byte("test-secret-32chars-minimum!!!")
	k1 := DeriveCookieKey(secret)
	k2 := DeriveCookieKey(secret)
	if !bytes.Equal(k1, k2) {
		t.Fatal("same secret must produce same key")
	}
}

func TestDeriveCookieKey_DifferentSecrets(t *testing.T) {
	k1 := DeriveCookieKey([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"))
	k2 := DeriveCookieKey([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2"))
	if bytes.Equal(k1, k2) {
		t.Fatal("different secrets must produce different keys")
	}
}

func TestDeriveCookieKey_Length(t *testing.T) {
	key := DeriveCookieKey([]byte("test-secret-32chars-minimum!!!"))
	if len(key) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(key))
	}
}

func TestDeriveMailAttachmentTokenKey_DeterministicAndDomainSeparated(t *testing.T) {
	secret := []byte("test-secret-32chars-minimum!!!")
	got := DeriveMailAttachmentTokenKey(secret)
	if len(got) != 32 {
		t.Fatalf("key length = %d, want 32", len(got))
	}
	if !bytes.Equal(got, DeriveMailAttachmentTokenKey(secret)) {
		t.Fatal("same secret must derive the same attachment-token key")
	}
	if bytes.Equal(got, secret) || bytes.Equal(got, DeriveCookieKey(secret)) || bytes.Equal(got, DeriveOIDCCryptoKey(secret)) {
		t.Fatal("attachment-token key must be domain-separated from raw and existing derived keys")
	}
}

func TestDeriveCookieKey_NotEmpty(t *testing.T) {
	key := DeriveCookieKey([]byte("test-secret-32chars-minimum!!!"))
	zero := make([]byte, 32)
	if bytes.Equal(key, zero) {
		t.Fatal("key must not be all zeros")
	}
}

// TestDerive_DomainSeparation pins HKDF domain separation across the three
// purpose-specific derivations from ONE shared secret: cookie, OIDC, and DB
// column keys must be pairwise distinct. They differ only by their HKDF `info`
// string; a regression that copy-pastes one info string into another (an easy,
// real mistake) would cross-wire e.g. the cookie key and the DB-column key —
// a catastrophic key-reuse failure. Existing tests only check determinism and a
// different-*secret* case; none compares ACROSS purposes for a shared secret.
func TestDerive_DomainSeparation(t *testing.T) {
	secret := []byte("shared-master-secret-32-bytes!!!")

	cookie := DeriveCookieKey(secret)
	oidc := DeriveOIDCCryptoKey(secret)
	db := DeriveDBEncryptionKey(secret, ProfileStandard)

	pairs := []struct {
		name string
		a, b []byte
	}{
		{"cookie vs oidc", cookie, oidc},
		{"cookie vs db", cookie, db},
		{"oidc vs db", oidc, db},
	}
	for _, p := range pairs {
		if bytes.Equal(p.a, p.b) {
			t.Fatalf("SECURITY: HKDF domain separation broken — %s derived IDENTICAL keys from the shared secret", p.name)
		}
	}
}
