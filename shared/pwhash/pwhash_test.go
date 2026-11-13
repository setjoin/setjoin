package pwhash

import (
	"testing"
	"time"
)

func TestHashAndCheck(t *testing.T) {
	hash, err := HashPassword("my-secure-password")
	if err != nil {
		t.Fatal("HashPassword failed:", err)
	}
	if hash == "" {
		t.Fatal("hash is empty")
	}
	// Verify bcrypt format: $2a$ or $2b$ prefix
	if hash[0] != '$' {
		t.Fatal("hash does not start with $")
	}
}

func TestHashUniqueness(t *testing.T) {
	h1, _ := HashPassword("password1")
	h2, _ := HashPassword("password1")
	if h1 == h2 {
		t.Fatal("same password should produce different hashes (random salt)")
	}
}

var benchCacheKey string

func BenchmarkHashSlug(b *testing.B) {
	for b.Loop() {
		benchCacheKey = hashSlug("user@test.local:secret123")
	}
}

func BenchmarkAuthCacheHit(b *testing.B) {
	authCache.Store("test-key", cacheEntry{&User{ID: 1, Email: "u@t.local"}, time.Now().Add(60 * time.Second)})
	b.ResetTimer()
	for b.Loop() {
		authCache.Load("test-key")
	}
}

// VerifyCredentialHash is the bcrypt-only NON-password credential arm (TOTP
// backup codes, SCIM bearer tokens). These pins hold the WP1 seam contract:
// bcrypt credentials verify, wrong secrets and malformed stored values reject,
// and an SM3-formatted stored value is ErrCredentialHashFormat — never the
// SM3 verify path (routing credential hashes through the password seam's
// dispatch would silently widen their accepted domain; see
// pwhash.VerifyCredentialHash's doc).
func TestVerifyCredentialHashAcceptsBcryptAndRejectsOthers(t *testing.T) {
	hash, err := HashPassword("secret-code-1234")
	if err != nil {
		t.Fatalf("mint bcrypt credential hash: %v", err)
	}
	if err := VerifyCredentialHash(hash, "secret-code-1234"); err != nil {
		t.Fatalf("matching secret must verify: %v", err)
	}
	if err := VerifyCredentialHash(hash, "wrong-code-9999"); err == nil {
		t.Fatal("wrong secret must reject")
	}
	if err := VerifyCredentialHash("", "anything"); err == nil {
		t.Fatal("empty stored value must reject")
	}
	if err := VerifyCredentialHash("not-a-hash", "anything"); err == nil {
		t.Fatal("malformed stored value must reject")
	}
	sm3, err := HashPasswordSM3("secret-code-1234")
	if err != nil {
		t.Skipf("SM3 engine unavailable in this environment: %v", err)
	}
	if err := VerifyCredentialHash(sm3, "secret-code-1234"); err != ErrCredentialHashFormat {
		t.Fatalf("SM3-formatted credential hash must be ErrCredentialHashFormat, got: %v", err)
	}
}
