package pwhash

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestAuthCacheKey_InvalidatesOnHashChange pins the fix for the stale-credential
// bug: the cache key folds in the STORED HASH, so a password change (new hash)
// yields a different key — a cache miss — and the old credential stops working at
// once. Keying on the password alone (the prior bug) left it valid for the TTL.
func TestAuthCacheKey_InvalidatesOnHashChange(t *testing.T) {
	const email, pw = "user@example.com", "correct horse"
	hash1, _ := HashPassword(pw)
	hash2, _ := HashPassword(pw) // bcrypt salts → a different hash for the same pw

	k1 := authCacheKey(email, hash1, pw)
	k2 := authCacheKey(email, hash2, pw)

	if k1 == k2 {
		t.Fatal("cache key must change when the stored hash changes (password rotation must invalidate the cache)")
	}
	// Same triple → stable key (otherwise the cache never hits).
	if authCacheKey(email, hash1, pw) != k1 {
		t.Fatal("cache key must be stable for an identical (email, hash, password)")
	}
	// Different password → different key (a wrong password must not hit a cached success).
	if authCacheKey(email, hash1, "wrong") == k1 {
		t.Fatal("cache key must change with the password")
	}
	// The raw password must not appear in the key (it is slugged).
	if got := authCacheKey(email, hash1, pw); contains(got, pw) {
		t.Fatalf("cache key must not embed the raw password, got %q", got)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		(haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// TestNeedsRehash covers the downgrade floor for both hash families.
func TestNeedsRehash(t *testing.T) {
	weak, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost) // cost 4 < floor
	strong, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.DefaultCost)
	currentSM3, _ := HashPasswordSM3("pw") // 100k iterations (current floor)

	cases := []struct {
		name string
		hash string
		want bool
	}{
		{"bcrypt below floor", string(weak), true},
		{"bcrypt at floor", string(strong), false},
		{"sm3 at floor", currentSM3, false},
		{"sm3 below floor", "$sm3$1000$AAAA$AAAA", true},
		{"unparseable", "not-a-hash", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		if got := NeedsRehash(c.hash); got != c.want {
			t.Errorf("%s: NeedsRehash = %v, want %v", c.name, got, c.want)
		}
	}
}
