package auth

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash")
	}
	// Verify the hash is a valid bcrypt hash
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("correct-horse-battery-staple")); err != nil {
		t.Errorf("bcrypt compare failed: %v", err)
	}
	// Verify wrong password fails
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("wrong-password")); err == nil {
		t.Error("expected wrong password to fail bcrypt compare")
	}
}

func TestUserStructHasMustChangePassword(t *testing.T) {
	u := User{ID: 1, MustChangePassword: true}
	if !u.MustChangePassword {
		t.Error("expected MustChangePassword to be true")
	}
}

var benchHashPasswordResult string

func BenchmarkHashPassword(b *testing.B) {
	for b.Loop() {
		benchHashPasswordResult, _ = HashPassword("benchmark-password-128")
	}
}
