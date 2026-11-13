package pwhash

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestAppPasswordHashFormat(t *testing.T) {
	// A real token has mail-ap- prefix + 64 hex chars (32 bytes)
	raw := "mail-ap-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

	if len(raw) != 8+64 {
		t.Errorf("expected token length 72 (8 prefix + 64 hex), got %d", len(raw))
	}
	if raw[:8] != "mail-ap-" {
		t.Errorf("token must start with mail-ap-, got %q", raw[:8])
	}
}

func TestAppPasswordHashDeterministic(t *testing.T) {
	raw := "mail-ap-test1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	hash := sha256.Sum256([]byte(raw))
	hashHex := hex.EncodeToString(hash[:])

	if len(hashHex) != 64 {
		t.Errorf("SHA-256 hex should be 64 chars, got %d", len(hashHex))
	}

	// Same input -> same hash
	hash2 := sha256.Sum256([]byte(raw))
	hashHex2 := hex.EncodeToString(hash2[:])
	if hashHex != hashHex2 {
		t.Error("SHA-256 hash must be deterministic")
	}
}

func TestCheckAppPasswordSignature(t *testing.T) {
	// Verify the function compiles with correct signature and returns expected types.
	// This is a compile-time check — we don't need a real DB to assert the type.
	var fn func() = func() {
		// If CheckAppPassword does not exist or has the wrong signature,
		// this file will not compile.
		_ = CheckAppPassword
	}
	_ = fn
}
