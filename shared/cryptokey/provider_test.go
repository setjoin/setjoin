package cryptokey

import (
	"bytes"
	"testing"
)

// --- CryptoProfile parsing ---

func TestParseCryptoProfile(t *testing.T) {
	tests := []struct {
		input    string
		expected CryptoProfile
	}{
		{"standard", ProfileStandard},
		{"smx", ProfileSMx},
		{"hybrid", ProfileHybrid},
		{"", ProfileStandard},
		{"unknown", ProfileStandard},
		{"SMX", ProfileStandard}, // case-sensitive
		{"STANDARD", ProfileStandard},
		{"Hybrid", ProfileStandard},
	}
	for _, tt := range tests {
		got := ParseCryptoProfile(tt.input)
		if got != tt.expected {
			t.Errorf("ParseCryptoProfile(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// --- DeriveEncryptionKey ---

func TestDeriveEncryptionKey_StandardProfile_32Bytes(t *testing.T) {
	secret := []byte("test-secret-32-chars-minimum!!")
	key := DeriveEncryptionKey(secret, "test-info", ProfileStandard)
	if len(key) != 32 {
		t.Errorf("standard profile: got %d bytes, want 32", len(key))
	}
}

func TestDeriveEncryptionKey_SMxProfile_16Bytes(t *testing.T) {
	secret := []byte("test-secret-16-char")
	key := DeriveEncryptionKey(secret, "test-info", ProfileSMx)
	if len(key) != 16 {
		t.Errorf("smx profile: got %d bytes, want 16", len(key))
	}
}

func TestDeriveEncryptionKey_HybridProfile_32Bytes(t *testing.T) {
	secret := []byte("test-secret-32-chars-minimum!!")
	key := DeriveEncryptionKey(secret, "test-info", ProfileHybrid)
	if len(key) != 32 {
		t.Errorf("hybrid profile: got %d bytes, want 32", len(key))
	}
}

func TestDeriveEncryptionKey_SameSecretDifferentInfo(t *testing.T) {
	secret := []byte("test-secret-32-chars-minimum!!")
	k1 := DeriveEncryptionKey(secret, "purpose-a", ProfileStandard)
	k2 := DeriveEncryptionKey(secret, "purpose-b", ProfileStandard)
	if bytes.Equal(k1, k2) {
		t.Error("different info strings should produce different keys")
	}
}

func TestDeriveEncryptionKey_Deterministic(t *testing.T) {
	secret := []byte("test-secret-32-chars-minimum!!")
	k1 := DeriveEncryptionKey(secret, "info", ProfileStandard)
	k2 := DeriveEncryptionKey(secret, "info", ProfileStandard)
	if !bytes.Equal(k1, k2) {
		t.Error("DeriveEncryptionKey must be deterministic for same inputs")
	}
}

func TestDeriveEncryptionKey_NotEmpty(t *testing.T) {
	secret := []byte("test-secret-32-chars-minimum!!")
	key := DeriveEncryptionKey(secret, "info", ProfileStandard)
	zero := make([]byte, len(key))
	if bytes.Equal(key, zero) {
		t.Error("key must not be all zeros")
	}
}
