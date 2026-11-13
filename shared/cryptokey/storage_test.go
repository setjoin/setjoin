package cryptokey

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestEncryptDecryptBlob(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := make([]byte, 1024*1024) // 1MB
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	blobID := hex.EncodeToString(sha256Hash(plaintext))
	encrypted, err := EncryptBlob(plaintext, key, blobID, ProfileStandard)
	if err != nil {
		t.Fatalf("EncryptBlob: %v", err)
	}

	// Encrypted data should be larger (envelope overhead) and different
	if len(encrypted) <= len(plaintext) {
		t.Errorf("encrypted len %d <= plaintext len %d", len(encrypted), len(plaintext))
	}

	decrypted, err := DecryptBlob(encrypted, key, blobID)
	if err != nil {
		t.Fatalf("DecryptBlob: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("blob round-trip mismatch")
	}
}

func TestEncryptBlob_Deterministic_DedupSafe(t *testing.T) {
	// CRITICAL: Same plaintext must produce identical ciphertext for S3 dedup.
	// The blobID (SHA-256 of plaintext) is used as the S3 key.
	// ref_count upsert relies on identical content producing identical stored bytes.
	key := make([]byte, 32)
	plaintext := []byte("test email attachment — must dedup correctly")

	blobID := hex.EncodeToString(sha256Hash(plaintext))

	encrypted1, err := EncryptBlob(plaintext, key, blobID, ProfileStandard)
	if err != nil {
		t.Fatalf("EncryptBlob #1: %v", err)
	}
	encrypted2, err := EncryptBlob(plaintext, key, blobID, ProfileStandard)
	if err != nil {
		t.Fatalf("EncryptBlob #2: %v", err)
	}

	// Identical plaintext + same blobID → identical ciphertext
	if string(encrypted1) != string(encrypted2) {
		t.Error("DEDUP BROKEN: same plaintext produced different ciphertext — ref_count upsert would store wrong bytes")
	}
}

func TestEncryptBlob_DifferentContent_DifferentCiphertext(t *testing.T) {
	key := make([]byte, 32)
	a := []byte("attachment A")
	b := []byte("attachment B")

	blobIDA := hex.EncodeToString(sha256Hash(a))
	blobIDB := hex.EncodeToString(sha256Hash(b))

	encA, _ := EncryptBlob(a, key, blobIDA, ProfileStandard)
	encB, _ := EncryptBlob(b, key, blobIDB, ProfileStandard)

	// Different plaintext should produce different ciphertext
	if string(encA) == string(encB) {
		t.Error("different plaintexts produced identical ciphertext — confidentiality leak")
	}
}

func TestEncryptBlob_SM4(t *testing.T) {
	key := make([]byte, 16)
	plaintext := []byte("国密加密存储测试")
	blobID := hex.EncodeToString(sha256Hash(plaintext))

	encrypted, err := EncryptBlob(plaintext, key, blobID, ProfileSMx)
	if err != nil {
		t.Fatalf("EncryptBlob SM4: %v", err)
	}
	decrypted, err := DecryptBlob(encrypted, key, blobID)
	if err != nil {
		t.Fatalf("DecryptBlob SM4: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Error("SM4 blob round-trip mismatch")
	}
}

func TestEncryptBlob_OldAlgorithm_StillReadable(t *testing.T) {
	// Simulate profile switch: encrypt with AES, then "switch" to SM4,
	// verify AES-encrypted blob still decrypts correctly.
	key := make([]byte, 32)
	plaintext := []byte("data encrypted before SMx migration")
	blobID := hex.EncodeToString(sha256Hash(plaintext))

	// Encrypt with AES-256-GCM (standard profile)
	encrypted, err := EncryptBlob(plaintext, key, blobID, ProfileStandard)
	if err != nil {
		t.Fatalf("EncryptBlob (standard): %v", err)
	}

	// Verify envelope says AES-256-GCM
	if AlgorithmTag(encrypted[4]) != AlgoAES256GCM {
		t.Errorf("expected AES-256-GCM tag, got %d", encrypted[4])
	}

	// DecryptBlob reads algorithm from envelope header — must still work
	decrypted, err := DecryptBlob(encrypted, key, blobID)
	if err != nil {
		t.Fatalf("DecryptBlob after profile switch: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Error("old data not readable after profile switch")
	}
}

func TestEncryptBlob_Empty(t *testing.T) {
	key := make([]byte, 32)
	blobID := hex.EncodeToString(sha256Hash(nil))
	encrypted, err := EncryptBlob(nil, key, blobID, ProfileStandard)
	if err != nil {
		t.Fatalf("EncryptBlob empty: %v", err)
	}
	decrypted, err := DecryptBlob(encrypted, key, blobID)
	if err != nil {
		t.Fatalf("DecryptBlob empty: %v", err)
	}
	if len(decrypted) != 0 {
		t.Errorf("expected 0 bytes, got %d", len(decrypted))
	}
}

func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
