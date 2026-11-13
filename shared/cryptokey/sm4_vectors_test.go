package cryptokey

import (
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/emmansun/gmsm/sm4"
)

// TestSM4VectorsRoundTrip verifies each oracle vector decrypts back to its
// plaintext using gmsm directly — gmsm seals AND opens correctly.
func TestSM4VectorsRoundTrip(t *testing.T) {
	for i, v := range SM4Vectors() {
		block, err := sm4.NewCipher(v.Key)
		if err != nil {
			t.Fatalf("vector %d: NewCipher: %v", i, err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatalf("vector %d: NewGCM: %v", i, err)
		}
		got, err := gcm.Open(nil, v.Nonce, v.CiphertextTag, v.AAD)
		if err != nil {
			t.Fatalf("vector %d: gcm.Open: %v", i, err)
		}
		if string(got) != string(v.Plaintext) {
			t.Errorf("vector %d: decrypted %q, want %q", i, got, v.Plaintext)
		}
	}
}

// goldenEntry is the JSON shape emitted to sm4_vectors.golden.json.
type goldenEntry struct {
	Key           string `json:"key"`
	Nonce         string `json:"nonce"`
	Plaintext     string `json:"plaintext"`
	AAD           string `json:"aad"`
	CiphertextTag string `json:"ciphertext_tag"`
}

// TestEmitSM4Golden writes the golden JSON when WRITE_GOLDEN=1.
// Run:
//
//	WRITE_GOLDEN=1 go test ./cryptokey/ -run TestEmitSM4Golden
func TestEmitSM4Golden(t *testing.T) {
	if os.Getenv("WRITE_GOLDEN") != "1" {
		t.Skip("set WRITE_GOLDEN=1 to regenerate golden vectors")
	}

	// Build path from this source file so it works regardless of where
	// `go test` is invoked from (Go sets CWD to the package directory).
	_, thisFile, _, _ := runtime.Caller(0)
	outPath := filepath.Join(
		filepath.Dir(thisFile), // shared/cryptokey/
		"..", "..",             // repo root
		"clients", "rust", "offline-core", "tests", "sm4_vectors.golden.json",
	)

	entries := make([]goldenEntry, 0)
	for _, v := range SM4Vectors() {
		entries = append(entries, goldenEntry{
			Key:           hex.EncodeToString(v.Key),
			Nonce:         hex.EncodeToString(v.Nonce),
			Plaintext:     hex.EncodeToString(v.Plaintext),
			AAD:           hex.EncodeToString(v.AAD),
			CiphertextTag: hex.EncodeToString(v.CiphertextTag),
		})
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", outPath, err)
	}
	t.Logf("wrote %d vectors to %s", len(entries), outPath)
}
