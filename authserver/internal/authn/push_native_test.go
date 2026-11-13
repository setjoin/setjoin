package authn_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"

	"setjoin.com/authserver/internal/authn"
)

func TestECIESRoundtrip(t *testing.T) {
	// Device generates keypair
	curve := ecdh.P256()
	devKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubBytes := devKey.PublicKey().Bytes() // uncompressed, 65 bytes

	// Server encrypts
	plaintext := []byte("42")
	payload, err := authn.EncryptECIES(pubBytes, plaintext)
	if err != nil {
		t.Fatalf("EncryptECIES: %v", err)
	}

	// Verify payload format: [65 uncompressed pub][12 nonce][ct+tag]
	if len(payload) < 65+12+16 {
		t.Fatalf("payload too short: %d bytes (want >= %d)", len(payload), 65+12+16)
	}

	// Manual decrypt to verify roundtrip
	ephPubBytes := payload[:65]
	nonceBytes := payload[65:77]
	ct := payload[77:]

	// Parse ephemeral public key
	ephPub, err := curve.NewPublicKey(ephPubBytes)
	if err != nil {
		t.Fatalf("parse ephemeral pub: %v", err)
	}

	// ECDH shared secret
	shared, err := devKey.ECDH(ephPub)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}

	// HKDF-SHA256 -> 32-byte AES key
	hkdfReader := hkdf.New(sha256.New, shared, nil, []byte("push-challenge"))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		t.Fatalf("hkdf: %v", err)
	}

	// AES-256-GCM decrypt
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	decrypted, err := gcm.Open(nil, nonceBytes, ct, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted %q, want %q", string(decrypted), string(plaintext))
	}
	t.Logf("EncryptECIES roundtrip OK: payload %d bytes", len(payload))
}
