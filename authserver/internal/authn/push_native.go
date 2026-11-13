package authn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// EncryptECIES encrypts plaintext to a device's uncompressed P-256 public key.
//
// recipientPubBytes must be the 65-byte uncompressed encoding of the device's
// P-256 public key (as returned by ecdh.PublicKey.Bytes() in Go, or
// p256::PublicKey::to_encoded_point(false) in Rust).
//
// Wire format: [65-byte uncompressed ephemeral pub] [12-byte nonce] [ciphertext+tag]
// The device decrypts using decrypt_ecies() in guard-core (Rust).
//
// This is the production entry point: it samples a fresh ephemeral keypair and a
// fresh GCM nonce from crypto/rand on every call (ECIES is non-deterministic by
// design). The actual algorithm lives in encryptECIESDeterministic so a test can
// pin the ephemeral key + nonce and assert byte-for-byte output against the
// committed cross-end golden vector (see push_native_test.go / guard-core's
// tests/ecdh_golden.rs). See docs/standards/PUSH_ECIES_CONTRACT.md for the
// authoritative wire-format / KDF / AEAD contract both ends cite.
func EncryptECIES(recipientPubBytes []byte, plaintext []byte) ([]byte, error) {
	curve := ecdh.P256()

	// Generate ephemeral keypair
	ephKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	// Fresh 12-byte GCM nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}

	return encryptECIESDeterministic(recipientPubBytes, plaintext, ephKey, nonce)
}

// encryptECIESDeterministic performs the ECIES encryption with a caller-supplied
// ephemeral key and nonce. It is the single implementation of the wire format and
// KDF/AEAD parameters; EncryptECIES wraps it with fresh randomness in production.
//
// Tests inject a FIXED ephemeral key + nonce here to make the output byte-for-byte
// reproducible, which is how the cross-end golden vector pins the Go encrypt and
// the Rust decrypt to identical bytes. Never call this from production with a
// reused or low-entropy (ephemeral key, nonce) pair — GCM nonce reuse under the
// same derived key is catastrophic.
func encryptECIESDeterministic(recipientPubBytes, plaintext []byte, ephKey *ecdh.PrivateKey, nonce []byte) ([]byte, error) {
	curve := ecdh.P256()

	// Parse recipient public key (uncompressed 65-byte encoding)
	recipPub, err := curve.NewPublicKey(recipientPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse recipient key: %w", err)
	}

	if len(nonce) != 12 {
		return nil, fmt.Errorf("nonce must be 12 bytes, got %d", len(nonce))
	}

	// ECDH shared secret
	shared, err := ephKey.ECDH(recipPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}

	// HKDF-SHA256 -> 32-byte AES key (salt=nil, info="push-challenge"; must match guard-core)
	hkdfReader := hkdf.New(sha256.New, shared, nil, []byte("push-challenge"))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}

	// AES-256-GCM encrypt
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)

	// Serialize: uncompressed ephemeral pub (65 bytes) | nonce (12) | ct+tag
	ephPubBytes := ephKey.PublicKey().Bytes() // uncompressed, 65 bytes for P-256
	out := make([]byte, 0, len(ephPubBytes)+len(nonce)+len(ct))
	out = append(out, ephPubBytes...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}
