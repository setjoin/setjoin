// Package cryptokey derives cryptographic keys from secrets using HKDF-SHA256.
// Follows NIST SP-800 for proper key derivation with domain separation.
package cryptokey

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveCookieKey derives a 32-byte AES-256 key from the JWT secret.
// Uses HKDF-SHA256 with a domain-separated info string for cookie encryption.
func DeriveCookieKey(secret []byte) []byte {
	h := hkdf.New(sha256.New, secret, []byte("mailserver-cookie-key-v1"), nil)
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		// HKDF ReadFull cannot fail for SHA-256 with valid inputs
		panic("cryptokey: io.ReadFull failed: " + err.Error())
	}
	return key
}

// DeriveOIDCCryptoKey derives a 32-byte AES-256 key from the JWT secret
// for OIDC Provider token encryption. Uses HKDF-SHA256 with a different
// domain-separated info string than the cookie key.
func DeriveOIDCCryptoKey(secret []byte) []byte {
	h := hkdf.New(sha256.New, secret, []byte("mailserver-oidc-cryptokey-v1"), nil)
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		panic("cryptokey: io.ReadFull failed: " + err.Error())
	}
	return key
}

// DeriveMailAttachmentTokenKey derives the gateway-only HS256 key used for
// short-lived, one-blob mail attachment transfer tokens. Domain separation
// keeps this narrow signer from sharing raw JWT_SECRET key material with
// normal authserver tokens or the Drive native-token bridge.
func DeriveMailAttachmentTokenKey(secret []byte) []byte {
	h := hkdf.New(sha256.New, secret, []byte("mailserver-mail-attachment-token-v1"), nil)
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		panic("cryptokey: io.ReadFull failed: " + err.Error())
	}
	return key
}

// DeriveEncryptionKey derives a per-purpose encryption key from a secret,
// adapting output length to the active crypto profile.
// Standard (AES-256): 32 bytes. SMx (SM4): 16 bytes. Hybrid: 32 bytes (AES for data-at-rest).
func DeriveEncryptionKey(secret []byte, info string, profile CryptoProfile) []byte {
	size := 32
	if profile == ProfileSMx {
		size = 16 // SM4-128
	}
	h := hkdf.New(sha256.New, secret, []byte(info), nil)
	key := make([]byte, size)
	if _, err := io.ReadFull(h, key); err != nil {
		panic("cryptokey: io.ReadFull failed: " + err.Error())
	}
	return key
}

// DeriveDBEncryptionKey derives an encryption key for pgcrypto column data.
func DeriveDBEncryptionKey(secret []byte, profile CryptoProfile) []byte {
	return DeriveEncryptionKey(secret, "mailserver-db-encryption-v1", profile)
}

// EncryptColumn encrypts a single database column value using the active
// crypto profile. Returns nil if plaintext is nil (NULL column).
// The ciphertext is an envelope: magic + algo + key_len + nonce_len + nonce + ciphertext+tag.
func EncryptColumn(plaintext, masterKey []byte, profile CryptoProfile) ([]byte, error) {
	return EncryptColumnWithAAD(plaintext, masterKey, profile, nil)
}

// EncryptColumnWithAAD encrypts a single database column value and binds the
// ciphertext to caller-supplied, non-secret context. The exact same AAD must be
// supplied to DecryptColumnWithAAD; moving a ciphertext to another row/key then
// fails authentication.
func EncryptColumnWithAAD(plaintext, masterKey []byte, profile CryptoProfile, aad []byte) ([]byte, error) {
	if plaintext == nil {
		return nil, nil
	}
	colKey := DeriveDBEncryptionKey(masterKey, profile)
	algo := AlgorithmTagFromProfile(profile)
	return SealEnvelope(algo, colKey, plaintext, aad)
}

// DecryptColumn decrypts a database column value. Returns nil if ciphertext
// is nil (NULL column). Handles envelope format (reads algorithm tag from header).
func DecryptColumn(ciphertext, masterKey []byte) ([]byte, error) {
	return DecryptColumnWithAAD(ciphertext, masterKey, nil)
}

// DecryptColumnWithAAD decrypts a database column envelope using the exact AAD
// supplied at encryption time. The envelope remains self-describing across
// AES-256-GCM and SM4-GCM profile changes.
func DecryptColumnWithAAD(ciphertext, masterKey, aad []byte) ([]byte, error) {
	if ciphertext == nil {
		return nil, nil
	}
	// The envelope format is self-describing — OpenEnvelope reads the algorithm
	// tag and key length from the header.
	// We re-derive the key at the length the envelope expects.
	if len(ciphertext) < envelopeHeaderSize {
		return nil, fmt.Errorf("cryptokey: column ciphertext too short (%d bytes)", len(ciphertext))
	}
	// Read key length from envelope header (bytes 5-9, uint32 big-endian)
	keyLen := int(binary.BigEndian.Uint32(ciphertext[5:9]))
	// Re-derive key at the stored length (works whether it is AES-256=32 or SM4=16)
	info := "mailserver-db-encryption-v1"
	h := hkdf.New(sha256.New, masterKey, []byte(info), nil)
	colKey := make([]byte, keyLen)
	if _, err := io.ReadFull(h, colKey); err != nil {
		return nil, fmt.Errorf("cryptokey: key derivation failed: %w", err)
	}
	plaintext, _, err := OpenEnvelope(ciphertext, colKey, aad)
	return plaintext, err
}
