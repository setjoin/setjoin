package cryptokey

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// EncryptBlob encrypts a blob for S3/SeaweedFS storage with deterministic encryption.
//
// blobID is the SHA-256 of the plaintext (hex-encoded). It serves two purposes:
//  1. It is the S3 object key — same content → same key → dedup via ref_count upsert.
//  2. It is used to derive a deterministic nonce — same content → same nonce →
//     same ciphertext → dedup-safe (second upload overwrites with identical bytes).
//
// The envelope format (magic + algo tag + key_len + nonce_len + nonce + ciphertext+tag)
// is self-describing — old blobs remain readable after crypto profile switches.
func EncryptBlob(plaintext []byte, masterKey []byte, blobID string, profile CryptoProfile) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, nil
	}

	blobKey := DeriveEncryptionKey(masterKey, "mailserver-blob-encryption-v1", profile)
	algo := AlgorithmTagFromProfile(profile)

	// Deterministic nonce from blobID — ensures same plaintext → same ciphertext
	nonce := deriveNonce(blobKey, blobID, algo)

	return SealEnvelopeDeterministic(algo, blobKey, nonce, plaintext, nil)
}

// DecryptBlob decrypts a blob from S3/SeaweedFS storage.
// blobID is only used for key derivation consistency; the algorithm tag
// is read from the envelope header at byte 4.
func DecryptBlob(envelope []byte, masterKey []byte, blobID string) ([]byte, error) {
	if len(envelope) == 0 {
		return nil, nil
	}
	if len(envelope) < envelopeHeaderSize {
		return nil, fmt.Errorf("storage: blob too short for envelope header (%d bytes)", len(envelope))
	}

	// Read algorithm and key length from envelope header
	algo := AlgorithmTag(envelope[4])
	keyLen := int(binary.BigEndian.Uint32(envelope[5:9]))

	// Re-derive the key at the stored length (works for both AES-256=32 and SM4=16)
	h := hkdf.New(sha256.New, masterKey, []byte("mailserver-blob-encryption-v1"), nil)
	blobKey := make([]byte, keyLen)
	if _, err := io.ReadFull(h, blobKey); err != nil {
		return nil, fmt.Errorf("storage: key derivation failed: %w", err)
	}

	// Read nonce from envelope (offset 13, length at bytes 11-12)
	nonceLen := int(binary.BigEndian.Uint16(envelope[11:13]))
	if len(envelope) < envelopeHeaderSize+nonceLen {
		return nil, fmt.Errorf("storage: blob too short for nonce")
	}
	nonce := envelope[envelopeHeaderSize : envelopeHeaderSize+nonceLen]
	ciphertext := envelope[envelopeHeaderSize+nonceLen:]

	_, gcm, err := newGCM(algo, blobKey)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("storage: decryption failed: %w", err)
	}
	return plaintext, nil
}

// deriveNonce produces a deterministic 12-byte nonce from the key and blobID.
// HKDF-SHA256 ensures the nonce is uniformly distributed and unique per content.
func deriveNonce(key []byte, blobID string, algo AlgorithmTag) []byte {
	nonceLen := 12 // GCM standard nonce size
	h := hkdf.New(sha256.New, key, nil, []byte("blob-nonce-"+blobID))
	nonce := make([]byte, nonceLen)
	io.ReadFull(h, nonce)
	return nonce
}

// BlobID computes the content-addressable storage key for a plaintext blob.
// This is the SHA-256 of the plaintext, used as both the S3 key and dedup anchor.
// The encryption is deterministic with respect to this blobID.
func BlobID(plaintext []byte) string {
	h := sha256.Sum256(plaintext)
	return hex.EncodeToString(h[:])
}
