package cryptokey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Envelope format (binary layout):
//
//   Offset  Size  Field
//     0      4    Magic bytes "EK01" (Envelope Key v01)
//     4      1    Algorithm tag (uint8)
//     5      4    Key length in bytes (uint32, big-endian)
//     9      2    Reserved (must be zero)
//    11      2    Nonce length in bytes (uint16, big-endian)
//    13    var    Nonce (12 bytes for GCM)
//  13+N    var    Ciphertext + 16-byte GCM tag
//
// Total overhead: 13 bytes header + 12 bytes nonce + 16 bytes tag = 41 bytes.
// Old data keeps its original algorithm tag forever — no migration needed.
// New data always uses the active crypto profile's algorithm.

// EnvelopeMagic is the 4-byte magic number identifying a SetJoin envelope.
var EnvelopeMagic = []byte("EK01")

const envelopeHeaderSize = 13 // 4 magic + 1 algo + 4 key_len + 2 reserved + 2 nonce_len

// AlgorithmTag identifies the encryption algorithm used.
type AlgorithmTag uint8

const (
	AlgoAES256GCM      AlgorithmTag = 0 // AES-256 in GCM mode (12-byte nonce, 16-byte tag)
	AlgoSM4GCM         AlgorithmTag = 1 // SM4-128 in GCM mode (12-byte nonce, 16-byte tag)
	AlgoAES256Kyber768 AlgorithmTag = 2 // AES-256 with Kyber-768 KEM (post-quantum, future)
)

func (a AlgorithmTag) String() string {
	switch a {
	case AlgoAES256GCM:
		return "AES-256-GCM"
	case AlgoSM4GCM:
		return "SM4-GCM"
	case AlgoAES256Kyber768:
		return "AES-256-Kyber768"
	default:
		return fmt.Sprintf("unknown-%d", a)
	}
}

// AlgorithmTagFromProfile maps a CryptoProfile to its default symmetric algorithm.
func AlgorithmTagFromProfile(profile CryptoProfile) AlgorithmTag {
	switch profile {
	case ProfileSMx:
		return AlgoSM4GCM
	default:
		return AlgoAES256GCM
	}
}

// SealEnvelope encrypts plaintext with the given algorithm and key, returning
// the full envelope bytes: magic + algo + key_len + reserved + nonce_len + nonce + ciphertext+tag.
func SealEnvelope(algo AlgorithmTag, key, plaintext, aad []byte) ([]byte, error) {
	_, gcm, err := newGCM(algo, key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("envelope: nonce generation failed: %w", err)
	}

	return buildEnvelope(algo, key, nonce, plaintext, aad, gcm), nil
}

// SealEnvelopeDeterministic encrypts plaintext with a caller-supplied nonce.
// For blob storage, the nonce is derived from the content hash (blobID),
// ensuring identical plaintexts produce identical ciphertexts — preserves S3 dedup.
func SealEnvelopeDeterministic(algo AlgorithmTag, key, nonce, plaintext, aad []byte) ([]byte, error) {
	_, gcm, err := newGCM(algo, key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("envelope: nonce length %d != required %d", len(nonce), gcm.NonceSize())
	}

	return buildEnvelope(algo, key, nonce, plaintext, aad, gcm), nil
}

// buildEnvelope constructs the binary envelope: header + nonce + sealed(ciphertext+tag).
func buildEnvelope(algo AlgorithmTag, key, nonce, plaintext, aad []byte, gcm cipher.AEAD) []byte {
	hdr := make([]byte, envelopeHeaderSize)
	copy(hdr[0:4], EnvelopeMagic)
	hdr[4] = byte(algo)
	binary.BigEndian.PutUint32(hdr[5:9], uint32(len(key)))
	// hdr[9:11] reserved, already zero
	binary.BigEndian.PutUint16(hdr[11:13], uint16(len(nonce)))

	// Seal: ciphertext+tag (nonce is prepended separately, not by gcm.Seal)
	sealed := gcm.Seal(nil, nonce, plaintext, aad)

	result := make([]byte, 0, len(hdr)+len(nonce)+len(sealed))
	result = append(result, hdr...)
	result = append(result, nonce...)
	result = append(result, sealed...)
	return result
}

// OpenEnvelope decrypts an envelope and returns (plaintext, algorithmTag, error).
// It reads the algorithm tag from the envelope header and uses the corresponding cipher.
// aad must match the additional authenticated data passed to SealEnvelope — pass nil
// if no AAD was used during encryption.
func OpenEnvelope(envelope, key, aad []byte) ([]byte, AlgorithmTag, error) {
	if len(envelope) < envelopeHeaderSize {
		return nil, 0, errors.New("envelope: too short for header")
	}

	// Verify magic
	if string(envelope[0:4]) != string(EnvelopeMagic) {
		return nil, 0, fmt.Errorf("envelope: bad magic %q", string(envelope[0:4]))
	}

	algo := AlgorithmTag(envelope[4])
	keyLen := binary.BigEndian.Uint32(envelope[5:9])
	if envelope[9] != 0 || envelope[10] != 0 {
		return nil, 0, errors.New("envelope: reserved bytes must be zero")
	}
	nonceLen := int(binary.BigEndian.Uint16(envelope[11:13]))

	if int(keyLen) != len(key) {
		return nil, 0, fmt.Errorf("envelope: key length mismatch: envelope expects %d bytes, got %d", keyLen, len(key))
	}
	_, gcm, err := newGCM(algo, key)
	if err != nil {
		return nil, 0, err
	}
	if nonceLen != gcm.NonceSize() {
		return nil, 0, fmt.Errorf("envelope: nonce length %d != required %d", nonceLen, gcm.NonceSize())
	}
	if len(envelope) < envelopeHeaderSize+nonceLen+gcm.Overhead() {
		return nil, 0, errors.New("envelope: ciphertext is shorter than authentication tag")
	}

	nonce := envelope[envelopeHeaderSize : envelopeHeaderSize+nonceLen]
	ciphertext := envelope[envelopeHeaderSize+nonceLen:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, 0, fmt.Errorf("envelope: decryption failed: %w", err)
	}

	return plaintext, algo, nil
}

// newGCM creates a GCM cipher from the algorithm tag and key.
func newGCM(algo AlgorithmTag, key []byte) (cipher.Block, cipher.AEAD, error) {
	var block cipher.Block
	var err error

	switch algo {
	case AlgoAES256GCM:
		block, err = aes.NewCipher(key)
	case AlgoSM4GCM:
		// Import sm4 only when needed — avoids hard dependency when smx feature is off
		block, err = newSM4Block(key)
	default:
		return nil, nil, fmt.Errorf("envelope: unknown algorithm tag %d", algo)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("envelope: cipher init failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	return block, gcm, nil
}

// sm4Bridge lives in smx.go — avoids import cycle and keeps SM4 optional.
var newSM4Block func(key []byte) (cipher.Block, error)
