package device

import (
	"errors"
	"fmt"

	"setjoin.com/shared/cryptokey"
)

// SecretCodec seals and opens per-device HMAC secrets at rest in the family's
// AES-256-GCM EK01 column envelope (med-auth-baseline-secrets-001).
//
// The stored form mirrors signing_keys.private_key_enc: cryptokey.EncryptColumn
// seals the secret from the RAW master secret (DeriveDBEncryptionKey inside the
// seam — never pre-derive and never pass key material into SQL), and the
// envelope is self-describing across profile changes. A non-secret key-version
// id is stamped BESIDE the envelope (devices.hmac_secret_key_id) following the
// system_config secret-codec convention, so a future rotation decision can be
// made without another migration.
//
// The codec is constructed once per process from the process's master secret
// and threaded explicitly to the register/read seams (RegisterDevice,
// GetDeviceSecret/VerifyDeviceRequest, DeviceCredentialResolver). A nil codec
// at a seam fails closed: after the at-rest cutover, silently accepting a
// plaintext-only world would defeat the control.
//
// Rotation/rollback semantics for already-issued keys (in-place re-encrypt
// with key-id dual-verify versus forced re-attestation) are an explicit OPEN
// decision (med-auth-baseline-secrets-001 openQuestions); this codec implements
// the single-active-key form only and fails closed on unknown key ids.
type SecretCodec struct {
	masterKey []byte
	profile   cryptokey.CryptoProfile
}

// SecretKeyIDV1 is the active master-key version stamped beside newly sealed
// device HMAC secret envelopes.
const SecretKeyIDV1 = "v1"

// NewSecretCodec builds a codec over the RAW master secret (the JWT secret) —
// cryptokey derives the column key internally; do NOT pre-derive here or the
// envelope would double-derive (signing_keys contract).
func NewSecretCodec(masterKey []byte, profile cryptokey.CryptoProfile) *SecretCodec {
	return &SecretCodec{masterKey: append([]byte(nil), masterKey...), profile: profile}
}

// ActiveKeyID is the key version stamped beside newly sealed envelopes. The
// master key bytes are intentionally never exposed.
func (c *SecretCodec) ActiveKeyID() string {
	if c == nil {
		return ""
	}
	return SecretKeyIDV1
}

// Seal encrypts one device HMAC secret into the EK01 column envelope.
func (c *SecretCodec) Seal(plaintext string) ([]byte, error) {
	if c == nil || len(c.masterKey) == 0 {
		return nil, errors.New("device: secret codec not configured")
	}
	envelope, err := cryptokey.EncryptColumn([]byte(plaintext), c.masterKey, c.profile)
	if err != nil {
		return nil, fmt.Errorf("device: seal hmac secret: %w", err)
	}
	return envelope, nil
}

// Open decrypts one stored envelope. keyID must be the id this codec's master
// key version stamped at seal time; an unknown or unstamped id fails closed
// (never fall back to decrypting under the wrong key generation).
func (c *SecretCodec) Open(envelope []byte, keyID string) (string, error) {
	if c == nil || len(c.masterKey) == 0 {
		return "", errors.New("device: secret codec not configured")
	}
	if keyID != SecretKeyIDV1 {
		return "", fmt.Errorf("device: hmac secret requires unavailable key version %q", keyID)
	}
	plaintext, err := cryptokey.DecryptColumn(envelope, c.masterKey)
	if err != nil {
		return "", fmt.Errorf("device: open hmac secret envelope: %w", err)
	}
	return string(plaintext), nil
}
