package mdm

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/google/uuid"
)

// DeviceIdentity represents a device's stable identifiers.
type DeviceIdentity struct {
	Fingerprint uuid.UUID `json:"fingerprint"` // UUID from OS keychain, stable identifier
	Secret      string    `json:"-"`           // HMAC key for checkin signing, never serialized
	Platform    string    `json:"platform"`
	DeviceName  string    `json:"device_name"`
}

// GenerateDeviceSecret creates a new random 32-byte HMAC key, hex-encoded.
func GenerateDeviceSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// ValidateFingerprint checks that a device fingerprint string is a valid,
// non-nil UUID.
func ValidateFingerprint(fp string) bool {
	if fp == "" {
		return false
	}
	u, err := uuid.Parse(fp)
	if err != nil {
		return false
	}
	// Reject the nil UUID
	return u != uuid.Nil
}
