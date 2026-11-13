package mdm

import (
	"testing"

	"github.com/google/uuid"
)

// ── Device identity unit tests (no DB required) ───────────────────────────

func TestGenerateDeviceSecret(t *testing.T) {
	s1, err := GenerateDeviceSecret()
	if err != nil {
		t.Fatalf("GenerateDeviceSecret() error = %v", err)
	}
	if len(s1) != 64 { // 32 bytes hex-encoded = 64 chars
		t.Errorf("expected 64-char hex secret, got %d chars", len(s1))
	}

	// Verify uniqueness
	s2, err := GenerateDeviceSecret()
	if err != nil {
		t.Fatalf("second GenerateDeviceSecret() error = %v", err)
	}
	if s1 == s2 {
		t.Error("expected unique secrets, got identical")
	}
}

func TestGenerateDeviceSecret_HexEncoding(t *testing.T) {
	s, err := GenerateDeviceSecret()
	if err != nil {
		t.Fatalf("GenerateDeviceSecret() error = %v", err)
	}
	// Verify all characters are valid hex
	for _, ch := range s {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			t.Errorf("non-hex character in secret: %c (0x%x)", ch, ch)
		}
	}
}

func TestValidateFingerprint(t *testing.T) {
	valid := uuid.New()
	if !ValidateFingerprint(valid.String()) {
		t.Error("expected valid UUID fingerprint to pass validation")
	}

	if ValidateFingerprint("") {
		t.Error("expected empty fingerprint to fail validation")
	}
	if ValidateFingerprint("not-a-uuid") {
		t.Error("expected non-UUID fingerprint to fail validation")
	}
	if ValidateFingerprint("00000000-0000-0000-0000-000000000000") {
		t.Error("expected nil UUID to fail validation")
	}
}

func TestValidateFingerprint_UpperCase(t *testing.T) {
	// UUIDs are case-insensitive — uppercase should work
	valid := uuid.New()
	if !ValidateFingerprint(valid.String()) {
		t.Error("expected lowercase UUID to pass")
	}
	// Uppercase valid UUID should also pass
	if !ValidateFingerprint("F47AC10B-58CC-4372-A567-0E02B2C3D479") {
		t.Error("expected uppercase valid UUID to pass")
	}
}

func TestDeviceIdentity(t *testing.T) {
	fp := uuid.New()
	secret, _ := GenerateDeviceSecret()

	id := DeviceIdentity{
		Fingerprint: fp,
		Secret:      secret,
		Platform:    "ios",
		DeviceName:  "Test iPhone",
	}

	if id.Fingerprint != fp {
		t.Error("fingerprint mismatch")
	}
	if id.Platform != "ios" {
		t.Errorf("expected platform=ios, got %s", id.Platform)
	}
	if id.Secret != secret {
		t.Error("secret mismatch")
	}
	if id.DeviceName != "Test iPhone" {
		t.Errorf("expected device_name='Test iPhone', got %s", id.DeviceName)
	}
}
