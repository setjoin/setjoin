package storage

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// ── ValidateWORMConfig tests ─────────────────────────────────────────────

func TestValidateWORMConfig_ModeWithoutRetentionDays(t *testing.T) {
	err := ValidateWORMConfig("compliance", 0)
	if err == nil {
		t.Fatal("expected error when WORM_MODE is set but retention days is 0")
	}
}

func TestValidateWORMConfig_InvalidMode(t *testing.T) {
	err := ValidateWORMConfig("bananas", 2557)
	if err == nil {
		t.Fatal("expected error for invalid WORM_MODE value")
	}
}

func TestValidateWORMConfig_ValidCompliance(t *testing.T) {
	err := ValidateWORMConfig("compliance", 2557)
	if err != nil {
		t.Errorf("unexpected error for valid compliance config: %v", err)
	}
}

func TestValidateWORMConfig_ValidGovernance(t *testing.T) {
	err := ValidateWORMConfig("governance", 30)
	if err != nil {
		t.Errorf("unexpected error for valid governance config: %v", err)
	}
}

func TestValidateWORMConfig_BelowMinimumRetention(t *testing.T) {
	// Below-minimum retention days should NOT block — only warn (SRE can override).
	err := ValidateWORMConfig("compliance", 30)
	if err != nil {
		t.Errorf("below-minimum retention should not block startup, got: %v", err)
	}
}

func TestValidateWORMConfig_EmptyMode(t *testing.T) {
	// Empty mode = WORM disabled. No error expected.
	err := ValidateWORMConfig("", 0)
	if err != nil {
		t.Errorf("empty mode should mean WORM disabled, got: %v", err)
	}
}

func TestValidateWORMConfig_EmptyModeWithRetention(t *testing.T) {
	// Empty mode with retention days set = inconsistent, should error.
	err := ValidateWORMConfig("", 2557)
	if err == nil {
		t.Fatal("expected error when retention days set but no WORM mode")
	}
}

// ── StartupWORMCheck tests ────────────────────────────────────────────────

type mockWORMDriver struct {
	lockConfig *BucketLockConfig
	lockErr    error
}

func (m *mockWORMDriver) PutObject(ctx context.Context, key string, data io.Reader, size int64) error {
	return nil
}
func (m *mockWORMDriver) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	return nil, nil
}
func (m *mockWORMDriver) DeleteObject(ctx context.Context, key string) error { return nil }
func (m *mockWORMDriver) ListObjects(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	return nil, nil
}
func (m *mockWORMDriver) HeadObject(ctx context.Context, key string) (*ObjectInfo, error) {
	return nil, nil
}
func (m *mockWORMDriver) EnsureBucket(ctx context.Context) error { return nil }
func (m *mockWORMDriver) BucketExists(ctx context.Context) (bool, error) {
	return true, nil
}
func (m *mockWORMDriver) ProviderName() string { return "mock-worm" }
func (m *mockWORMDriver) Endpoint() string     { return "" }
func (m *mockWORMDriver) CopyObject(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string) error {
	return nil
}
func (m *mockWORMDriver) Ping(ctx context.Context) error { return nil }
func (m *mockWORMDriver) StatObject(ctx context.Context, key string) (*ObjectInfo, error) {
	return &ObjectInfo{Key: key}, nil
}

// Retention methods — delegate to lockConfig for GetBucketObjectLockConfig.
func (m *mockWORMDriver) PutObjectRetention(ctx context.Context, key, mode string, retainUntil time.Time) error {
	return nil
}
func (m *mockWORMDriver) GetObjectRetention(ctx context.Context, key string) (*RetentionStatus, error) {
	return nil, nil
}
func (m *mockWORMDriver) PutObjectLegalHold(ctx context.Context, key, status string) error {
	return nil
}
func (m *mockWORMDriver) GetObjectLegalHold(ctx context.Context, key string) (string, error) {
	return "", nil
}
func (m *mockWORMDriver) EnsureBucketObjectLock(ctx context.Context, mode string, retentionDays int) error {
	return nil
}
func (m *mockWORMDriver) GetBucketObjectLockConfig(ctx context.Context) (*BucketLockConfig, error) {
	return m.lockConfig, m.lockErr
}

func TestStartupWORMCheck_BucketHasObjectLock(t *testing.T) {
	d := &mockWORMDriver{
		lockConfig: &BucketLockConfig{
			Enabled:             true,
			Mode:                "compliance",
			RetentionPeriodDays: 2557,
		},
	}
	err := StartupWORMCheck(context.Background(), d, "compliance")
	if err != nil {
		t.Errorf("expected success when bucket has matching Object Lock, got: %v", err)
	}
}

func TestStartupWORMCheck_BucketMissingObjectLock(t *testing.T) {
	d := &mockWORMDriver{
		lockConfig: &BucketLockConfig{Enabled: false},
	}
	err := StartupWORMCheck(context.Background(), d, "compliance")
	if err == nil {
		t.Fatal("expected error when bucket lacks Object Lock")
	}
}

func TestStartupWORMCheck_ModeMismatch(t *testing.T) {
	d := &mockWORMDriver{
		lockConfig: &BucketLockConfig{
			Enabled: true,
			Mode:    "governance",
		},
	}
	err := StartupWORMCheck(context.Background(), d, "compliance")
	if err == nil {
		t.Fatal("expected error when configured mode differs from bucket mode")
	}
}

func TestStartupWORMCheck_GetBucketConfigError(t *testing.T) {
	d := &mockWORMDriver{
		lockErr: errors.New("network timeout"),
	}
	err := StartupWORMCheck(context.Background(), d, "compliance")
	if err == nil {
		t.Fatal("expected error when bucket config lookup fails")
	}
}

func TestIsWORMConfigured(t *testing.T) {
	tests := []struct {
		mode   string
		wantOK bool
	}{
		{"compliance", true},
		{"governance", true},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsWORMConfigured(tt.mode); got != tt.wantOK {
			t.Errorf("IsWORMConfigured(%q) = %v, want %v", tt.mode, got, tt.wantOK)
		}
	}
}

func TestWORMRetentionDaysDefault(t *testing.T) {
	if DefaultWORMRetentionDays != 2557 {
		t.Errorf("DefaultWORMRetentionDays = %d, want 2557", DefaultWORMRetentionDays)
	}
}

func TestMinWORMRetentionDays(t *testing.T) {
	if MinWORMRetentionDays <= 0 {
		t.Errorf("MinWORMRetentionDays = %d, want positive value", MinWORMRetentionDays)
	}
}
