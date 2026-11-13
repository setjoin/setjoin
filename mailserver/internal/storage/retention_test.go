package storage

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// ── RetentionPolicy interface tests ──────────────────────────────────────

// TestRetentionInfo verifies the RetentionInfo struct.
func TestRetentionInfo(t *testing.T) {
	info := RetentionInfo{
		Type:        "worm_s3_object_lock",
		Mode:        "compliance",
		Description: "S3 Object Lock compliance mode — SEC 17a-4(f)",
	}
	if info.Type != "worm_s3_object_lock" {
		t.Errorf("Type = %q", info.Type)
	}
	if info.Mode != "compliance" {
		t.Errorf("Mode = %q", info.Mode)
	}
	if info.Description == "" {
		t.Error("Description should not be empty")
	}
}

// ── WORMRetentionPolicy tests ─────────────────────────────────────────────

type testRetentionDriver struct {
	putRetentionCalls int
	getRetentionCalls int
	putLegalHoldCalls int
	getLegalHoldCalls int
	retentionStatus   *RetentionStatus
	retentionErr      error
	legalHold         string
	legalHoldErr      error
}

func (d *testRetentionDriver) PutObject(ctx context.Context, key string, data io.Reader, size int64) error {
	return nil
}
func (d *testRetentionDriver) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	return nil, nil
}
func (d *testRetentionDriver) DeleteObject(ctx context.Context, key string) error {
	return nil
}
func (d *testRetentionDriver) ListObjects(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	return nil, nil
}
func (d *testRetentionDriver) HeadObject(ctx context.Context, key string) (*ObjectInfo, error) {
	return nil, nil
}
func (d *testRetentionDriver) EnsureBucket(ctx context.Context) error {
	return nil
}
func (d *testRetentionDriver) BucketExists(ctx context.Context) (bool, error) {
	return true, nil
}
func (d *testRetentionDriver) ProviderName() string { return "test-retention" }
func (d *testRetentionDriver) Endpoint() string     { return "test://" }
func (d *testRetentionDriver) CopyObject(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string) error {
	return nil
}
func (d *testRetentionDriver) Ping(ctx context.Context) error { return nil }
func (d *testRetentionDriver) StatObject(ctx context.Context, key string) (*ObjectInfo, error) {
	return &ObjectInfo{Key: key}, nil
}
func (d *testRetentionDriver) PutObjectRetention(ctx context.Context, key, mode string, retainUntil time.Time) error {
	d.putRetentionCalls++
	return d.retentionErr
}
func (d *testRetentionDriver) GetObjectRetention(ctx context.Context, key string) (*RetentionStatus, error) {
	d.getRetentionCalls++
	return d.retentionStatus, d.retentionErr
}
func (d *testRetentionDriver) PutObjectLegalHold(ctx context.Context, key, status string) error {
	d.putLegalHoldCalls++
	return d.legalHoldErr
}
func (d *testRetentionDriver) GetObjectLegalHold(ctx context.Context, key string) (string, error) {
	d.getLegalHoldCalls++
	return d.legalHold, d.legalHoldErr
}
func (d *testRetentionDriver) EnsureBucketObjectLock(ctx context.Context, mode string, retentionDays int) error {
	return nil
}
func (d *testRetentionDriver) GetBucketObjectLockConfig(ctx context.Context) (*BucketLockConfig, error) {
	return &BucketLockConfig{Enabled: true, Mode: "compliance", RetentionPeriodDays: 2557}, nil
}

// TestWORMRetentionPolicy_Apply sets retention on the object.
func TestWORMRetentionPolicy_Apply(t *testing.T) {
	driver := &testRetentionDriver{}
	policy := NewWORMRetentionPolicy(driver, "compliance", 2557, nil)

	err := policy.Apply(context.Background(), "test-object-key")
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if driver.putRetentionCalls != 1 {
		t.Errorf("expected 1 PutObjectRetention call, got %d", driver.putRetentionCalls)
	}
}

// TestWORMRetentionPolicy_Apply_NoopWhenDisabled verifies that when WORM is
// disabled (empty mode, zero days), Apply is a no-op.
func TestWORMRetentionPolicy_Apply_NoopWhenDisabled(t *testing.T) {
	driver := &testRetentionDriver{}
	policy := NewWORMRetentionPolicy(driver, "", 0, nil)

	err := policy.Apply(context.Background(), "test-key")
	if err != nil {
		t.Fatalf("Apply on disabled policy should not error: %v", err)
	}
	if driver.putRetentionCalls != 0 {
		t.Errorf("expected 0 calls when WORM disabled, got %d", driver.putRetentionCalls)
	}
}

// TestWORMRetentionPolicy_Verify checks object retention status.
func TestWORMRetentionPolicy_Verify(t *testing.T) {
	driver := &testRetentionDriver{
		retentionStatus: &RetentionStatus{
			Mode:        "compliance",
			RetainUntil: time.Now().AddDate(7, 0, 0),
			LegalHold:   false,
		},
	}
	policy := NewWORMRetentionPolicy(driver, "compliance", 2557, nil)

	status, err := policy.Verify(context.Background(), "test-key")
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if status.Mode != "compliance" {
		t.Errorf("expected compliance mode, got %s", status.Mode)
	}
	if driver.getRetentionCalls != 1 {
		t.Errorf("expected 1 GetObjectRetention call, got %d", driver.getRetentionCalls)
	}
}

// TestWORMRetentionPolicy_Release_ComplianceModeReturnsErrImmutable verifies
// that Release on compliance mode always returns ErrImmutable (even root can't
// delete a compliance-mode locked object).
func TestWORMRetentionPolicy_Release_ComplianceModeReturnsErrImmutable(t *testing.T) {
	driver := &testRetentionDriver{}
	policy := NewWORMRetentionPolicy(driver, "compliance", 2557, nil)

	err := policy.Release(context.Background(), "test-key")
	if !errors.Is(err, ErrImmutable) {
		t.Errorf("expected ErrImmutable for compliance mode, got %v", err)
	}
}

// TestWORMRetentionPolicy_Release_GovernanceModeAllowsRelease verifies that
// governance mode permits release (with BypassGovernanceRetention header).
func TestWORMRetentionPolicy_Release_GovernanceModeAllowsRelease(t *testing.T) {
	driver := &testRetentionDriver{}
	policy := NewWORMRetentionPolicy(driver, "governance", 30, nil)

	err := policy.Release(context.Background(), "test-key")
	if err != nil {
		t.Fatalf("Release in governance mode should succeed: %v", err)
	}
	if driver.putRetentionCalls != 1 {
		t.Errorf("expected 1 PutObjectRetention call (to remove), got %d", driver.putRetentionCalls)
	}
}

// TestWORMRetentionPolicy_Info returns policy metadata.
func TestWORMRetentionPolicy_Info(t *testing.T) {
	policy := NewWORMRetentionPolicy(nil, "compliance", 2557, nil)
	info := policy.Info()

	if info.Type != "worm_s3_object_lock" {
		t.Errorf("Type = %q, want worm_s3_object_lock", info.Type)
	}
	if info.Mode != "compliance" {
		t.Errorf("Mode = %q, want compliance", info.Mode)
	}
	if info.Description == "" {
		t.Error("Description should not be empty")
	}
}

// ── RetentionPolicyRegistry tests ─────────────────────────────────────────

func TestRetentionPolicyRegistry_ApplyAll(t *testing.T) {
	d1 := &testRetentionDriver{}
	d2 := &testRetentionDriver{}
	p1 := NewWORMRetentionPolicy(d1, "compliance", 2557, nil)
	p2 := NewWORMRetentionPolicy(d2, "compliance", 2557, nil)
	registry := NewRetentionPolicyRegistry(p1, p2)

	err := registry.ApplyAll(context.Background(), "test-key")
	if err != nil {
		t.Fatalf("ApplyAll failed: %v", err)
	}
	if d1.putRetentionCalls != 1 {
		t.Errorf("policy 1: expected 1 call, got %d", d1.putRetentionCalls)
	}
	if d2.putRetentionCalls != 1 {
		t.Errorf("policy 2: expected 1 call, got %d", d2.putRetentionCalls)
	}
}

func TestRetentionPolicyRegistry_ApplyAll_EmptyRegistry(t *testing.T) {
	registry := NewRetentionPolicyRegistry()
	err := registry.ApplyAll(context.Background(), "test-key")
	if err != nil {
		t.Fatalf("ApplyAll on empty registry should not error: %v", err)
	}
}

func TestRetentionPolicyRegistry_ApplyAll_FirstErrorStops(t *testing.T) {
	d1 := &testRetentionDriver{retentionErr: errors.New("fail")}
	d2 := &testRetentionDriver{}
	p1 := NewWORMRetentionPolicy(d1, "compliance", 2557, nil)
	p2 := NewWORMRetentionPolicy(d2, "compliance", 2557, nil)
	registry := NewRetentionPolicyRegistry(p1, p2)

	err := registry.ApplyAll(context.Background(), "test-key")
	if err == nil {
		t.Fatal("expected error from first failing policy")
	}
	if d2.putRetentionCalls != 0 {
		t.Error("second policy should not be called after first fails")
	}
}

func TestRetentionPolicyRegistry_VerifyAll(t *testing.T) {
	now := time.Now()
	d1 := &testRetentionDriver{
		retentionStatus: &RetentionStatus{Mode: "compliance", RetainUntil: now},
	}
	registry := NewRetentionPolicyRegistry(NewWORMRetentionPolicy(d1, "compliance", 2557, nil))

	statuses, err := registry.VerifyAll(context.Background(), "test-key")
	if err != nil {
		t.Fatalf("VerifyAll failed: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
	if statuses[0].Mode != "compliance" {
		t.Errorf("expected compliance, got %s", statuses[0].Mode)
	}
}

func TestRetentionPolicyRegistry_Infos(t *testing.T) {
	d := &testRetentionDriver{}
	p1 := NewWORMRetentionPolicy(d, "compliance", 2557, nil)
	p2 := NewWORMRetentionPolicy(d, "governance", 30, nil)
	registry := NewRetentionPolicyRegistry(p1, p2)

	infos := registry.Infos()
	if len(infos) != 2 {
		t.Fatalf("expected 2 infos, got %d", len(infos))
	}
	if infos[0].Mode != "compliance" {
		t.Errorf("policy 0 mode = %q", infos[0].Mode)
	}
	if infos[1].Mode != "governance" {
		t.Errorf("policy 1 mode = %q", infos[1].Mode)
	}
}

// TestRetentionPolicyRegistry_ImplementsInterface is a compile-time check.
func TestRetentionPolicyRegistry_ImplementsInterface(t *testing.T) {
	var _ RetentionPolicy = NewWORMRetentionPolicy(nil, "compliance", 2557, nil)
}

// TestErrImmutable ensures the sentinel error exists.
func TestErrImmutable(t *testing.T) {
	if ErrImmutable == nil {
		t.Fatal("ErrImmutable must not be nil")
	}
	if !errors.Is(ErrImmutable, ErrImmutable) {
		t.Error("ErrImmutable must be a valid error")
	}
}
