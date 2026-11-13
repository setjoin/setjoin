package storage

import (
	"context"
	"io"
	"testing"
	"time"
)

// objectIOSurface mirrors the object-I/O methods every storage path consumes
// THROUGH the Driver type after retention was segregated out of Driver:
//   - ProviderName / HeadObject / GetObject / PutObject — migration orchestrator
//     (blobMover, via admin_storage_migrate.go) + the data-mover consumers.
//
// Asserting NewDriver's return satisfies this surface guards against
// over-narrowing Driver below what the factory/data-mover callers require.
type objectIOSurface interface {
	ProviderName() string
	HeadObject(ctx context.Context, key string) (*ObjectInfo, error)
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)
	PutObject(ctx context.Context, key string, data io.Reader, size int64) error
}

// retentionSurface mirrors the WORM/admin methods now reached via the
// SEGREGATED Retention capability (obtained from a Driver with RetentionOf),
// not through the Driver type:
//   - EnsureBucketObjectLock / GetBucketObjectLockConfig — startup/worm.go + StartupWORMCheck
//   - PutObjectRetention / GetObjectRetention             — WORMRetentionPolicy Apply/Verify/Release
type retentionSurface interface {
	PutObjectRetention(ctx context.Context, key, mode string, retainUntil time.Time) error
	GetObjectRetention(ctx context.Context, key string) (*RetentionStatus, error)
	EnsureBucketObjectLock(ctx context.Context, mode string, retentionDays int) error
	GetBucketObjectLockConfig(ctx context.Context) (*BucketLockConfig, error)
}

func TestNewDriver_SatisfiesObjectIOSurface(t *testing.T) {
	d, err := NewDriver(DriverConfig{Provider: "posix", Bucket: t.TempDir()})
	if err != nil {
		t.Fatalf("NewDriver(posix): %v", err)
	}
	var _ objectIOSurface = d // Driver carries the object-I/O surface
}

func TestNewDriver_RetentionViaCapability(t *testing.T) {
	d, err := NewDriver(DriverConfig{Provider: "posix", Bucket: t.TempDir()})
	if err != nil {
		t.Fatalf("NewDriver(posix): %v", err)
	}

	// Retention is NOT on the Driver type — it is obtained as a capability.
	r, ok := RetentionOf(d)
	if !ok {
		t.Fatal("RetentionOf(posix driver): want capability present")
	}
	var _ retentionSurface = r // the capability carries the WORM/admin surface

	// WORMRetentionPolicy must compile against the Retention-typed value.
	_ = NewWORMRetentionPolicy(r, "governance", 1, nil)
}
