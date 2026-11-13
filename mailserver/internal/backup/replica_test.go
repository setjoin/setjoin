package backup

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/storage"
)

func TestEngine_ReplicaOptional(t *testing.T) {
	e := &Engine{replica: nil}
	if e.replica != nil {
		t.Error("replica should be nil when not configured")
	}
}

func TestEngine_ReplicaConfigured(t *testing.T) {
	d := &mockDriver{}
	e := &Engine{replica: d}
	if e.replica == nil {
		t.Error("replica should be non-nil when configured")
	}
}

func TestEngine_HasReplica(t *testing.T) {
	e := &Engine{replica: nil}
	if e.hasReplica() {
		t.Error("hasReplica should return false when replica is nil")
	}

	e.replica = &mockDriver{}
	if !e.hasReplica() {
		t.Error("hasReplica should return true when replica is set")
	}
}

// mockDriver implements storage.Driver for testing.
type mockDriver struct{}

func (d *mockDriver) PutObject(ctx context.Context, key string, data io.Reader, size int64) error {
	return nil
}
func (d *mockDriver) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}
func (d *mockDriver) DeleteObject(ctx context.Context, key string) error { return nil }
func (d *mockDriver) ListObjects(ctx context.Context, prefix string) ([]storage.ObjectInfo, error) {
	return nil, nil
}
func (d *mockDriver) HeadObject(ctx context.Context, key string) (*storage.ObjectInfo, error) {
	return nil, nil
}
func (d *mockDriver) EnsureBucket(ctx context.Context) error         { return nil }
func (d *mockDriver) BucketExists(ctx context.Context) (bool, error) { return false, nil }
func (d *mockDriver) ProviderName() string                           { return "mock" }
func (d *mockDriver) Endpoint() string                               { return "" }
func (d *mockDriver) CopyObject(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string) error {
	return nil
}
func (d *mockDriver) Ping(ctx context.Context) error { return nil }
func (d *mockDriver) StatObject(ctx context.Context, key string) (*storage.ObjectInfo, error) {
	return &storage.ObjectInfo{Key: key}, nil
}
func (d *mockDriver) PutObjectRetention(ctx context.Context, key, mode string, retainUntil time.Time) error {
	return nil
}
func (d *mockDriver) GetObjectRetention(ctx context.Context, key string) (*storage.RetentionStatus, error) {
	return &storage.RetentionStatus{}, nil
}
func (d *mockDriver) PutObjectLegalHold(ctx context.Context, key, status string) error { return nil }
func (d *mockDriver) GetObjectLegalHold(ctx context.Context, key string) (string, error) {
	return "OFF", nil
}
func (d *mockDriver) EnsureBucketObjectLock(ctx context.Context, mode string, retentionDays int) error {
	return nil
}
func (d *mockDriver) GetBucketObjectLockConfig(ctx context.Context) (*storage.BucketLockConfig, error) {
	return nil, nil
}
