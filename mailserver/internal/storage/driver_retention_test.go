package storage

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// TestDriverRetentionInterface verifies that the Driver interface includes
// all retention and legal-hold methods. This is a compile-time assertion.
func TestDriverRetentionInterface(t *testing.T) {
	// Compile-time check: a nil backupS3Driver pointer satisfies Driver
	// (which means all new methods are declared on the type).
	var _ Driver = (*backupS3Driver)(nil)
}

// TestRetentionErrors verifies sentinel errors used across the retention API.
func TestRetentionErrors(t *testing.T) {
	t.Run("ErrRetentionNotSupported", func(t *testing.T) {
		if ErrRetentionNotSupported == nil {
			t.Fatal("ErrRetentionNotSupported must not be nil")
		}
		if !errors.Is(ErrRetentionNotSupported, ErrRetentionNotSupported) {
			t.Error("ErrRetentionNotSupported must be a valid error")
		}
	})
	t.Run("ErrObjectLocked", func(t *testing.T) {
		if ErrObjectLocked == nil {
			t.Fatal("ErrObjectLocked must not be nil")
		}
	})
	t.Run("ErrLegalHoldActive", func(t *testing.T) {
		if ErrLegalHoldActive == nil {
			t.Fatal("ErrLegalHoldActive must not be nil")
		}
	})
}

// TestBucketLockConfig verifies the BucketLockConfig struct.
func TestBucketLockConfig(t *testing.T) {
	cfg := BucketLockConfig{
		Enabled:             true,
		Mode:                "compliance",
		RetentionPeriodDays: 2557,
	}
	if !cfg.Enabled {
		t.Error("Enabled should be true")
	}
	if cfg.Mode != "compliance" {
		t.Errorf("Mode = %q, want compliance", cfg.Mode)
	}
	if cfg.RetentionPeriodDays != 2557 {
		t.Errorf("RetentionPeriodDays = %d, want 2557", cfg.RetentionPeriodDays)
	}
}

// TestRetentionStatus verifies the RetentionStatus struct.
func TestRetentionStatus(t *testing.T) {
	now := time.Now().UTC()
	s := RetentionStatus{
		Mode:        "compliance",
		RetainUntil: now,
		LegalHold:   true,
	}
	if s.Mode != "compliance" {
		t.Errorf("Mode = %q, want compliance", s.Mode)
	}
	if !s.RetainUntil.Equal(now) {
		t.Errorf("RetainUntil = %v, want %v", s.RetainUntil, now)
	}
	if !s.LegalHold {
		t.Error("LegalHold should be true")
	}
}

// fakeRetentionDriver implements Driver with no-op retention methods for testing.
type fakeRetentionDriver struct{}

func (f *fakeRetentionDriver) PutObject(ctx context.Context, key string, data io.Reader, size int64) error {
	return nil
}
func (f *fakeRetentionDriver) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	return nil, nil
}
func (f *fakeRetentionDriver) DeleteObject(ctx context.Context, key string) error {
	return nil
}
func (f *fakeRetentionDriver) ListObjects(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	return nil, nil
}
func (f *fakeRetentionDriver) HeadObject(ctx context.Context, key string) (*ObjectInfo, error) {
	return nil, nil
}
func (f *fakeRetentionDriver) EnsureBucket(ctx context.Context) error {
	return nil
}
func (f *fakeRetentionDriver) BucketExists(ctx context.Context) (bool, error) {
	return true, nil
}
func (f *fakeRetentionDriver) ProviderName() string { return "fake" }
func (f *fakeRetentionDriver) Endpoint() string     { return "fake://" }
func (f *fakeRetentionDriver) CopyObject(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string) error {
	return nil
}
func (f *fakeRetentionDriver) Ping(ctx context.Context) error { return nil }
func (f *fakeRetentionDriver) StatObject(ctx context.Context, key string) (*ObjectInfo, error) {
	return &ObjectInfo{Key: key}, nil
}

// Retention method stubs — return not-supported by default.
func (f *fakeRetentionDriver) PutObjectRetention(ctx context.Context, key, mode string, retainUntil time.Time) error {
	return ErrRetentionNotSupported
}
func (f *fakeRetentionDriver) GetObjectRetention(ctx context.Context, key string) (*RetentionStatus, error) {
	return nil, ErrRetentionNotSupported
}
func (f *fakeRetentionDriver) PutObjectLegalHold(ctx context.Context, key, status string) error {
	return ErrRetentionNotSupported
}
func (f *fakeRetentionDriver) GetObjectLegalHold(ctx context.Context, key string) (string, error) {
	return "", ErrRetentionNotSupported
}
func (f *fakeRetentionDriver) EnsureBucketObjectLock(ctx context.Context, mode string, retentionDays int) error {
	return ErrRetentionNotSupported
}
func (f *fakeRetentionDriver) GetBucketObjectLockConfig(ctx context.Context) (*BucketLockConfig, error) {
	return nil, ErrRetentionNotSupported
}

// TestFakeRetentionDriverImplementsDriver ensures the fake implements Driver.
func TestFakeRetentionDriverImplementsDriver(t *testing.T) {
	var _ Driver = (*fakeRetentionDriver)(nil)
}

// TestFakeRetentionDriverReturnsNotSupported verifies the default behavior.
func TestFakeRetentionDriverReturnsNotSupported(t *testing.T) {
	d := &fakeRetentionDriver{}
	ctx := context.Background()

	t.Run("PutObjectRetention", func(t *testing.T) {
		err := d.PutObjectRetention(ctx, "test-key", "compliance", time.Now())
		if !errors.Is(err, ErrRetentionNotSupported) {
			t.Errorf("expected ErrRetentionNotSupported, got %v", err)
		}
	})
	t.Run("GetObjectRetention", func(t *testing.T) {
		_, err := d.GetObjectRetention(ctx, "test-key")
		if !errors.Is(err, ErrRetentionNotSupported) {
			t.Errorf("expected ErrRetentionNotSupported, got %v", err)
		}
	})
	t.Run("PutObjectLegalHold", func(t *testing.T) {
		err := d.PutObjectLegalHold(ctx, "test-key", "ON")
		if !errors.Is(err, ErrRetentionNotSupported) {
			t.Errorf("expected ErrRetentionNotSupported, got %v", err)
		}
	})
	t.Run("GetObjectLegalHold", func(t *testing.T) {
		_, err := d.GetObjectLegalHold(ctx, "test-key")
		if !errors.Is(err, ErrRetentionNotSupported) {
			t.Errorf("expected ErrRetentionNotSupported, got %v", err)
		}
	})
	t.Run("EnsureBucketObjectLock", func(t *testing.T) {
		err := d.EnsureBucketObjectLock(ctx, "compliance", 2557)
		if !errors.Is(err, ErrRetentionNotSupported) {
			t.Errorf("expected ErrRetentionNotSupported, got %v", err)
		}
	})
	t.Run("GetBucketObjectLockConfig", func(t *testing.T) {
		_, err := d.GetBucketObjectLockConfig(ctx)
		if !errors.Is(err, ErrRetentionNotSupported) {
			t.Errorf("expected ErrRetentionNotSupported, got %v", err)
		}
	})
}
