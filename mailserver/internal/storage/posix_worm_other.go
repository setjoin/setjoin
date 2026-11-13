//go:build !linux

package storage

import (
	"context"
	"time"
)

func (d *posixDriver) isImmutable(path string) bool {
	return false
}

func (d *posixDriver) PutObjectRetention(_ context.Context, key, mode string, retainUntil time.Time) error {
	return ErrRetentionNotSupported
}

func (d *posixDriver) GetObjectRetention(_ context.Context, key string) (*RetentionStatus, error) {
	return &RetentionStatus{}, nil
}

func (d *posixDriver) PutObjectLegalHold(_ context.Context, key, status string) error {
	return ErrRetentionNotSupported
}

func (d *posixDriver) GetObjectLegalHold(_ context.Context, key string) (string, error) {
	return "OFF", nil
}

func (d *posixDriver) EnsureBucketObjectLock(_ context.Context, _ string, _ int) error {
	return ErrRetentionNotSupported
}

func (d *posixDriver) GetBucketObjectLockConfig(_ context.Context) (*BucketLockConfig, error) {
	return &BucketLockConfig{Enabled: false}, nil
}
