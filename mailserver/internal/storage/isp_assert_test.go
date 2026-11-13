package storage

import (
	"context"
	"io"
	"testing"
	"time"
)

// Mirror of the consumer interfaces, declared locally to avoid an import
// cycle (blob/backup/restore/migration all import storage). These MUST stay
// in sync with blob.BlobStore / backup.BackupStore / restore.RestoreStore /
// migration.MigrationStore and the in-package blobMover. The subset
// assertions in the consumer packages (vs the value NewDriver returns) catch
// real drift; this file proves the concrete unexported drivers carry the
// methods. Test-only: adds no production coupling.

type mirrorBlobStore interface { // blob.BlobStore
	PutObject(ctx context.Context, key string, data io.Reader, size int64) error
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)
	DeleteObject(ctx context.Context, key string) error
	CopyObject(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string) error
}

type mirrorMoverStore interface { // restore.RestoreStore core (Head/Get/Put)
	HeadObject(ctx context.Context, key string) (*ObjectInfo, error)
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)
	PutObject(ctx context.Context, key string, data io.Reader, size int64) error
}

type mirrorProviderMover interface { // migration.MigrationStore + storage.blobMover
	ProviderName() string
	HeadObject(ctx context.Context, key string) (*ObjectInfo, error)
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)
	PutObject(ctx context.Context, key string, data io.Reader, size int64) error
}

type mirrorRetention interface { // backup.BackupStore retention sub-interface
	PutObjectRetention(ctx context.Context, key, mode string, retainUntil time.Time) error
	GetObjectRetention(ctx context.Context, key string) (*RetentionStatus, error)
	PutObjectLegalHold(ctx context.Context, key, status string) error
	GetObjectLegalHold(ctx context.Context, key string) (string, error)
}

// TestConcreteDrivers_SatisfyConsumerMirrors proves every concrete (unexported)
// driver carries the method sets each consumer interface declares. Compile-time
// only; the body is intentionally empty.
func TestConcreteDrivers_SatisfyConsumerMirrors(_ *testing.T) {
	var (
		_ mirrorBlobStore = (*s3HotDriver)(nil)
		_ mirrorBlobStore = (*backupS3Driver)(nil)
		_ mirrorBlobStore = (*posixDriver)(nil)
		_ mirrorBlobStore = (*ossDriver)(nil)

		_ mirrorMoverStore = (*s3HotDriver)(nil)
		_ mirrorMoverStore = (*backupS3Driver)(nil)
		_ mirrorMoverStore = (*posixDriver)(nil)
		_ mirrorMoverStore = (*ossDriver)(nil)

		_ mirrorProviderMover = (*s3HotDriver)(nil)
		_ mirrorProviderMover = (*backupS3Driver)(nil)
		_ mirrorProviderMover = (*posixDriver)(nil)
		_ mirrorProviderMover = (*ossDriver)(nil)

		_ mirrorRetention = (*s3HotDriver)(nil)
		_ mirrorRetention = (*backupS3Driver)(nil)
		_ mirrorRetention = (*posixDriver)(nil) // posix has stubs (ErrRetentionNotSupported on non-linux)
		_ mirrorRetention = (*ossDriver)(nil)
	)
}
