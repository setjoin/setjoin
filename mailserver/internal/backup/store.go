package backup

import (
	"context"
	"io"

	"setjoin.com/mailserver/internal/storage"
)

// BackupStore is the storage contract the backup engine depends on:
// idempotent existence check, read, write, and a provider label for logging.
// Consumer-defined (ISP): no ListObjects / EnsureBucket / Ping / StatObject /
// CopyObject — and, since the segregation of WORM out of storage.Driver, no
// retention ops either: the backup engine copies blobs to the backup target but
// never sets per-object retention itself (the WORM mandate is enforced on the
// PRIMARY blob bucket by storage.WORMRetentionPolicy, and on the backup bucket
// by the backup-S3 driver's bucket-level Object Lock + PutObject-time retention).
// Dropping retentionOps keeps BackupStore a pure subset of storage.Driver, so
// storage.NewDriver(...) results remain assignable with no caller edit.
//
// Method names mirror storage.Driver exactly so the consolidated drivers
// satisfy it structurally with no implementation change.
type BackupStore interface {
	HeadObject(ctx context.Context, key string) (*storage.ObjectInfo, error)
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)
	PutObject(ctx context.Context, key string, data io.Reader, size int64) error
	// DeleteObject removes a manifest/config index object during GFS retention.
	// (storage.Driver already provides it — a pure subset, so NewDriver results
	// stay assignable.) Retention deletes only index objects, never blobs.
	DeleteObject(ctx context.Context, key string) error
	ProviderName() string
}
