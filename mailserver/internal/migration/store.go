package migration

import (
	"context"
	"io"

	"setjoin.com/mailserver/internal/storage"
)

// MigrationStore is the minimal storage contract a storage-backed migration
// step depends on: existence check, read, write, and a provider label for the
// migration record/logging. Consumer-defined (ISP): no list/copy/ping/retention.
//
// Method names mirror storage.Driver exactly so the consolidated drivers
// satisfy it structurally with no implementation change; storage.Driver is a
// superset, so NewDriver(...) results are assignable with no caller edit.
//
// DECLARED-CONTRACT-ONLY: no code in internal/migration currently holds a
// storage.Driver (the EWS/IMAP/M365 import clients fetch over the wire; the
// actual cross-driver blob move lives in storage.Migration). MigrationStore
// stands as the canonical contract for any future storage-backed migration
// step. The store_test.go subset assertion proves the consolidated drivers
// already satisfy it.
type MigrationStore interface {
	HeadObject(ctx context.Context, key string) (*storage.ObjectInfo, error)
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)
	PutObject(ctx context.Context, key string, data io.Reader, size int64) error
	ProviderName() string
}
