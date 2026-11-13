package restore

import (
	"context"
	"io"

	"setjoin.com/mailserver/internal/storage"
)

// RestoreStore is the minimal storage contract restore depends on: check
// existence in primary, read from backup, write to primary. Consumer-defined
// (ISP): restore never lists, copies, pings, or touches retention.
//
// Method names mirror storage.Driver exactly so the consolidated drivers
// satisfy it structurally with no implementation change; storage.Driver is a
// superset, so NewDriver(...) results are assignable with no caller edit.
type RestoreStore interface {
	HeadObject(ctx context.Context, key string) (*storage.ObjectInfo, error)
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)
	PutObject(ctx context.Context, key string, data io.Reader, size int64) error
}
