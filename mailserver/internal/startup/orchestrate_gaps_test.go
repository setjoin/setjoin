package startup

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/minio/minio-go/v7"

	"setjoin.com/mailserver/internal/config"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// quietLogger discards the deliberate Error lines the fail-closed arms emit.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// deadMinioClient builds a client whose endpoint is a closed local port:
// construction succeeds (lazy), every operation fails fast.
func deadMinioClient(t *testing.T) *minio.Client {
	t.Helper()
	mc, err := minio.New("127.0.0.1:1", &minio.Options{})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}
	return mc
}

// TestEnsureWormBucket_UnreachableEndpointFailsClosed pins the WORM
// bootstrap probe: a bucket-existence check that cannot reach the store
// fails the bootstrap (never create blind, never continue WORM-less).
func TestEnsureWormBucket_UnreachableEndpointFailsClosed(t *testing.T) {
	err := ensureWormBucket(context.Background(), deadMinioClient(t), "worm-probe-bucket", quietLogger())
	if err == nil {
		t.Fatal("ensureWormBucket against an unreachable store = nil error, want probe failure")
	}
}

// TestRunStartupChecks_PartitionFailureRefusesBoot pins the fail-closed
// partition arm: when the monthly partition ensure cannot run, startup
// initialization returns the error instead of continuing the boot.
func TestRunStartupChecks_PartitionFailureRefusesBoot(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ownerPool := testsupport.OpenTestPool(t)
	ownerPool.Close()

	cfg := &config.Config{}
	_, err := RunStartupChecks(
		context.Background(),
		cfg,
		pool,
		pgxutil.WorkerPool{Pool: pool},
		ownerPool,
		nil,
		quietLogger(),
	)
	if err == nil {
		t.Fatal("RunStartupChecks with unusable owner pool = nil error, want partition-init failure")
	}
}

// TestRunStartupChecks_WORMBootstrapFailureRefusesBoot pins the WORM arm:
// a configured WORM mode whose bucket cannot be probed refuses the boot.
func TestRunStartupChecks_WORMBootstrapFailureRefusesBoot(t *testing.T) {
	pool := testsupport.OpenTestPool(t)

	cfg := &config.Config{
		WORMMode: "governance",
		S3Bucket: "worm-gap-bucket",
	}
	_, err := RunStartupChecks(
		context.Background(),
		cfg,
		pool,
		pgxutil.WorkerPool{Pool: pool},
		pool,
		deadMinioClient(t),
		quietLogger(),
	)
	if err == nil {
		t.Fatal("RunStartupChecks with unreachable MinIO under WORM = nil error, want bootstrap failure")
	}
}
