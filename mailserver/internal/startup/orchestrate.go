package startup

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/config"
	"setjoin.com/mailserver/internal/storage"
	"setjoin.com/shared/pgxutil"
)

// RunStartupChecks runs the boot-time recovery + first-boot bootstrap steps in
// their mandatory order: ensure the current + next month's partitions (so
// delivery/audit never depend on pg_cron — fatal on failure so the audit write
// path cannot silently break at the next month boundary), abort stale
// multiparts from a prior crash, WORM-aware bucket bootstrap, ping MinIO, WORM
// init, and secret bootstrap. Extracted from mailserverd's runGateway
// (arch A5 — shrinking the ~2,470-line boot monolith); the partition-ensure and
// WORM-first-boot steps are fail-closed (a partition-creation failure or a
// lock-less-bucket hazard refuses the boot instead of degrading silently).
func RunStartupChecks(
	ctx context.Context,
	cfg *config.Config,
	pool *pgxpool.Pool,
	workerPool pgxutil.WorkerPool,
	ownerPool *pgxpool.Pool,
	minioClient *minio.Client,
	logger *slog.Logger,
) (*storage.RetentionPolicyRegistry, error) {
	// Native-RLS boot check FIRST: refuse to boot if the runtime role can silently
	// bypass tenant isolation (BYPASSRLS/SUPERUSER on the app role, or the app role
	// owns a FORCE'd table → owner-bypass). Runs on the customer's own cluster,
	// where the CI coverage guard + rls_role_model.pg cannot. Inert (self-skips) on
	// the pre-flip superuser identity. Fail-closed: downtime beats silent leakage.
	if err := AssertRLSRoleInvariants(ctx, pool, logger); err != nil {
		logger.Error("native-RLS boot check FAILED — refusing to start", "error", err)
		os.Exit(1)
	}

	if err := EnsureMonthlyPartitions(ctx, ownerPool, logger); err != nil {
		// Fail-closed initialization: the audit/auth write path must not be left
		// silently scheduled to break at the next month boundary (STARTUP-INIT-
		// FAIL-CLOSED). Downtime beats an audit trail that stops on a roll-over.
		logger.Error("monthly partition ensure failed — refusing to start", "error", err)
		return nil, err
	}

	if err := RunDatabaseRecovery(ctx, workerPool, logger); err != nil {
		logger.Error("database startup recovery failed — refusing to start", "error", err)
		return nil, err
	}

	// WORM-aware bucket bootstrap (creation-time immutability): PingMinIO's
	// convenience MakeBucket below is lock-less, so on a WORM-configured first
	// boot the blob bucket must be created with Object Lock enabled BEFORE that
	// path can run. Otherwise a fresh install self-inflicts a lock-less bucket
	// and defers the immutability guarantee to post-hoc lock enablement, which
	// strict S3 semantics refuse (STARTUP-003 initialization-order defect).
	if cfg.WORMMode != "" {
		if err := ensureWormBucket(ctx, minioClient, cfg.S3Bucket, logger); err != nil {
			logger.Error("WORM bucket bootstrap failed — refusing to start", "error", err)
			return nil, err
		}
	}

	if err := AbortStaleMultiparts(ctx, minioClient, cfg.S3Bucket, logger); err != nil {
		// Non-fatal: log and continue. Orphaned parts are cleaned up by the pg_cron orphan job too.
		logger.Warn("startup: stale multipart abort encountered errors", "error", err)
	}

	if err := PingMinIO(ctx, minioClient, cfg.S3Bucket, pool, logger); err != nil {
		logger.Warn("startup: MinIO ping failed — blobs unavailable until MinIO is reachable", "error", err)
	}

	retentionRegistry, err := InitWORM(ctx, cfg, logger)
	if err != nil {
		return nil, err
	}

	configPath := filepath.Join(cfg.ConfigDir, "config.env")
	if envPath := os.Getenv("CONFIG_PATH"); envPath != "" {
		configPath = envPath
	}
	if err := BootstrapSecrets(configPath, false); err != nil {
		logger.Error("secret bootstrap failed", "error", err)
		os.Exit(1)
	}

	return retentionRegistry, nil
}

// ensureWormBucket creates the blob bucket with Object Lock enabled when it is
// missing on a WORM-configured boot. S3 semantics make Object Lock a
// creation-time bucket property: a bucket created lock-less can never fully
// regain creation-time immutability, so WORM first-run creation must not go
// through the lock-less convenience path. An existing bucket is left untouched
// — applying bucket-default retention to it stays InitWORM's (operator-visible,
// fail-closed) job.
func ensureWormBucket(ctx context.Context, mc *minio.Client, bucket string, logger *slog.Logger) error {
	exists, err := mc.BucketExists(ctx, bucket)
	if err != nil {
		return fmt.Errorf("probe bucket %q for WORM bootstrap: %w", bucket, err)
	}
	if exists {
		return nil
	}
	logger.Info("WORM-configured first boot: creating blob bucket with Object Lock enabled", "bucket", bucket)
	if err := mc.MakeBucket(ctx, bucket, minio.MakeBucketOptions{ObjectLocking: true}); err != nil {
		return fmt.Errorf("create bucket %q with Object Lock: %w", bucket, err)
	}
	return nil
}
