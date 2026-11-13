package startup

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
)

// PingMinIO verifies MinIO is reachable and the blob bucket exists.
// Creates the bucket if it is missing (first-run convenience).
// Writes the result to health_history so the health dashboard reflects MinIO state
// from the very first check cycle.
func PingMinIO(ctx context.Context, mc *minio.Client, bucket string, pool *pgxpool.Pool, logger *slog.Logger) error {
	exists, err := mc.BucketExists(ctx, bucket)

	status := "ok"
	details := fmt.Sprintf("MinIO reachable, bucket %q exists", bucket)

	switch {
	case err != nil:
		status = "error"
		details = fmt.Sprintf("MinIO ping failed: %v", err)
	case !exists:
		logger.Info("blob bucket missing, creating", "bucket", bucket)
		if mkErr := mc.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); mkErr != nil {
			status = "error"
			details = fmt.Sprintf("MinIO reachable but bucket %q creation failed: %v", bucket, mkErr)
			err = mkErr
		} else {
			details = fmt.Sprintf("MinIO reachable, bucket %q created on first run", bucket)
		}
	}

	if _, dbErr := pool.Exec(ctx,
		`INSERT INTO health_history (check_name, status, details) VALUES ($1, $2, $3)`,
		"minio_connectivity", status, details,
	); dbErr != nil {
		logger.Warn("failed to record MinIO health check in health_history", "error", dbErr)
	}

	if err != nil {
		return fmt.Errorf("minio startup ping: %w", err)
	}
	logger.Info("MinIO startup check passed", "bucket", bucket)
	return nil
}

// AbortStaleMultiparts aborts any incomplete MinIO multipart uploads older than one hour.
// These are left over from gateway crashes that occurred mid-upload. Aborting them
// reclaims MinIO storage and prevents orphaned parts accumulating over time.
func AbortStaleMultiparts(ctx context.Context, mc *minio.Client, bucket string, logger *slog.Logger) error {
	cutoff := time.Now().Add(-time.Hour)
	aborted := 0

	for upload := range mc.ListIncompleteUploads(ctx, bucket, "", true) {
		if upload.Err != nil {
			return fmt.Errorf("list incomplete uploads: %w", upload.Err)
		}
		if !upload.Initiated.Before(cutoff) {
			continue
		}
		if err := mc.RemoveIncompleteUpload(ctx, bucket, upload.Key); err != nil {
			logger.Warn("failed to abort stale multipart upload",
				"key", upload.Key,
				"initiated_at", upload.Initiated,
				"error", err,
			)
			continue
		}
		aborted++
		logger.Info("aborted stale multipart upload",
			"key", upload.Key,
			"initiated_at", upload.Initiated,
			"age_hours", time.Since(upload.Initiated).Hours(),
		)
	}

	if aborted > 0 {
		logger.Info("startup: aborted stale MinIO multipart uploads", "count", aborted)
	}
	return nil
}
