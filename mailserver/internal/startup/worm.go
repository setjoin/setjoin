package startup

import (
	"context"
	"fmt"
	"log/slog"

	"setjoin.com/mailserver/internal/config"
	"setjoin.com/mailserver/internal/storage"
)

// InitWORM initializes WORM (Write Once Read Many) immutability if configured.
// When WORM_MODE is empty, WORM is disabled and the function returns nil.
// When WORM_MODE is set, it validates configuration, ensures the storage bucket
// has Object Lock enabled, and returns a RetentionPolicyRegistry for blob writes.
func InitWORM(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*storage.RetentionPolicyRegistry, error) {
	if cfg.WORMMode == "" {
		logger.Info("WORM immutability: disabled (WORM_MODE not set)")
		return nil, nil
	}

	if err := storage.ValidateWORMConfig(cfg.WORMMode, cfg.WORMRetentionDays); err != nil {
		logger.Error("WORM configuration invalid", "error", err)
		return nil, err
	}

	primaryDriver, err := storage.NewDriver(storage.DriverConfig{
		Endpoint:  cfg.S3Endpoint,
		Bucket:    cfg.S3Bucket,
		AccessKey: cfg.S3AccessKey,
		SecretKey: cfg.S3SecretKey,
		// WORM/legal-hold traffic honors the same transport-TLS posture as the
		// blob hot path (D-MAILSERVER-INTERNAL-STORAGE-F-001): previously this
		// driver was hardcoded plaintext even with S3_SECURE=true.
		Secure:                  &cfg.S3Secure,
		ObjectLockMode:          cfg.WORMMode,
		ObjectLockRetentionDays: cfg.WORMRetentionDays,
	})
	if err != nil {
		logger.Error("WORM storage driver init failed", "error", err)
		return nil, err
	}

	// WORM is a configured mandate, so the backend MUST advertise the Retention
	// capability. Detect its absence explicitly here instead of letting an
	// ErrRetentionNotSupported leak out of a later object-lock call.
	retention, ok := storage.RetentionOf(primaryDriver)
	if !ok {
		err := fmt.Errorf("storage backend %q does not support WORM/Object Lock retention", primaryDriver.ProviderName())
		logger.Error("WORM is configured but the storage backend cannot enforce immutability — gateway cannot start",
			"error", err,
			"provider", primaryDriver.ProviderName(),
			"fix", "Use an Object-Lock-capable backend (S3 with Object Lock, or POSIX on Linux), or unset WORM_MODE.")
		return nil, err
	}

	if err := retention.EnsureBucketObjectLock(ctx, cfg.WORMMode, cfg.WORMRetentionDays); err != nil {
		logger.Error("WORM startup check failed — gateway cannot start without compliant storage",
			"error", err,
			"fix", "Create the blob bucket with Object Lock enabled in "+cfg.WORMMode+" mode, then restart.")
		return nil, err
	}

	if storage.RetentionDaysBelowMinimum(cfg.WORMRetentionDays) {
		logger.Warn("WORM retention is below the regulatory minimum of 2557 days (7 years) — "+
			"this may not satisfy SEC 17a-4(f) / FINRA 4511(c) requirements",
			"configured_days", cfg.WORMRetentionDays)
	}

	wormPolicy := storage.NewWORMRetentionPolicy(retention, cfg.WORMMode, cfg.WORMRetentionDays, nil)
	registry := storage.NewRetentionPolicyRegistry(wormPolicy)
	registry.SetLegalHoldBackend(retention, cfg.WORMLegalHoldEnabled)
	logger.Info("WORM immutability: active", "mode", cfg.WORMMode, "retention_days", cfg.WORMRetentionDays,
		"legal_hold_enabled", cfg.WORMLegalHoldEnabled)
	return registry, nil
}
