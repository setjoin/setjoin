package startup

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"setjoin.com/mailserver/internal/config"
)

// TestInitWORM_TLSPosture pins the WORM/legal-hold leg of the storage TLS
// matrix (D-MAILSERVER-INTERNAL-STORAGE-F-001): InitWORM builds its primary
// driver with Secure wired to cfg.S3Secure, so the resolver's fail-closed
// verdicts fire BEFORE any network I/O. Only pre-network construction
// outcomes are asserted here — the happy-path posture is covered by the
// storage package matrix.
func TestInitWORM_TLSPosture(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	t.Run("WORM_MODE empty stays disabled", func(t *testing.T) {
		cfg := &config.Config{S3Endpoint: "minio.internal:9000"}
		registry, err := InitWORM(ctx, cfg, logger)
		if err != nil || registry != nil {
			t.Fatalf("InitWORM = (%v, %v), want (nil, nil)", registry, err)
		}
	})

	t.Run("scheme-less remote endpoint rejected fail-closed before any I/O", func(t *testing.T) {
		cfg := &config.Config{
			WORMMode:             "governance",
			WORMRetentionDays:    2557,
			S3Endpoint:           "minio.internal:9000",
			S3Bucket:             "blobs",
			S3AccessKey:          "k",
			S3SecretKey:          "s",
			S3Secure:             false, // the historical insecure default
			WORMLegalHoldEnabled: false,
		}
		registry, err := InitWORM(ctx, cfg, logger)
		if err == nil {
			t.Fatal("InitWORM with scheme-less remote endpoint succeeded, want fail-closed rejection")
		}
		if registry != nil {
			t.Fatal("registry must be nil on rejection")
		}
	})

	t.Run("https endpoint with S3_SECURE=false is a rejected conflict", func(t *testing.T) {
		// This verdict is only reachable because worm.go wires Secure to
		// &cfg.S3Secure — a nil Secure would silently derive TLS instead.
		cfg := &config.Config{
			WORMMode:          "governance",
			WORMRetentionDays: 2557,
			S3Endpoint:        "https://minio.internal:9000",
			S3Bucket:          "blobs",
			S3AccessKey:       "k",
			S3SecretKey:       "s",
			S3Secure:          false,
		}
		if _, err := InitWORM(ctx, cfg, logger); err == nil {
			t.Fatal("InitWORM with https endpoint and S3_SECURE=false succeeded, want conflict rejection")
		}
	})
}
