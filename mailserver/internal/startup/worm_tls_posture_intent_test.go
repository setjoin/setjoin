package startup

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/config"
)

// TestInitWORM_TransportIntentVerdicts pins the residual transport-intent arm
// of the WORM driver leg (med-startup-transport-intent-b1r2-008): InitWORM must
// honor S3_SECURE in BOTH directions and fail startup with the RESOLVER's
// transport verdict, not an incidental downstream I/O error. The existing
// TestInitWORM_TLSPosture asserts only err != nil with S3Secure=false, which a
// constant or nil Secure wiring could satisfy vacuously via a network error;
// the message assertions here make those regressions non-vacuous:
//
//   - Secure wired to a constant false  → case 1 constructs plaintext and
//     dials instead of returning the explicit-true conflict verdict.
//   - Secure wired to a constant true   → case 2 resolves TLS for the
//     scheme-less remote and dials instead of returning the plaintext
//     fail-closed verdict.
//   - Secure wired to nil               → case 1 derives plaintext and dials.
//
// Both verdicts fire inside storage.NewDriver before any network I/O, so the
// happy-path TLS posture itself stays pinned by the storage package matrix.
func TestInitWORM_TransportIntentVerdicts(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	t.Run("loopback http with S3_SECURE=true is a startup conflict verdict", func(t *testing.T) {
		// Only reachable when the TRUE value flows from cfg.S3Secure into
		// DriverConfig.Secure — the arm that pins operator TLS intent.
		cfg := &config.Config{
			WORMMode:          "governance",
			WORMRetentionDays: 2557,
			S3Endpoint:        "http://127.0.0.1:9000",
			S3Bucket:          "blobs",
			S3AccessKey:       "k",
			S3SecretKey:       "s",
			S3Secure:          true,
		}
		registry, err := InitWORM(ctx, cfg, logger)
		if err == nil {
			t.Fatal("InitWORM with http endpoint and S3_SECURE=true succeeded, want conflict rejection")
		}
		if !strings.Contains(err.Error(), "contradictory transport config") {
			t.Fatalf("InitWORM error %q is not the resolver's transport verdict (a later I/O error means S3_SECURE=true was not honored)", err)
		}
		if registry != nil {
			t.Fatal("registry must be nil on rejection")
		}
	})

	t.Run("scheme-less remote with S3_SECURE=false fails with the plaintext verdict", func(t *testing.T) {
		cfg := &config.Config{
			WORMMode:          "governance",
			WORMRetentionDays: 2557,
			S3Endpoint:        "minio.internal:9000",
			S3Bucket:          "blobs",
			S3AccessKey:       "k",
			S3SecretKey:       "s",
			S3Secure:          false,
		}
		_, err := InitWORM(ctx, cfg, logger)
		if err == nil {
			t.Fatal("InitWORM with scheme-less remote endpoint succeeded, want fail-closed rejection")
		}
		if !strings.Contains(err.Error(), "PLAINTEXT") {
			t.Fatalf("InitWORM error %q is not the resolver's fail-closed plaintext verdict (a later I/O error means the posture was derived, not asserted)", err)
		}
	})
}
