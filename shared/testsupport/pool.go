// Package testsupport centralizes DB-backed test setup so the
// connect-or-skip policy lives in ONE place across all modules — including the
// fail-closed behavior CI depends on.
//
// The bug this closes: CI ran `go test` with no Postgres/DB_DSN, so every
// DB-backed test t.Skip'd and CI was green while none of the data-layer or
// auth-critical adversarial tests actually executed. Each test package had its
// own copy-pasted "read DB_DSN, else t.Skip" helper, so the policy could not be
// fixed in one edit. OpenTestPool is that one edit: with REQUIRE_DB set (CI), a
// missing DB_DSN FAILS instead of silently skipping.
package testsupport

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/pgxutil"
)

// OpenTestPool returns a pgx pool to DB_DSN, registering a t.Cleanup to close it.
//
// When DB_DSN is unset:
//   - REQUIRE_DB set (any non-empty value, e.g. CI) → t.Fatal (FAIL-CLOSED: a
//     DB-backed test must never silently skip into a green CI run).
//   - otherwise → t.Skip (local-dev convenience when no Postgres is running).
func OpenTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is unset but REQUIRE_DB is set — fail-closed: a DB-backed test must not pass as a silent skip in CI")
		}
		t.Skip("DB_DSN not set — skipping DB-backed test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

// OpenTestPoolWithGUC returns a pgx pool to DB_DSN carrying the
// app.encryption_key GUC set via the SAME AfterConnect mechanism production
// pools use (pgxutil.OpenPool), so a _enc-column regression test exercises the
// real risk (a misconfigured pool) rather than a hand-rolled substitute.
//
// encryptionKey == "" opens a pool that never sets the GUC at all (simulates
// the hook being missing/bypassed — every pgp_sym_decrypt on that connection
// must fail closed, never return plaintext/NULL). A non-empty key that doesn't
// match the data's encryption key simulates a wrong-key misconfiguration.
//
// Shares OpenTestPool's fail-closed skip policy: DB_DSN unset + REQUIRE_DB set
// (CI) is a t.Fatal, not a silent skip — a GUC regression test skipping
// silently in CI is exactly the "coverage claims need a machine guard" gap
// this helper exists to close.
func OpenTestPoolWithGUC(t *testing.T, encryptionKey string) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is unset but REQUIRE_DB is set — fail-closed: a DB-backed test must not pass as a silent skip in CI")
		}
		t.Skip("DB_DSN not set — skipping DB-backed test")
	}
	pool, err := pgxutil.OpenPool(context.Background(), dsn, 5, encryptionKey, "")
	if err != nil {
		t.Fatalf("pgxutil.OpenPool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

// SetFeatureToggleForTest changes one database-backed feature toggle for the
// lifetime of a test and restores its exact prior value afterward. A
// session-level advisory lock keyed by the toggle serializes packages because
// `go test ./...` runs package processes concurrently against the same test
// database; without it, one package's cleanup can switch a feature off while
// another package is still exercising the enabled path.
func SetFeatureToggleForTest(t *testing.T, pool *pgxpool.Pool, key string, enabled bool) {
	t.Helper()
	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire feature-toggle test connection: %v", err)
	}
	if _, err := conn.Exec(ctx,
		`SELECT pg_advisory_lock(hashtextextended('test-feature-toggle:'||$1,0))`,
		key,
	); err != nil {
		conn.Release()
		t.Fatalf("lock feature toggle %q for test: %v", key, err)
	}

	var previous bool
	if err := conn.QueryRow(ctx,
		`SELECT enabled FROM feature_toggles WHERE key=$1`,
		key,
	).Scan(&previous); err != nil {
		_, _ = conn.Exec(ctx,
			`SELECT pg_advisory_unlock(hashtextextended('test-feature-toggle:'||$1,0))`,
			key,
		)
		conn.Release()
		t.Fatalf("read feature toggle %q for test: %v", key, err)
	}
	t.Cleanup(func() {
		cleanupCtx := context.Background()
		// Both cleanup errors are checked and FAIL the test
		// (D-SHARED-TESTSUPPORT-001): a swallowed restore error can leave a
		// flipped security toggle in the shared test database, and a swallowed
		// advisory-unlock error stalls every waiter on the per-toggle key —
		// either silently weakens the evidentiary value of a green run.
		// t.Cleanup runs even after t.Fatal, so a failure inside the test body
		// still restores (or at minimum reports) the drifted row.
		_, restoreErr := conn.Exec(cleanupCtx,
			`UPDATE feature_toggles SET enabled=$2,updated_at=statement_timestamp() WHERE key=$1`,
			key, previous,
		)
		_, unlockErr := conn.Exec(cleanupCtx,
			`SELECT pg_advisory_unlock(hashtextextended('test-feature-toggle:'||$1,0))`,
			key,
		)
		if restoreErr != nil {
			t.Errorf("restore feature toggle %q after test: %v — the shared test DB may hold the test's flipped value", key, restoreErr)
		}
		if unlockErr != nil {
			t.Errorf("unlock feature toggle %q after test: %v — other packages waiting on this advisory key may stall", key, unlockErr)
		}
		conn.Release()
	})

	if _, err := conn.Exec(ctx,
		`UPDATE feature_toggles SET enabled=$2,updated_at=statement_timestamp() WHERE key=$1`,
		key, enabled,
	); err != nil {
		t.Fatalf("set feature toggle %q for test: %v", key, err)
	}
}

// TestLogger returns a quiet (error-level) slog logger for tests — the other
// per-package helper that was copy-pasted everywhere.
func TestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}
