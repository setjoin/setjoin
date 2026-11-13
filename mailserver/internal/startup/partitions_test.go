package startup

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/testsupport"
)

// TestEnsureMonthlyPartitions_CoversAuditTables guards the regression that broke
// the authserver pgTAP suite: audit_log/auth_attempts/login_events are month-
// partitioned with NO default catch-all, so a missing month hard-fails every
// insert. The fixtures create only the CURRENT month, so the NEXT-month partition
// for these tables exists only if EnsureMonthlyPartitions ran for them — its
// absence means a table fell out of the ensure list.
func TestEnsureMonthlyPartitions_CoversAuditTables(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	if err := EnsureMonthlyPartitions(ctx, pool, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("EnsureMonthlyPartitions: %v", err)
	}

	next := time.Now().UTC().AddDate(0, 1, 0)
	suffix := time.Date(next.Year(), next.Month(), 1, 0, 0, 0, 0, time.UTC).Format("2006_01")

	for _, tbl := range []string{"audit_log", "auth_attempts", "login_events"} {
		part := tbl + "_" + suffix
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, part).Scan(&exists); err != nil {
			t.Fatalf("checking %s: %v", part, err)
		}
		if !exists {
			t.Errorf("EnsureMonthlyPartitions did not create next-month partition %s", part)
		}
	}
}

// TestEnsureMonthlyPartitions_FailClosed pins the STARTUP-INIT-FAIL-CLOSED
// contract: an Exec failure must surface as a returned error (so
// RunStartupChecks can refuse the boot), never be swallowed into a log line.
// Uses an unreachable DSN so no live DB is required — the dial fails fast.
func TestEnsureMonthlyPartitions_FailClosed(t *testing.T) {
	cfg, err := pgxpool.ParseConfig("postgres://setjoin_failclosed:test@127.0.0.1:1/none")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.ConnectTimeout = 2 * time.Second
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewWithConfig: %v", err)
	}
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = EnsureMonthlyPartitions(ctx, pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("EnsureMonthlyPartitions on unreachable DB = nil, want error (fail-closed)")
	}
}
