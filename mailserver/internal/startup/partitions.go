package startup

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureMonthlyPartitions ensures the current and next month's range partitions
// exist for every month-partitioned table by calling the catalog-derived
// create_monthly_partitions(1) reducer (offsets 0..1 = current + next month).
//
// Ownership split: boot (this call, on the OWNER pool — see RunStartupChecks —
// so new partitions are owner-owned) guarantees both months exist on every
// start; the cron create-monthly-partitions task (25th) keeps the window
// rolling on long-running gateways. Both route through the ONE reducer, which
// derives the table set from pg_partitioned_table — no Go list to drift.
// audit_log/auth_attempts/login_events have NO default catch-all, so a missing
// month HARD-FAILS the insert ("no partition of relation ... found for row")
// and breaks audit + auth-attempt logging; messages/message_trace carry a
// DEFAULT so a missing partition only loses pruning. Neither path depends on
// pg_cron.
//
// Fail-closed initialization (STARTUP-INIT-FAIL-CLOSED): the error is returned
// so RunStartupChecks refuses the boot. Log-and-continue left the gateway
// serving traffic while its audit/auth write path was scheduled to break at the
// next month boundary, discoverable only from this one boot log line.
func EnsureMonthlyPartitions(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) error {
	if _, err := pool.Exec(ctx, `SELECT create_monthly_partitions(1)`); err != nil {
		logger.Error("startup: create_monthly_partitions failed — audit/auth inserts will hard-fail once a month boundary passes without its partition",
			"error", err)
		return fmt.Errorf("ensure monthly partitions: %w", err)
	}
	logger.Info("monthly partitions ready (current + next month, catalog-derived)")
	return nil
}
