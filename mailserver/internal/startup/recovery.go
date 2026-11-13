package startup

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"setjoin.com/shared/pgxutil"
)

// RunDatabaseRecovery repairs cross-tenant crash residue before any listener
// or background worker can claim it. The reducer touches queue and mailbox
// state across tenants, so the distinct BYPASSRLS worker pool is mandatory.
func RunDatabaseRecovery(ctx context.Context, pool pgxutil.WorkerPool, logger *slog.Logger) error {
	var result json.RawMessage
	if err := pool.QueryRow(ctx, `SELECT startup_recovery()`).Scan(&result); err != nil {
		return fmt.Errorf("startup_recovery: %w", err)
	}
	logger.Info("database startup recovery completed", "result", string(result))
	SendRecoveryReport(ctx, pool.Pool, result, logger)
	return nil
}
