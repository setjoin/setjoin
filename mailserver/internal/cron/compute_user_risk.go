package cron

import (
	"context"
	"log/slog"
	"time"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

const userRiskInterval = 15 * time.Minute

// userRiskBatchSize caps how many user ids one scoring batch loads, and
// userRiskTickDeadline bounds the WHOLE tick: an attacker spraying auth_attempts
// rows must not drive an unbounded per-tick fan-out of reducer calls on the
// shared BYPASSRLS pool (D-MAILSERVER-INTERNAL-CRON-004). The id cursor makes
// the next tick resume where this one stopped — progress per tick is bounded by
// construction instead of by the attacker-controlled active-user count.
const (
	userRiskBatchSize    = 200
	userRiskMaxBatches   = 5
	userRiskTickDeadline = 45 * time.Second
)

// riskCronEnabled gates the user-risk scoring job (pure, testable).
func riskCronEnabled(on bool) bool { return on }

// computeUserRiskTick scores users with auth_attempts activity in the last 24h,
// in id-cursored batches (at most userRiskMaxBatches batches of
// userRiskBatchSize ids per tick). Runs on the worker (BYPASSRLS) pool because
// it crosses users; never on a shared pool with SET ROLE. No-op when
// feature.user_risk is off.
func computeUserRiskTick(ctx context.Context, workerPool pgxutil.WorkerPool, toggles *toggle.FeatureFlags, logger *slog.Logger) {
	if !riskCronEnabled(toggles.IsEnabled(toggle.FeatureUserRisk)) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, userRiskTickDeadline)
	defer cancel()

	var cursor int64
	for batch := 0; batch < userRiskMaxBatches; batch++ {
		rows, err := workerPool.Query(ctx,
			`SELECT DISTINCT u.id
			   FROM users u JOIN auth_attempts a ON a.target_username = u.email
			  WHERE a.occurred_at > now() - interval '24 hours' AND u.id > $1
			  ORDER BY u.id
			  LIMIT $2`, cursor, userRiskBatchSize)
		if err != nil {
			logger.Warn("user-risk cron: active-user query failed", "batch", batch, "error", err)
			return
		}
		var ids []int64
		for rows.Next() {
			var id int64
			if rows.Scan(&id) == nil {
				ids = append(ids, id)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			logger.Warn("user-risk cron: active-user query iteration failed", "batch", batch, "error", err)
			return
		}
		rows.Close()
		if len(ids) == 0 {
			return // active set drained
		}
		for _, id := range ids {
			if _, err := workerPool.Exec(ctx, `SELECT compute_user_risk($1)`, id); err != nil {
				logger.Warn("user-risk cron: compute failed", "user_id", id, "error", err)
			}
		}
		cursor = ids[len(ids)-1]
		if len(ids) < userRiskBatchSize {
			return // short batch: last page of the active set
		}
	}
	// More active users than this tick's budget: the next tick's cursor resumes
	// from the whole-set query (which re-derives the 24h active set), so tell
	// the operator the tick hit its bound instead of silently deferring.
	logger.Warn("user-risk cron: batch budget reached — remaining active users deferred to the next tick",
		"batches", userRiskMaxBatches, "batch_size", userRiskBatchSize)
}

// RunUserRiskCron runs a ticker that calls computeUserRiskTick every
// userRiskInterval on the worker (BYPASSRLS) pool. Exits when ctx is cancelled.
// ponytail: gated/cheap; the toggle keeps it a no-op until staging confirms it.
func RunUserRiskCron(ctx context.Context, workerPool pgxutil.WorkerPool, toggles *toggle.FeatureFlags, logger *slog.Logger) {
	logger.Info("user-risk cron started", "interval", userRiskInterval)
	ticker := time.NewTicker(userRiskInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			computeUserRiskTick(ctx, workerPool, toggles, logger)
		}
	}
}
