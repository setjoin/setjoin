package booking

import (
	"context"
	"log/slog"
	"time"

	"setjoin.com/shared/pgxutil"
)

// Sweeper calls booking_expire_due on a ticker to expire overdue pending
// (never-verified) booking requests. Copies the approvaljobs.Worker skeleton
// exactly — same lifecycle, same "one reducer call on a ticker" shape.
const sweepInterval = 10 * time.Minute

type Sweeper struct {
	pool   pgxutil.WorkerPool
	logger *slog.Logger
}

// NewSweeper creates a Sweeper. Runs on the workerPool (BYPASSRLS) — the
// expiry sweep is cross-tenant by nature (every pending request, any page).
func NewSweeper(pool pgxutil.WorkerPool, logger *slog.Logger) *Sweeper {
	return &Sweeper{pool: pool, logger: logger}
}

// Run starts the ticker loop. It exits cleanly when ctx is cancelled.
func (s *Sweeper) Run(ctx context.Context) {
	s.logger.Info("booking sweeper started", "interval", sweepInterval)
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("booking sweeper stopped")
			return
		case <-ticker.C:
			var n int
			if err := s.pool.QueryRow(ctx, `SELECT booking_expire_due()`).Scan(&n); err != nil {
				s.logger.Error("booking sweeper: booking_expire_due failed", "error", err)
				continue
			}
			if n > 0 {
				s.logger.Info("booking sweeper: expired pending requests", "count", n)
			}
		}
	}
}
