// Package notifyjobs drains the notify_intents queue (V088, NOTIFY decouple).
//
// When feature.notify_decouple is ON, app_notify writes a durable intent row
// inside the reducer transaction instead of calling pg_notify in the hot
// commit (each NOTIFY at commit takes a DB-wide AccessExclusiveLock on the
// notify queue). This worker emits the real pg_notify on its own short
// transactions, moving that lock off the write path without changing reducer
// semantics. Toggle OFF = the table stays empty and every tick is one no-op
// DELETE — so the worker runs unconditionally (it also drains any residue
// left behind when the toggle is flipped back off).
//
// Runs once at startup on the workerPool (BYPASSRLS is irrelevant here — the
// table has no RLS — but the queue is cross-tenant, so the worker pool is the
// right home). SKIP LOCKED keeps concurrent replicas from double-notifying.
package notifyjobs

import (
	"context"
	"log/slog"
	"time"

	"setjoin.com/shared/pgxutil"
)

const (
	drainInterval = time.Second
	batchSize     = 500
)

// Worker polls notify_intents and re-emits each intent as a pg_notify.
type Worker struct {
	pool   pgxutil.WorkerPool
	logger *slog.Logger
}

// NewWorker creates a Worker that will drain the notify_intents queue.
func NewWorker(pool pgxutil.WorkerPool, logger *slog.Logger) *Worker {
	return &Worker{pool: pool, logger: logger}
}

// Run starts the ticker loop. It exits cleanly when ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	w.logger.Info("notify drain worker started", "interval", drainInterval)
	ticker := time.NewTicker(drainInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("notify drain worker stopped")
			return
		case <-ticker.C:
			// Drain full batches before waiting for the next tick.
			for {
				n, err := w.drainOnce(ctx)
				if err != nil {
					if ctx.Err() == nil {
						w.logger.Warn("notifyjobs: drain failed", "error", err)
					}
					break
				}
				if n < batchSize {
					break
				}
			}
		}
	}
}

// drainOnce deletes up to batchSize intents and fires their pg_notify in ONE
// short transaction — the NOTIFYs are emitted at its commit, off the reducer
// hot path. Delivery is at-most-once per intent row (DELETE and NOTIFY commit
// atomically); ORDER BY id preserves intent order.
// ponytail: identical (channel,payload) pairs inside one batch collapse into a
// single notification (pg_notify txn dedupe) — harmless for invalidation
// pushes; per-intent txns if a consumer ever needs one-notify-per-intent.
func (w *Worker) drainOnce(ctx context.Context) (int, error) {
	tag, err := w.pool.Exec(ctx, `
		WITH batch AS (
			DELETE FROM notify_intents
			 WHERE id IN (SELECT id FROM notify_intents
			               ORDER BY id LIMIT $1 FOR UPDATE SKIP LOCKED)
			 RETURNING channel, payload
		)
		SELECT pg_notify(channel, payload) FROM batch`, batchSize)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
