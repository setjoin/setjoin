// Package bulkroles drains the bulk_role_jobs queue by calling the
// bulk_role_job_apply reducer for each queued row.
//
// The worker is started once at server startup on the workerPool (BYPASSRLS)
// so the cross-tenant bulk-apply can see every mailbox.  It uses
// SELECT … FOR UPDATE SKIP LOCKED to claim jobs atomically — multiple
// replicas can run the worker concurrently without double-processing.
//
// Deviation from eapjobs: claim + apply + finalize run in ONE transaction so
// the row stays locked for the whole apply run (prevents rolling-deploy
// double-processing). The reducer may set status='error' itself; the final
// UPDATE is gated on status='running' so a reducer-set 'error' is preserved.
package bulkroles

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"setjoin.com/shared/pgxutil"
)

const workerInterval = 3 * time.Second

// Worker polls bulk_role_jobs and processes one queued job per tick.
type Worker struct {
	pool   pgxutil.WorkerPool
	logger *slog.Logger
}

// NewWorker creates a Worker that will drain the bulk_role_jobs queue.
func NewWorker(pool pgxutil.WorkerPool, logger *slog.Logger) *Worker {
	return &Worker{pool: pool, logger: logger}
}

// reclaim flips any stale 'running' rows back to 'queued' on startup.
// A row can be left 'running' if the server crashed mid-job.
func (w *Worker) reclaim(ctx context.Context) error {
	_, err := w.pool.Exec(ctx,
		`UPDATE bulk_role_jobs SET status='queued', updated_at=now() WHERE status='running'`)
	return err
}

// Run starts the ticker loop. It exits cleanly when ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	w.logger.Info("bulkroles worker started", "interval", workerInterval)
	if err := w.reclaim(ctx); err != nil {
		w.logger.Warn("bulkroles: failed to reclaim running jobs on startup", "error", err)
	}
	ticker := time.NewTicker(workerInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("bulkroles worker stopped")
			return
		case <-ticker.C:
			// Drain all queued jobs before waiting for the next tick.
			for {
				claimed, err := w.processOnce(ctx)
				if err != nil {
					w.logger.Error("bulkroles: processOnce error", "error", err)
					break
				}
				if !claimed {
					break
				}
			}
		}
	}
}

// applyFailureIsCancellation reports whether err is a shutdown/cancellation
// failure (context.Canceled / context.DeadlineExceeded anywhere in the chain)
// rather than a reducer-authored or persistent failure — only the former is
// left queued for retry; the latter is marked terminal 'error'
// (D-MAILSERVER-INTERNAL-BULKROLES-001).
func applyFailureIsCancellation(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// processOnce claims the oldest queued job and processes it in a SINGLE tx so the
// job row stays locked for the whole run — a second replica's SKIP LOCKED can't
// claim it and a startup reclaim can't flip a genuinely-running job. Returns
// (claimed bool, err error); claimed=false means the queue was empty.
func (w *Worker) processOnce(ctx context.Context) (bool, error) {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var id int64
	err = tx.QueryRow(ctx,
		`SELECT id FROM bulk_role_jobs WHERE status='queued'
           ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, `UPDATE bulk_role_jobs SET status='running',updated_at=now() WHERE id=$1`, id); err != nil {
		return true, err
	}
	if _, err = tx.Exec(ctx, `SELECT bulk_role_job_apply($1)`, id); err != nil {
		// The TX will be rolled back by the deferred Rollback, reverting the
		// status='running' UPDATE and leaving the job as 'queued'.
		tx.Rollback(ctx) //nolint:errcheck
		markErr := fmt.Errorf("bulk_role_job_apply: %w", err)
		// Classify before marking terminal (D-MAILSERVER-INTERNAL-BULKROLES-001):
		// a cancellation/deadline (shutdown or a torn-down request context) must
		// NOT irreversibly convert an approved operation into a terminal 'error' —
		// the rollback above already left the job 'queued' and the startup
		// reclaim/drain re-processes it. Only non-cancellation failures reach the
		// terminal mark below (reducer-authored rejections persist, per the
		// deliberate liveness design that stops deterministically failing jobs
		// from retrying forever).
		if applyFailureIsCancellation(err) {
			w.logger.Warn("bulkroles: job apply cancelled — left queued for retry", "id", id, "error", err)
			return true, markErr
		}
		// Terminal mark runs on the worker ctx with a short grace timeout rather
		// than raw context.Background(): shutdown cancellation must not hang the
		// worker here, and a failed mark stays loud (previously the mark error was
		// logged but the mark itself rode an un-boundable background context).
		markCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, pErr := w.pool.Exec(markCtx,
			`UPDATE bulk_role_jobs SET status='error', updated_at=now(), error=$2 WHERE id=$1`,
			id, markErr.Error()); pErr != nil {
			w.logger.Error("bulkroles: failed to mark job error", "id", id, "mark_error", pErr, "original", err)
		}
		return true, markErr
	}
	// bulk_role_job_apply may have set status='error'; only promote running→done.
	if _, err = tx.Exec(ctx,
		`UPDATE bulk_role_jobs SET status='done',updated_at=now() WHERE id=$1 AND status='running'`, id); err != nil {
		return true, err
	}
	return true, tx.Commit(ctx)
}
