// Package eapjobs drains the eap_apply_jobs queue by calling the
// email_address_policy_apply_bulk reducer for each queued row.
//
// The worker is started once at server startup on the workerPool (BYPASSRLS)
// so the cross-tenant bulk-apply can see every mailbox.  It uses
// SELECT … FOR UPDATE SKIP LOCKED to claim jobs atomically — multiple
// replicas can run the worker concurrently without double-processing.
package eapjobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"setjoin.com/shared/pgxutil"
)

const (
	workerInterval = 3 * time.Second
	// Retry-budget discipline (D-MAILSERVER-INTERNAL-EAPJOBS-001): a job whose
	// error-persist UPDATE ALSO fails would previously be re-claimed every
	// workerInterval forever. The worker now backs off per job and dead-letters
	// (stops claiming) after maxPersistFailures consecutive persist failures.
	// The budget is in-memory: a restart resets it, and a durable
	// attempts/dead-letter column is the recorded owner follow-up.
	maxPersistFailures = 5
	baseRetryBackoff   = 6 * time.Second
	maxRetryBackoff    = 5 * time.Minute
)

// retryState tracks consecutive error-persist failures for one job.
type retryState struct {
	attempts  int
	nextRetry time.Time
	dead      bool
}

// Worker polls eap_apply_jobs and processes one queued job per tick.
type Worker struct {
	pool   pgxutil.WorkerPool
	logger *slog.Logger

	mu       sync.Mutex
	failures map[int64]*retryState
}

// NewWorker creates a Worker that will drain the eap_apply_jobs queue.
func NewWorker(pool pgxutil.WorkerPool, logger *slog.Logger) *Worker {
	return &Worker{pool: pool, logger: logger, failures: map[int64]*retryState{}}
}

// excludedIDs returns the job ids currently under backoff or dead-lettered —
// the claim query skips them until their retry time arrives (or forever, when
// dead-lettered).
func (w *Worker) excludedIDs(now time.Time) []int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	ids := make([]int64, 0, len(w.failures))
	for id, st := range w.failures {
		if st.dead || now.Before(st.nextRetry) {
			ids = append(ids, id)
		}
	}
	return ids
}

// noteFailure records one error-persist failure for jobID and applies the
// backoff / dead-letter discipline.
func (w *Worker) noteFailure(now time.Time, jobID int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failures == nil {
		w.failures = map[int64]*retryState{}
	}
	st := w.failures[jobID]
	if st == nil {
		st = &retryState{}
		w.failures[jobID] = st
	}
	st.attempts++
	backoff := baseRetryBackoff * time.Duration(1<<(st.attempts-1))
	if backoff > maxRetryBackoff || backoff <= 0 {
		backoff = maxRetryBackoff
	}
	st.nextRetry = now.Add(backoff)
	if st.attempts >= maxPersistFailures {
		st.dead = true
		if w.logger != nil {
			w.logger.Error("eapjobs: job dead-lettered after repeated error-persist failures — it will NOT be re-claimed until process restart; durable dead-letter status requires schema support",
				"job_id", jobID, "attempts", st.attempts)
		}
	}
}

// clearFailure drops the retry state once a job reaches a durable terminal
// status (error persisted, or done).
func (w *Worker) clearFailure(jobID int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.failures, jobID)
}

// Run starts the ticker loop.  It exits cleanly when ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	w.logger.Info("eap apply worker started", "interval", workerInterval)
	if _, err := w.pool.Exec(ctx, `UPDATE eap_apply_jobs SET status='queued', updated_at=now() WHERE status='running'`); err != nil {
		w.logger.Warn("eapjobs: failed to reclaim running jobs on startup", "error", err)
	}
	ticker := time.NewTicker(workerInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("eap apply worker stopped")
			return
		case <-ticker.C:
			// Drain all queued jobs before waiting for the next tick.
			for {
				claimed, err := w.processOne(ctx)
				if err != nil {
					// processOne already logged the error; stop draining this tick.
					break
				}
				if !claimed {
					break
				}
			}
		}
	}
}

// processOne claims one queued job atomically and runs the reducer.
// Returns (true, nil) when a job was processed, (false, nil) when the
// queue is empty, or (false, err) on a database error.
func (w *Worker) processOne(ctx context.Context) (claimed bool, err error) {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("eapjobs: begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(ctx)
		}
	}()

	// Claim one queued job; SKIP LOCKED lets concurrent workers avoid contention.
	// Jobs under persist-failure backoff (or dead-lettered) are excluded so a
	// poison job cannot be re-claimed on every tick (D-MAILSERVER-INTERNAL-
	// EAPJOBS-001).
	excluded := w.excludedIDs(time.Now())
	var jobID int64
	var policyID *int64
	claimErr := tx.QueryRow(ctx, `
		UPDATE eap_apply_jobs
		   SET status = 'running', updated_at = now()
		 WHERE id = (
		   SELECT id FROM eap_apply_jobs
		    WHERE status = 'queued'
		      AND NOT (id = ANY($1))
		    ORDER BY id
		    FOR UPDATE SKIP LOCKED
		    LIMIT 1
		 )
		 RETURNING id, policy_id`,
		excluded,
	).Scan(&jobID, &policyID)
	if errors.Is(claimErr, pgx.ErrNoRows) {
		_ = tx.Rollback(ctx)
		return false, nil
	}
	if claimErr != nil {
		_ = tx.Rollback(ctx)
		return false, fmt.Errorf("eapjobs: claim job: %w", claimErr)
	}

	// Set total up front: email_address_policy_apply_bulk sweeps ALL policy-enabled
	// primary mailboxes regardless of policy_id, so the denominator is the all-NULL
	// match_count (every policy-enabled primary mailbox).
	var total int
	if scanErr := tx.QueryRow(ctx,
		`SELECT email_address_policy_match_count(NULL,NULL,NULL,NULL)`,
	).Scan(&total); scanErr != nil {
		w.logger.Warn("eapjobs: failed to count total candidates", "job_id", jobID, "error", scanErr)
	} else {
		if _, updErr := tx.Exec(ctx,
			`UPDATE eap_apply_jobs SET total=$2 WHERE id=$1`, jobID, total,
		); updErr != nil {
			w.logger.Warn("eapjobs: failed to set initial total", "job_id", jobID, "error", updErr)
		}
	}

	// Run the reducer inside the same transaction so claim + result are atomic.
	var applied int
	reducerErr := tx.QueryRow(ctx,
		`SELECT email_address_policy_apply_bulk($1)`, policyID,
	).Scan(&applied)

	if reducerErr != nil {
		// The failing SELECT already left tx in Postgres's aborted-transaction
		// state: every further statement on tx (including a status update) is
		// rejected with "current transaction is aborted", and COMMIT on an
		// aborted transaction is just a rollback — so writing the error record
		// on tx and then committing silently discards it, along with the
		// earlier queued->running claim (the job reverts to 'queued' as if
		// nothing had happened). Roll back this txn and record the failure on
		// a fresh connection from the pool instead.
		_ = tx.Rollback(ctx)
		if _, updErr := w.pool.Exec(ctx, `
			UPDATE eap_apply_jobs
			   SET status = 'error', error = $2, updated_at = now()
			 WHERE id = $1`,
			jobID, reducerErr.Error(),
		); updErr != nil {
			// The error persist itself failed: without bookkeeping the job stays
			// 'queued' and would be re-claimed every workerInterval forever.
			// Apply the in-memory backoff/dead-letter budget instead.
			w.logger.Error("eapjobs: failed to mark job as error",
				"job_id", jobID, "update_error", updErr, "reducer_error", reducerErr)
			w.noteFailure(time.Now(), jobID)
		} else {
			w.clearFailure(jobID) // durably terminal — budget no longer needed
		}
		w.logger.Error("eapjobs: reducer failed",
			"job_id", jobID, "policy_id", policyID, "error", reducerErr)
		return false, reducerErr
	}

	// Mark done.
	if _, updErr := tx.Exec(ctx, `
		UPDATE eap_apply_jobs
		   SET status = 'done', applied = $2, total = $2, updated_at = now()
		 WHERE id = $1`,
		jobID, applied,
	); updErr != nil {
		_ = tx.Rollback(ctx)
		return false, fmt.Errorf("eapjobs: mark done: %w", updErr)
	}

	if err = tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("eapjobs: commit: %w", err)
	}

	w.clearFailure(jobID)
	w.logger.Info("eapjobs: job completed",
		"job_id", jobID, "policy_id", policyID, "applied", applied)
	return true, nil
}
