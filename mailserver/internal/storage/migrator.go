package storage

// migrator.go — the process-lifetime owner for storage migrations (AR-01,
// "one lifetime owner"). One Migrator is constructed in mailserverd for the
// whole process; HTTP handlers shrink to adapters over Start/Cancel/Status.
//
// Contracts implemented here (packet L2-AR01-storage-lifetime-proposal, r2/r3
// amendments with the r4 amendment binding):
//
//   - Run contexts derive from the service-owned lifecycle context, NEVER from
//     the HTTP request that admitted the run (a request dying must not kill the
//     worker), and admission is refused once shutdown begins (AR01-1).
//   - Cancel is a bounded handshake, not a status write: the RUN performs its
//     own terminal `cancelled` write through the detached setStatus path after
//     its in-flight driver call returns and cancellation is observed at the
//     next copyRows boundary. DB `cancelled` therefore implies the worker has
//     stopped copying. Join expiry is an ESCALATION TRIGGER, never a completion
//     claim (r3-1): drivers are not context-cooperative — a timed wait bounds
//     the WAIT, never the worker — so expiry yields typed ErrDrainTimeout, no
//     owner status write, and the run stays registered (ownership retained).
//   - Shutdown closes admission, arms its own drain deadline BEFORE and
//     covering every wait — the pending-admission waits included (r4-1 as
//     amended by Astra impl-r2 r3 finding 1; never derived from a caller
//     watchdog that may start later) — and joins every live run. An admission
//     already past the closing check is tracked as PENDING and disposed
//     atomically with shutdown (Astra AR01 finding 2): Shutdown snapshots the
//     pending list in the same critical section that sets closing, waits for
//     each pending INSERT inside the drain budget, and folds any registered
//     run into its drain set — a pending admission can never launch an
//     unjoined worker past the snapshot, and a stalled admission can no
//     longer defer failed-drain logging or termination escalation.
//   - Cancel is a bounded handshake whose success is coordinated with the
//     run's selected outcome (Astra impl-r2 r3 finding 2): cutover
//     persistence runs on a detached context, so a handshake draining against
//     an exit that rests at `cutover` is a typed ErrNotCancellable refusal,
//     never a false "cancelled" success.
//     Drained (exit OBSERVED) is the
//     only outcome that releases execution ownership and permits dependency
//     closure. Undrained at the drain deadline: failed-drain ERROR, no owner
//     status write, dependency teardown withheld while the worker is live. On
//     OUTER-deadline overrun with a worker still live the path escalates to
//     ACTUAL process termination (terminateProcess; production os.Exit, which
//     runs no deferred functions, so deferred dependency closes cannot fire).
//     Shutdown never returns through dependency closure with a worker live —
//     the r3 "crash-equivalent return" fallback is erased (r4-1).
//   - A finished run is RELEASED from the registry when its goroutine stops
//     (Astra AR01 finding 4): Recover therefore treats only genuinely
//     undrained entries as live, and a completed run neither shadows
//     proven-exclusive recovery nor retains its context and driver handles
//     for the process lifetime.
//   - Startup Recover reclaims orphaned transitional rows ONLY under proven
//     exclusive execution ownership (AR01-2); without a caller-supplied
//     exclusivity attestation (E5's future lease mechanism) the pass is
//     log/observe-only and the mutation is deferred. No convergence claim is
//     logged, ever.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Typed cancellation/drain outcomes. The admin handler (adapter) maps these to
// Problem-JSON: ErrUnknownMigration/ErrNotCancellable → 404/409,
// ErrAdmissionClosed → 409/503, ErrDrainTimeout → non-success (caller retries
// or polls Status).
var (
	// ErrAdmissionClosed is returned by Start once shutdown has begun.
	ErrAdmissionClosed = errors.New("migration: admission closed — service shutdown in progress")
	// ErrUnknownMigration is returned when no such migration row exists.
	ErrUnknownMigration = errors.New("migration: unknown migration id")
	// ErrNotCancellable is returned when the row is terminal (completed,
	// failed, cancelled) or already rests at cutover; the row is unchanged.
	ErrNotCancellable = errors.New("migration: not in a cancellable state")
	// ErrNotRunning is returned for a transitional row that has no live run in
	// this process. A database row alone proves nothing about execution
	// ownership (AR01-2) — another process may own it — so the row is never
	// touched from here.
	ErrNotRunning = errors.New("migration: no live run for this migration in this process")
	// ErrDrainTimeout is the undrained outcome of the bounded cancel
	// handshake: the join deadline expired with the run goroutine still live.
	// It is NEVER a completed join — no owner status write happened, execution
	// ownership is retained, and the caller retries or polls Status.
	ErrDrainTimeout = errors.New("migration: cancel drain deadline expired — run goroutine still live")
)

// cancelJoinTimeout bounds the cancel handshake's wait on the run goroutine.
// A var (not const) so tests can pin bounded termination with a short deadline.
var cancelJoinTimeout = 10 * time.Second

// migratorStore is the persistence surface the owner needs: the terminal
// status write (statusStore) plus single-row reads/writes for admission,
// cancel-state checks and the Status read model. Satisfied structurally by
// *pgxpool.Pool; consumer-defined (ISP) so the lifetime contracts are
// unit-testable without a database.
type migratorStore interface {
	statusStore
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// migrationRun is one live migration owned by the Migrator.
type migrationRun struct {
	id     int64
	ctx    context.Context // derived from the Migrator's lifecycle context
	cancel context.CancelFunc
	done   chan struct{} // closed when the run goroutine has exited (observed)
	mig    *Migration    // per-run execution machinery (run/backfill/setStatus)
}

// pendingAdmission tracks a Start that is past the closing check but whose
// durable admission INSERT has not yet resolved into a registered run (Astra
// AR01 finding 2). Shutdown snapshots the pending list in the same critical
// section that closes admission, waits for every entry to resolve, and folds
// a resolved run into its drain set — so an in-flight admission can never
// launch an unjoined worker after the registry snapshot.
type pendingAdmission struct {
	done chan struct{} // closed exactly once, when the admission resolved
	id   int64         // valid when run != nil; written before done closes
	run  *migrationRun // nil ⇒ the admission failed; written before done closes
}

// Migrator owns execution, cancellation, status and recovery for every
// storage migration in this process.
type Migrator struct {
	lifecycle context.Context // service-owned lifetime; parent of run contexts
	pool      *pgxpool.Pool
	store     migratorStore
	logger    *slog.Logger

	mu      sync.Mutex
	runs    map[int64]*migrationRun
	closing bool // admission closed once shutdown begins (AR01-1)
	// pendingAdmissions holds Starts between the closing check and run
	// registration (Astra AR01 finding 2); shutdown disposes them atomically.
	pendingAdmissions []*pendingAdmission

	// Seams for unit tests; nil in production falls back to defaults.
	newMigration       func(source, target blobMover) *Migration
	scanOrphans        func(ctx context.Context) (scanCursor, error)
	exclusiveOwnership func() bool // nil ⇒ exclusivity never proven (AR01-2)
	terminateProcess   func(code int)
}

// NewMigrator constructs the process-lifetime migration owner. lifecycle is
// the mailserverd service context — cancelled on shutdown, propagating into
// every live run. pool may be nil only in tests, which then inject store and
// the run seams themselves.
func NewMigrator(lifecycle context.Context, pool *pgxpool.Pool, logger *slog.Logger) *Migrator {
	if lifecycle == nil {
		lifecycle = context.Background()
	}
	if logger == nil {
		logger = slog.Default()
	}
	m := &Migrator{
		lifecycle: lifecycle,
		pool:      pool,
		logger:    logger,
		runs:      map[int64]*migrationRun{},
	}
	if pool != nil {
		m.store = pool
	}
	m.newMigration = func(source, target blobMover) *Migration {
		return NewMigration(pool, source, target, logger)
	}
	m.scanOrphans = func(ctx context.Context) (scanCursor, error) {
		if pool == nil {
			return nil, errors.New("migration: recover: no database pool configured")
		}
		return pool.Query(ctx,
			`SELECT id, status FROM storage_migrations WHERE status IN ('dual_write', 'backfill') ORDER BY id`)
	}
	m.terminateProcess = os.Exit
	return m
}

// Start durably admits a migration and spawns its run.
//
// The admission INSERT commits on the CALLER's context (the 202 response
// carries the id, so admission must complete synchronously — the r2 AR01-3
// oracle). The run context itself does NOT descend from the caller's context:
// it derives from the service-owned lifecycle context, so a request returning
// (net/http cancelling r.Context()) can never kill the worker, while service
// shutdown propagates into it (AR01-1).
func (m *Migrator) Start(ctx context.Context, source, target blobMover) (int64, error) {
	if source == nil || target == nil {
		return 0, errors.New("migration: source and target drivers are required")
	}
	if m.store == nil {
		return 0, errors.New("migration: no database store configured")
	}

	// The closing check and the pending-admission reservation share ONE
	// critical section (Astra AR01 finding 2): the INSERT below is a slow DB
	// round trip, so without the reservation Shutdown could close admission
	// and snapshot an empty registry while a Start sat between the check and
	// registration — then return into dependency closure while Start launched
	// an unjoined worker.
	m.mu.Lock()
	if m.closing {
		m.mu.Unlock()
		return 0, ErrAdmissionClosed
	}
	pending := &pendingAdmission{done: make(chan struct{})}
	m.pendingAdmissions = append(m.pendingAdmissions, pending)
	m.mu.Unlock()

	var id int64
	err := m.store.QueryRow(ctx,
		`INSERT INTO storage_migrations (source_driver, target_driver, status)
		 VALUES ($1, $2, 'dual_write') RETURNING id`,
		source.ProviderName(), target.ProviderName(),
	).Scan(&id)
	if err != nil {
		m.resolvePending(pending, 0, nil)
		return 0, fmt.Errorf("migration: record start: %w", err)
	}

	runCtx, cancel := context.WithCancel(m.lifecycle)
	run := &migrationRun{
		id:     id,
		ctx:    runCtx,
		cancel: cancel,
		done:   make(chan struct{}),
		mig:    m.newMigration(source, target),
	}
	run.mig.lastStatus = MigDualWrite

	// Registration and pending resolution are one visible step for Shutdown:
	// once pending.done closes, the run is already in the registry.
	m.mu.Lock()
	m.runs[id] = run
	m.removePendingLocked(pending)
	pending.id, pending.run = id, run
	m.mu.Unlock()
	close(pending.done)

	m.logger.Info("migration: admitted", "id", id,
		"source", source.ProviderName(), "target", target.ProviderName())
	go m.execRun(run)
	return id, nil
}

// resolvePending marks an admission resolved — with its registered run, or
// nil when the admission failed — and drops it from the pending list. Safe
// against Shutdown's wait: Shutdown reads id/run only after done closes.
func (m *Migrator) resolvePending(pending *pendingAdmission, id int64, run *migrationRun) {
	m.mu.Lock()
	m.removePendingLocked(pending)
	pending.id, pending.run = id, run
	m.mu.Unlock()
	close(pending.done)
}

// removePendingLocked drops a resolved admission from the pending list.
// slices.Delete (not a manual re-slice) so the vacated backing-array slot is
// zeroed (Astra impl-r2 finding 3): otherwise the obsolete slot retains the
// admission, whose run field retains the completed migration and its driver
// handles even after registry release.
func (m *Migrator) removePendingLocked(pending *pendingAdmission) {
	for i, p := range m.pendingAdmissions {
		if p == pending {
			m.pendingAdmissions = slices.Delete(m.pendingAdmissions, i, i+1)
			return
		}
	}
}

// execRun is the run goroutine: the ONLY writer of the run's statuses. On exit
// it releases the run's execution ownership (Astra AR01 finding 4): the
// registry entry is deleted and the derived context freed BEFORE the observed
// exit is published, so Recover treats only genuinely undrained entries as
// live and a finished run neither shadows proven-exclusive recovery nor
// retains its driver/context handles for the process lifetime. A run whose
// drain expired is still live at that moment, so the ownership-retention
// contracts (r3-1) are unaffected — the release happens only when execution
// actually stops.
func (m *Migrator) execRun(run *migrationRun) {
	run.mig.run(run.ctx, run.id)
	run.cancel() // frees the derived context; a no-op on the backfill itself
	m.mu.Lock()
	delete(m.runs, run.id)
	m.mu.Unlock()
	close(run.done) // the observed exit ("drained") releases execution ownership
}

// Cancel performs the bounded cancel handshake.
//
// Terminal/non-cancellable rows are refused with a typed error and the row is
// left unchanged (no unconditional status overwrite). For a live run the
// handshake cancels the run's context and joins the goroutine with a bounded
// wait; success (nil) means the goroutine exit was OBSERVED and the run
// performed its own terminal `cancelled` write through the detached setStatus
// path — so DB `cancelled` implies the worker has stopped copying. Expiry
// returns ErrDrainTimeout: no owner status write, ownership retained, the run
// stays registered (r3-1 b/c).
//
// A drained handshake is coordinated with the run's selected outcome (Astra
// impl-r2 r3 finding 2): cutover persistence runs on a detached context, so a
// handshake requested while the cutover UPDATE is in flight can drain against
// an exit whose outcome rests at `cutover` (or a shutdown-driven `failed`).
// Reporting nil there would emit HTTP "cancelled" over a row that is not
// cancelled, so the outcome is verified after the join and anything but the
// run's own `cancelled` is a typed ErrNotCancellable refusal — the row is
// left as the run wrote it.
func (m *Migrator) Cancel(ctx context.Context, id int64) error {
	status, err := m.rowStatus(ctx, id)
	if err != nil {
		return fmt.Errorf("%w %d: %w", ErrUnknownMigration, id, err)
	}
	if !cancellableStatus(status) {
		return fmt.Errorf("%w: migration %d is %q", ErrNotCancellable, id, status)
	}

	m.mu.Lock()
	run, ok := m.runs[id]
	m.mu.Unlock()
	if !ok {
		// Transitional row without a live run here. Local absence cannot
		// authorize mutating another executor's row (AR01-2) — refuse with
		// the row unchanged.
		return fmt.Errorf("%w: migration %d (row status %q)", ErrNotRunning, id, status)
	}

	// Handshake: ask the run to stop. The run publishes its own terminal
	// `cancelled` after the in-flight driver call returns and the cancellation
	// is observed at the next copyRows boundary — never from here.
	run.mig.cancelRequested.Store(true)
	run.cancel()

	timer := time.NewTimer(cancelJoinTimeout)
	defer timer.Stop()
	select {
	case <-run.done:
		// The handshake drained: success (nil) requires the run to have
		// published its own terminal `cancelled`. Cutover may have won the
		// race (Astra impl-r2 r3 finding 2) — the request landed while the
		// detached cutover write was in flight — in which case the row rests
		// at a forward state the handshake must not misreport as cancelled.
		switch outcome := run.mig.outcome(); outcome {
		case MigCancelled:
			return nil
		case MigCutover:
			return fmt.Errorf("%w: migration %d rests at %q — the run completed its backfill before the handshake could stop it", ErrNotCancellable, id, outcome)
		default:
			return fmt.Errorf("%w: migration %d stopped at %q — not the cancelled outcome", ErrNotCancellable, id, outcome)
		}
	case <-timer.C:
		// Undrained: a deadline bounds the WAIT, never the worker (drivers are
		// not context-cooperative). The expiry is an escalation trigger, not a
		// completion claim — nothing is written, ownership is retained.
		m.logger.Error("migration: cancel drain deadline expired — run goroutine still live; ownership retained, no owner status write, row keeps its transitional status",
			"id", id, "status", status, "wait", cancelJoinTimeout)
		return ErrDrainTimeout
	}
}

// Status returns the migration row as a read model from the database (the DB
// stays the sole truth for STATUS; the registry is only execution ownership).
func (m *Migrator) Status(ctx context.Context, id int64) (map[string]any, error) {
	if m.store == nil {
		return nil, errors.New("migration: no database store configured")
	}
	var status string
	var total, migrated int64
	var lastKey *string
	var started time.Time
	var completed *time.Time
	// total_blobs is NULL between admission (Start inserts without it) and the
	// run's first progress write. COALESCE it (and the schema-nullable migrated)
	// to 0 — the read model's already-defined "not started" shape: total 0 omits
	// progress_pct exactly like the zero-total case, so a just-started migration
	// reports a defined Status instead of a "cannot scan NULL into *int64" error
	// (D-4).
	err := m.store.QueryRow(ctx,
		`SELECT status, COALESCE(total_blobs, 0), COALESCE(migrated, 0), last_key, started_at, completed_at
		 FROM storage_migrations WHERE id = $1`, id,
	).Scan(&status, &total, &migrated, &lastKey, &started, &completed)
	if err != nil {
		return nil, err
	}
	result := map[string]any{
		"id": id, "status": status, "total": total, "migrated": migrated,
		"started": started,
	}
	if lastKey != nil {
		result["last_key"] = *lastKey
	}
	if completed != nil {
		result["completed"] = *completed
	}
	if total > 0 {
		result["progress_pct"] = float64(migrated) * 100 / float64(total)
	}
	return result, nil
}

// Shutdown closes admission and drains every live run before the caller
// proceeds to dependency closure (DB pool, blob drivers).
//
// Drain contract (r3-1 as amended r4-1, plus the Astra AR01 finding 2
// pending-admission disposition):
//
//   - closing and the pending-admission snapshot are taken under one lock, so
//     every Start past the closing check is either registered in the snapshot
//     or tracked as pending — never in between.
//   - Each pending admission is resolved WITHIN the drain budget: a failed
//     admission is gone, a registered one is cancelled and folded into the
//     drain set — never an unjoined worker launched past the snapshot. One
//     still in flight at the deadline is a failed drain itself (Astra impl-r2
//     finding 1, r3): it may still launch a worker, so it is held for on the
//     outer path below — never a reason to return into dependency closure.
//   - The drain deadline is armed HERE, BEFORE every wait — the pending
//     waits included — and covers them all. It is never derived from a caller
//     watchdog that may start later, and a stalled admission can no longer
//     defer failed-drain logging or termination escalation past it.
//   - Drained (goroutine exit OBSERVED within the bound): the only outcome
//     that releases execution ownership and permits the caller to close
//     dependencies — Shutdown returning IS that gate.
//   - Undrained at the drain deadline: failed-drain ERROR naming the id, NO
//     owner status write (the row keeps its transitional status and is
//     reclaimable next start only under the AR01-2/E5 exclusivity rule), the
//     run stays registered, and Shutdown keeps holding — it waits deadline-free
//     on the run-done channel within the OUTER ctx instead of returning.
//   - OUTER overrun with the worker still live: the failed-drain ERROR is
//     emitted first, then ACTUAL process termination fires (terminateProcess;
//     production os.Exit runs no deferred functions, so deferred dependency
//     closes cannot fire). Shutdown never returns through dependency closure
//     with a worker live; after a seamed (non-lethal) termination it continues
//     holding for an observed exit.
func (m *Migrator) Shutdown(ctx context.Context, drain time.Duration) error {
	m.mu.Lock()
	m.closing = true
	runs := make([]*migrationRun, 0, len(m.runs))
	for _, run := range m.runs {
		runs = append(runs, run)
	}
	pending := make([]*pendingAdmission, len(m.pendingAdmissions))
	copy(pending, m.pendingAdmissions)
	m.mu.Unlock()

	// Signal the known runs to stop while in-flight admissions resolve.
	for _, run := range runs {
		run.cancel()
	}

	// Drain deadline armed BEFORE EVERY wait — the pending-admission waits
	// included (Astra impl-r2 finding 1, r3): one budget covers resolving the
	// pending admissions AND joining every run, so a stalled admission can
	// never defer failed-drain logging or termination escalation past the
	// deadlines, even while an existing worker remains live.
	deadline := time.NewTimer(drain)
	defer deadline.Stop()
	deadlineFired := false

	// Dispose pending admissions atomically with shutdown (Astra AR01 finding
	// 2), now WITHIN the drain budget: each either resolves in time — a failed
	// admission is gone, a registered one is cancelled and folded into the
	// drain set like any other run — or is still in flight at the deadline and
	// becomes a failed drain itself (it may still launch a worker), held for in
	// the pendingHot pass below.
	pendingHot := make([]*pendingAdmission, 0, len(pending))
	for _, p := range pending {
		if deadlineFired {
			// Budget already exhausted by an earlier wait: deadline-free
			// resolution within the OUTER ctx only. On outer expiry the
			// admission is still in flight — its run field is NOT safe to
			// read here (Start writes it under m.mu just before done closes,
			// and neither the mutex nor a done-receive covers this read), so
			// this admission is resolved exclusively in the pendingHot pass
			// below, which waits on done before touching it.
			select {
			case <-p.done:
			case <-ctx.Done():
				pendingHot = append(pendingHot, p)
				continue
			}
		} else {
			select {
			case <-p.done:
			case <-deadline.C:
				deadlineFired = true
				m.logPendingUndrained()
				pendingHot = append(pendingHot, p)
				continue
			case <-ctx.Done():
				pendingHot = append(pendingHot, p)
				continue
			}
		}
		if p.run != nil {
			p.run.cancel()
			runs = append(runs, p.run)
		}
	}

	// Resolve the admissions that were still in flight at the drain deadline —
	// deadline-free within the OUTER ctx, whose overrun escalates exactly as
	// for a live worker (the admission can still launch one; the r4-1
	// dependency-closure gate must stay shut until it cannot). A run that
	// materializes joins the drain set below with the same contract.
	for _, p := range pendingHot {
		select {
		case <-p.done:
		case <-ctx.Done():
			m.logger.Error("migration: shutdown outer deadline overran with a pending migration admission unresolved — terminating process; the admission could still launch a live worker; execution ownership NOT released; dependency teardown bypassed")
			m.terminateProcess(1)
			// Production os.Exit never returns (no deferred functions run).
			// A seamed test hook does, so keep holding for the resolution.
			<-p.done
		}
		if p.run != nil {
			p.run.cancel()
			runs = append(runs, p.run)
		}
	}

	sort.Slice(runs, func(i, j int) bool { return runs[i].id < runs[j].id })

	m.logger.Info("migration: shutdown draining live runs", "count", len(runs), "drain", drain)

	// Signal every run to stop up front so they drain in parallel, then join.
	for _, run := range runs {
		run.cancel()
	}

	undrained := make([]*migrationRun, 0, len(runs))
	for _, run := range runs {
		if deadlineFired {
			// Budget already exhausted by an earlier run: deadline-free join
			// within the OUTER ctx only.
			select {
			case <-run.done:
			case <-ctx.Done():
				undrained = append(undrained, run)
			}
			continue
		}
		select {
		case <-run.done:
		case <-deadline.C:
			deadlineFired = true
			m.logUndrained(run)
			undrained = append(undrained, run)
		}
	}

	// Hold for the undrained runs instead of returning into dependency
	// teardown with a live worker. Deadline-free join, bounded only by the
	// OUTER ctx — whose overrun escalates to actual process termination.
	for _, run := range undrained {
		select {
		case <-run.done:
			m.logger.Info("migration: late drain observed — execution ownership released, dependency closure may proceed",
				"id", run.id)
		case <-ctx.Done():
			m.logger.Error("migration: shutdown outer deadline overran with a live migration worker — terminating process; execution ownership NOT released; dependency teardown bypassed",
				"id", run.id)
			m.terminateProcess(1)
			// Production os.Exit never returns (no deferred functions run).
			// A seamed test hook does, so keep holding for an observed exit —
			// the dependency-closure gate stays shut while the worker is live.
			<-run.done
			m.logger.Info("migration: late drain observed after termination escalation — ownership released",
				"id", run.id)
		}
	}
	return nil
}

// logUndrained emits the failed-drain ERROR for an expiry that must never be
// reported as a completed join (r3-1 a).
func (m *Migrator) logUndrained(run *migrationRun) {
	m.logger.Error("migration: drain deadline expired — run goroutine still live; failed drain, ownership retained, no owner status write, dependency teardown withheld",
		"id", run.id)
}

// logPendingUndrained emits the failed-drain ERROR for a pending admission
// still unresolved at the drain deadline (Astra impl-r2 finding 1, r3): like
// an undrained worker it withholds dependency teardown — the admission can
// still launch one — and the id is logged when the admission resolves into a
// run and its own drain expires.
func (m *Migrator) logPendingUndrained() {
	m.logger.Error("migration: drain deadline expired with a pending migration admission unresolved — failed drain; dependency teardown withheld until it resolves and any launched worker exits")
}

// Recover is the bounded startup pass over orphaned transitional rows
// (dual_write/backfill left by a previous process).
//
// The reclaim mutation (mark failed + completed_at) runs ONLY under proven
// exclusive execution ownership: a caller-supplied probe (E5's future
// lease/claim mechanism) must attest that this process provably excludes every
// other executor. The in-process registry alone proves nothing at startup, and
// a database row alone provides neither exclusivity nor lease safety — local
// absence of a live run cannot authorize marking another process's active job
// failed (AR01-2). Without the attestation the pass is log/observe-only and
// the mutation is deferred to the joint E5 authority. No convergence claim is
// logged; surviving rows stay enumerated for reconciliation.
func (m *Migrator) Recover(ctx context.Context) error {
	// The registry holds only undrained (live) runs: execRun releases the
	// entry when execution stops (Astra AR01 finding 4), so a finished run is
	// never treated as live here and cannot shadow proven-exclusive recovery.
	m.mu.Lock()
	live := make(map[int64]struct{}, len(m.runs))
	for id := range m.runs {
		live[id] = struct{}{}
	}
	m.mu.Unlock()

	proven := m.exclusiveOwnership != nil && m.exclusiveOwnership()
	if !proven {
		m.logger.Info("migration: recover — exclusive execution ownership not proven; reclaim mutations deferred to the joint E5 authority (observe-only pass)")
	}

	rows, err := m.scanOrphans(ctx)
	if err != nil {
		return fmt.Errorf("migration: recover: scan orphaned transitional rows: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id int64
		var status string
		if err := rows.Scan(&id, &status); err != nil {
			m.logger.Warn("migration: recover — orphan row scan failed", "error", err)
			continue
		}
		if _, isLive := live[id]; isLive {
			m.logger.Info("migration: recover — row has a live run in this process; untouched",
				"id", id, "status", status)
			continue
		}
		if !proven {
			m.logger.Warn("migration: recover — orphaned transitional row observed; reclaim deferred (exclusive execution ownership not proven)",
				"id", id, "status", status)
			continue
		}
		if m.store == nil {
			m.logger.Error("migration: recover — exclusivity proven but no store configured; reclaim skipped",
				"id", id, "status", status)
			continue
		}
		if _, err := m.store.Exec(ctx,
			`UPDATE storage_migrations SET status = 'failed', completed_at = now() WHERE id = $1`, id); err != nil {
			m.logger.Error("migration: recover — reclaim write failed", "id", id, "error", err)
			continue
		}
		m.logger.Info("migration: recover — orphaned transitional row reclaimed",
			"id", id, "from", status, "to", string(MigFailed),
			"reason", "no live run; exclusive execution ownership proven")
	}
	return rows.Err()
}

// rowStatus reads the row's current status; the DB stays the sole truth for
// STATE, the registry only for execution ownership.
func (m *Migrator) rowStatus(ctx context.Context, id int64) (string, error) {
	if m.store == nil {
		return "", errors.New("migration: no database store configured")
	}
	var status string
	err := m.store.QueryRow(ctx,
		`SELECT status FROM storage_migrations WHERE id = $1`, id).Scan(&status)
	return status, err
}

// cancellableStatus reports whether a cancel handshake may proceed for a row
// in this status. Only in-flight transitional states are cancellable; a run
// that already rests at cutover (or any terminal state) is refused, with the
// row unchanged.
func cancellableStatus(status string) bool {
	switch MigrationStatus(status) {
	case MigDualWrite, MigBackfill:
		return true
	}
	return false
}
