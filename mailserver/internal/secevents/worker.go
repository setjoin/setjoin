// Package secevents drains the durable security_event_outbox (V253, L2-C4 —
// MEDIUM XINCHUANG-DB-001/002 substrate). The outbox row IS the event: this
// worker's ticker is the durability floor, and LISTEN/NOTIFY (channel
// security_event_outbox) is only a latency optimization — a wakeup means
// "drain due rows", never "here is the event" (federation_enqueue.sql:20-25
// contract). A degraded notifier loses latency, not events.
//
// Claim semantics follow the repo-standard queue shape (pushjobs worker.go,
// scheduled_actions lineage: FOR UPDATE SKIP LOCKED + attempts + lease via
// next_attempt_at, capped exponential backoff), with the L2-C4 r2/r3
// corrections that the copied pushjobs shape lacked:
//
//   - The claim selector caps claims at attempts < maxAttempts, and a bounded
//     per-tick sweep terminalizes pending rows that reach the cap without any
//     settlement (crash cycles) to failed.
//   - Deliveries per tick are bounded (defaultDrainBatch) and the
//     terminalization sweep runs every tick — behind a full batch, not only
//     after the queue drains — so a continuously supplied queue cannot starve
//     crash-cycle terminalization (L2-C4 HOLD item 2).
//   - Every settlement (done/retry/fail) is claim-generation-fenced: it
//     predicates on the claim_generation returned by the claim, so a worker
//     whose lease lapsed and whose row was reclaimed cannot overwrite the new
//     claimant's state (webhook_delivery_complete.sql:18-24 precedent). Rows
//     only ever move pending→done or pending→failed.
//   - Every Deliver call runs under a context with a per-delivery deadline
//     strictly below the 120s lease (DefaultDeliverDeadline 90s, so deadline +
//     settlement margin < lease). A ctx error (deadline or shutdown
//     cancellation) is an ordinary failed attempt: last_error names the cause
//     and the fenced settlement runs on a context detached from the delivery
//     and worker cancellation (context.WithoutCancel + short timeout), so a
//     cancelled attempt still records its state before exit.
//
// Delivery is AT-LEAST-ONCE: a crash after sink acceptance but before
// settlement yields a redelivery carrying the same stable event id (the
// immutable outbox id, surfaced on Event.ID as the dedupe key). There is no
// exactly-once mode anywhere in this contract.
//
// Rows are terminal-only (pending→done|failed). Retention is the
// owner-approved reap decision (W-P1.5 "C4 residue", 2026-09-13 — V253
// originally retained everything pending that decision): DELIVERED rows
// (status='done') are pruned past the system_config window
// security_event_outbox_retain_days (default 90, resolved by
// security_event_outbox_prune()) on a rate-limited sweep hung off this worker's
// tick. Pending rows are never pruned (an aged pending row is still owed its
// delivery promise) and failed rows are retained deliberately — status='failed'
// is the durable alert signal. The sweep is a worker-owned SECURITY DEFINER
// reducer (app EXECUTE denied via the provision-roles worker-only carve-out)
// called on the same BYPASSRLS pool; a nil sink keeps the whole drain inert
// (no claim, no sweep, no retention), preserving the documented OFF posture.
//
// Mounting: NewWorker takes the BYPASSRLS worker pool (security_event_outbox
// is FORCE-RLS deny-all to every runtime role; the drain is cross-tenant by
// design) and is launched with launchWorker(ctx, logger, "security-event-
// delivery", w.Run) in cmd/mailserverd. The sink is injected; a nil sink is a
// fully inert drain (rows and attempts untouched) plus a startup log — with no
// production producer admitted (L2-C4 behavior stays OFF) the queue is empty
// and the loop is a no-op. Each worker package owning its claim SQL is the
// established norm (SKIP LOCKED appears in eapjobs, notifyjobs, calendarsync,
// bulkroles, federation/sender, drive, webhook — table names are fixed Go
// string constants at every call site, never request-derived).
package secevents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"setjoin.com/shared/pgxutil"
)

const (
	workerInterval = 3 * time.Second
	maxAttempts    = 5
	// leaseWindow is how long one claim holds a row before it becomes
	// reclaimable (no 'processing' status — lease-only design, pushjobs shape).
	leaseWindow = 2 * time.Minute

	// settleTimeout bounds each settlement exec. The binding invariant (r3):
	// deliver deadline + settleTimeout < leaseWindow. DefaultDeliverDeadline
	// (90s) + settleTimeout (5s) = 95s < 120s.
	settleTimeout = 5 * time.Second

	// exhaustedSweepLimit bounds the per-tick exhausted-claim terminalization
	// sweep (r2: "a bounded per-tick sweep").
	exhaustedSweepLimit = 100

	// defaultDrainBatch bounds deliveries per drain tick (L2-C4 HOLD item 2).
	// The drain loop previously ran until nothing was claimable, so a
	// continuously supplied queue deferred the exhausted-claim sweep forever —
	// terminalizeExhausted only ran once the loop drained. The batch bound
	// returns the loop every tick, and the sweep runs EVERY tick regardless of
	// whether deliveries stopped at the bound, the empty queue, or an error.
	defaultDrainBatch = 200

	// retentionSweepInterval rate-limits the delivered-row retention sweep
	// (W-P1.5): a daily-class prune does not need to run on every 3s tick. The
	// sweep still runs on the FIRST tick after startup (zero lastRetention), so
	// a restarted worker catches up immediately; a failed sweep does not move
	// lastRetention, so it retries next tick.
	retentionSweepInterval = time.Hour
)

// DefaultDeliverDeadline is the package-level per-delivery deadline applied to
// every Deliver call (r3: a package-level setting, never a hardcoded literal at
// the call site). It must stay strictly below leaseWindow so a fully-deadlined
// delivery still leaves lease time for the fenced settlement; SetDeliverDeadline
// enforces deadline + settleTimeout < leaseWindow. The blocked-delivery test
// shortens it per worker.
const DefaultDeliverDeadline = 90 * time.Second

// Event is one claimed security_event_outbox row handed to a Sink. ID is the
// immutable stable event id — the dedupe key for at-least-once redelivery.
type Event struct {
	ID        int64
	EventType string
	// Payload is the event's JSON object as enqueued (verbatim outbox payload).
	Payload json.RawMessage
	// Attempts is the post-increment attempt count for this delivery.
	Attempts int
}

// Sink is the delivery target for security events. Deliver MUST be
// context-aware: the ctx the worker passes derives from both the per-delivery
// deadline and the worker's shutdown ctx, so deadline expiry and shutdown
// cancellation both reach the in-flight call. A sink that ignores ctx violates
// the interface contract (it pins its delivery goroutine past the lease and
// stalls the drain). Deliver returning a ctx error is an ordinary failed
// attempt: the row stays pending with backoff scheduled (at-least-once — the
// sink must tolerate redelivery and dedupe on Event.ID).
type Sink interface {
	Deliver(ctx context.Context, ev Event) error
}

// Worker drains security_event_outbox on the BYPASSRLS worker pool.
type Worker struct {
	pool            pgxutil.WorkerPool
	sink            Sink
	logger          *slog.Logger
	deliverDeadline time.Duration
	// drainBatch caps deliveries per drain tick (defaultDrainBatch). Unexported
	// and defaulted in NewWorker; tests shrink it to exercise the bound.
	drainBatch int
	// retentionInterval rate-limits the delivered-row retention sweep
	// (retentionSweepInterval). Unexported and defaulted in NewWorker; tests
	// shrink it to force a sweep (drainBatch precedent).
	retentionInterval time.Duration
	// lastRetention is when the retention sweep last SUCCEEDED. Zero value →
	// the first tick sweeps (startup catch-up).
	lastRetention time.Time
}

// NewWorker creates the outbox drain worker. sink may be nil: the drain is then
// fully inert (no claim, no sweep — seeded rows and their attempts stay
// untouched) with a startup log stating so. logger may be nil (slog.Default()
// is used, tagged with the fixed secevents component).
func NewWorker(pool pgxutil.WorkerPool, sink Sink, logger *slog.Logger) *Worker {
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{
		pool:              pool,
		sink:              sink,
		logger:            logger.With("component", "secevents"),
		deliverDeadline:   DefaultDeliverDeadline,
		drainBatch:        defaultDrainBatch,
		retentionInterval: retentionSweepInterval,
	}
}

// SetDeliverDeadline overrides the per-delivery deadline (r3: package-level
// default, per-worker override so tests can shorten it). Panics on a value
// that breaks the binding invariant deadline + settleTimeout < leaseWindow —
// that is a startup-time programming error, not a runtime condition.
func (w *Worker) SetDeliverDeadline(d time.Duration) {
	if d <= 0 || d+settleTimeout >= leaseWindow {
		panic(fmt.Sprintf("secevents: deliver deadline %s must be >0 and leave a %s settlement margin under the %s lease",
			d, settleTimeout, leaseWindow))
	}
	w.deliverDeadline = d
}

// Run starts the ticker loop. The first drain runs immediately (startup
// reclaim of past-due pending rows), then every workerInterval. Exits cleanly
// when ctx is cancelled — in-flight Deliver calls receive the cancellation via
// their derived deadline ctx and settle on a detached context before the loop
// returns.
func (w *Worker) Run(ctx context.Context) {
	w.logger.Info("security-event delivery worker started",
		"interval", workerInterval.String(),
		"lease_window", leaseWindow.String(),
		"deliver_deadline", w.deliverDeadline.String(),
		"max_attempts", maxAttempts,
		"retention_interval", w.retentionInterval.String(),
		"sink_configured", w.sink != nil)
	if w.sink == nil {
		w.logger.Info("secevents: nil sink — drain inert, outbox rows and attempts untouched (no production sink admitted; behavior OFF)")
	}

	w.drain(ctx)
	ticker := time.NewTicker(workerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			w.logger.Info("security-event delivery worker stopped")
			return
		case <-ticker.C:
			w.drain(ctx)
		}
	}
}

// drain processes one bounded batch of due rows, then runs the exhausted-claim
// sweep. The batch bound (L2-C4 HOLD item 2) exists for the sweep, not the
// deliveries: an unbounded drain loop only reached terminalizeExhausted after
// the queue fully drained, so a continuously supplied queue starved crash-cycle
// terminalization forever. With the bound, the sweep runs EVERY tick — after a
// full batch, an empty queue, or a claim error — and catches up across ticks
// (the sweep itself is bounded by exhaustedSweepLimit). The delivered-row
// retention sweep rides the same tick, rate-limited by retentionInterval
// (W-P1.5).
func (w *Worker) drain(ctx context.Context) {
	if w.sink == nil || ctx.Err() != nil {
		return
	}
	for delivered := 0; delivered < w.drainBatch; delivered++ {
		claimed, err := w.processOne(ctx)
		if err != nil {
			if ctx.Err() == nil {
				w.logger.Warn("secevents: process failed", "error", err)
			}
			break
		}
		if !claimed {
			break
		}
	}
	w.terminalizeExhausted(ctx)
	w.pruneDelivered(ctx)
}

// processOne claims one due pending row (attempts < maxAttempts in the
// selector), delivers it under the per-delivery deadline, and settles fenced.
// Returns (true,nil) when a row was processed, (false,nil) when the queue is
// empty or idle.
func (w *Worker) processOne(ctx context.Context) (bool, error) {
	ev, gen, err := w.claim(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("secevents: claim: %w", err)
	}

	dctx, cancel := context.WithTimeout(ctx, w.deliverDeadline)
	deliverErr := w.sink.Deliver(dctx, ev)
	cancel()

	w.settleDelivery(ctx, ev, gen, deliverErr)
	return true, nil
}

// claimSQL leases one due pending row under the claim cap and bumps the
// fencing carrier. $1 = leaseWindow seconds, $2 = maxAttempts. A fixed Go
// string constant — never request-derived.
const claimSQL = `
UPDATE security_event_outbox
   SET attempts = attempts + 1,
       claim_generation = claim_generation + 1,
       next_attempt_at = now() + make_interval(secs => $1)
 WHERE id = (
   SELECT id FROM security_event_outbox
    WHERE status = 'pending'
      AND next_attempt_at <= now()
      AND attempts < $2
    ORDER BY next_attempt_at, id
    FOR UPDATE SKIP LOCKED
    LIMIT 1
 )
 RETURNING id, event_type, payload::text, attempts, claim_generation`

// claim leases one row. The returned generation is the fencing carrier: every
// settlement predicates on it.
func (w *Worker) claim(ctx context.Context) (ev Event, gen int, err error) {
	var payload string
	err = w.pool.QueryRow(ctx, claimSQL, leaseWindow.Seconds(), maxAttempts).
		Scan(&ev.ID, &ev.EventType, &payload, &ev.Attempts, &gen)
	if err != nil {
		return Event{}, 0, err
	}
	ev.Payload = json.RawMessage(payload)
	return ev, gen, nil
}

// doneSQL settles a successful delivery, fenced on the claim generation and
// clearing the carrier. $1 = id, $2 = claim_generation.
const doneSQL = `
UPDATE security_event_outbox
   SET status = 'done', delivered_at = now(), next_attempt_at = now(),
       last_error = NULL, claim_generation = 0
 WHERE id = $1 AND status = 'pending' AND claim_generation = $2`

// retrySQL re-queues with backoff, fenced on the claim generation (the carrier
// stays claimed — a superseding claim must bump it first). $1 = id,
// $2 = claim_generation, $3 = backoff seconds, $4 = cause.
const retrySQL = `
UPDATE security_event_outbox
   SET status = 'pending', next_attempt_at = now() + make_interval(secs => $3),
       last_error = $4
 WHERE id = $1 AND status = 'pending' AND claim_generation = $2`

// failSQL terminalizes at the attempt cap, fenced on the claim generation.
// $1 = id, $2 = claim_generation, $3 = cause.
const failSQL = `
UPDATE security_event_outbox
   SET status = 'failed', next_attempt_at = now(), last_error = $3,
       claim_generation = 0
 WHERE id = $1 AND status = 'pending' AND claim_generation = $2`

// settleDelivery settles the claim fenced: done on success; on failure a
// capped-backoff retry or — at the attempt cap — terminal failed. Settlements
// run on a context detached from the delivery/worker cancellation
// (context.WithoutCancel + settleTimeout) so a cancelled attempt still records
// its state before exit (r3); a settlement that finds its claim superseded is
// a logged zero-row no-op (r2 fencing).
func (w *Worker) settleDelivery(ctx context.Context, ev Event, gen int, deliverErr error) {
	cause := settleCause(w.deliverDeadline, deliverErr)
	if deliverErr != nil {
		// slog Error per failed delivery with the fixed component tag (alert
		// signal a); status='failed' at the cap is the durable alert signal.
		w.logger.Error("secevents: delivery failed",
			"event_id", ev.ID, "event_type", ev.EventType,
			"attempt", ev.Attempts, "cause", cause)
	}

	settleCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), settleTimeout)
	defer cancel()

	if deliverErr == nil {
		w.execSettlement(settleCtx, doneSQL, "done", ev.ID, gen)
		return
	}
	if ev.Attempts >= maxAttempts {
		tag, err := w.pool.Exec(settleCtx, failSQL, ev.ID, gen, cause)
		if err != nil {
			w.logger.Error("secevents: fenced fail settlement failed (row stays leased until expiry)",
				"event_id", ev.ID, "claim_generation", gen, "error", err)
			return
		}
		w.logStaleSettlement(tag, "failed", ev.ID, gen)
		return
	}
	// Capped exponential backoff — same schedule as pushjobs
	// (min(1min * 2^attempts, 1h)).
	backoff := backoffFor(ev.Attempts)
	tag, err := w.pool.Exec(settleCtx, retrySQL, ev.ID, gen, backoff.Seconds(), cause)
	if err != nil {
		w.logger.Error("secevents: fenced retry settlement failed (row stays leased until expiry)",
			"event_id", ev.ID, "claim_generation", gen, "error", err)
		return
	}
	w.logStaleSettlement(tag, "retry", ev.ID, gen)
}

// execSettlement runs a single-cause settlement (done) and logs a superseded
// claim as a zero-row no-op.
func (w *Worker) execSettlement(ctx context.Context, query, kind string, id int64, gen int) {
	tag, err := w.pool.Exec(ctx, query, id, gen)
	if err != nil {
		w.logger.Error("secevents: fenced settlement failed (row stays leased until expiry)",
			"kind", kind, "event_id", id, "claim_generation", gen, "error", err)
		return
	}
	w.logStaleSettlement(tag, kind, id, gen)
}

// logStaleSettlement reports a zero-rows settlement as a stale no-op (r2: the
// claim was superseded — the row now belongs to another claimant or is
// terminal; nothing may be changed from this late worker).
func (w *Worker) logStaleSettlement(tag pgconn.CommandTag, kind string, id int64, gen int) {
	if tag.RowsAffected() == 0 {
		w.logger.Warn("secevents: stale settlement ignored (claim superseded)",
			"kind", kind, "event_id", id, "claim_generation", gen)
	}
}

// exhaustedSQL is the bounded per-tick terminalization sweep (r2): pending
// rows at the attempt cap whose lease expired without any settlement (crash
// cycles) move pending→failed with last_error naming the exhaustion. Rows only
// ever move pending→done or pending→failed. $1 = maxAttempts, $2 = limit.
const exhaustedSQL = `
UPDATE security_event_outbox
   SET status = 'failed',
       next_attempt_at = now(),
       claim_generation = 0,
       last_error = 'delivery attempts exhausted without settlement (' || attempts || ' attempts)'
 WHERE id IN (
   SELECT id FROM security_event_outbox
    WHERE status = 'pending'
      AND attempts >= $1
      AND next_attempt_at <= now()
    ORDER BY next_attempt_at, id
    LIMIT $2
 )
 AND status = 'pending'`

// terminalizeExhausted runs the bounded exhausted-claim sweep. The five-
// delivery promise holds even when no settlement ever runs (repeated crash/
// reclaim cycles): once a row reaches maxAttempts and its lease lapses, the
// sweep terminalizes it.
func (w *Worker) terminalizeExhausted(ctx context.Context) {
	tag, err := w.pool.Exec(ctx, exhaustedSQL, maxAttempts, exhaustedSweepLimit)
	if err != nil {
		if ctx.Err() == nil {
			w.logger.Warn("secevents: exhausted-claim sweep failed", "error", err)
		}
		return
	}
	if tag.RowsAffected() > 0 {
		w.logger.Error("secevents: terminalized claims exhausted without settlement (crash cycles)",
			"rows", tag.RowsAffected())
	}
}

// pruneSQL is the delivered-row retention sweep (W-P1.5, owner-approved reap
// decision): delete delivered (status='done') rows past the
// security_event_outbox_retain_days window via the installed reducer function
// (reducers/security_event_outbox_prune.sql, V261). Pending rows are never
// eligible and failed rows are the retained durable alert signal — the
// function, not this file, owns that predicate so the reducer reload stays the
// single live source. The sweep is a worker-only seam (SECURITY DEFINER owned
// by setjoin_worker; the app credential is denied EXECUTE by the reducer ACL
// footer + provision-roles carve-out); this worker runs on the BYPASSRLS pool
// by contract and holds the EXECUTE grant.
const pruneSQL = `SELECT security_event_outbox_prune()`

// pruneDelivered runs the rate-limited retention sweep. A failed sweep does not
// advance lastRetention, so it retries on the next tick; the swept count is
// logged only when non-zero (Info — an operator-visible retention fact, not an
// alert).
func (w *Worker) pruneDelivered(ctx context.Context) {
	if ctx.Err() != nil || time.Since(w.lastRetention) < w.retentionInterval {
		return
	}
	var pruned int64
	err := w.pool.QueryRow(ctx, pruneSQL).Scan(&pruned)
	if err != nil {
		if ctx.Err() == nil {
			w.logger.Warn("secevents: retention sweep failed", "error", err)
		}
		return
	}
	w.lastRetention = time.Now()
	if pruned > 0 {
		w.logger.Info("secevents: retention pruned delivered outbox rows",
			"rows", pruned)
	}
}

// settleCause names the delivery failure for last_error. A ctx error is an
// ordinary failed attempt (r3) but last_error must name the deadline or
// cancellation as the cause.
func settleCause(deadline time.Duration, err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	if len(text) > 2048 {
		text = text[:2048] // webhook_delivery_complete left(...,2048) convention
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Sprintf("delivery deadline exceeded (%s): %s", deadline, text)
	case errors.Is(err, context.Canceled):
		return "delivery cancelled: " + text
	default:
		return text
	}
}

// backoffFor returns min(1min * 2^attempts, 1h) — copied from pushjobs
// (scheduled_actions lineage), capped exponential.
func backoffFor(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	if attempts > 6 {
		attempts = 6 // 2^6 min = 64 min → capped to 1h anyway; guards the shift
	}
	d := time.Duration(1<<uint(attempts)) * time.Minute
	if d > time.Hour {
		d = time.Hour
	}
	return d
}
