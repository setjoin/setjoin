package secevents

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// recordingSink captures every delivered event.
type recordingSink struct {
	mu     sync.Mutex
	events []Event
	fn     func(ctx context.Context, ev Event) error // optional override
}

func (s *recordingSink) Deliver(ctx context.Context, ev Event) error {
	s.mu.Lock()
	s.events = append(s.events, ev)
	fn := s.fn
	s.mu.Unlock()
	if fn != nil {
		return fn(ctx, ev)
	}
	return nil
}

func (s *recordingSink) delivered() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.events...)
}

// blockingSink blocks until its ctx is done and records the cancellation —
// the r3 blocked-delivery probe. A sink that ignores ctx violates the
// interface contract; this one honors it.
type blockingSink struct {
	mu     sync.Mutex
	starts chan struct{}
	errs   []error
}

func newBlockingSink() *blockingSink {
	return &blockingSink{starts: make(chan struct{}, 16)}
}

func (s *blockingSink) Deliver(ctx context.Context, ev Event) error {
	s.starts <- struct{}{}
	<-ctx.Done()
	s.mu.Lock()
	s.errs = append(s.errs, ctx.Err())
	s.mu.Unlock()
	return ctx.Err()
}

func (s *blockingSink) startCount() int {
	return len(s.starts)
}

func (s *blockingSink) recordedErrs() []error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]error(nil), s.errs...)
}

// failingSink always fails with a plain (non-ctx) error.
type failingSink struct{ msg string }

func (s *failingSink) Deliver(context.Context, Event) error { return errors.New(s.msg) }

type rowState struct {
	status    string
	attempts  int
	gen       int
	lastError *string
	leaseDue  bool // next_attempt_at <= now()
	delivered *time.Time
}

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return testsupport.OpenTestPool(t)
}

func cleanupEvents(t *testing.T, pool *pgxpool.Pool, eventType string) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM security_event_outbox WHERE event_type = $1`, eventType)
	})
}

func seedEvent(t *testing.T, pool *pgxpool.Pool, eventType, payload string, dueIn time.Duration) int64 {
	t.Helper()
	var id int64
	err := pool.QueryRow(t.Context(),
		`INSERT INTO security_event_outbox (event_type, payload, next_attempt_at)
		 VALUES ($1, $2::jsonb, now() + make_interval(secs => $3)) RETURNING id`,
		eventType, payload, dueIn.Seconds()).Scan(&id)
	if err != nil {
		t.Fatalf("seed event: %v", err)
	}
	cleanupEvents(t, pool, eventType)
	return id
}

// expireLease makes a claimed/due row claimable again (simulates lease expiry
// or a past-due pending row).
func expireLease(t *testing.T, pool *pgxpool.Pool, id int64) {
	t.Helper()
	if _, err := pool.Exec(t.Context(),
		`UPDATE security_event_outbox SET next_attempt_at = now() - interval '1 second' WHERE id = $1`,
		id); err != nil {
		t.Fatalf("expire lease: %v", err)
	}
}

func fetchState(t *testing.T, pool *pgxpool.Pool, id int64) rowState {
	t.Helper()
	var st rowState
	err := pool.QueryRow(t.Context(),
		`SELECT status, attempts, claim_generation, last_error,
		        next_attempt_at <= now(), delivered_at
		   FROM security_event_outbox WHERE id = $1`, id).
		Scan(&st.status, &st.attempts, &st.gen, &st.lastError, &st.leaseDue, &st.delivered)
	if err != nil {
		t.Fatalf("fetch state: %v", err)
	}
	return st
}

func newTestWorker(pool *pgxpool.Pool, sink Sink) *Worker {
	return NewWorker(pgxutil.WorkerPool{Pool: pool}, sink, nil)
}

func TestDeliverSuccessMarksDone(t *testing.T) {
	pool := testPool(t)
	id := seedEvent(t, pool, "secevents_test_done", `{"alert":"login"}`, -time.Second)

	sink := &recordingSink{}
	w := newTestWorker(pool, sink)

	claimed, err := w.processOne(t.Context())
	if err != nil || !claimed {
		t.Fatalf("processOne = (%v,%v), want (true,nil)", claimed, err)
	}
	got := sink.delivered()
	if len(got) != 1 {
		t.Fatalf("sink got %d deliveries, want 1", len(got))
	}
	if got[0].ID != id || got[0].EventType != "secevents_test_done" {
		t.Fatalf("delivered event %+v, want id %d", got[0], id)
	}
	// jsonb round-trips normalized; compare compacted forms.
	var want, gotPayload bytes.Buffer
	_ = json.Compact(&want, []byte(`{"alert":"login"}`))
	_ = json.Compact(&gotPayload, got[0].Payload)
	if !bytes.Equal(want.Bytes(), gotPayload.Bytes()) {
		t.Fatalf("delivered payload %s, want the enqueued payload verbatim", got[0].Payload)
	}
	st := fetchState(t, pool, id)
	if st.status != "done" || st.delivered == nil {
		t.Fatalf("status=%q delivered=%v, want done + delivered_at", st.status, st.delivered)
	}
	if st.lastError != nil {
		t.Fatalf("last_error = %q on success, want NULL", *st.lastError)
	}
	if st.gen != 0 {
		t.Fatalf("claim_generation = %d after done, want 0 (carrier cleared)", st.gen)
	}
}

func TestDeliverFailureRetainsPendingWithBackoff(t *testing.T) {
	pool := testPool(t)
	id := seedEvent(t, pool, "secevents_test_fail", `{"alert":"x"}`, -time.Second)

	w := newTestWorker(pool, &failingSink{msg: "sink down"})
	claimed, err := w.processOne(t.Context())
	if err != nil || !claimed {
		t.Fatalf("processOne = (%v,%v), want (true,nil)", claimed, err)
	}

	st := fetchState(t, pool, id)
	if st.status != "pending" {
		t.Fatalf("status = %q, want pending (failed delivery is retained, never dropped)", st.status)
	}
	if st.attempts != 1 {
		t.Fatalf("attempts = %d, want 1", st.attempts)
	}
	if st.lastError == nil || *st.lastError != "sink down" {
		t.Fatalf("last_error = %v, want the sink cause", st.lastError)
	}
	if st.leaseDue {
		t.Fatal("next_attempt_at must be scheduled into the future (backoff), got due")
	}
}

func TestBoundedRetryThenTerminalFailed(t *testing.T) {
	pool := testPool(t)
	id := seedEvent(t, pool, "secevents_test_exhaust", `{}`, -time.Second)

	w := newTestWorker(pool, &failingSink{msg: "sink down"})
	// Claim+settle cycles until the cap: attempts 1..5.
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		expireLease(t, pool, id)
		claimed, err := w.processOne(t.Context())
		if err != nil || !claimed {
			t.Fatalf("attempt %d: processOne = (%v,%v)", attempt, claimed, err)
		}
		if st := fetchState(t, pool, id); st.attempts != attempt {
			t.Fatalf("attempt %d: row attempts = %d", attempt, st.attempts)
		}
	}
	st := fetchState(t, pool, id)
	if st.status != "failed" {
		t.Fatalf("status = %q after %d attempts, want failed", st.status, maxAttempts)
	}
	if st.lastError == nil || *st.lastError != "sink down" {
		t.Fatalf("last_error = %v, want the recorded cause", st.lastError)
	}

	// A failed row is terminal and never re-claimed (never deleted either).
	expireLease(t, pool, id)
	claimed, err := w.processOne(t.Context())
	if err != nil {
		t.Fatalf("processOne after failure: %v", err)
	}
	if claimed {
		t.Fatal("claimed a failed row — terminal rows must never be re-claimed")
	}
}

func TestExhaustedClaimSweepTerminalizesCrashCycles(t *testing.T) {
	pool := testPool(t)
	w := newTestWorker(pool, &recordingSink{})

	// crashCycles drives num real crash/reclaim cycles against one row: each
	// cycle claims (attempt + generation bump, lease re-armed) and then
	// "crashes" — no settlement ever runs — and the lease lapses so the next
	// cycle can reclaim.
	crashCycles := func(id int64, num int) {
		t.Helper()
		for cycle := 1; cycle <= num; cycle++ {
			if cycle > 1 {
				expireLease(t, pool, id)
			}
			_, gen, err := w.claim(t.Context())
			if err != nil {
				t.Fatalf("crash cycle %d: claim: %v", cycle, err)
			}
			if st := fetchState(t, pool, id); st.attempts != cycle || st.gen != gen {
				t.Fatalf("crash cycle %d: attempts=%d gen=%d, want %d/%d",
					cycle, st.attempts, st.gen, cycle, gen)
			}
		}
	}

	// Crash-cycle row: FIVE real crash/reclaim cycles — not preset attempts
	// (L2-C4 HOLD item 2 acceptance proof). The claim selector itself stops at
	// the cap and the row sits pending due with no settlement ever recorded.
	id := seedEvent(t, pool, "secevents_test_crashcycle", `{}`, -time.Second)
	crashCycles(id, maxAttempts)
	expireLease(t, pool, id) // the last crash — lease lapses without settlement
	if _, _, err := w.claim(t.Context()); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("claim at the cap = %v, want ErrNoRows (selector excludes attempts >= maxAttempts)", err)
	}
	if st := fetchState(t, pool, id); st.status != "pending" {
		t.Fatalf("pre-sweep status = %q, want pending (crash cycles alone never terminalize)", st.status)
	}

	// In-flight row at the cap whose lease is still live must NOT be swept:
	// the same five real cycles with the final lease left running.
	liveID := seedEvent(t, pool, "secevents_test_crashlive", `{}`, -time.Second)
	crashCycles(liveID, maxAttempts)

	w.terminalizeExhausted(t.Context())

	if st := fetchState(t, pool, id); st.status != "failed" {
		t.Fatalf("crash-cycle row status = %q, want failed (sweep terminalizes)", st.status)
	} else if st.lastError == nil || !strings.Contains(*st.lastError, "delivery attempts exhausted") {
		t.Fatalf("last_error = %v, want the exhaustion cause", st.lastError)
	}

	if st := fetchState(t, pool, liveID); st.status != "pending" {
		t.Fatalf("live-lease row status = %q, want pending (lease still in flight)", st.status)
	}

	// The swept row is terminal — never re-claimed (never deleted either).
	expireLease(t, pool, id)
	claimed, err := w.processOne(t.Context())
	if err != nil || claimed {
		t.Fatalf("swept row re-claimed: (%v,%v)", claimed, err)
	}
}

// TestDrainBatchBoundCannotStarveExhaustedSweep covers L2-C4 HOLD item 2: the
// exhausted-claim sweep must make progress in the same tick even when the
// delivery batch stops early. The pre-fix drain looped until nothing was
// claimable and only then swept, so a continuously supplied queue deferred
// crash-cycle terminalization forever.
func TestDrainBatchBoundCannotStarveExhaustedSweep(t *testing.T) {
	pool := testPool(t)
	sink := &recordingSink{}
	w := newTestWorker(pool, sink)
	w.drainBatch = 2 // shrink the per-tick bound so the tick ends mid-supply

	// One crash-cycle row at the cap: five real crash/reclaim cycles, then the
	// lease lapses with no settlement — pending, due, and unclaimable. Driven
	// BEFORE the supply rows exist so each crash cycle claims this row, not a
	// cheaper pending neighbor.
	crashID := seedEvent(t, pool, "secevents_test_crashsupply", `{}`, -time.Second)
	for cycle := 1; cycle <= maxAttempts; cycle++ {
		if cycle > 1 {
			expireLease(t, pool, crashID)
		}
		if _, _, err := w.claim(t.Context()); err != nil {
			t.Fatalf("crash cycle %d: claim: %v", cycle, err)
		}
	}
	expireLease(t, pool, crashID)

	// Three due rows: a full batch leaves one claimable — the continuous
	// supply the old unbounded loop would have kept chasing forever.
	for i := 1; i <= 3; i++ {
		seedEvent(t, pool, fmt.Sprintf("secevents_test_supply_%d", i), `{}`, -time.Second)
	}

	w.drain(t.Context())

	if got := len(sink.delivered()); got != w.drainBatch {
		t.Fatalf("drain delivered %d rows, want exactly the %d-row batch bound (rows remained claimable)",
			got, w.drainBatch)
	}

	// The sweep still ran in the same tick despite the unclaimed supply row.
	if st := fetchState(t, pool, crashID); st.status != "failed" {
		t.Fatalf("crash-cycle row status = %q after a bound-stopped tick, want failed — a supplied queue must not starve the exhausted-claim sweep", st.status)
	}

	// Exactly one supplied row remains unclaimed by the bound: still pending,
	// untouched, due next tick.
	var remaining int
	if err := pool.QueryRow(t.Context(),
		`SELECT count(*) FROM security_event_outbox
		  WHERE event_type IN ('secevents_test_supply_1','secevents_test_supply_2','secevents_test_supply_3')
		    AND status = 'pending' AND attempts = 0`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Fatalf("supplied rows the bound left untouched = %d, want exactly 1", remaining)
	}
}

func TestRestartResumeReclaimsPastDue(t *testing.T) {
	pool := testPool(t)
	id := seedEvent(t, pool, "secevents_test_restart", `{"n":1}`, -time.Second)

	// Fresh worker (as after a restart): the past-due pending row is claimed
	// on the first drain.
	w := newTestWorker(pool, &recordingSink{})
	claimed, err := w.processOne(t.Context())
	if err != nil || !claimed {
		t.Fatalf("processOne = (%v,%v), want (true,nil)", claimed, err)
	}
	if st := fetchState(t, pool, id); st.attempts != 1 || st.status != "done" {
		t.Fatalf("restart-resume row: status=%q attempts=%d, want done/1", st.status, st.attempts)
	}
}

func TestLeaseExpiryRecoveryAndStaleSettlementFenced(t *testing.T) {
	pool := testPool(t)
	id := seedEvent(t, pool, "secevents_test_stale", `{}`, -time.Second)

	w1 := newTestWorker(pool, &recordingSink{})
	ev1, gen1, err := w1.claim(t.Context())
	if err != nil {
		t.Fatalf("claim 1: %v", err)
	}
	if st := fetchState(t, pool, id); st.attempts != 1 || st.gen != gen1 || st.leaseDue {
		t.Fatalf("after claim: %+v gen=%d — want attempts=1, live lease", fetchState(t, pool, id), gen1)
	}
	_ = ev1

	// Lease lapses (crash); another worker reclaims: generation bumps.
	expireLease(t, pool, id)
	w2 := newTestWorker(pool, &recordingSink{})
	_, gen2, err := w2.claim(t.Context())
	if err != nil {
		t.Fatalf("claim 2 (recovery): %v", err)
	}
	if gen2 != gen1+1 {
		t.Fatalf("claim generation %d after reclaim, want %d", gen2, gen1+1)
	}

	// Worker 1 comes back from the dead and settles its lapsed claim: fenced
	// off — zero rows, the new claimant's state is intact.
	w1.settleDelivery(t.Context(), ev1, gen1, nil)
	st := fetchState(t, pool, id)
	if st.status != "pending" {
		t.Fatalf("status = %q after stale done settlement, want pending (fenced)", st.status)
	}
	if st.attempts != 2 || st.gen != gen2 {
		t.Fatalf("stale settlement mutated the row: attempts=%d gen=%d, want 2/%d",
			st.attempts, st.gen, gen2)
	}
	if st.delivered != nil {
		t.Fatal("stale settlement set delivered_at on the new claimant's row")
	}
}

func TestSkipLockedTwoWorkersClaimDistinctRows(t *testing.T) {
	pool := testPool(t)
	seedEvent(t, pool, "secevents_test_lock_a", `{}`, -time.Second)
	seedEvent(t, pool, "secevents_test_lock_b", `{}`, -time.Second)

	ctx := t.Context()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Worker 1 claims inside an uncommitted transaction — the row lock is
	// held until rollback.
	var ev1 Event
	var gen1 int
	var payload string
	if err := tx.QueryRow(ctx, claimSQL, leaseWindow.Seconds(), maxAttempts).
		Scan(&ev1.ID, &ev1.EventType, &payload, &ev1.Attempts, &gen1); err != nil {
		t.Fatalf("tx claim: %v", err)
	}

	// Worker 2 must SKIP the locked row and claim the other one.
	w2 := newTestWorker(pool, &recordingSink{})
	ev2, _, err := w2.claim(ctx)
	if err != nil {
		t.Fatalf("concurrent claim: %v", err)
	}
	if ev2.ID == ev1.ID {
		t.Fatalf("both workers claimed row %d — SKIP LOCKED is not skipping", ev1.ID)
	}
}

func TestEmptyQueueNoOp(t *testing.T) {
	pool := testPool(t)
	w := newTestWorker(pool, &recordingSink{})

	claimed, err := w.processOne(t.Context())
	if err != nil || claimed {
		t.Fatalf("empty queue: processOne = (%v,%v), want (false,nil)", claimed, err)
	}
	// The sweep is a no-op on an empty queue.
	w.terminalizeExhausted(t.Context())
}

func TestSinkAcceptanceBeforeAckRedeliversSameStableID(t *testing.T) {
	pool := testPool(t)
	id := seedEvent(t, pool, "secevents_test_redeliver", `{"seq":7}`, -time.Second)

	sink := &recordingSink{}
	w := newTestWorker(pool, sink)
	ctx := t.Context()

	// First delivery: sink accepts (Delivery returns nil) but the settlement
	// is lost (simulated crash before settleDelivery).
	ev1, _, err := w.claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Deliver(ctx, ev1); err != nil {
		t.Fatal(err)
	}

	// Lease expires; the row is reclaimed and delivered again.
	expireLease(t, pool, id)
	claimed, err := w.processOne(ctx)
	if err != nil || !claimed {
		t.Fatalf("redelivery claim: (%v,%v)", claimed, err)
	}

	got := sink.delivered()
	if len(got) != 2 {
		t.Fatalf("sink got %d deliveries, want 2 (at-least-once redelivery)", len(got))
	}
	if got[0].ID != got[1].ID || got[0].ID != id {
		t.Fatalf("redelivery carried ids %d/%d, want the same stable id %d",
			got[0].ID, got[1].ID, id)
	}
}

func TestBlockedDeliveryDeadlineReleasesWorkerAndSettlesFenced(t *testing.T) {
	pool := testPool(t)
	id := seedEvent(t, pool, "secevents_test_deadline", `{}`, -time.Second)
	second := seedEvent(t, pool, "secevents_test_deadline2", `{}`, -time.Second)

	sink := newBlockingSink()
	w := newTestWorker(pool, sink)
	w.SetDeliverDeadline(150 * time.Millisecond)

	start := time.Now()
	claimed, err := w.processOne(t.Context())
	elapsed := time.Since(start)
	if err != nil || !claimed {
		t.Fatalf("processOne = (%v,%v)", claimed, err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("worker pinned %s by the blocked sink — deadline did not release it", elapsed)
	}

	if errs := sink.recordedErrs(); len(errs) != 1 || !errors.Is(errs[0], context.DeadlineExceeded) {
		t.Fatalf("sink recorded %v, want the deadline reaching the in-flight call", errs)
	}

	st := fetchState(t, pool, id)
	if st.status != "pending" || st.attempts != 1 {
		t.Fatalf("after cancelled attempt: status=%q attempts=%d, want pending/1 (ordinary failed attempt)",
			st.status, st.attempts)
	}
	if st.lastError == nil || !contains(*st.lastError, "delivery deadline exceeded") {
		t.Fatalf("last_error = %v, want it to name the deadline", st.lastError)
	}

	// The drain continues after the blocked call returns.
	claimed, err = w.processOne(t.Context())
	if err != nil || !claimed {
		t.Fatalf("drain did not continue: (%v,%v)", claimed, err)
	}
	if st := fetchState(t, pool, second); st.attempts != 1 {
		t.Fatalf("second row attempts = %d, want 1", st.attempts)
	}
}

func TestBlockedDeliveryWorkerShutdownCancelsInFlightAndSettles(t *testing.T) {
	pool := testPool(t)
	id := seedEvent(t, pool, "secevents_test_shutdown", `{}`, -time.Second)

	sink := newBlockingSink()
	w := newTestWorker(pool, sink)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	// Wait until a delivery is in flight, then shut the worker down.
	select {
	case <-sink.starts:
	case <-time.After(5 * time.Second):
		t.Fatal("delivery never started")
	}
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return promptly on shutdown — it waited on the blocked sink")
	}

	if errs := sink.recordedErrs(); len(errs) != 1 || !errors.Is(errs[0], context.Canceled) {
		t.Fatalf("sink recorded %v, want the shutdown cancellation", errs)
	}
	st := fetchState(t, pool, id)
	if st.status != "pending" || st.attempts != 1 {
		t.Fatalf("after shutdown: status=%q attempts=%d, want pending/1", st.status, st.attempts)
	}
	if st.lastError == nil || !contains(*st.lastError, "delivery cancelled") {
		t.Fatalf("last_error = %v, want it to name the cancellation", st.lastError)
	}
}

func TestStaleSettlementAfterCancelledDeliveryIsNoOp(t *testing.T) {
	pool := testPool(t)
	id := seedEvent(t, pool, "secevents_test_cancelstale", `{}`, -time.Second)

	sink := newBlockingSink()
	w := newTestWorker(pool, sink)
	w.SetDeliverDeadline(30 * time.Second) // not the exit path — worker cancel is

	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		claimed bool
		err     error
	}
	done := make(chan result, 1)
	go func() {
		claimed, err := w.processOne(ctx)
		done <- result{claimed, err}
	}()

	select {
	case <-sink.starts:
	case <-time.After(5 * time.Second):
		t.Fatal("delivery never started")
	}

	// While the delivery is blocked, the lease lapses and another worker
	// reclaims the row (generation bumps).
	expireLease(t, pool, id)
	w2 := newTestWorker(pool, &recordingSink{})
	_, gen2, err := w2.claim(context.Background())
	if err != nil {
		t.Fatalf("superseding claim: %v", err)
	}

	// Now the worker shuts down: the in-flight delivery returns cancelled and
	// its settlement must be a fenced zero-row no-op.
	cancel()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("processOne: %v", r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("processOne did not return after cancellation")
	}

	st := fetchState(t, pool, id)
	if st.status != "pending" {
		t.Fatalf("status = %q, want pending", st.status)
	}
	if st.gen != gen2 || st.attempts != 2 {
		t.Fatalf("stale settlement mutated the superseded claim: attempts=%d gen=%d, want 2/%d",
			st.attempts, st.gen, gen2)
	}
	if st.lastError != nil {
		t.Fatalf("stale settlement wrote last_error %q on the new claimant's row", *st.lastError)
	}
}

func TestNilSinkInert(t *testing.T) {
	pool := testPool(t)
	id := seedEvent(t, pool, "secevents_test_nil", `{}`, -time.Second)

	w := newTestWorker(pool, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	w.Run(ctx) // returns promptly; drain inert

	st := fetchState(t, pool, id)
	if st.status != "pending" || st.attempts != 0 || st.gen != 0 {
		t.Fatalf("nil sink touched the row: status=%q attempts=%d gen=%d — seeded rows must stay untouched",
			st.status, st.attempts, st.gen)
	}
}

func TestRunStartupReclaimAndPromptShutdown(t *testing.T) {
	pool := testPool(t)
	id := seedEvent(t, pool, "secevents_test_runreclaim", `{}`, -time.Second)

	sink := &recordingSink{}
	w := newTestWorker(pool, sink)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	// The first drain runs immediately at startup (restart-resume).
	deadline := time.After(5 * time.Second)
	for {
		if got := sink.delivered(); len(got) >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("startup drain never delivered the past-due row")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if st := fetchState(t, pool, id); st.status != "done" {
		t.Fatalf("startup-reclaimed row status = %q, want done", st.status)
	}
}

func TestSetDeliverDeadlineEnforcesLeaseInvariant(t *testing.T) {
	w := NewWorker(pgxutil.WorkerPool{}, nil, nil)

	cases := []time.Duration{
		0,
		-1 * time.Second,
		leaseWindow,                 // equals the lease — no settlement margin
		leaseWindow - settleTimeout, // exactly the margin — still not strictly below
	}
	for _, d := range cases {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("SetDeliverDeadline(%s) accepted a value breaking deadline+margin<lease", d)
				}
			}()
			w.SetDeliverDeadline(d)
		}()
	}
	w.SetDeliverDeadline(DefaultDeliverDeadline)
	w.SetDeliverDeadline(30 * time.Second)
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}
