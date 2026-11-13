package secevents

// Retention sweep tests (W-P1.5 "C4 residue", owner-approved reap decision for
// the V253 outbox). The V253 contract retained every row; the owner decision
// prunes only DELIVERED (status='done') rows past the
// security_event_outbox_retain_days window, resolved in SQL by
// security_event_outbox_prune() (reducers/security_event_outbox_prune.sql).
// These tests pin the Go side: pending rows are never pruned (the delivery
// promise), failed rows are never pruned (the durable alert signal), the sweep
// is rate-limited per worker, and it rides the drain tick.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const retentionTestType = "secevents_test_retention"

// retainDaysKey is the system_config key the SQL sweep resolves; seeded to '90'
// by V261.
const retainDaysKey = "security_event_outbox_retain_days"

// setRetainDays pins the system_config retention window for the duration of a
// test and restores the prior value afterwards (tests must not leak a mutated
// knob into other suites).
func setRetainDays(t *testing.T, pool *pgxpool.Pool, days string) {
	t.Helper()
	var prev *string
	err := pool.QueryRow(t.Context(),
		`SELECT value #>> '{}' FROM system_config WHERE key = $1`, retainDaysKey).
		Scan(&prev)
	if err != nil && err != pgx.ErrNoRows {
		t.Fatalf("read %s: %v", retainDaysKey, err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		if prev == nil {
			_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key = $1`, retainDaysKey)
			return
		}
		_, _ = pool.Exec(ctx,
			`INSERT INTO system_config (key, value, encrypted, updated_at)
			 VALUES ($1, to_jsonb($2::text), false, now())
			 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
			retainDaysKey, *prev)
	})
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO system_config (key, value, encrypted, updated_at)
		 VALUES ($1, to_jsonb($2::text), false, now())
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
		retainDaysKey, days); err != nil {
		t.Fatalf("set %s=%s: %v", retainDaysKey, days, err)
	}
}

// markDelivered settles a seeded row as delivered at now()-age (the
// delivered_shape CHECK requires delivered_at exactly when status='done').
func markDelivered(t *testing.T, pool *pgxpool.Pool, id int64, age time.Duration) {
	t.Helper()
	if _, err := pool.Exec(t.Context(),
		`UPDATE security_event_outbox
		   SET status = 'done', delivered_at = now() - make_interval(secs => $2),
		       next_attempt_at = now(), claim_generation = 0, last_error = NULL
		 WHERE id = $1`, id, age.Seconds()); err != nil {
		t.Fatalf("mark delivered: %v", err)
	}
}

// markFailed terminalizes a seeded row as failed at now()-age (delivered_at
// stays NULL per the terminal shape CHECK).
func markFailed(t *testing.T, pool *pgxpool.Pool, id int64, age time.Duration) {
	t.Helper()
	if _, err := pool.Exec(t.Context(),
		`UPDATE security_event_outbox
		   SET status = 'failed', next_attempt_at = now() - make_interval(secs => $2),
		       claim_generation = 0, last_error = 'retention test failure'
		 WHERE id = $1`, id, age.Seconds()); err != nil {
		t.Fatalf("mark failed: %v", err)
	}
}

// rowExists reports whether the outbox row is still present.
func rowExists(t *testing.T, pool *pgxpool.Pool, id int64) bool {
	t.Helper()
	var n int
	err := pool.QueryRow(t.Context(),
		`SELECT count(*) FROM security_event_outbox WHERE id = $1`, id).Scan(&n)
	if err != nil {
		t.Fatalf("row exists: %v", err)
	}
	return n == 1
}

// TestRetentionPrunesOnlyDeliveredPastWindow: the sweep deletes exactly the
// delivered rows whose delivery left the window. Pending rows — even long
// past-due ones — keep their delivery promise; failed rows keep the durable
// alert signal; in-window delivered rows are untouched.
func TestRetentionPrunesOnlyDeliveredPastWindow(t *testing.T) {
	pool := testPool(t)
	setRetainDays(t, pool, "1") // 1-day window

	staleDone := seedEvent(t, pool, retentionTestType, `{"k":"stale-done"}`, -time.Second)
	freshDone := seedEvent(t, pool, retentionTestType, `{"k":"fresh-done"}`, -time.Second)
	stalePending := seedEvent(t, pool, retentionTestType, `{"k":"stale-pending"}`, -time.Second)
	staleFailed := seedEvent(t, pool, retentionTestType, `{"k":"stale-failed"}`, -time.Second)

	markDelivered(t, pool, staleDone, 2*24*time.Hour) // delivered 2d ago → outside 1d window
	markDelivered(t, pool, freshDone, time.Hour)      // delivered 1h ago → inside window
	expireLease(t, pool, stalePending)                // long past-due pending → still owed delivery
	markFailed(t, pool, staleFailed, 2*24*time.Hour)  // dead-lettered 2d ago → alert signal retained

	w := newTestWorker(pool, &recordingSink{})
	w.retentionInterval = 0 // force the sweep on this call
	w.pruneDelivered(t.Context())

	if rowExists(t, pool, staleDone) {
		t.Fatalf("stale delivered row %d survived the retention sweep", staleDone)
	}
	for _, tc := range []struct {
		id     int64
		why    string
		status string
	}{
		{freshDone, "in-window delivered row", "done"},
		{stalePending, "past-due pending row (delivery promise)", "pending"},
		{staleFailed, "failed row (durable alert signal)", "failed"},
	} {
		if !rowExists(t, pool, tc.id) {
			t.Fatalf("%s %d was pruned; only delivered rows past the window are eligible", tc.why, tc.id)
		}
		if st := fetchState(t, pool, tc.id); st.status != tc.status {
			t.Fatalf("%s %d: status = %q, want %q (retention must not mutate survivors)", tc.why, tc.id, st.status, tc.status)
		}
	}
}

// TestRetentionIntervalGateSkipsSweep: the tick-side gate. A sweep inside the
// rate-limit window does nothing even for a row far past the default window;
// an expired gate (zero lastRetention — startup catch-up) sweeps it.
func TestRetentionIntervalGateSkipsSweep(t *testing.T) {
	pool := testPool(t)
	// Default window (V261 seed: 90 days) — no config mutation here.
	staleDone := seedEvent(t, pool, retentionTestType, `{"k":"gated"}`, -time.Second)
	markDelivered(t, pool, staleDone, 91*24*time.Hour)

	w := newTestWorker(pool, &recordingSink{})
	w.lastRetention = time.Now() // gate closed: swept within retentionSweepInterval
	w.pruneDelivered(t.Context())
	if !rowExists(t, pool, staleDone) {
		t.Fatal("rate-limited sweep pruned anyway — the retentionInterval gate leaked")
	}

	w.lastRetention = time.Time{} // gate open (startup catch-up shape)
	w.pruneDelivered(t.Context())
	if rowExists(t, pool, staleDone) {
		t.Fatal("due retention sweep left a delivered row past the default window")
	}
	if w.lastRetention.IsZero() {
		t.Fatal("successful sweep did not advance lastRetention — the next tick would re-sweep")
	}
}

// TestDrainRunsRetentionSweep pins the tick wiring: drain (the per-tick entry)
// runs the retention sweep after the exhausted-claim sweep, advancing the gate,
// without disturbing the delivery path (empty queue → no deliveries).
func TestDrainRunsRetentionSweep(t *testing.T) {
	pool := testPool(t)
	staleDone := seedEvent(t, pool, retentionTestType, `{"k":"drain-sweep"}`, -time.Second)
	markDelivered(t, pool, staleDone, 91*24*time.Hour)

	sink := &recordingSink{}
	w := newTestWorker(pool, sink)
	w.retentionInterval = 0
	w.drain(t.Context())

	if rowExists(t, pool, staleDone) {
		t.Fatal("drain tick did not run the retention sweep (wiring missing)")
	}
	if got := len(sink.delivered()); got != 0 {
		t.Fatalf("retention-only tick delivered %d events, want 0", got)
	}
	if w.lastRetention.IsZero() {
		t.Fatal("drain-run sweep did not advance lastRetention")
	}
}

// TestNilSinkInertSkipsRetention: the documented nil-sink inertness covers the
// whole drain — no claim, no sweep, no retention — so the OFF posture never
// prunes either.
func TestNilSinkInertSkipsRetention(t *testing.T) {
	pool := testPool(t)
	staleDone := seedEvent(t, pool, retentionTestType, `{"k":"nil-sink"}`, -time.Second)
	markDelivered(t, pool, staleDone, 91*24*time.Hour)

	w := newTestWorker(pool, nil)
	w.retentionInterval = 0
	w.drain(t.Context())
	if !rowExists(t, pool, staleDone) {
		t.Fatal("nil-sink drain pruned delivered rows — inert posture broken")
	}
}
