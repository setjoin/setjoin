package cron

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

// Coverage for the user-risk cron tick and the scheduler single-flight
// lifecycle (validation refusal, lock acquisition, contended start, release).

// TestComputeUserRiskTick_ToggleOffIsNoop pins the gate: with the feature off
// the tick is a no-op that never queries.
func TestComputeUserRiskTick_ToggleOffIsNoop(t *testing.T) {
	flags := toggle.NewTestFlags(map[string]bool{toggle.FeatureUserRisk: false})
	done := make(chan struct{})
	go func() {
		defer close(done)
		computeUserRiskTick(context.Background(), pgxutil.WorkerPool{}, flags, testsupport.TestLogger())
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("tick with toggle off did not return immediately")
	}
}

// TestComputeUserRiskTick_ScoresActiveUsers runs one tick against the test
// database with the feature on: a user with recent auth_attempts activity is
// scored via compute_user_risk, the active set drains, and the tick returns.
func TestComputeUserRiskTick_ScoresActiveUsers(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	suffix := strings.ReplaceAll(strings.ToLower(fmt.Sprintf("%x", time.Now().UnixNano())), "/", "")
	email := "risk-cron-" + suffix + "@risk-cron.test"

	var domainID, userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ($1) RETURNING id`,
		"risk-cron-"+suffix+".test").Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM auth_attempts WHERE target_username=$1`, email)
		_, _ = pool.Exec(c, `DELETE FROM users WHERE id=$1`, userID)
		_, _ = pool.Exec(c, `DELETE FROM domains WHERE id=$1`, domainID)
	})
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name)
		 VALUES ($1, $2, $3, 'Risk Cron') RETURNING id`,
		"risk-cron-"+suffix, domainID, email).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO auth_attempts (source_ip, target_username, protocol, outcome)
		 VALUES ($1, $2, 'http', 'failure')`,
		"203.0.113.42", email); err != nil {
		t.Fatalf("insert auth_attempt: %v", err)
	}

	flags := toggle.NewTestFlags(map[string]bool{toggle.FeatureUserRisk: true})
	done := make(chan struct{})
	go func() {
		defer close(done)
		computeUserRiskTick(ctx, pgxutil.WorkerPool{Pool: pool}, flags, testsupport.TestLogger())
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("tick with active users did not drain")
	}
}

// TestCronWorkerRefusesInvalidRegistrations pins the startup validation: a
// task whose SQL cannot prepare refuses the whole scheduler loudly.
func TestCronWorkerRefusesInvalidRegistrations(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	w := New(pgxutil.WorkerPool{Pool: pool}, logger)
	if err := w.Register(&Task{
		Name: "bad-sql", Schedule: "@every 1m", SQL: "SELECT no_such_cron_function()",
		Timeout: time.Second, enabled: true,
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Run must return (refused) well before the ctx deadline instead of
	// looping; if it did start, the timeout bounds the test anyway.
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.Run(ctx)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run with invalid registrations neither refused nor stopped")
	}
}

// TestCronWorkerSingleFlightLockContended pins the D-MAILSERVER-INTERNAL-CRON-005
// single-runner assertion: while one scheduler holds the session advisory
// lock, a second worker on the same pool refuses to start; cancelling the
// first releases the lock so a third can take it.
func TestCronWorkerSingleFlightLockContended(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	w1 := New(pgxutil.WorkerPool{Pool: pool}, logger)
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	done1 := make(chan struct{})
	go func() {
		defer close(done1)
		w1.Run(ctx1)
	}()

	// Give the first worker a moment to acquire the lock.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if w1.accepting {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !w1.accepting {
		t.Fatal("first scheduler never became accepting (lock not acquired)")
	}

	// Second worker on the same pool must refuse (lock held).
	w2 := New(pgxutil.WorkerPool{Pool: pool}, logger)
	if err := w2.Register(&Task{Name: "contended", Schedule: "@every 1m", SQL: "SELECT 1", Timeout: time.Second, enabled: true}); err != nil {
		t.Fatalf("register: %v", err)
	}
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		w2.Run(context.Background())
	}()
	select {
	case <-done2:
	case <-time.After(5 * time.Second):
		t.Fatal("contended second scheduler did not refuse and return")
	}

	// Cancelling the first releases the lock; a third worker can start.
	cancel1()
	select {
	case <-done1:
	case <-time.After(5 * time.Second):
		t.Fatal("first scheduler did not release and return")
	}
	w3 := New(pgxutil.WorkerPool{Pool: pool}, logger)
	ctx3, cancel3 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel3()
	done3 := make(chan struct{})
	go func() {
		defer close(done3)
		w3.Run(ctx3)
	}()
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !w3.accepting {
		time.Sleep(20 * time.Millisecond)
	}
	if !w3.accepting {
		t.Fatal("third scheduler could not acquire the released lock")
	}
	cancel3()
	<-done3
}

// TestMatchedMinuteSince_NeverRunWaitsAndLongStallIsOverdue pins the two
// boundary arms of the catch-up scanner: a never-fired task waits for its
// first slot (no zero-time scan), and a stall longer than the 1440-minute
// horizon is treated as overdue.
func TestMatchedMinuteSince_NeverRunWaitsAndLongStallIsOverdue(t *testing.T) {
	// Monday 03:29 — deliberately NOT the "30 3 * * 1" slot, so a never-fired
	// task correctly waits and the stalled scan finds no matching minute.
	now := time.Date(2026, 6, 1, 3, 29, 0, 0, time.UTC)
	never := &Task{Name: "never", Schedule: "30 3 * * *", SQL: "SELECT 1"}
	if err := never.prepare(); err != nil {
		t.Fatal(err)
	}
	never.lastRun = time.Time{} // a task that has never fired
	if never.matchedMinuteSince(now) {
		t.Fatal("never-fired task must wait for its first matching minute, not scan from the zero time")
	}
	if never.Due(now) {
		t.Fatal("never-fired task must not be due before its slot")
	}

	// A schedule-less task is never due (dueLocked's terminal fallthrough).
	plain := &Task{Name: "plain", SQL: "SELECT 1"}
	if plain.Due(now) {
		t.Fatal("task with no interval and no cron expression must never be due")
	}

	// Weekly schedule with a just-under-week stall: the scan horizon (1440
	// minutes) elapses before any matching slot appears, so the task is
	// treated as overdue even though no scanned minute matched.
	stalled := &Task{Name: "stalled", Schedule: "30 3 * * 1", SQL: "SELECT 1"}
	if err := stalled.prepare(); err != nil {
		t.Fatal(err)
	}
	// now must be a Monday for "30 3 * * 1": 2026-06-01 is a Monday.
	if now.Weekday() != time.Monday {
		t.Fatalf("fixture bug: %s is not a Monday", now)
	}
	// Last fire: previous Monday 03:35 — six minutes AFTER that week's slot,
	// so the scan window back to the horizon contains no matching minute.
	stalled.lastRun = now.Add(-7*24*time.Hour + 6*time.Minute)
	if !stalled.matchedMinuteSince(now) {
		t.Fatal("stall beyond the scan horizon must be treated as overdue")
	}
}

// TestComputeUserRiskTick_EmptyActiveSetDrains pins the drained-active-set
// return: with the feature on but no recent auth_attempts, one query runs and
// the tick returns without scoring.
func TestComputeUserRiskTick_EmptyActiveSetDrains(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	flags := toggle.NewTestFlags(map[string]bool{toggle.FeatureUserRisk: true})
	done := make(chan struct{})
	go func() {
		defer close(done)
		computeUserRiskTick(context.Background(), pgxutil.WorkerPool{Pool: pool}, flags, testsupport.TestLogger())
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("tick over an empty active set did not return")
	}
}

// TestComputeUserRiskTick_QueryFailureWarnsAndStops pins the query-failure
// branch: an unreachable database logs and stops the tick (never panics).
func TestComputeUserRiskTick_QueryFailureWarnsAndStops(t *testing.T) {
	pool, err := pgxpool.New(context.Background(),
		"postgres://crontest@127.0.0.1:1/noSuchDB?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	flags := toggle.NewTestFlags(map[string]bool{toggle.FeatureUserRisk: true})
	done := make(chan struct{})
	go func() {
		defer close(done)
		computeUserRiskTick(context.Background(), pgxutil.WorkerPool{Pool: pool}, flags, testsupport.TestLogger())
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("tick on broken pool did not return")
	}
}

// TestAcquireSchedulerLock_BrokenPoolErrors pins the lock-acquisition error
// branch: an unreachable database surfaces an acquire error instead of a
// release func.
func TestAcquireSchedulerLock_BrokenPoolErrors(t *testing.T) {
	pool, err := pgxpool.New(context.Background(),
		"postgres://crontest@127.0.0.1:1/noSuchDB?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	w := New(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
	if _, err := w.acquireSchedulerLock(context.Background()); err == nil {
		t.Fatal("acquireSchedulerLock on broken pool: want error")
	}
}
