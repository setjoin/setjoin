package cron

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

type fakeTicker struct{ ch <-chan time.Time }

func (t fakeTicker) C() <-chan time.Time { return t.ch }
func (fakeTicker) Stop()                 {}

type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	ticks   chan time.Time
	after   chan time.Time
	ready   chan struct{}
	readyMu sync.Once
}

func newFakeClock(now time.Time) *fakeClock {
	return &fakeClock{
		now:   now,
		ticks: make(chan time.Time, 16),
		after: make(chan time.Time, 1),
		ready: make(chan struct{}),
	}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTicker(time.Duration) ticker {
	c.readyMu.Do(func() { close(c.ready) })
	return fakeTicker{ch: c.ticks}
}

func (c *fakeClock) After(time.Duration) <-chan time.Time { return c.after }

func (c *fakeClock) Tick(now time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
	c.ticks <- now
}

type fakeExecutor struct {
	mu        sync.Mutex
	calls     int
	active    int
	maxActive int
	called    chan struct{}
	run       func(context.Context, string) error
}

func newFakeExecutor(run func(context.Context, string) error) *fakeExecutor {
	return &fakeExecutor{called: make(chan struct{}, 32), run: run}
}

func (e *fakeExecutor) Exec(ctx context.Context, sql string) error {
	e.mu.Lock()
	e.calls++
	e.active++
	if e.active > e.maxActive {
		e.maxActive = e.active
	}
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.active--
		e.mu.Unlock()
	}()
	e.called <- struct{}{}
	if e.run == nil {
		return nil
	}
	return e.run(ctx, sql)
}

func (e *fakeExecutor) snapshot() (calls, active, maxActive int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls, e.active, e.maxActive
}

func startTestWorker(t *testing.T, task *Task, exec *fakeExecutor, clk *fakeClock, joinBudget time.Duration) (*Worker, context.CancelFunc, <-chan struct{}) {
	t.Helper()
	w := newWorker(exec, clk, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), joinBudget)
	if err := w.Register(task); err != nil {
		t.Fatalf("register: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()
	select {
	case <-clk.ready:
	case <-time.After(time.Second):
		t.Fatal("worker ticker did not start")
	}
	return w, cancel, done
}

func stopTestWorker(t *testing.T, cancel context.CancelFunc, done <-chan struct{}) {
	t.Helper()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
}

func TestDueCheckReservesBeforeConcurrentDispatch(t *testing.T) {
	now := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	task := &Task{Name: "overlap", Schedule: "@every 1m", SQL: "SELECT 1", enabled: true}
	if err := task.prepare(); err != nil {
		t.Fatal(err)
	}
	task.lastRun = now.Add(-2 * time.Minute)

	start := make(chan struct{})
	var wg sync.WaitGroup
	var reserved int
	var mu sync.Mutex
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if task.reserve(now) {
				mu.Lock()
				reserved++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if reserved != 1 {
		t.Fatalf("concurrent reservations = %d, want 1", reserved)
	}
}

func TestWorkerDueNonDueAndOncePerMinute(t *testing.T) {
	base := time.Date(2026, 8, 13, 3, 30, 0, 0, time.UTC)
	t.Run("interval due and non-due", func(t *testing.T) {
		task := &Task{Name: "interval", Schedule: "@every 1m", SQL: "SELECT 1", Timeout: time.Second, enabled: true, lastRun: base}
		exec := newFakeExecutor(nil)
		clk := newFakeClock(base)
		_, cancel, done := startTestWorker(t, task, exec, clk, time.Second)
		clk.Tick(base.Add(30 * time.Second))
		time.Sleep(10 * time.Millisecond)
		if calls, _, _ := exec.snapshot(); calls != 0 {
			t.Fatalf("non-due calls = %d, want 0", calls)
		}
		clk.Tick(base.Add(61 * time.Second))
		waitCalls(t, exec, 1)
		stopTestWorker(t, cancel, done)
	})

	t.Run("cron once per matching minute", func(t *testing.T) {
		task := &Task{Name: "minute", Schedule: "30 3 * * *", SQL: "SELECT 1", Timeout: time.Second, enabled: true, lastRun: base.Add(-time.Minute)}
		exec := newFakeExecutor(nil)
		clk := newFakeClock(base)
		_, cancel, done := startTestWorker(t, task, exec, clk, time.Second)
		clk.Tick(base.Add(5 * time.Second))
		waitCalls(t, exec, 1)
		clk.Tick(base.Add(45 * time.Second))
		time.Sleep(10 * time.Millisecond)
		if calls, _, _ := exec.snapshot(); calls != 1 {
			t.Fatalf("same-minute calls = %d, want 1", calls)
		}
		stopTestWorker(t, cancel, done)
	})
}

func TestWorkerSingleFlightNoOverlap(t *testing.T) {
	base := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	release := make(chan struct{})
	exec := newFakeExecutor(func(context.Context, string) error { <-release; return nil })
	task := &Task{Name: "single", Schedule: "@every 1s", SQL: "SELECT 1", Timeout: time.Second, enabled: true}
	clk := newFakeClock(base)
	_, cancel, done := startTestWorker(t, task, exec, clk, time.Second)
	clk.Tick(base)
	waitCalls(t, exec, 1)
	clk.Tick(base.Add(2 * time.Second))
	time.Sleep(10 * time.Millisecond)
	if calls, _, maxActive := exec.snapshot(); calls != 1 || maxActive != 1 {
		t.Fatalf("overlap calls/max = %d/%d, want 1/1", calls, maxActive)
	}
	close(release)
	waitActive(t, exec, 0)
	waitTaskStopped(t, task)
	clk.Tick(base.Add(3 * time.Second))
	waitCalls(t, exec, 2)
	stopTestWorker(t, cancel, done)
}

func TestWorkerAccountsSuccessErrorTimeoutAndPanic(t *testing.T) {
	tests := []struct {
		name string
		run  func(context.Context, string) error
		want func(TaskMetrics) bool
	}{
		{name: "success", want: func(m TaskMetrics) bool { return m.SuccessCount == 1 }},
		{name: "error", run: func(context.Context, string) error { return errors.New("boom") }, want: func(m TaskMetrics) bool { return m.FailureCount == 1 && m.LastError == "boom" }},
		{name: "timeout", run: func(ctx context.Context, _ string) error { <-ctx.Done(); return ctx.Err() }, want: func(m TaskMetrics) bool { return m.TimeoutCount == 1 }},
		{name: "panic", run: func(context.Context, string) error { panic("sentinel") }, want: func(m TaskMetrics) bool { return m.PanicCount == 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
			exec := newFakeExecutor(tt.run)
			task := &Task{Name: tt.name, Schedule: "@every 1s", SQL: "SELECT 1", Timeout: 10 * time.Millisecond, enabled: true}
			clk := newFakeClock(base)
			worker, cancel, done := startTestWorker(t, task, exec, clk, time.Second)
			clk.Tick(base)
			waitMetric(t, worker, tt.name, tt.want)
			waitTaskStopped(t, task)
			stopTestWorker(t, cancel, done)
		})
	}
}

func TestWorkerCancelStopsAdmissionAndJoins(t *testing.T) {
	base := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	returned := make(chan struct{})
	exec := newFakeExecutor(func(ctx context.Context, _ string) error {
		<-ctx.Done()
		close(returned)
		return ctx.Err()
	})
	task := &Task{Name: "cancel", Schedule: "@every 1s", SQL: "SELECT 1", Timeout: time.Hour, enabled: true}
	clk := newFakeClock(base)
	_, cancel, done := startTestWorker(t, task, exec, clk, time.Second)
	clk.Tick(base)
	waitCalls(t, exec, 1)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker returned before joining canceled execution")
	}
	select {
	case <-returned:
	default:
		t.Fatal("execution had not returned when worker join completed")
	}
}

func TestWorkerCancelJoinIsBoundedAndLoud(t *testing.T) {
	base := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	release := make(chan struct{})
	exec := newFakeExecutor(func(context.Context, string) error { <-release; return nil })
	task := &Task{Name: "stuck", Schedule: "@every 1s", SQL: "SELECT 1", Timeout: time.Hour, enabled: true}
	clk := newFakeClock(base)
	var logs bytes.Buffer
	worker := newWorker(exec, clk, slog.New(slog.NewTextHandler(&logs, nil)), time.Minute)
	if err := worker.Register(task); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { worker.Run(ctx); close(done) }()
	<-clk.ready
	clk.Tick(base)
	waitCalls(t, exec, 1)
	cancel()
	clk.after <- base.Add(time.Minute)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bounded join did not return")
	}
	if !strings.Contains(logs.String(), "cron_join_timeout") {
		t.Fatalf("missing cron_join_timeout diagnostic: %s", logs.String())
	}
	close(release)
}

func TestWorkerRegistryValidationAndWorkerRole(t *testing.T) {
	var constructor func(pgxutil.WorkerPool, *slog.Logger) *Worker = New
	if constructor == nil {
		t.Fatal("worker-role constructor missing")
	}
	worker := newWorker(newFakeExecutor(nil), newFakeClock(time.Now()), slog.Default(), time.Second)
	if err := worker.Register(&Task{Name: "", Schedule: "@every 1m", SQL: "SELECT 1"}); err == nil {
		t.Fatal("empty task name accepted")
	}
	if err := worker.Register(&Task{Name: "bad", Schedule: "bad", SQL: "SELECT 1"}); err == nil {
		t.Fatal("invalid schedule accepted")
	}
	if err := worker.Register(
		&Task{Name: "duplicate", Schedule: "@every 1m", SQL: "SELECT 1"},
		&Task{Name: "duplicate", Schedule: "@every 1m", SQL: "SELECT 1"},
	); err == nil {
		t.Fatal("duplicate task accepted")
	}
	if got := len(worker.Tasks()); got != 0 {
		t.Fatalf("failed registration partially mutated registry: %d tasks", got)
	}
}

func waitCalls(t *testing.T, exec *fakeExecutor, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		calls, _, _ := exec.snapshot()
		if calls >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("calls = %d, want %d", calls, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitActive(t *testing.T, exec *fakeExecutor, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		_, active, _ := exec.snapshot()
		if active == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("active = %d, want %d", active, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitMetric(t *testing.T, worker *Worker, name string, want func(TaskMetrics) bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		metric := worker.metrics.Snapshot()[name]
		if want(metric) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("metric for %s did not reach expected state: %+v", name, metric)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitTaskStopped(t *testing.T, task *Task) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		task.mu.RLock()
		running := task.running
		task.mu.RUnlock()
		if !running {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("task %q reservation was not released", task.Name)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestSchedulerLock_SecondInstanceRefused pins the cross-instance
// single-runner primitive (D-MAILSERVER-INTERNAL-CRON-005): the lifetime
// advisory lock is held per SESSION — a second session (the misconfigured
// second mailserverd) must fail pg_try_advisory_lock and be refused, while the
// holding session is unaffected. Uses two held pool connections to stand in
// for the two processes' sessions.
//
// The primitive is key-parameterized, so the test pins it on a PRIVATE per-run
// key: a concurrently-running scheduler on the shared CI database (another
// package's Worker test holding cron:scheduler-single-flight) would otherwise
// make the first try-lock spuriously fail. Session-scoped exclusivity is
// identical for every key; the production key wiring itself is exercised by
// the Worker lifecycle tests.
func TestSchedulerLock_SecondInstanceRefused(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	key := cronSchedulerLockKey + ":test-" + strconv.FormatInt(time.Now().UnixNano(), 36)

	conn1, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire conn1: %v", err)
	}
	// t.Cleanup runs AFTER the test body's defers, and a Released pgxpool.Conn
	// must never be used again — so the unlock (while this session still holds
	// lock and connection) and the release happen in the SAME cleanup.
	t.Cleanup(func() {
		_, _ = conn1.Exec(context.Background(),
			`SELECT pg_advisory_unlock(hashtextextended($1, 0))`, key)
		conn1.Release()
	})

	var got bool
	if err := conn1.QueryRow(ctx,
		`SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, key,
	).Scan(&got); err != nil || !got {
		t.Fatalf("first holder must acquire the scheduler lock (got=%v err=%v)", got, err)
	}

	conn2, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire conn2: %v", err)
	}
	defer conn2.Release()

	if err := conn2.QueryRow(ctx,
		`SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, key,
	).Scan(&got); err != nil {
		t.Fatalf("second session try-lock: %v", err)
	}
	if got {
		t.Error("a second session must NOT be able to acquire the held scheduler lock")
	}
}
