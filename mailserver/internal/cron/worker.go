// Package cron provides the in-process scheduler that replaces pg_cron.
package cron

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/pgxutil"
)

const (
	checkInterval     = time.Second
	defaultJoinBudget = 30 * time.Second
)

// executor is deliberately Exec-only. Reducers remain the business authority;
// the scheduler may choose when to invoke their fixed SQL, never inspect data.
type executor interface {
	Exec(ctx context.Context, sql string) error
}

type workerPoolExecutor struct{ pool pgxutil.WorkerPool }

func (e workerPoolExecutor) Exec(ctx context.Context, sql string) error {
	_, err := e.pool.Exec(ctx, sql)
	return err
}

// Worker atomically reserves due tasks, runs at most one instance per task,
// and joins admitted executions during cancellation up to joinBudget.
type Worker struct {
	executor   executor
	clock      clock
	logger     *slog.Logger
	metrics    *Metrics
	joinBudget time.Duration
	// pool backs the startup registration validation in Run. It is nil for
	// executor-only workers (unit tests); validation is skipped in that case.
	pool *pgxpool.Pool

	mu        sync.RWMutex
	tasks     []*Task
	started   bool
	accepting bool
	wg        sync.WaitGroup
}

// New preserves the worker-role boundary at the composition root while
// exposing only Exec to the scheduler internals.
func New(pool pgxutil.WorkerPool, logger *slog.Logger) *Worker {
	w := newWorker(workerPoolExecutor{pool: pool}, realClock{}, logger, defaultJoinBudget)
	w.pool = pool.Pool
	return w
}

func newWorker(exec executor, clk clock, logger *slog.Logger, joinBudget time.Duration) *Worker {
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{
		executor:   exec,
		clock:      clk,
		logger:     logger,
		metrics:    NewMetrics(),
		joinBudget: joinBudget,
	}
}

// Register validates and atomically adds tasks. Invalid or duplicate registry
// rows fail before Run can begin; registration after Run is refused.
func (w *Worker) Register(tasks ...*Task) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started {
		return errors.New("cron registry is already running")
	}
	seen := make(map[string]struct{}, len(w.tasks)+len(tasks))
	for _, task := range w.tasks {
		seen[task.Name] = struct{}{}
	}
	for _, task := range tasks {
		if task == nil {
			return errors.New("cron registry contains nil task")
		}
		if err := task.prepare(); err != nil {
			return err
		}
		if _, exists := seen[task.Name]; exists {
			return fmt.Errorf("duplicate cron task %q", task.Name)
		}
		seen[task.Name] = struct{}{}
	}
	w.tasks = append(w.tasks, tasks...)
	return nil
}

// Tasks returns a snapshot of registered task pointers for admin display.
func (w *Worker) Tasks() []*Task {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return append([]*Task(nil), w.tasks...)
}

// Run blocks until cancellation, then stops admission and joins executions up
// to the gateway's existing shutdown budget. A bound breach is logged loudly.
//
// Startup gate: when the worker was built from a live pool, Run first
// validates that every registered enabled task's SQL resolves against the
// managed schema (prepare-only, nothing executes). On drift the worker
// refuses to start and logs loudly — a registry row that cannot resolve would
// otherwise fail on every run while the worker looks healthy.
func (w *Worker) Run(ctx context.Context) {
	w.mu.Lock()
	if w.started {
		w.mu.Unlock()
		w.logger.Error("cron worker Run called more than once")
		return
	}
	w.started = true
	taskCount := len(w.tasks)
	tasks := append([]*Task(nil), w.tasks...)
	w.mu.Unlock()

	if w.pool != nil {
		if err := ValidateRegistrations(ctx, w.pool, tasks); err != nil {
			w.logger.Error("cron worker refused to start", "error", err)
			return
		}
	}

	// Single-runner assertion (D-MAILSERVER-INTERNAL-CRON-005): the in-process
	// reserve/complete single-flight is per-process only, so a misconfigured
	// second mailserverd would double-execute tasks lacking reducer-side claim
	// semantics. A session-scoped advisory lock held for the Worker's LIFETIME
	// makes the supported single-scheduler topology enforceable: a second
	// worker fails (or stands by) loudly instead of racing the first. Nil-pool
	// executor-only workers (unit tests) skip the lock.
	if w.pool != nil {
		release, err := w.acquireSchedulerLock(ctx)
		if err != nil {
			w.logger.Error("cron worker refused to start — another scheduler instance holds the single-flight lock", "error", err)
			return
		}
		defer release()
	}

	w.mu.Lock()
	w.accepting = true
	w.mu.Unlock()

	tick := w.clock.NewTicker(checkInterval)
	defer tick.Stop()
	w.logger.Info("cron worker started", "tasks", taskCount)

	for {
		select {
		case <-ctx.Done():
			w.stopAdmission()
			w.join()
			w.logger.Info("cron worker stopped")
			return
		case now := <-tick.C():
			w.runDueTasks(ctx, now)
		}
	}
}

// cronSchedulerLockKey namespaces the lifetime advisory lock. Session-scoped
// (pg_try_advisory_lock on a held pool connection): released when the worker
// stops and the connection returns, or automatically if the process dies.
const cronSchedulerLockKey = "cron:scheduler-single-flight"

// acquireSchedulerLock takes the session-scoped advisory lock on a dedicated
// pooled connection and returns a release func. It fails when another process
// already holds the lock (the misconfigured second-scheduler case).
func (w *Worker) acquireSchedulerLock(ctx context.Context) (func(), error) {
	conn, err := w.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire lock connection: %w", err)
	}
	var got bool
	if err := conn.QueryRow(ctx,
		`SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, cronSchedulerLockKey,
	).Scan(&got); err != nil {
		conn.Release()
		return nil, fmt.Errorf("try advisory lock: %w", err)
	}
	if !got {
		conn.Release()
		return nil, fmt.Errorf("lock %q is held by another scheduler instance", cronSchedulerLockKey)
	}
	release := func() {
		// The worker ctx may already be cancelled at release time — unlock on a
		// fresh context so the session parameter is cleared before the conn
		// returns to the pool.
		_, _ = conn.Exec(context.WithoutCancel(ctx),
			`SELECT pg_advisory_unlock(hashtextextended($1, 0))`, cronSchedulerLockKey)
		conn.Release()
	}
	return release, nil
}

func (w *Worker) stopAdmission() {
	w.mu.Lock()
	w.accepting = false
	w.mu.Unlock()
}

func (w *Worker) runDueTasks(ctx context.Context, now time.Time) {
	if ctx.Err() != nil {
		return
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if !w.accepting {
		return
	}
	disabled := make(map[string]bool)
	for _, name := range strings.Split(os.Getenv("GO_WORKERS_OFF"), ",") {
		disabled[strings.TrimSpace(name)] = true
	}
	for _, task := range w.tasks {
		// Each reducer-backed task transfers with its own route family (#244).
		if disabled["cron:"+task.Name] || !task.reserve(now) {
			continue
		}
		w.wg.Add(1)
		go w.execute(ctx, task)
	}
}

func (w *Worker) execute(ctx context.Context, task *Task) {
	defer w.wg.Done()
	started := w.clock.Now()
	success := false
	errText := ""
	defer func() {
		finished := w.clock.Now()
		if recovered := recover(); recovered != nil {
			errText = fmt.Sprintf("panic: %v", recovered)
			w.logger.Error("cron task panicked", "task", task.Name, "panic", recovered)
			w.metrics.recordPanic(task.Name, finished, errText)
		}
		task.complete(finished, errText, success)
		w.metrics.recordDuration(task.Name, finished, finished.Sub(started))
	}()

	taskCtx, cancel := context.WithTimeout(ctx, task.Timeout)
	defer cancel()
	if err := w.executor.Exec(taskCtx, task.SQL); err != nil {
		errText = err.Error()
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(taskCtx.Err(), context.DeadlineExceeded) {
			w.logger.Error("cron task timed out", "task", task.Name, "error", err)
			w.metrics.recordTimeout(task.Name, w.clock.Now(), errText)
		} else {
			w.logger.Error("cron task failed", "task", task.Name, "error", err)
			w.metrics.recordFailure(task.Name, w.clock.Now(), errText)
		}
		return
	}

	success = true
	w.metrics.recordSuccess(task.Name, w.clock.Now())
}

func (w *Worker) join() {
	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-w.clock.After(w.joinBudget):
		w.logger.Error("cron_join_timeout", "budget", w.joinBudget)
	}
}
