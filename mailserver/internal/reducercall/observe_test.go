package reducercall

// Reducer-observability tests (TODOS "Reducer observability"): every invocation
// through PoolCaller records reducer name, SQLSTATE (if any) and duration via
// slog — WARN for classified BZ business errors and slow calls, ERROR for
// unclassified errors, nothing for a fast success. Errors must pass through
// unwrapped-compatible (errors.As on *pgconn.PgError keeps working downstream).
// DB-backed (DB_DSN), same harness as the c5/c3 proof tests in
// reducercall_test.go.

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// recordingHandler is the smallest slog.Handler that captures records for
// assertion. ponytail: test-local, not a shared fixture — lift to testsupport
// only when a second package needs it.
type recordingHandler struct {
	mu   sync.Mutex
	recs []capturedLog
}

type capturedLog struct {
	level slog.Level
	msg   string
	attrs map[string]any
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := map[string]any{}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recs = append(h.recs, capturedLog{level: r.Level, msg: r.Message, attrs: attrs})
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordingHandler) records() []capturedLog {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]capturedLog(nil), h.recs...)
}

// recordingCaller returns a PoolCaller whose observability records land in the
// returned handler instead of the process default logger.
func recordingCaller(pool *pgxpool.Pool) (PoolCaller, *recordingHandler) {
	rec := &recordingHandler{}
	return PoolCaller{Pool: pool, Logger: slog.New(rec)}, rec
}

// mustCreateFn installs a throwaway SQL function and registers its drop.
func mustCreateFn(t *testing.T, pool *pgxpool.Pool, create, drop string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), create); err != nil {
		t.Fatalf("create fn: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), drop) }) //nolint:errcheck // best-effort test cleanup
}

// TestObserve_BZErrorLogsWarnWithNameCodeDuration: an erroring reducer with a
// classified BZ code logs ONE WARN carrying reducer name, sqlstate and
// duration — and the error still reaches the caller as a *pgconn.PgError
// (errors.As pass-through, requirement (a)).
func TestObserve_BZErrorLogsWarnWithNameCodeDuration(t *testing.T) {
	pool := testPoolDB(t)
	const raiser = "obs_proof_bz_raiser"
	mustCreateFn(t, pool,
		`CREATE OR REPLACE FUNCTION `+raiser+`(p_n BIGINT) RETURNS JSONB
		 LANGUAGE plpgsql AS $$
		 BEGIN RAISE EXCEPTION 'observability forced failure' USING ERRCODE='BZ099'; END $$`,
		`DROP FUNCTION IF EXISTS `+raiser+`(BIGINT)`)

	c, rec := recordingCaller(pool)
	_, err := c.Call(context.Background(), raiser, int64(1))
	if err == nil {
		t.Fatal("Call returned nil error, want the BZ099 failure")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "BZ099" {
		t.Fatalf("error = %v, want *pgconn.PgError BZ099 — observability must not break the BZ→protocol map", err)
	}

	recs := rec.records()
	if len(recs) != 1 {
		t.Fatalf("got %d log records, want exactly 1: %+v", len(recs), recs)
	}
	r := recs[0]
	if r.level != slog.LevelWarn {
		t.Errorf("level = %v, want WARN for a classified BZ error", r.level)
	}
	if got := r.attrs["reducer"]; got != raiser {
		t.Errorf("reducer attr = %v, want %q", got, raiser)
	}
	if got := r.attrs["sqlstate"]; got != "BZ099" {
		t.Errorf("sqlstate attr = %v, want BZ099", got)
	}
	if ms, ok := r.attrs["duration_ms"].(int64); !ok || ms < 0 {
		t.Errorf("duration_ms attr = %v (%T), want a non-negative int64", r.attrs["duration_ms"], r.attrs["duration_ms"])
	}
}

// TestObserve_UnclassifiedErrorLogsError: a non-BZ SQLSTATE (here 42883
// undefined_function) logs at ERROR — it is a bug, not a business outcome.
func TestObserve_UnclassifiedErrorLogsError(t *testing.T) {
	pool := testPoolDB(t)
	c, rec := recordingCaller(pool)

	_, err := c.Call(context.Background(), "obs_proof_no_such_reducer")
	if err == nil {
		t.Fatal("Call returned nil error, want undefined_function")
	}

	recs := rec.records()
	if len(recs) != 1 {
		t.Fatalf("got %d log records, want exactly 1: %+v", len(recs), recs)
	}
	r := recs[0]
	if r.level != slog.LevelError {
		t.Errorf("level = %v, want ERROR for an unclassified SQLSTATE", r.level)
	}
	if got := r.attrs["sqlstate"]; got != "42883" {
		t.Errorf("sqlstate attr = %v, want 42883 (undefined_function)", got)
	}
	if got := r.attrs["reducer"]; got != "obs_proof_no_such_reducer" {
		t.Errorf("reducer attr = %v, want the attempted fn name", got)
	}
}

// TestObserve_SlowReducerLogsWarn: a SUCCESSFUL call slower than SlowThreshold
// logs one WARN with name + duration. pg_sleep is the injectable clock — the
// threshold is a package var, lowered here and restored.
func TestObserve_SlowReducerLogsWarn(t *testing.T) {
	pool := testPoolDB(t)
	const slow = "obs_proof_slow"
	mustCreateFn(t, pool,
		`CREATE OR REPLACE FUNCTION `+slow+`(p_n BIGINT) RETURNS JSONB
		 LANGUAGE sql AS $$ SELECT jsonb_build_object('slept', pg_sleep(0.05) IS NOT NULL, 'n', p_n) $$`,
		`DROP FUNCTION IF EXISTS `+slow+`(BIGINT)`)

	orig := SlowThreshold
	SlowThreshold = time.Millisecond
	t.Cleanup(func() { SlowThreshold = orig })

	c, rec := recordingCaller(pool)
	raw, err := c.Call(context.Background(), slow, int64(7))
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("Call returned empty JSON — observability must not eat the result")
	}

	recs := rec.records()
	if len(recs) != 1 {
		t.Fatalf("got %d log records, want exactly 1 slow-reducer WARN: %+v", len(recs), recs)
	}
	r := recs[0]
	if r.level != slog.LevelWarn {
		t.Errorf("level = %v, want WARN", r.level)
	}
	if got := r.attrs["reducer"]; got != slow {
		t.Errorf("reducer attr = %v, want %q", got, slow)
	}
	if ms, ok := r.attrs["duration_ms"].(int64); !ok || ms < 40 {
		t.Errorf("duration_ms attr = %v, want >= 40 (pg_sleep(0.05))", r.attrs["duration_ms"])
	}
}

// TestObserve_FastSuccessLogsNothing: a fast successful call under the default
// threshold produces ZERO records — the wrapper is silent on the happy path.
func TestObserve_FastSuccessLogsNothing(t *testing.T) {
	pool := testPoolDB(t)
	const echo = "obs_proof_echo"
	mustCreateFn(t, pool,
		`CREATE OR REPLACE FUNCTION `+echo+`(p_n BIGINT) RETURNS JSONB
		 LANGUAGE sql AS $$ SELECT jsonb_build_object('n', p_n) $$`,
		`DROP FUNCTION IF EXISTS `+echo+`(BIGINT)`)

	c, rec := recordingCaller(pool)
	if _, err := c.Call(context.Background(), echo, int64(1)); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if recs := rec.records(); len(recs) != 0 {
		t.Fatalf("got %d log records for a fast success, want 0: %+v", len(recs), recs)
	}
}

// TestObserve_CallScopedErrorRecords: CallScoped is wrapped too — the same
// erroring reducer records under its name through the scoped path.
func TestObserve_CallScopedErrorRecords(t *testing.T) {
	pool := testPoolDB(t)
	const raiser = "obs_proof_scoped_raiser"
	mustCreateFn(t, pool,
		`CREATE OR REPLACE FUNCTION `+raiser+`(p_mailbox_id BIGINT) RETURNS JSONB
		 LANGUAGE plpgsql AS $$
		 BEGIN RAISE EXCEPTION 'scoped observability failure' USING ERRCODE='BZ099'; END $$`,
		`DROP FUNCTION IF EXISTS `+raiser+`(BIGINT)`)

	c, rec := recordingCaller(pool)
	_, err := c.CallScoped(context.Background(), 7, raiser)
	if err == nil {
		t.Fatal("CallScoped returned nil error, want BZ099")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "BZ099" {
		t.Fatalf("error = %v, want *pgconn.PgError BZ099 through the scoped path", err)
	}
	recs := rec.records()
	if len(recs) != 1 {
		t.Fatalf("got %d log records, want 1: %+v", len(recs), recs)
	}
	if got := recs[0].attrs["reducer"]; got != raiser {
		t.Errorf("reducer attr = %v, want %q", got, raiser)
	}
	if got := recs[0].attrs["sqlstate"]; got != "BZ099" {
		t.Errorf("sqlstate attr = %v, want BZ099", got)
	}
}

// TestObserve_BatchRecordsFailingLeg: CallScopedBatch observes PER LEG — the
// record names the leg that failed, not the batch, and the fn-name-wrapped
// batch error still exposes the PgError to errors.As.
func TestObserve_BatchRecordsFailingLeg(t *testing.T) {
	pool := testPoolDB(t)
	const ok = "obs_proof_batch_ok"
	const bad = "obs_proof_batch_bad"
	mustCreateFn(t, pool,
		`CREATE OR REPLACE FUNCTION `+ok+`(p_mailbox_id BIGINT) RETURNS JSONB
		 LANGUAGE sql AS $$ SELECT '{"ok":true}'::JSONB $$`,
		`DROP FUNCTION IF EXISTS `+ok+`(BIGINT)`)
	mustCreateFn(t, pool,
		`CREATE OR REPLACE FUNCTION `+bad+`(p_mailbox_id BIGINT) RETURNS JSONB
		 LANGUAGE plpgsql AS $$
		 BEGIN RAISE EXCEPTION 'batch leg failure' USING ERRCODE='BZ099'; END $$`,
		`DROP FUNCTION IF EXISTS `+bad+`(BIGINT)`)

	c, rec := recordingCaller(pool)
	_, err := c.CallScopedBatch(context.Background(), 7,
		ScopedCall{Fn: ok},
		ScopedCall{Fn: bad},
	)
	if err == nil {
		t.Fatal("CallScopedBatch returned nil error, want BZ099")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "BZ099" {
		t.Fatalf("error = %v, want *pgconn.PgError BZ099 through the batch wrap", err)
	}
	recs := rec.records()
	if len(recs) != 1 {
		t.Fatalf("got %d log records, want 1 (the ok leg is fast+successful): %+v", len(recs), recs)
	}
	if got := recs[0].attrs["reducer"]; got != bad {
		t.Errorf("reducer attr = %v, want the FAILING leg %q", got, bad)
	}
}
