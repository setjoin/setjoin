package cron

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// resolveTestPool returns a pool over the managed test schema (DB_DSN). The
// registration-validation tests are read-only (prepare + deallocate, never
// execute), so no fixtures are created; the pool is closed via t.Cleanup.
func resolveTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set; cron registration validation needs the managed schema")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("cannot connect to test DB: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestAllTasks_ResolveAgainstManagedSchema is the startup-drift gate as a
// test: it fails, naming the offending tasks, when any registered enabled
// cron task's SQL no longer resolves against the managed schema (missing
// function, changed signature, dropped table — the drift class that used to
// surface as a silent 42883 on every scheduled run).
func TestAllTasks_ResolveAgainstManagedSchema(t *testing.T) {
	pool := resolveTestPool(t)
	if err := ValidateRegistrations(context.Background(), pool, AllTasks()); err != nil {
		t.Fatalf("registered cron tasks do not resolve against the managed schema:\n%v", err)
	}
}

// TestValidateRegistrations_FailsOnMissingFunction is the negative control for
// the validator itself: a task whose function is absent from the managed
// schema MUST be named in a validation error — a validator that silently
// passes drift would make TestAllTasks_ResolveAgainstManagedSchema vacuous.
func TestValidateRegistrations_FailsOnMissingFunction(t *testing.T) {
	pool := resolveTestPool(t)
	drift := []*Task{{
		Name:     "missing-function-drift-probe",
		Schedule: "@every 1h",
		SQL:      "SELECT cron_task_function_that_does_not_exist_anywhere()",
		Timeout:  time.Second,
		enabled:  true,
	}}
	err := ValidateRegistrations(context.Background(), pool, drift)
	if err == nil {
		t.Fatal("ValidateRegistrations accepted a task calling a function absent from the managed schema")
	}
	if !strings.Contains(err.Error(), "missing-function-drift-probe") {
		t.Errorf("validation error %q does not name the drifted task", err)
	}
}

// TestValidateRegistrations_SkipsDisabledTasks pins the gate's scope: a
// disabled task is not scheduled, so unresolved SQL in it must not block the
// registry (the finding was about ENABLED tasks failing 42883 every run).
func TestValidateRegistrations_SkipsDisabledTasks(t *testing.T) {
	pool := resolveTestPool(t)
	disabled := []*Task{{
		Name:     "disabled-drift-probe",
		Schedule: "@every 1h",
		SQL:      "SELECT cron_task_function_that_does_not_exist_anywhere()",
		Timeout:  time.Second,
		enabled:  false,
	}}
	if err := ValidateRegistrations(context.Background(), pool, disabled); err != nil {
		t.Errorf("ValidateRegistrations rejected a disabled task: %v", err)
	}
}
