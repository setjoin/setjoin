package cron

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ValidateRegistrations verifies that every ENABLED task's SQL resolves
// against the managed schema without executing any of it. Each distinct
// statement is prepared on one pooled connection and deallocated again:
// preparation performs PostgreSQL parse analysis only, which is exactly the
// "resolves against the managed schema" check — it resolves every referenced
// function (42883 on drift), its argument types and every referenced relation,
// but runs no reducer and changes no data. Utility statements in task SQL
// (REFRESH MATERIALIZED VIEW, bare DELETE) prepare the same way.
//
// This is the startup/test-time gate for the drift class where a registered
// task referenced a function absent from the managed schema and then failed
// 42883 on every single run while the worker stayed green. The returned error
// names every failing task, not just the first.
func ValidateRegistrations(ctx context.Context, pool *pgxpool.Pool, tasks []*Task) error {
	if pool == nil {
		return nil
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("cron registration validation cannot acquire a connection: %w", err)
	}
	defer conn.Release()

	var failures []string
	seen := make(map[string]struct{})
	for i, task := range tasks {
		if task == nil || !task.enabled || task.SQL == "" {
			continue
		}
		if _, done := seen[task.SQL]; done {
			continue
		}
		// Unique per task index: a failed prepare must not collide with the
		// next candidate's statement name.
		stmt := fmt.Sprintf("cron_registration_validate_%d", i)
		if _, err := conn.Conn().Prepare(ctx, stmt, task.SQL); err != nil {
			failures = append(failures, fmt.Sprintf("task %q: %v", task.Name, err))
			continue
		}
		seen[task.SQL] = struct{}{}
		// Leave no prepared statement behind on the pooled session.
		_ = conn.Conn().Deallocate(ctx, stmt)
	}
	if len(failures) > 0 {
		return fmt.Errorf("%d registered cron task(s) do not resolve against the managed schema:\n%s",
			len(failures), strings.Join(failures, "\n"))
	}
	return nil
}
