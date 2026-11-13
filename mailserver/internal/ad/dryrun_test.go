package ad

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestDryRunNeverCallsSync is the regression for the "Test mutates the users
// table" bug: TestConnection used to call SyncNow (the full mutating sync).
// DryRun must never reach upsertUser / resolveManagerIDs / the cursor writer /
// the identity_sync_log writer — proven here by counting rows in every table
// those write to, before and after a DryRun call. overrideHost non-empty skips
// SRV discovery (serverHosts=["127.0.0.1:636"]); nothing listens there, so the
// call fails at connect() — but the zero-writes property must hold on any code
// path, not just the happy one.
func TestDryRunNeverCallsSync(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	client, err := NewClient("example.com", "cn=svc", "pw", "127.0.0.1", testLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	w := NewSyncWorker(client, pool, testLogger(), 15)

	// The counts are GLOBAL, and `go test ./...` runs packages in parallel
	// against the shared test DB — a concurrent package creating/deleting rows
	// perturbs them. A buggy DryRun yields a nonzero delta on EVERY attempt (its
	// writes are deterministic per call); cross-package churn is transient — so
	// retry the whole measure-cycle and only fail if the delta never settles.
	var before, after int
	for attempt := 1; attempt <= 5; attempt++ {
		before = countRows(t, pool, "users") + countRows(t, pool, "identity_sync_log") + countRows(t, pool, "system_config")
		_, _ = w.DryRun(ctx) // error expected; writes are what's under test
		after = countRows(t, pool, "users") + countRows(t, pool, "identity_sync_log") + countRows(t, pool, "system_config")
		if after == before {
			return
		}
		t.Logf("attempt %d: row counts moved (before=%d after=%d) — retrying in case of concurrent-package churn", attempt, before, after)
	}
	t.Errorf("DryRun changed row counts on every attempt: before=%d after=%d — it must never write", before, after)
}

func countRows(t *testing.T, pool *pgxpool.Pool, table string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}
