package threat

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestLoadAllPoliciesUnfiltered(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set — skipping integration test (set to postgres://...@127.0.0.1:5432/mailserver_test_ca?sslmode=disable)")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store := NewPolicyStore(pool, acrTestLogger())

	// Seed two enabled policies with different scopes so we can assert both are returned.
	// Pre-delete any leftover rows from a prior run (name has no unique constraint, priority does
	// when enabled=true — so we clean first to make the INSERT idempotent across re-runs).
	_, _ = pool.Exec(context.Background(),
		`DELETE FROM conditional_access_policies WHERE name IN ('loadall_test_a','loadall_test_b')`)
	_, err = pool.Exec(context.Background(),
		`INSERT INTO conditional_access_policies (priority, name, scope_type, scope_target, enabled)
		 VALUES (91,'loadall_test_a','user','7', true),(92,'loadall_test_b','group','3', true)`)
	if err != nil {
		t.Fatalf("seed policies: %v", err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM conditional_access_policies WHERE name IN ('loadall_test_a','loadall_test_b')`)
	}()

	rows, err := store.LoadAllPolicies(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Must return ALL enabled policies unfiltered — at minimum our two seeds.
	if len(rows) < 2 {
		t.Fatalf("LoadAllPolicies must return ALL enabled policies unfiltered, got %d", len(rows))
	}

	// Verify ordering: every row's priority must be ≤ the next row's priority.
	for i := 1; i < len(rows); i++ {
		if rows[i].Priority < rows[i-1].Priority {
			t.Fatalf("LoadAllPolicies returned rows out of priority order at index %d: priority %d < %d",
				i, rows[i].Priority, rows[i-1].Priority)
		}
	}

	// Verify both seeded scopes are present (user and group) — proving no scope filter applied.
	var foundUser, foundGroup bool
	for _, r := range rows {
		if r.ScopeType == "user" && r.ScopeTarget == "7" {
			foundUser = true
		}
		if r.ScopeType == "group" && r.ScopeTarget == "3" {
			foundGroup = true
		}
	}
	if !foundUser {
		t.Error("LoadAllPolicies missing seeded user-scope policy (scope_type='user', scope_target='7')")
	}
	if !foundGroup {
		t.Error("LoadAllPolicies missing seeded group-scope policy (scope_type='group', scope_target='3')")
	}
}
