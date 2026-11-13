package threat

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// med-shard3-022 / D-SHARED-THREAT-003 (CA-SCOPE-RESOLUTION-FAIL-OPEN-CACHED).
// A transient scope-resolution error must SURFACE — skip-with-signal, or a
// failModeDecision route for fail-closed callers — instead of silently reading
// as empty membership and being cached for the 60s scope TTL, which bypassed
// every enforcing group/role-scoped CA policy for the window.

func newFaultScopeStore(t *testing.T) *pgxPolicyStore {
	t.Helper()
	s, ok := NewPolicyStore(nil, slog.New(slog.NewTextHandler(io.Discard, nil))).(*pgxPolicyStore)
	if !ok {
		t.Fatal("NewPolicyStore did not return *pgxPolicyStore")
	}
	return s
}

// TestResolveUserScopeTransientErrorNotCached pins the full error contract on
// the production fetch wiring: surface the error, never cache the failure, and
// honor recovery immediately (no 60s empty-membership window).
func TestResolveUserScopeTransientErrorNotCached(t *testing.T) {
	s := newFaultScopeStore(t)

	blip := errors.New("simulated transient scope query blip")
	calls := 0
	fail := true
	s.userScopes.fetch = func(_ context.Context, _ int64) ([]int64, []int64, error) {
		calls++
		if fail {
			return nil, nil, blip
		}
		return []int64{42}, []int64{7}, nil
	}

	base := time.Now()
	s.userScopes.now = func() time.Time { return base } // frozen: every resolve below is inside the 60s TTL

	ctx := context.Background()

	// 1. The transient error must SURFACE — never be swallowed into (nil, nil, nil).
	g, r, err := s.ResolveUserScope(ctx, 7)
	if !errors.Is(err, blip) {
		t.Fatalf("transient scope error must be returned as the fail signal (callers route it to failModeDecision); got err=%v groups=%v roles=%v", err, g, r)
	}
	if g != nil || r != nil {
		t.Fatalf("error path must not return partial membership; got groups=%v roles=%v", g, r)
	}

	// 2. The failure must NOT be cached: an immediately-following resolve within
	// the TTL re-queries (calls==2). Pre-fix, the fetch closure swallowed the
	// resolver error into empty membership and the cache stored it — one query,
	// empty groups for 60s.
	if _, _, _ = s.ResolveUserScope(ctx, 7); calls != 2 {
		t.Fatalf("failed resolution must not be cached (retry must re-fetch): fetch calls=%d, want 2", calls)
	}

	// 3. Recovery is honored IMMEDIATELY — membership resolved right after the
	// blip is the real set, not the 60s-empty window.
	fail = false
	g, r, err = s.ResolveUserScope(ctx, 7)
	if err != nil || len(g) != 1 || g[0] != 42 || len(r) != 1 || r[0] != 7 {
		t.Fatalf("post-blip resolve must return fresh membership; got groups=%v roles=%v err=%v", g, r, err)
	}
	if calls != 3 {
		t.Fatalf("recovery resolve must hit the fetch: calls=%d, want 3", calls)
	}

	// 4. Success IS cached within the TTL (normal behavior preserved).
	if _, _, err := s.ResolveUserScope(ctx, 7); err != nil {
		t.Fatalf("cached success resolve: %v", err)
	}
	if calls != 3 {
		t.Fatalf("successful resolution must be served from cache within TTL: calls=%d, want 3", calls)
	}

	// 5. TTL expiry still re-fetches.
	s.userScopes.now = func() time.Time { return base.Add(61 * time.Second) }
	if _, _, err := s.ResolveUserScope(ctx, 7); err != nil {
		t.Fatalf("post-TTL resolve: %v", err)
	}
	if calls != 4 {
		t.Fatalf("expired entry must re-fetch: calls=%d, want 4", calls)
	}
}

// TestResolveUserGroupsCheckedSurfacesQueryError drives the resolver-level fault
// arm against a real pool: a query failure must return a non-nil error (the
// signal callers need for failModeDecision routing), never silently read as
// "no groups". The deprecated wrappers keep their documented degrade-to-empty
// behavior for existing out-of-package call sites.
func TestResolveUserGroupsCheckedSurfacesQueryError(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set — skipping integration test (set to postgres://mail@127.0.0.1:5432/mailserver_test?sslmode=disable)")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	ctx := context.Background()

	// Healthy pool: R1 scoping sanity — a user id with no memberships resolves
	// empty WITHOUT an error.
	ids, err := ResolveUserGroupsChecked(ctx, pool, 1)
	if err != nil {
		t.Fatalf("healthy pool must not error: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected no memberships for user 1, got %v", ids)
	}

	// Closed pool: the query error must SURFACE (wrapped), never read as
	// "no groups" — that swallow was the finding.
	pool.Close()
	if _, err := ResolveUserGroupsChecked(ctx, pool, 1); err == nil {
		t.Fatal("query error on a closed pool must surface as an error (it used to be silently swallowed into empty membership)")
	}
	if _, err := ResolveRoleGroupsChecked(ctx, pool, 1); err == nil {
		t.Fatal("role-group query error on a closed pool must surface as an error")
	}

	// The deprecated wrappers still degrade to empty (never panic, never leak
	// partial state) — their contract for existing callers is unchanged.
	if g := ResolveUserGroups(ctx, pool, 1); len(g) != 0 {
		t.Fatalf("wrapper must degrade to empty on error; got %v", g)
	}
	if r := ResolveRoleGroups(ctx, pool, 1); len(r) != 0 {
		t.Fatalf("wrapper must degrade to empty on error; got %v", r)
	}
}
