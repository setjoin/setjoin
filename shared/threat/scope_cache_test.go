package threat

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"setjoin.com/shared/toggle"
)

// fakeScopeDB is a minimal PolicyStore that counts ResolveUserScope queries
// (via scopeQueryCount) and returns canned groups/roleGroups per call.
// It reuses the pgxPolicyStore seam by exposing a query-count hook via
// a side-channel (atomic int32), injected through the now-func on scopeCache.
//
// ponytail: we test ResolveUserScope directly on a pgxPolicyStore-like struct,
// but pgxPolicyStore requires a real *pgxpool.Pool. Instead we test the
// scopeCache logic by constructing the cache struct directly and wiring a fake
// fetcher. The integration path (real SQL) is covered by TestResolveUserGroupsAndRoles.
type fakeScopeEntry struct {
	groups     []int64
	roleGroups []int64
	err        error
}

// newTestScopeCache builds a scopeCache with an injectable now-func and fetcher
// for unit-testing without a real DB.
func newTestScopeCache(ttl time.Duration, now func() time.Time, fetch scopeCacheFetch) *scopeCache {
	return &scopeCache{ttl: ttl, now: now, fetch: fetch}
}

func TestResolveUserScopeCachesResult(t *testing.T) {
	var calls atomic.Int32
	fetch := func(_ context.Context, userID int64) ([]int64, []int64, error) {
		calls.Add(1)
		return []int64{10, 20}, []int64{99}, nil
	}
	now := time.Now()
	sc := newTestScopeCache(60*time.Second, func() time.Time { return now }, fetch)
	ctx := context.Background()

	g1, r1, err := sc.resolve(ctx, 7)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if len(g1) != 2 || g1[0] != 10 || g1[1] != 20 {
		t.Fatalf("first call groups: want [10 20], got %v", g1)
	}
	if len(r1) != 1 || r1[0] != 99 {
		t.Fatalf("first call roleGroups: want [99], got %v", r1)
	}

	// Second call within TTL must hit cache (no new fetch).
	g2, r2, err2 := sc.resolve(ctx, 7)
	if err2 != nil {
		t.Fatalf("second call: %v", err2)
	}
	if len(g2) != 2 || len(r2) != 1 {
		t.Fatalf("second call: want same result, got groups=%v roleGroups=%v", g2, r2)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("within-TTL second call must NOT re-query; want 1 fetch, got %d", n)
	}
}

func TestResolveUserScopeDifferentUsersIsolated(t *testing.T) {
	var calls atomic.Int32
	fetch := func(_ context.Context, userID int64) ([]int64, []int64, error) {
		calls.Add(1)
		if userID == 1 {
			return []int64{1}, nil, nil
		}
		return []int64{2}, nil, nil
	}
	now := time.Now()
	sc := newTestScopeCache(60*time.Second, func() time.Time { return now }, fetch)
	ctx := context.Background()

	g1, _, _ := sc.resolve(ctx, 1)
	g2, _, _ := sc.resolve(ctx, 2)

	if len(g1) != 1 || g1[0] != 1 {
		t.Fatalf("user 1 groups: want [1], got %v", g1)
	}
	if len(g2) != 1 || g2[0] != 2 {
		t.Fatalf("user 2 groups: want [2], got %v", g2)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("two distinct users: want 2 fetches, got %d", n)
	}

	// Cross-user guard: user 1's cache must not serve user 2's data.
	g1again, _, _ := sc.resolve(ctx, 1)
	if len(g1again) != 1 || g1again[0] != 1 {
		t.Fatalf("user 1 after user 2 cached: got %v (cross-user leak)", g1again)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("second user-1 call must cache-hit; want 2 total fetches, got %d", n)
	}
}

func TestResolveUserScopeExpiry(t *testing.T) {
	var calls atomic.Int32
	fetch := func(_ context.Context, userID int64) ([]int64, []int64, error) {
		calls.Add(1)
		return []int64{42}, nil, nil
	}
	ts := time.Now()
	sc := newTestScopeCache(60*time.Second, func() time.Time { return ts }, fetch)
	ctx := context.Background()

	sc.resolve(ctx, 5) //nolint:errcheck
	if n := calls.Load(); n != 1 {
		t.Fatalf("first call: want 1 fetch, got %d", n)
	}

	// Advance past TTL: entry should be stale → re-fetch.
	ts = ts.Add(61 * time.Second)
	sc.resolve(ctx, 5) //nolint:errcheck
	if n := calls.Load(); n != 2 {
		t.Fatalf("after TTL expiry: want 2 fetches, got %d", n)
	}
}

// TestResolveUserScopeDecoupledFromInvalidateCache is the key isolation assertion:
// calling PolicyEngine.InvalidateCache() on a separate engine (which flushes the
// policy-set + decision caches) must NOT evict entries in the scope cache.
// The scope cache lives on pgxPolicyStore, not on PolicyEngine.
func TestResolveUserScopeDecoupledFromInvalidateCache(t *testing.T) {
	var calls atomic.Int32
	fetch := func(_ context.Context, userID int64) ([]int64, []int64, error) {
		calls.Add(1)
		return []int64{77}, nil, nil
	}
	now := time.Now()
	sc := newTestScopeCache(60*time.Second, func() time.Time { return now }, fetch)
	ctx := context.Background()

	sc.resolve(ctx, 3) //nolint:errcheck
	if n := calls.Load(); n != 1 {
		t.Fatalf("first resolve: want 1 fetch, got %d", n)
	}

	// Build a PolicyEngine and call InvalidateCache — must not touch sc.
	store := &fakeRawStore{rows: nil}
	tg := toggle.NewStatic(map[string]bool{toggle.FeatureConditionalAccess: true})
	pe := NewPolicyEngine(store, tg, nil, nil, testLogger(), false)
	pe.InvalidateCache() // flushes policy/decision caches; must leave sc untouched

	// Assert: the scope cache still holds the entry (call count stays at 1).
	sc.resolve(ctx, 3) //nolint:errcheck
	if n := calls.Load(); n != 1 {
		t.Fatalf("after InvalidateCache: scope cache must still hold user 3 entry; want 1 fetch, got %d", n)
	}

	// Also verify the entry is actually in the map (not silently dropped).
	raw, ok := sc.m.Load(int64(3))
	if !ok {
		t.Fatal("scope cache map entry for user 3 must still exist after PolicyEngine.InvalidateCache()")
	}
	entry := raw.(scopeCacheEntry)
	if len(entry.groups) != 1 || entry.groups[0] != 77 {
		t.Fatalf("scope cache entry groups: want [77], got %v", entry.groups)
	}
}
