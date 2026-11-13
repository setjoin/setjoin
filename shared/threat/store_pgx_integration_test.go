package threat

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
)

// Integration coverage for the SQL-backed stores in store.go. These run against
// the loaded test database (DB_DSN / testsupport.OpenTestPool) because the pgx
// adapters are thin SQL seams: the only meaningful failure modes are signature
// drift against the worker-owned SECURITY DEFINER accessors and wrong
// result-shape mapping, both of which only surface against a real database.

// brokenStorePoolValue returns a lazily-connected pool that fails on first use
// (connection refused: port 1 on loopback has no listener). This exercises the
// error-return branches of the pgx adapters without touching real data.
func brokenStorePoolValue(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := "postgres://storetest@127.0.0.1:1/noSuchDB?sslmode=disable&connect_timeout=1"
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New(refused): %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

// TestPGXLockoutStoreLifecycle covers pgxLockoutStore end to end: IsLocked on a
// clean key, escalation to lockout via lockout_escalate, the locked read
// (locked=true with the longest remaining window), and lockout_clear reset.
func TestPGXLockoutStoreLifecycle(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	store := &pgxLockoutStore{pool: pool}
	key := fmt.Sprintf("store-lifecycle-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM auth_lockouts WHERE lockout_key=$1`, key)
	})

	// Clean key: not locked, zero remaining, no error.
	locked, remaining, err := store.IsLocked(ctx, []string{key})
	if err != nil {
		t.Fatalf("IsLocked(clean): %v", err)
	}
	if locked || remaining != 0 {
		t.Fatalf("IsLocked(clean) = (%v,%v), want (false,0)", locked, remaining)
	}

	// Fresh row below threshold (failed_count=4, threshold 5): one more
	// escalation arms the lock (see lockout_escalate.sql).
	if _, err := pool.Exec(ctx,
		`INSERT INTO auth_lockouts (lockout_key, failed_count, locked_until, escalation_level)
		 VALUES ($1, 4, now(), 0)`, key); err != nil {
		t.Fatalf("seed pre-threshold lockout row: %v", err)
	}
	if err := store.Escalate(ctx, key); err != nil {
		t.Fatalf("Escalate: %v", err)
	}

	locked, remaining, err = store.IsLocked(ctx, []string{key})
	if err != nil {
		t.Fatalf("IsLocked(armed): %v", err)
	}
	if !locked {
		t.Fatal("IsLocked(armed) = false, want true after threshold escalation")
	}
	if remaining <= 0 {
		t.Fatalf("remaining = %v, want > 0 for an armed lockout", remaining)
	}

	// Auth-success reset path.
	if err := store.Clear(ctx, []string{key}); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	locked, remaining, err = store.IsLocked(ctx, []string{key})
	if err != nil {
		t.Fatalf("IsLocked(cleared): %v", err)
	}
	if locked || remaining != 0 {
		t.Fatalf("IsLocked(cleared) = (%v,%v), want (false,0)", locked, remaining)
	}
}

// TestPGXSprayStoreSideEffects covers pgxSprayStore: detect_spray read,
// lockout_arm write, audit_log insert and the spray pg_notify.
func TestPGXSprayStoreSideEffects(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	store := &pgxSprayStore{pool: pool}
	runID := fmt.Sprintf("store-test-%d", time.Now().UnixNano())
	ip := fmt.Sprintf("203.0.113.%d", time.Now().UnixNano()%200+10)
	lockKey := "ip:" + ip
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM auth_lockouts WHERE lockout_key=$1`, lockKey)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM audit_log WHERE event_type='spray_detected' AND metadata->>'detector'=$1`, runID)
	})

	// Detect on an IP with no recorded failures: false, no error.
	detected, err := store.Detect(ctx, ip, 600, 5)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if detected {
		t.Fatal("Detect on clean IP = true, want false")
	}

	// LockIP arms the spray lock through lockout_arm.
	if err := store.LockIP(ctx, ip, 5); err != nil {
		t.Fatalf("LockIP: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM auth_lockouts WHERE lockout_key=$1 AND locked_until > now()`,
		lockKey).Scan(&count); err != nil {
		t.Fatalf("verify armed lockout row: %v", err)
	}
	if count != 1 {
		t.Fatalf("LockIP did not arm ip lockout row: count=%d", count)
	}

	// Audit writes the spray_detected audit row.
	meta := []byte(fmt.Sprintf(`{"detector":%q}`, runID))
	if err := store.Audit(ctx, ip, meta); err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM audit_log WHERE event_type='spray_detected' AND metadata->>'detector'=$1`,
		runID).Scan(&count); err != nil {
		t.Fatalf("verify audit row: %v", err)
	}
	if count != 1 {
		t.Fatalf("Audit did not persist spray_detected row: count=%d", count)
	}

	// Notify publishes on the alert channel; success is just "no error".
	if err := store.Notify(ctx, ip); err != nil {
		t.Fatalf("Notify: %v", err)
	}
}

// TestPGXPolicyStoreResolveUserScopeCaches covers NewPolicyStore wiring and the
// scopeCache-backed ResolveUserScope: a seeded group membership resolves from
// the DB on first call and from cache on the second (identical result), and a
// successful fetch stores the entry (success return path of the fetch closure).
func TestPGXPolicyStoreResolveUserScopeCaches(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	store, ok := NewPolicyStore(pool, testsupport.TestLogger()).(*pgxPolicyStore)
	if !ok {
		t.Fatal("NewPolicyStore must return *pgxPolicyStore")
	}

	var domainID, uid int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ('store-scope-test.example') RETURNING id`).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM domains WHERE id=$1`, domainID) })
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name)
		 VALUES ('store-scope', $1, 'store-scope@store-scope-test.example', 'Store Scope') RETURNING id`,
		domainID).Scan(&uid); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM user_group_members WHERE user_id=$1`, uid)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, uid)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_group_members (user_id, group_id) VALUES ($1, 42)`, uid); err != nil {
		t.Fatalf("insert membership: %v", err)
	}

	groups, roleGroups, err := store.ResolveUserScope(ctx, uid)
	if err != nil {
		t.Fatalf("ResolveUserScope(first): %v", err)
	}
	if len(groups) != 1 || groups[0] != 42 {
		t.Fatalf("groups = %v, want [42]", groups)
	}
	if len(roleGroups) != 0 {
		t.Fatalf("roleGroups = %v, want empty", roleGroups)
	}

	// Second call inside the TTL must serve the identical cached entry.
	groups2, roleGroups2, err := store.ResolveUserScope(ctx, uid)
	if err != nil {
		t.Fatalf("ResolveUserScope(cached): %v", err)
	}
	if len(groups2) != 1 || groups2[0] != 42 || len(roleGroups2) != 0 {
		t.Fatalf("cached scope = (%v,%v), want ([42],[])", groups2, roleGroups2)
	}
}

// TestPGXPolicyStoreScopeErrorNotCached pins the error contract
// (CA-SCOPE-RESOLUTION-FAIL-OPEN-CACHED): a fetch failure is returned, never
// converted to empty membership, and is not stored — a subsequent resolve
// retries the DB instead of serving the failed result from cache.
func TestPGXPolicyStoreScopeErrorNotCached(t *testing.T) {
	pool := brokenStorePoolValue(t)
	store, ok := NewPolicyStore(pool, testsupport.TestLogger()).(*pgxPolicyStore)
	if !ok {
		t.Fatal("NewPolicyStore must return *pgxPolicyStore")
	}

	for i := 0; i < 2; i++ {
		groups, roleGroups, err := store.ResolveUserScope(context.Background(), 999123)
		if err == nil {
			t.Fatalf("ResolveUserScope on broken pool call %d: want error", i+1)
		}
		if groups != nil || roleGroups != nil {
			t.Fatalf("ResolveUserScope on broken pool call %d returned membership (%v,%v) with error — must return nil, nil, err",
				i+1, groups, roleGroups)
		}
	}
}

// TestPGXStoresErrorPaths exercises the error-return branches of the lockout
// and spray adapters against a pool that cannot connect.
func TestPGXStoresErrorPaths(t *testing.T) {
	pool := brokenStorePoolValue(t)
	ctx := context.Background()

	lockout := &pgxLockoutStore{pool: pool}
	if _, _, err := lockout.IsLocked(ctx, []string{"k"}); err == nil {
		t.Error("IsLocked on unreachable DB: want error")
	}
	if err := lockout.Escalate(ctx, "k"); err == nil {
		t.Error("Escalate on unreachable DB: want error")
	}
	if err := lockout.Clear(ctx, []string{"k"}); err == nil {
		t.Error("Clear on unreachable DB: want error")
	}

	spray := &pgxSprayStore{pool: pool}
	if _, err := spray.Detect(ctx, "203.0.113.5", 60, 5); err == nil {
		t.Error("Detect on unreachable DB: want error")
	}
	if err := spray.LockIP(ctx, "203.0.113.5", 5); err == nil {
		t.Error("LockIP on unreachable DB: want error")
	}
	if err := spray.Audit(ctx, "203.0.113.5", []byte("{}")); err == nil {
		t.Error("Audit on unreachable DB: want error")
	}
	if err := spray.Notify(ctx, "203.0.113.5"); err == nil {
		t.Error("Notify on unreachable DB: want error")
	}
}
