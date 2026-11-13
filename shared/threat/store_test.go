package threat

import (
	"context"
	"fmt"
	"testing"
	"time"

	"setjoin.com/shared/testsupport"
)

// Compile-time guarantees: the SQL-backed stores implement the narrow seams.
var (
	_ LockoutStore   = (*pgxLockoutStore)(nil)
	_ SprayStore     = (*pgxSprayStore)(nil)
	_ RateLimitStore = (*pgxRateLimitStore)(nil)
	_ PolicyStore    = (*pgxPolicyStore)(nil)
)

func TestStoreInterfacesExist(t *testing.T) {
	// Existence/conformance is checked by the var block above at compile time.
	// This test body documents intent; it passes once store.go compiles.
}

func TestFormatRoleGroupIDs(t *testing.T) {
	if got := formatRoleGroupIDs(nil); got != "{}" {
		t.Fatalf("nil = %q, want {}", got)
	}
	if got := formatRoleGroupIDs([]int64{1, 5, 9}); got != "{1,5,9}" {
		t.Fatalf("got %q, want {1,5,9}", got)
	}
}

func TestPGXRateLimitStoreExpiredWindowResetsCount(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	key := fmt.Sprintf("store-expired-window-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM rate_limit_counters WHERE key=$1`, key)
	})

	if _, err := pool.Exec(ctx,
		`INSERT INTO rate_limit_counters (key,count,window_start)
		 VALUES ($1,999,now()-interval '2 minutes')`, key); err != nil {
		t.Fatalf("seed expired counter: %v", err)
	}

	store := &pgxRateLimitStore{pool: pool}
	first, err := store.Incr(ctx, key)
	if err != nil {
		t.Fatalf("increment expired counter: %v", err)
	}
	if first != 1 {
		t.Fatalf("expired window count = %d, want reset to 1", first)
	}

	second, err := store.Incr(ctx, key)
	if err != nil {
		t.Fatalf("increment current counter: %v", err)
	}
	if second != 2 {
		t.Fatalf("same-window count = %d, want 2", second)
	}
}
