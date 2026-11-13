package threat

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"setjoin.com/shared/testsupport"
)

// DB-backed coverage for DeviceTrustResolver.Resolve's device_registry arm:
// the "known" tier requires last_seen within 90 days AND auth_count >= 3;
// stale or low-count devices fall through to unknown/risky. isKnownDevice runs
// under dbscope.RunUserScoped, so this also proves the GUC pairing works
// against the V254 FORCE-RLS posture.
func TestResolveKnownDeviceTiers(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	var domainID, userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ('known-device-test.example') RETURNING id`).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM domains WHERE id=$1`, domainID) })
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name)
		 VALUES ('known-dev', $1, 'known-dev@known-device-test.example', 'Known Device') RETURNING id`,
		domainID).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM device_registry WHERE user_id=$1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	resolver := NewDeviceTrustResolver(pool, testsupport.TestLogger())
	hashFor := func(fp string) string {
		return fmt.Sprintf("%x", sha256.Sum256([]byte(fp)))
	}
	seed := func(fp string, lastSeen string, authCount int) {
		if _, err := pool.Exec(ctx,
			`INSERT INTO device_registry (user_id, device_hash, last_seen, auth_count)
			 VALUES ($1, $2, now() - $3::interval, $4)`,
			userID, hashFor(fp), lastSeen, authCount); err != nil {
			t.Fatalf("seed device_registry (%s): %v", fp, err)
		}
	}

	// Recent + frequent → known.
	seed("fp-known-recent", "1 hour", 5)
	// Recent but rare (auth_count below the >=3 floor) → not known.
	seed("fp-known-rare", "1 hour", 1)
	// Frequent but stale (beyond the 90-day window) → not known.
	seed("fp-known-stale", "100 days", 99)

	// Unknown device hash with no rows at all → not known.
	seed("fp-known-none", "1 hour", 5)

	if got := resolver.Resolve(ctx, "fp-known-recent", userID, false); got != "known" {
		t.Errorf("Resolve(recent+frequent) = %q, want known", got)
	}
	if got := resolver.Resolve(ctx, "fp-known-rare", userID, false); got != "unknown" {
		t.Errorf("Resolve(recent+rare) = %q, want unknown", got)
	}
	if got := resolver.Resolve(ctx, "fp-known-rare", userID, true); got != "risky" {
		t.Errorf("Resolve(recent+rare+vpn) = %q, want risky", got)
	}
	if got := resolver.Resolve(ctx, "fp-known-stale", userID, false); got != "unknown" {
		t.Errorf("Resolve(stale+frequent) = %q, want unknown", got)
	}
	if got := resolver.Resolve(ctx, "fp-never-seen", userID, false); got != "unknown" {
		t.Errorf("Resolve(no rows) = %q, want unknown", got)
	}
	if got := resolver.Resolve(ctx, "", userID, false); got != "unknown" {
		t.Errorf("Resolve(empty fp) = %q, want unknown", got)
	}

	// Error path: an unreachable pool must fail closed to unknown, not panic.
	broken := NewDeviceTrustResolver(brokenStorePoolValue(t), testsupport.TestLogger())
	if got := broken.Resolve(ctx, "fp-known-recent", userID, false); got != "unknown" {
		t.Errorf("Resolve(broken pool) = %q, want unknown (fail closed)", got)
	}
}
