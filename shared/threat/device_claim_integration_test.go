package threat

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/testsupport"
)

// DB-backed proof of the full P1 produce path: a managed_devices row, keyed by
// the same device_hash the resolver derives (sha256-hex of MakeDeviceFP), maps
// to the DeviceClaim the gateway gate reads. Runs only when DB_DSN points at a
// loaded mailserver_test; the pure mapper test (device_test.go) covers the logic
// without a DB.
func TestResolveDeviceClaim_Integration(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	// Provision an isolated domain + user (managed_devices FKs users(id)).
	var domainID, userID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ('devtrust-test.example') RETURNING id`).Scan(&domainID)
	if err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id=$1`, domainID) })

	err = pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name)
		 VALUES ('devtrust', $1, 'devtrust@devtrust-test.example', 'Dev Trust') RETURNING id`,
		domainID).Scan(&userID)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, userID) })

	resolver := NewDeviceTrustResolver(pool, testsupport.TestLogger())

	hashFor := func(fp string) string {
		return fmt.Sprintf("%x", sha256.Sum256([]byte(fp)))
	}
	seed := func(fp, status string) {
		_, err := pool.Exec(ctx,
			`INSERT INTO managed_devices (device_hash, user_id, compliance_status)
			 VALUES ($1, $2, $3)`, hashFor(fp), userID, status)
		if err != nil {
			t.Fatalf("seed managed_devices (%s): %v", status, err)
		}
	}

	// Clean up managed_devices BEFORE users/domains (registered last → runs first
	// under t.Cleanup's LIFO order). Without this the FK from managed_devices →
	// users makes the `DELETE FROM users` silently fail, leaking an enabled user
	// that contaminates other suites (e.g. gal_search in jmap_contact.pg).
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM managed_devices WHERE user_id=$1`, userID) })

	seed("fp-compliant", "compliant")
	seed("fp-noncompliant", "non_compliant")
	seed("fp-unknown", "unknown")

	t.Run("compliant -> compliant claim", func(t *testing.T) {
		got := resolver.ResolveDeviceClaim(ctx, "fp-compliant", userID)
		if got == nil || got.TrustTier != jwtutil.TrustTierCompliant {
			t.Fatalf("want compliant claim, got %+v", got)
		}
	})
	t.Run("non_compliant -> quarantined claim (blocks)", func(t *testing.T) {
		got := resolver.ResolveDeviceClaim(ctx, "fp-noncompliant", userID)
		if got == nil || got.TrustTier != jwtutil.TrustTierQuarantined {
			t.Fatalf("want quarantined claim, got %+v", got)
		}
	})
	t.Run("unknown status -> nil claim (pass-through)", func(t *testing.T) {
		if got := resolver.ResolveDeviceClaim(ctx, "fp-unknown", userID); got != nil {
			t.Fatalf("want nil claim for unknown status, got %+v", got)
		}
	})
	t.Run("unenrolled (no row) -> nil claim", func(t *testing.T) {
		if got := resolver.ResolveDeviceClaim(ctx, "fp-never-seen", userID); got != nil {
			t.Fatalf("want nil claim for unenrolled device, got %+v", got)
		}
	})
	t.Run("compliant device but wrong user -> nil (scoped by user_id)", func(t *testing.T) {
		if got := resolver.ResolveDeviceClaim(ctx, "fp-compliant", userID+99999); got != nil {
			t.Fatalf("want nil claim when user_id mismatches, got %+v", got)
		}
	})
}

// Cross-user trust-escalation guard for isManagedDevice. device_hash is NOT
// user-unique (= sha256(userAgent | /24-masked-IP)), so two users behind the
// same NAT with the same UA share a hash. Before the fix, isManagedDevice
// queried managed_devices by device_hash ALONE, so userB inherited userA's
// 'compliant' managed tier — a cross-tenant trust escalation enforced all the
// way through Resolve → policy engine. The query must scope by user_id, exactly
// like its siblings ResolveDeviceClaim/isKnownDevice.
func TestIsManagedDevice_ScopedByUser_Integration(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	var domainID, userA, userB int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ('devtrust-nat.example') RETURNING id`).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id=$1`, domainID) })

	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name)
		 VALUES ('nat-a', $1, 'nat-a@devtrust-nat.example', 'NAT A') RETURNING id`,
		domainID).Scan(&userA); err != nil {
		t.Fatalf("insert userA: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, userA) })

	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name)
		 VALUES ('nat-b', $1, 'nat-b@devtrust-nat.example', 'NAT B') RETURNING id`,
		domainID).Scan(&userB); err != nil {
		t.Fatalf("insert userB: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, userB) })

	resolver := NewDeviceTrustResolver(pool, testsupport.TestLogger())

	const sharedFP = "shared-nat-fingerprint"
	sharedHash := fmt.Sprintf("%x", sha256.Sum256([]byte(sharedFP)))

	// Only userA enrolled this (shared) device as compliant.
	if _, err := pool.Exec(ctx,
		`INSERT INTO managed_devices (device_hash, user_id, compliance_status)
		 VALUES ($1, $2, 'compliant')`, sharedHash, userA); err != nil {
		t.Fatalf("seed managed_devices for userA: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM managed_devices WHERE user_id IN ($1,$2)`, userA, userB)
	})

	if !resolver.isManagedDevice(ctx, sharedHash, userA) {
		t.Fatalf("userA enrolled this device compliant; isManagedDevice should be true")
	}
	// The escalation the fix closes: userB shares the device_hash but never
	// enrolled — must NOT inherit userA's managed tier.
	if resolver.isManagedDevice(ctx, sharedHash, userB) {
		t.Fatalf("cross-user escalation: userB inherited userA's managed tier via shared device_hash")
	}
}

// TestResolve_ManagedTierDoesNotCrossUsersOnSharedFingerprint is the full-path
// guard for the forgeable-fingerprint finding (occ_a2f0b8dcd018479c87ead765):
// MakeDeviceFP output is reproducible by any caller in the same masked range
// with the same User-Agent, so Resolve — the tier the conditional-access
// device_trust conditions consume — must derive the managed tier only from a
// managed_devices row scoped to the AUTHENTICATING user. Two users sharing one
// (forgeable) fingerprint: only the enrolled one sees "managed"; the other
// falls through to known/unknown.
func TestResolve_ManagedTierDoesNotCrossUsersOnSharedFingerprint(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	var domainID, userA, userB int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ('devtrust-fp.example') RETURNING id`).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id=$1`, domainID) })

	for _, u := range []struct{ name, email string }{
		{"fp-a", "fp-a@devtrust-fp.example"},
		{"fp-b", "fp-b@devtrust-fp.example"},
	} {
		if err := pool.QueryRow(ctx,
			`INSERT INTO users (username, domain_id, email, display_name)
			 VALUES ($1, $2, $3, 'FP User') RETURNING id`,
			u.name, domainID, u.email).Scan(new(int64)); err != nil {
			t.Fatalf("insert %s: %v", u.name, err)
		}
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE email = 'fp-a@devtrust-fp.example'`).Scan(&userA); err != nil {
		t.Fatalf("load userA: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE email = 'fp-b@devtrust-fp.example'`).Scan(&userB); err != nil {
		t.Fatalf("load userB: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE domain_id=$1`, domainID) })

	resolver := NewDeviceTrustResolver(pool, testsupport.TestLogger())

	// The exact FP shape the interceptor/CA path feeds the resolver.
	sharedFP := MakeDeviceFP("SetjoiniOS/3.2 (iPhone17,2)", "203.0.113.42")
	sharedHash := fmt.Sprintf("%x", sha256.Sum256([]byte(sharedFP)))

	if _, err := pool.Exec(ctx,
		`INSERT INTO managed_devices (device_hash, user_id, compliance_status)
		 VALUES ($1, $2, 'compliant')`, sharedHash, userA); err != nil {
		t.Fatalf("seed managed_devices for userA: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM managed_devices WHERE user_id IN ($1,$2)`, userA, userB)
	})

	if tier := resolver.Resolve(ctx, sharedFP, userA, false); tier != "managed" {
		t.Fatalf("enrolled user tier = %q, want managed", tier)
	}
	// The forgeable inheritance the finding describes, closed by the user_id
	// boundary: the second user presenting the SAME fingerprint gets no
	// managed tier — at best "unknown" (no registry history for this user).
	if tier := resolver.Resolve(ctx, sharedFP, userB, false); tier == "managed" {
		t.Fatal("forgeable fingerprint crossed users: Resolve returned managed for an unenrolled user")
	}
}
