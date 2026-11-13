package handlers

// Task 5: SSO-sweep trigger-coexistence tests.
//
// These tests verify that the sweep-exclusion predicate in applyGroupMappings
// (introduced to coexist with V032's trg_protect_last_super_admin trigger) behaves
// correctly across the four critical cases:
//
//  (a) sole SSO Super Admin, knob ON + still mapped → sweep leaves the role-1 row
//      (no BZ064, no error — idempotent re-sync).
//  (b) knob OFF + still-mapped group, with a second SA present → role-1 IS swept
//      (demotion works; trigger doesn't fire because the second SA remains).
//  (c) knob OFF + sole SA → row is retained (BZ064 swallowed by warn-only autocommit)
//      per the documented edge: the last-Super-Admin invariant wins.
//  (d) a non-super SSO role is still revoked on unmap (demotion-on-revoke intact).
//
// All tests are DB-backed (skipped when DB_DSN is unset).  They follow the same
// patterns as sso_group_mapping_test.go.

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"setjoin.com/authserver/internal/federation"
	"setjoin.com/shared/testsupport"
)

// superAdminSingletonLockKey is the well-known advisory-lock key under which the
// global-singleton SSO-sweep test serializes. The sole-SA edge
// (TestSSOSweep_KnobOff_SoleSA_RowRetained) asserts a PROCESS-GLOBAL invariant —
// that the seeded actor is the only enabled Super Admin — so the sweep's DELETE
// trips trg_protect_last_super_admin and BZ064 is swallowed warn-only. A test in
// another package that creates an enabled Super Admin in the shared DB at the same
// instant makes the trigger's remaining-SA count > 0, so BZ064 never fires and the
// row is swept — the known cross-package flake.
//
// ponytail: advisory lock serializes every test that takes this same key; the
// bounded sole-SA wait below also absorbs a transient foreign SA from a
// NON-cooperating package. Closing the flake completely under heavy cross-module
// concurrency would require every enabled-SA-creating test to take this key —
// verify under scripts/test.sh.
const superAdminSingletonLockKey int64 = 0x5341_5F31 // "SA_1"

// lockSuperAdminSingleton takes the session-scoped advisory lock on a dedicated
// pooled connection held for the test's duration (released via t.Cleanup), so the
// sole-SA test serializes against any cooperating Super-Admin-singleton test.
func lockSuperAdminSingleton(t *testing.T, ctx context.Context) {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire advisory-lock conn: %v", err)
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, superAdminSingletonLockKey); err != nil {
		conn.Release()
		t.Fatalf("pg_advisory_lock(super-admin singleton): %v", err)
	}
	t.Cleanup(func() {
		conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, superAdminSingletonLockKey)
		conn.Release()
	})
}

// otherEnabledSuperAdmins returns the count of enabled, active Super Admins OTHER
// than the given actor — the exact set trg_protect_last_super_admin counts when it
// decides whether removing the actor's role-1 row would orphan the last SA.
func otherEnabledSuperAdmins(t *testing.T, ctx context.Context, userID int64) int {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(DISTINCT ara.user_id)
		   FROM admin_role_assignments ara
		   JOIN users u ON u.id = ara.user_id
		  WHERE ara.role_group_id = 1
		    AND ara.user_id <> $1
		    AND (ara.expires_at IS NULL OR ara.expires_at > now())
		    AND u.enabled`,
		userID,
	).Scan(&n); err != nil {
		t.Fatalf("count other enabled super-admins: %v", err)
	}
	return n
}

// seedSSOTestActorWithRole inserts a user + primary mailbox + a single
// admin_role_assignments row (SSO-provisioned, granted_by IS NULL) and returns
// the user ID.  groupID is the role_group_id to seed (1 = Super Admin, 2 =
// User Admin, etc.).  The test is skipped on any schema mismatch.  Callers must
// call cleanSSOActorSweep in a defer to remove the rows.
func seedSSOTestActorWithRole(t *testing.T, ctx context.Context, tag string, groupID int64) int64 {
	t.Helper()
	pool := testsupport.OpenTestPool(t)

	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, sync_source, enabled, is_admin)
		 SELECT $1||'-'||floor(random()*1e9)::text,
		        $1||'-'||floor(random()*1e9)::text||'@sso-sweep-test.internal',
		        'SSO Sweep Test '||$1,
		        d.id, 'sso', TRUE, FALSE
		 FROM domains d WHERE d.is_local = TRUE ORDER BY d.id LIMIT 1
		 RETURNING id`,
		tag,
	).Scan(&userID); err != nil {
		t.Skipf("seed user (%s) failed (schema not loaded?): %v", tag, err)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		 SELECT u.id, u.domain_id, u.email, u.display_name, 'personal', TRUE
		 FROM users u WHERE u.id = $1`,
		userID,
	); err != nil {
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		t.Skipf("seed mailbox (%s) failed: %v", tag, err)
	}

	var assignmentID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, $2, NULL)
		 RETURNING id`, userID, groupID,
	).Scan(&assignmentID); err != nil {
		pool.Exec(ctx, `DELETE FROM mailboxes WHERE user_id = $1`, userID)
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		t.Skipf("seed admin_role_assignments (%s, group %d) failed: %v", tag, groupID, err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO sso_admin_role_provenance (provider_key, assignment_id)
		 VALUES ('test:default', $1)`,
		assignmentID,
	); err != nil {
		pool.Exec(ctx, `DELETE FROM admin_role_assignments WHERE id = $1`, assignmentID)
		pool.Exec(ctx, `DELETE FROM mailboxes WHERE user_id = $1`, userID)
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		t.Skipf("seed SSO admin provenance (%s, group %d) failed: %v", tag, groupID, err)
	}

	return userID
}

// seedSecondSuperAdmin inserts a second permanently-enabled Super Admin user
// (role_group_id=1, granted_by IS NULL).  This is used to satisfy
// trg_protect_last_super_admin so the first actor can be swept.  Returns the
// second user ID.  Call cleanSSOActorSweep for the second user when done.
func seedSecondSuperAdmin(t *testing.T, ctx context.Context) int64 {
	t.Helper()
	return seedSSOTestActorWithRole(t, ctx, "sweep-2nd-sa", 1)
}

// cleanSSOActorSweep removes all rows seeded for the actor.  Two triggers need
// care:
//
//  1. trg_protect_last_super_admin (BEFORE DELETE on admin_role_assignments):
//     fires when deleting the last enabled SA.  Bypassed by first expiring the
//     role-1 row — the trigger's early-exit returns OLD for expired rows.
//
//  2. trg_mailbox_primary_enforce (BEFORE DELETE on mailboxes):
//     fires when deleting the sole primary mailbox of a live user.  Bypassed by
//     deleting the user first: the FK mailboxes.user_id → users(id) ON DELETE
//     SET NULL clears user_id, and the trigger only fires when OLD.user_id IS
//     NOT NULL.  The mailbox is then cleaned up by its pre-collected ID.
func cleanSSOActorSweep(t *testing.T, ctx context.Context, userID int64) {
	t.Helper()
	pool := testsupport.OpenTestPool(t)

	// Collect mailbox IDs before any deletes.
	rows, _ := pool.Query(ctx, `SELECT id FROM mailboxes WHERE user_id = $1`, userID)
	var mbIDs []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			mbIDs = append(mbIDs, id)
		}
	}
	rows.Close()

	// Expire role-1 assignments so the protection trigger allows the DELETE.
	pool.Exec(ctx, `UPDATE admin_role_assignments
		SET expires_at = now() - interval '1 second'
		WHERE user_id = $1 AND role_group_id = 1`, userID)
	pool.Exec(ctx, `DELETE FROM admin_role_assignments WHERE user_id = $1`, userID)

	// Clear is_primary + user_id in one UPDATE so both constraints pass:
	//   • trg_mailbox_primary_enforce: NEW.user_id IS NULL → no check
	//   • mailboxes_shared_not_primary CHECK: is_primary=false OR user_id IS NOT NULL
	//     → satisfied when is_primary=false
	// After this, DELETE by pre-collected ID succeeds because OLD.user_id IS NULL.
	pool.Exec(ctx, `UPDATE mailboxes SET is_primary = FALSE, user_id = NULL WHERE user_id = $1`, userID)
	for _, mbID := range mbIDs {
		pool.Exec(ctx, `DELETE FROM mailboxes WHERE id = $1`, mbID)
	}

	pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
}

// ── (a) sole SSO Super Admin, knob ON + still mapped → sweep leaves role-1 row ──

// TestSSOSweep_SoleSuperAdmin_KnobOn_StillMapped_RowRetained verifies that when
// the operator has opted in (ssoAllowSuperAdminMapping=true) and the super_admin
// group is still present in the login's IdP claims, the sweep excludes role 1 —
// the re-sync is idempotent and trg_protect_last_super_admin never fires.
func TestSSOSweep_SoleSuperAdmin_KnobOn_StillMapped_RowRetained(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	// Actor is the ONLY Super Admin — no second SA seeded.
	userID := seedSSOTestActorWithRole(t, ctx, "sweep-a", 1)
	defer cleanSSOActorSweep(t, ctx, userID)

	// Mapper: super_admin is STILL mapped in this login's IdP groups.
	mapper := &staticMapper{mappings: []federation.GroupMapping{
		{IDPGroup: "idp-super", AdminRole: strPtr("super_admin")},
	}}
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger(), SSOAllowSuperAdminMapping: true})

	// Must not panic, must not produce a BZ064.
	h.applyGroupMappings(ctx, userID, []string{"idp-super"}, mapper)

	// The role-1 row must survive (sweep excluded it; upsert is ON CONFLICT DO NOTHING).
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments
		  WHERE user_id = $1 AND role_group_id = 1 AND granted_by IS NULL`,
		userID,
	).Scan(&count); err != nil {
		t.Fatalf("query role-1 row: %v", err)
	}
	if count != 1 {
		t.Errorf("(a) sole SSO SA, knob ON + still mapped: want role-1 row retained (count=1), got %d", count)
	}
}

// ── (b) knob OFF + still-mapped group, second SA present → role-1 IS swept ───

// TestSSOSweep_KnobOff_StillMapped_SecondSAPresent_RowSwept verifies that when
// the operator knob is OFF (ssoAllowSuperAdminMapping=false), the sweep INCLUDES
// role 1 even if the IdP group is still in the login claims — demotion works
// because a second SA is present (trg_protect_last_super_admin does not fire).
func TestSSOSweep_KnobOff_StillMapped_SecondSAPresent_RowSwept(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	// A second Super Admin must exist so the trigger allows the delete.
	secondID := seedSecondSuperAdmin(t, ctx)
	defer cleanSSOActorSweep(t, ctx, secondID)

	userID := seedSSOTestActorWithRole(t, ctx, "sweep-b", 1)
	defer cleanSSOActorSweep(t, ctx, userID)

	// Mapper: super_admin is STILL in IdP claims but the knob is OFF.
	mapper := &staticMapper{mappings: []federation.GroupMapping{
		{IDPGroup: "idp-super", AdminRole: strPtr("super_admin")},
	}}
	// knob OFF (default false)
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	h.applyGroupMappings(ctx, userID, []string{"idp-super"}, mapper)

	// The role-1 row must be swept (knob-OFF means excludeSuper=false → DELETE ran).
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments
		  WHERE user_id = $1 AND role_group_id = 1 AND granted_by IS NULL`,
		userID,
	).Scan(&count); err != nil {
		t.Fatalf("query role-1 row: %v", err)
	}
	if count != 0 {
		t.Errorf("(b) knob OFF + still-mapped + second SA: want role-1 swept (count=0), got %d", count)
	}
}

// ── (c) knob OFF + sole SA → row retained (BZ064 swallowed, warn-only) ────────

// TestSSOSweep_KnobOff_SoleSA_RowRetained verifies the documented edge case:
// when the operator knob is OFF (or the group is unmapped) and the swept user is
// the ONLY enabled Super Admin, the sweep's DELETE hits BZ064 from
// trg_protect_last_super_admin.  Because the sweep is non-transactional
// (autocommit) and warn-only, the BZ064 is swallowed and the role-1 row is
// RETAINED — the last-Super-Admin invariant wins.  This is INTENDED behaviour:
// to demote a sole SSO Super Admin, provision another Super Admin first.
func TestSSOSweep_KnobOff_SoleSA_RowRetained(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	// Verify the trigger exists in this test DB; skip if V032 not loaded.
	var trigExists bool
	_ = pool.QueryRow(ctx,
		`SELECT EXISTS (
		     SELECT 1 FROM pg_trigger t
		       JOIN pg_class c ON c.oid = t.tgrelid
		      WHERE c.relname = 'admin_role_assignments'
		        AND t.tgname = 'trg_protect_last_super_admin'
		 )`,
	).Scan(&trigExists)
	if !trigExists {
		t.Skip("trg_protect_last_super_admin trigger not present in test DB (V032 not loaded); skipping")
	}

	// Self-isolation: this test depends on the PROCESS-GLOBAL invariant that its
	// actor is the sole enabled Super Admin (so the sweep's DELETE trips BZ064).
	// Serialize against any cooperating singleton test on a well-known advisory
	// lock, then wait (holding it) for any transient foreign SA from a
	// non-cooperating concurrent package to clear before seeding/sweeping.
	lockSuperAdminSingleton(t, ctx)

	// Actor is the ONLY Super Admin.
	userID := seedSSOTestActorWithRole(t, ctx, "sweep-c", 1)
	defer cleanSSOActorSweep(t, ctx, userID)

	// Precondition wait: our actor must be the sole enabled SA at sweep time, or
	// the trigger sees another SA and skips BZ064 (the row would be swept). Hold
	// the lock and let a transient foreign SA drain; fail LOUDLY (never silently
	// skip) if a non-cooperating SA persists past the bound.
	for i := 0; i < 50 && otherEnabledSuperAdmins(t, ctx, userID) > 0; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if n := otherEnabledSuperAdmins(t, ctx, userID); n > 0 {
		t.Fatalf("(c) precondition: %d other enabled Super Admin(s) present despite the singleton lock — a non-cooperating concurrent test; it must serialize via superAdminSingletonLockKey", n)
	}

	// Capture warn log to confirm BZ064 is swallowed (Warn emitted).
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Mapper: super_admin is STILL in IdP claims but the knob is OFF.
	mapper := &staticMapper{mappings: []federation.GroupMapping{
		{IDPGroup: "idp-super", AdminRole: strPtr("super_admin")},
	}}
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: logger})

	// Must not panic; BZ064 must be swallowed (warn-only).
	h.applyGroupMappings(ctx, userID, []string{"idp-super"}, mapper)

	// The role-1 row must be RETAINED (BZ064 blocked the delete).
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments
		  WHERE user_id = $1 AND role_group_id = 1 AND granted_by IS NULL`,
		userID,
	).Scan(&count); err != nil {
		t.Fatalf("query role-1 row: %v", err)
	}
	if count != 1 {
		t.Errorf("(c) knob OFF + sole SA: want role-1 RETAINED (count=1, BZ064 swallowed), got %d", count)
	}

	// The Warn must have been emitted (BZ064 logged, not propagated).
	if !strings.Contains(logBuf.String(), "SSO stale admin-assignment cleanup failed") {
		t.Errorf("(c) knob OFF + sole SA: expected a Warn about the failed cleanup (BZ064 swallowed); got: %s", logBuf.String())
	}
}

// ── (d) non-super SSO role is revoked on unmap (demotion-on-revoke intact) ────

// TestSSOSweep_NonSuperRoleRevoked_OnUnmap verifies that the sweep-exclusion
// change does NOT break demotion for non-super roles: a prior user_admin (group 2)
// SSO grant is deleted when the user logs in without the corresponding IdP group.
func TestSSOSweep_NonSuperRoleRevoked_OnUnmap(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	// Actor has a user_admin (group 2) SSO row.
	userID := seedSSOTestActorWithRole(t, ctx, "sweep-d", 2)
	defer cleanSSOActorSweep(t, ctx, userID)

	// Login WITHOUT the idp-ua group (it no longer appears in IdP claims).
	mapper := &staticMapper{mappings: []federation.GroupMapping{
		{IDPGroup: "idp-ua", AdminRole: strPtr("user_admin")},
	}}
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	// idpGroups does NOT include "idp-ua" → the user_admin mapping is unmapped.
	h.applyGroupMappings(ctx, userID, []string{"idp-other"}, mapper)

	// The role-2 row must be swept (demotion-on-revoke intact).
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_role_assignments
		  WHERE user_id = $1 AND role_group_id = 2 AND granted_by IS NULL`,
		userID,
	).Scan(&count); err != nil {
		t.Fatalf("query role-2 row: %v", err)
	}
	if count != 0 {
		t.Errorf("(d) non-super role unmap: want role-2 swept (count=0), got %d (demotion-on-revoke broken)", count)
	}
}

// ── Static guard: sweep-exclusion predicate structure ─────────────────────────

// TestSSOSweep_StaticGuard_ExclusionPredicatePresent asserts (via AST/source
// inspection) that applyGroupMappings:
//  1. Computes superAdminStillMapped before the sweep DELETE.
//  2. Passes an excludeSuper boolean to the DELETE predicate.
//  3. Uses NOT (role_group_id = 1 AND ...) exclusion form.
//  4. The sweep comment documents the trigger-coexistence fix.
func TestSSOSweep_StaticGuard_ExclusionPredicatePresent(t *testing.T) {
	src := funcSrc(t, "auth.go", "applyGroupMappings")

	if !strings.Contains(src, "superAdminStillMapped") {
		t.Error("applyGroupMappings must compute superAdminStillMapped before the sweep DELETE")
	}
	if !strings.Contains(src, "excludeSuper") {
		t.Error("applyGroupMappings must gate the sweep exclusion via an excludeSuper bool")
	}
	if !strings.Contains(src, "role_group_id = 1") {
		t.Error("applyGroupMappings sweep must use NOT (role_group_id = 1 AND ...) exclusion form")
	}
	if !strings.Contains(src, "trg_protect_last_super_admin") {
		t.Error("applyGroupMappings must document the trigger-coexistence fix in a comment")
	}
	if !strings.Contains(src, "BZ064") {
		t.Error("applyGroupMappings must document the BZ064 edge case in a comment")
	}
	// The exclusion must be gated on BOTH conditions (mirrors re-insert gate).
	if !strings.Contains(src, "ssoAllowSuperAdminMapping") {
		t.Error("applyGroupMappings sweep exclusion must be gated on h.ssoAllowSuperAdminMapping")
	}
	// Pin the conjunction: superAdminStillMapped && ssoAllowSuperAdminMapping must
	// appear IN ORDER so a wrong-operator refactor (|| instead of &&) is caught.
	requireOrder(t, src, "sweep exclusion conjunction",
		"superAdminStillMapped", "&&", "ssoAllowSuperAdminMapping")
}
