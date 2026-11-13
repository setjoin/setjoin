package admin

// Round-3 Astra correction tests for the krb5_principal change (SetPrincipal →
// ad_principal_set reducer). The pre-correction gateway authorized the change
// BEFORE opening its transaction and then mutated under ID + old-principal value
// equality only, so revoking the actor's authority while the transaction waited
// on the user-row lock still permitted the change. These tests pin the fixed
// shape: live authority re-check INSIDE the row lock, value-conditional UPDATE
// (stale observation → no-op, never an overwrite), audit old→new and notify in
// the mutation transaction.
//
// Round-4 Astra correction: the in-lock re-check is
// admin_can_manage_with_permission(..., 'identity.write') — a current
// assignment must carry BOTH identity.write AND target reach — so tests that
// drive a SUCCESSFUL mutation grant the actor the test identity.write role
// group via grantIdentityWrite; the JWT permission claims injected into
// context never satisfy the reducer.
//
// Uses seedOUTestState (admin_roles_ou_test.go):
//   actorEngOUScoped (97901): OU-scoped to /eng
//   actorGlobal      (97902): unconfined (null scope)
//   userEng          (97903): in /eng — reachable for the global actor
//   userSales        (97905): in /sales — out of reach for the eng-scoped actor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/config"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/testsupport"
)

const (
	principalRevocationOld = "revoked-wait@LEGACY.REALM"
	principalRevocationNew = "revoked-wait@NEW.REALM"
)

// grantIdentityWrite gives the actor a LIVE persisted assignment whose role
// group carries exactly 'identity.write'. ouScope == 0 grants the assignment
// unscoped (global reach); ouScope > 0 grants it OU-scoped to that department
// so tests can pin the REACH axis independently of the permission axis. The
// corrected ad_principal_set contract resolves authority from DATABASE rows
// inside the mutation transaction — the AllPermissions JWT claims injected
// into test contexts never satisfy it — so every test driving a successful
// or stale-path mutation must grant the permission this way. Cleanup removes
// only the assignment; the fixed-name group row is reused across tests and
// reruns.
func grantIdentityWrite(t *testing.T, pool *pgxpool.Pool, userID, ouScope int64) {
	t.Helper()
	ctx := context.Background()
	const groupName = "Setjoin Test identity.write"
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_role_groups (name, description, permissions, domain_scope)
		SELECT $1, 'test-only identity.write carrier', ARRAY['identity.write']::text[], NULL
		WHERE NOT EXISTS (SELECT 1 FROM admin_role_groups WHERE name = $1)`, groupName); err != nil {
		t.Fatalf("seed identity.write role group: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_role_assignments (user_id, role_group_id, scope_type, scope_id, granted_by)
		SELECT $1, g.id,
		       CASE WHEN $2 = 0 THEN NULL ELSE 'ou' END,
		       NULLIF($2, 0),
		       $1
		  FROM admin_role_groups g
		 WHERE g.name = $3
		ON CONFLICT (user_id, role_group_id) DO UPDATE
		     SET scope_type = EXCLUDED.scope_type, scope_id = EXCLUDED.scope_id`,
		userID, ouScope, groupName); err != nil {
		t.Fatalf("assign identity.write role group: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, //nolint:errcheck
			`DELETE FROM admin_role_assignments WHERE user_id = $1
			   AND role_group_id = (SELECT id FROM admin_role_groups WHERE name = $2)`,
			userID, groupName)
	})
}

func countPrincipalChangeAudits(t *testing.T, pool *pgxpool.Pool, actorID, targetID int64) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_audit_log
		  WHERE action = 'ad_krb5_principal_change' AND user_id = $1 AND target_id = $2`,
		actorID, targetID).Scan(&n); err != nil {
		t.Fatalf("count ad_krb5_principal_change audit rows: %v", err)
	}
	return n
}

// waitForBlockedPrincipalSet polls pg_stat_activity until the ad_principal_set
// statement is observably BLOCKED on a lock, proving the revocation below
// commits strictly between the gateway's pre-lock checks and the reducer's
// in-lock authority re-check. On the pre-correction code the blocked statement
// was the handler's FOR UPDATE read; the pinned regression is identical: the
// authority decision must be re-made after the lock is released to us.
func waitForBlockedPrincipalSet(t *testing.T, pool *pgxpool.Pool, done <-chan int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			t.Fatal("SetPrincipal returned before ever blocking on the user-row lock")
		default:
		}
		var n int
		err := pool.QueryRow(context.Background(), `
			SELECT count(*) FROM pg_stat_activity
			 WHERE datname = current_database()
			   AND state = 'active'
			   AND wait_event_type = 'Lock'
			   AND query LIKE '%ad_principal_set%'`).Scan(&n)
		if err == nil && n > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("SetPrincipal never blocked on the user-row lock — pg_stat_activity never showed ad_principal_set waiting")
}

// TestSetPrincipal_RevokedWhileWaitingOnRowLock is the Astra-mandated
// blocked-row revocation test: a lock holder keeps the target user row locked
// while SetPrincipal's pre-lock fast-path checks pass; the actor's authority is
// revoked and COMMITTED while the mutation transaction waits on the row lock;
// when the lock is released the reducer must re-evaluate authority (identity.write
// + reach) inside the lock, observe the revocation, and fail with BZ061 —
// leaving the principal unchanged and writing no audit row. The actor holds a
// LIVE identity.write assignment first, so the revocation (not a missing
// permission) is the only possible cause of the 403.
func TestSetPrincipal_RevokedWhileWaitingOnRowLock(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	grantIdentityWrite(t, pool, st.actorGlobal, 0)
	h := NewADHandler(pool, testsupport.TestLogger(), &config.Config{})
	ctx := context.Background()

	if _, err := pool.Exec(ctx,
		`UPDATE users SET krb5_principal = $1 WHERE id = $2`,
		principalRevocationOld, st.userEng); err != nil {
		t.Fatalf("seed old principal: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, //nolint:errcheck
			`UPDATE users SET krb5_principal = NULL WHERE id = $1`, st.userEng)
		pool.Exec(ctx, //nolint:errcheck
			`UPDATE admin_role_assignments SET eligible = true, expires_at = NULL WHERE user_id = $1`, st.actorGlobal)
	})

	auditsBefore := countPrincipalChangeAudits(t, pool, st.actorGlobal, st.userEng)

	// 1) Lock holder: keep the target user row locked in its own transaction.
	holderConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire holder connection: %v", err)
	}
	defer holderConn.Release()
	holderTx, err := holderConn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin holder transaction: %v", err)
	}
	defer func() { _ = holderTx.Rollback(ctx) }() // no-op after the explicit rollback below
	if _, err := holderTx.Exec(ctx,
		`SELECT krb5_principal FROM users WHERE id = $1 FOR UPDATE`, st.userEng); err != nil {
		t.Fatalf("holder lock target row: %v", err)
	}

	// 2) Drive SetPrincipal concurrently: its fast-path reach check passes
	// (authority is still live), then the reducer's FOR UPDATE blocks.
	resCh := make(chan int, 1)
	go func() {
		body, _ := json.Marshal(map[string]any{"userId": st.userEng, "krb5Principal": principalRevocationNew})
		req := httptest.NewRequest(http.MethodPost, "/admin/ad/principal", strings.NewReader(string(body)))
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
			UserID: st.actorGlobal, IsAdmin: true, Permissions: permissions.AllPermissions,
		}))
		w := httptest.NewRecorder()
		h.SetPrincipal(w, req)
		resCh <- w.Code
	}()

	// 3) Wait until the mutation transaction is observably waiting on the lock.
	waitForBlockedPrincipalSet(t, pool, resCh)

	// 4) Revoke the actor's authority WHILE the mutation transaction waits, and
	// commit it. Revocation = expiry stamped in the past, which
	// admin_can_reach's `expires_at > now()` gate excludes for ANY reader (the
	// waiter's now() is frozen at its own earlier start, so a past expiry is
	// unambiguous there too). eligible flips are NOT a revocation while the
	// rbac.jit toggle is OFF, and expires_at = now() is future for the waiter —
	// both proved blind in earlier iterations of this test.
	if _, err := pool.Exec(ctx,
		`UPDATE admin_role_assignments SET expires_at = now() - interval '1 hour' WHERE user_id = $1`,
		st.actorGlobal); err != nil {
		t.Fatalf("revoke actor authority: %v", err)
	}

	// 5) Release the row lock: the reducer wins the lock and must observe the
	// revocation at mutation time.
	if err := holderTx.Rollback(ctx); err != nil {
		t.Fatalf("release holder lock: %v", err)
	}

	select {
	case code := <-resCh:
		if code != http.StatusForbidden {
			t.Fatalf("revoked-while-waiting SetPrincipal: want 403, got %d", code)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("SetPrincipal never returned after the lock was released")
	}

	var stored string
	if err := pool.QueryRow(ctx,
		`SELECT krb5_principal FROM users WHERE id = $1`, st.userEng).Scan(&stored); err != nil {
		t.Fatalf("read principal after denial: %v", err)
	}
	if stored != principalRevocationOld {
		t.Errorf("krb5_principal = %q, want unchanged %q (revoked actor must not mutate)", stored, principalRevocationOld)
	}
	if after := countPrincipalChangeAudits(t, pool, st.actorGlobal, st.userEng); after != auditsBefore {
		t.Errorf("audit rows for denied change: before=%d after=%d, want unchanged", auditsBefore, after)
	}
}

// TestAdPrincipalSet_ValueStalenessIsNoOp pins the value-conditional UPDATE: a
// caller whose observed old principal is no longer current under the lock gets
// the 'stale' result with NO write, NO audit row, and NO overwrite.
func TestAdPrincipalSet_ValueStalenessIsNoOp(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	grantIdentityWrite(t, pool, st.actorGlobal, 0)
	ctx := context.Background()

	const seeded = "stale-obs@LEGACY.REALM"
	if _, err := pool.Exec(ctx,
		`UPDATE users SET krb5_principal = $1 WHERE id = $2`, seeded, st.userEng); err != nil {
		t.Fatalf("seed principal: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, //nolint:errcheck
			`UPDATE users SET krb5_principal = NULL WHERE id = $1`, st.userEng)
	})

	auditsBefore := countPrincipalChangeAudits(t, pool, st.actorGlobal, st.userEng)

	var result string
	err := pool.QueryRow(ctx,
		`SELECT ad_principal_set($1,$2,$3,$4,NULL::inet)`,
		st.actorGlobal, st.userEng, "stale-obs@NEW.REALM", "never-was-current@GHOST",
	).Scan(&result)
	if err != nil {
		t.Fatalf("ad_principal_set with stale observation: %v", err)
	}
	if result != "stale" {
		t.Errorf("result = %q, want %q", result, "stale")
	}

	var stored string
	if err := pool.QueryRow(ctx,
		`SELECT krb5_principal FROM users WHERE id = $1`, st.userEng).Scan(&stored); err != nil {
		t.Fatalf("read principal: %v", err)
	}
	if stored != seeded {
		t.Errorf("krb5_principal = %q, want unchanged %q (stale observation must not overwrite)", stored, seeded)
	}
	if after := countPrincipalChangeAudits(t, pool, st.actorGlobal, st.userEng); after != auditsBefore {
		t.Errorf("audit rows after stale no-op: before=%d after=%d, want unchanged", auditsBefore, after)
	}
}

// TestAdPrincipalSet_AppliedWritesAuditsNotifies exercises the reducer happy
// path directly: 'applied' result, principal written, audit old→new in the same
// transaction, and the admin:alert notify routed through app_notify (asserted
// via the test-only capture tee).
func TestAdPrincipalSet_AppliedWritesAuditsNotifies(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	grantIdentityWrite(t, pool, st.actorGlobal, 0)
	ctx := context.Background()

	// Unique marker principal so the notify capture assert only sees THIS test's
	// push even if other tests capture on admin:alert.
	const oldPrincipal = "applied-old@LEGACY.REALM"
	newPrincipal := "ad_principal_set_capture@CORP.EXAMPLE.COM"
	if _, err := pool.Exec(ctx,
		`UPDATE users SET krb5_principal = $1 WHERE id = $2`, oldPrincipal, st.userEng); err != nil {
		t.Fatalf("seed old principal: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, //nolint:errcheck
			`UPDATE users SET krb5_principal = NULL WHERE id = $1`, st.userEng)
		pool.Exec(ctx, //nolint:errcheck
			`DELETE FROM _test_notify_log WHERE payload LIKE '%ad_principal_set_capture%'`)
	})

	auditsBefore := countPrincipalChangeAudits(t, pool, st.actorGlobal, st.userEng)

	// Pin one connection and turn the capture GUC on with SET LOCAL inside the
	// mutation transaction: the tee fires in the reducer's own transaction and
	// the captured rows are visible to the in-tx assert, with no session state
	// leaking back to the pool at commit.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire connection: %v", err)
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin pinned transaction: %v", err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL app.capture_notify = 'on'`); err != nil {
		t.Fatalf("enable notify capture: %v", err)
	}

	var result string
	if err := tx.QueryRow(ctx,
		`SELECT ad_principal_set($1,$2,$3,$4,NULL::inet)`,
		st.actorGlobal, st.userEng, newPrincipal, oldPrincipal,
	).Scan(&result); err != nil {
		t.Fatalf("ad_principal_set applied path: %v", err)
	}
	if result != "applied" {
		t.Errorf("result = %q, want %q", result, "applied")
	}

	// The notify fired in the SAME transaction (capture tee proves channel+payload).
	var kind, notifiedUserID string
	if err := tx.QueryRow(ctx, `
		SELECT payload::jsonb->>'kind', payload::jsonb->>'user_id'
		  FROM _test_notify_log
		 WHERE channel = 'admin:alert'
		   AND payload::jsonb->>'kind' = 'ad_krb5_principal_change'
		   AND payload::jsonb->>'user_id' = $1
		 ORDER BY seq DESC LIMIT 1`, strconv.FormatInt(st.userEng, 10)).Scan(&kind, &notifiedUserID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("no admin:alert notify captured for the principal change (app_notify must fire in-tx)")
		}
		t.Fatalf("read captured notify: %v", err)
	}
	if notifiedUserID == "" {
		t.Errorf("captured notify carries empty user_id")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit mutation transaction: %v", err)
	}

	var stored string
	if err := pool.QueryRow(ctx,
		`SELECT krb5_principal FROM users WHERE id = $1`, st.userEng).Scan(&stored); err != nil {
		t.Fatalf("read principal: %v", err)
	}
	if stored != newPrincipal {
		t.Errorf("krb5_principal = %q, want %q", stored, newPrincipal)
	}

	var before, after string
	if err := pool.QueryRow(ctx, `
		SELECT COALESCE(before_state->>'krb5_principal', ''),
		       COALESCE(after_state->>'krb5_principal', '')
		  FROM admin_audit_log
		 WHERE action = 'ad_krb5_principal_change' AND user_id = $1 AND target_id = $2
		 ORDER BY id DESC LIMIT 1`,
		st.actorGlobal, st.userEng).Scan(&before, &after); err != nil {
		t.Fatalf("read audit row: %v", err)
	}
	if before != oldPrincipal || after != newPrincipal {
		t.Errorf("audit old→new = %q→%q, want %q→%q", before, after, oldPrincipal, newPrincipal)
	}
	if got := countPrincipalChangeAudits(t, pool, st.actorGlobal, st.userEng); got != auditsBefore+1 {
		t.Errorf("audit rows: before=%d after=%d, want +1", auditsBefore, got)
	}
}

// TestAdPrincipalSet_UnauthorizedTargetRejected pins the reducer's own
// REACH gate for an authorized-but-out-of-scope actor (no fast-path involved):
// the eng-OU-scoped actor HOLDS a global identity.write assignment, but it
// cannot reach a /sales user, so the mutation is denied BZ061 with the value
// unchanged. (The permission axis alone is pinned by the pgTAP partial
// -revocation cases in sql/tests/ad_principal_set.pg.)
func TestAdPrincipalSet_UnauthorizedTargetRejected(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	grantIdentityWrite(t, pool, st.actorEngOUScoped, st.engDeptID)
	ctx := context.Background()

	t.Cleanup(func() {
		pool.Exec(ctx, //nolint:errcheck
			`UPDATE users SET krb5_principal = NULL WHERE id = $1`, st.userSales)
	})

	_, err := pool.Exec(ctx,
		`UPDATE users SET krb5_principal = $1 WHERE id = $2`, "sales@LEGACY.REALM", st.userSales)
	if err != nil {
		t.Fatalf("seed principal: %v", err)
	}

	var result string
	err = pool.QueryRow(ctx,
		`SELECT ad_principal_set($1,$2,$3,$4,NULL::inet)`,
		st.actorEngOUScoped, st.userSales, "sales@NEW.REALM", "sales@LEGACY.REALM",
	).Scan(&result)
	if err == nil {
		t.Fatalf("ad_principal_set by out-of-scope actor: want BZ061 error, got result %q", result)
	}
	if !reducererr.IsCode(err, "BZ061") {
		t.Fatalf("error = %v, want BZ061", err)
	}
	var stored string
	if err := pool.QueryRow(ctx,
		`SELECT krb5_principal FROM users WHERE id = $1`, st.userSales).Scan(&stored); err != nil {
		t.Fatalf("read principal: %v", err)
	}
	if stored != "sales@LEGACY.REALM" {
		t.Errorf("krb5_principal = %q, want unchanged %q", stored, "sales@LEGACY.REALM")
	}
}
