package admin

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"setjoin.com/shared/testsupport"
)

// TestMapProtectionErr verifies the BZ064/BZ065/BZ066 → HTTP status mapping.
// The audit-row write (pool.Exec) is skipped in unit tests because pool is nil
// — mapProtectionErr guards the nil pool before attempting the write.
// Unknown codes return false so the caller falls through to its own error path.
func TestMapProtectionErr(t *testing.T) {
	cases := []struct {
		code     string
		wantOK   bool // true = handled (returns true + wrote HTTP status)
		wantHTTP int
	}{
		{"BZ064", true, http.StatusConflict},  // self-lock / last-admin
		{"BZ065", true, http.StatusForbidden}, // protected-by-policy
		{"BZ066", true, http.StatusForbidden}, // protected-by-protected-target
		{"BZ060", false, 0},                   // unrelated BZ → not handled
		{"23505", false, 0},                   // SQL unique violation → not handled
	}

	for _, c := range cases {
		t.Run("code_"+c.code, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest("DELETE", "/admin/users/1", nil)
			pgErr := &pgconn.PgError{Code: c.code, Message: "test msg: " + c.code}

			// nil pool: audit write is skipped but mapping still works.
			handled := mapProtectionErr(nil, slog.Default(), rr, req, pgErr, 10, 20)
			if handled != c.wantOK {
				t.Errorf("code %s: handled=%v, want %v", c.code, handled, c.wantOK)
			}
			if c.wantOK && rr.Code != c.wantHTTP {
				t.Errorf("code %s: HTTP %d, want %d", c.code, rr.Code, c.wantHTTP)
			}
		})
	}
}

// TestMapProtectionErr_DenialSurvivesRollback asserts that after the conversion
// to audit.WriteAutonomous, a denial audit row committed independently from the
// (rolled-back) mutation tx. DB-backed; skipped when DB_DSN unset.
func TestMapProtectionErr_DenialSurvivesRollback(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	// Ensure a minimal user exists for the audit FK.
	_, _ = pool.Exec(ctx,
		`INSERT INTO domains (id, name, is_local) VALUES (88002, 'protection.test', TRUE) ON CONFLICT DO NOTHING`)
	_, _ = pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		 VALUES (88002, 'prot_test_actor', 88002, 'actor@protection.test', 'Prot Actor', TRUE)
		 ON CONFLICT (id) DO NOTHING`)

	const action = "admin_protection.denied"

	var before int64
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM admin_audit_log WHERE action = $1 AND user_id = 88002`, action,
	).Scan(&before); err != nil {
		t.Fatalf("count before: %v", err)
	}

	// Simulate a mutation tx that will be rolled back (denied escalation path).
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("DELETE", "/admin/users/1", nil)
	pgErr := &pgconn.PgError{Code: "BZ065", Message: "protected target"}

	// mapProtectionErr should write the denial via WriteAutonomous (pool, not tx).
	handled := mapProtectionErr(pool, slog.Default(), rr, req, pgErr, 88002, 88002)
	if !handled {
		t.Fatal("mapProtectionErr should handle BZ065")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("HTTP %d, want 403", rr.Code)
	}

	// Roll back the mutation tx — the denial row must still persist.
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	var after int64
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM admin_audit_log WHERE action = $1 AND user_id = 88002`, action,
	).Scan(&after); err != nil {
		t.Fatalf("count after: %v", err)
	}
	if after != before+1 {
		t.Errorf("denial audit row must survive rollback: before=%d after=%d (want +1)", before, after)
	}

	// Cleanup (disable append-only trigger momentarily — test-only).
	_, _ = pool.Exec(ctx, `ALTER TABLE admin_audit_log DISABLE TRIGGER admin_audit_append_only`)
	_, _ = pool.Exec(ctx, `DELETE FROM admin_audit_log WHERE action = $1 AND user_id = 88002`, action)
	_, _ = pool.Exec(ctx, `ALTER TABLE admin_audit_log ENABLE TRIGGER admin_audit_append_only`)
}

// TestAuditWrite_RoutineSupressedAtLean asserts that a routine-tier writer
// (e.g. app_blocked in middleware) is suppressed when audit_policy.level = 'lean'.
// DB-backed; skipped when DB_DSN unset.
func TestAuditWrite_RoutineSupressedAtLean(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	// Ensure actor user exists.
	_, _ = pool.Exec(ctx,
		`INSERT INTO domains (id, name, is_local) VALUES (88003, 'lean.test', TRUE) ON CONFLICT DO NOTHING`)
	_, _ = pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		 VALUES (88003, 'lean_test_actor', 88003, 'actor@lean.test', 'Lean Actor', TRUE)
		 ON CONFLICT (id) DO NOTHING`)

	// Set policy to lean (suppress routine).
	_, err := pool.Exec(ctx, `UPDATE audit_policy SET level = 'lean' WHERE id = 1`)
	if err != nil {
		t.Fatalf("set lean: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `UPDATE audit_policy SET level = 'full' WHERE id = 1`)
	})

	const action = "app_blocked"
	var before int64
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM admin_audit_log WHERE action = $1 AND user_id = 88003`, action,
	).Scan(&before); err != nil {
		t.Fatalf("count before: %v", err)
	}

	// Call audit_write directly with tier='routine' — must be suppressed at lean.
	_, execErr := pool.Exec(ctx,
		`SELECT audit_write($1, $2, 'app', NULL, NULL, NULL, NULL, 'test', 'routine')`,
		88003, action)
	if execErr != nil {
		t.Fatalf("audit_write call: %v", execErr)
	}

	var after int64
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM admin_audit_log WHERE action = $1 AND user_id = 88003`, action,
	).Scan(&after); err != nil {
		t.Fatalf("count after: %v", err)
	}
	if after != before {
		t.Errorf("routine write should be suppressed at lean: before=%d after=%d (want no change)", before, after)
	}
}
