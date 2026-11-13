package audit_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/shared/permissions"
)

// ── Tier derivation (pure, no DB) ───────────────────────────────────────────

func TestTierForPerm(t *testing.T) {
	// SensitivePermissions perm → core
	if got := audit.TierForPerm(permissions.PermUsersImpersonate); got != "core" {
		t.Errorf("TierForPerm(%q) = %q, want core", permissions.PermUsersImpersonate, got)
	}
	// security-class perm → core
	if got := audit.TierForPerm(permissions.PermSecurityWrite); got != "core" {
		t.Errorf("TierForPerm(%q) = %q, want core", permissions.PermSecurityWrite, got)
	}
	// audit-class perm → core
	if got := audit.TierForPerm(permissions.PermAuditRead); got != "core" {
		t.Errorf("TierForPerm(%q) = %q, want core", permissions.PermAuditRead, got)
	}
	// routine perm (queue.read: system class, not sensitive)
	if got := audit.TierForPerm(permissions.PermQueueRead); got != "routine" {
		t.Errorf("TierForPerm(%q) = %q, want routine", permissions.PermQueueRead, got)
	}
}

func TestTierForAction(t *testing.T) {
	core := []string{
		"audit_policy_change",
		"sensitive_action.reason_missing",
		"login.success",
		"login.failure",
		"mfa.enrolled",
		"mfa.challenge",
		"email_decrypt_read",
	}
	for _, a := range core {
		if got := audit.TierForAction(a); got != "core" {
			t.Errorf("TierForAction(%q) = %q, want core", a, got)
		}
	}
	if got := audit.TierForAction("user.created"); got != "routine" {
		t.Errorf("TierForAction(\"user.created\") = %q, want routine", got)
	}
}

// ── DB-backed tests ──────────────────────────────────────────────────────────

func mustPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// ensureTestUser creates (or reuses) a minimal user for audit FK tests.
// Returns the user id. Uses a fixed domain/user to avoid fixture noise.
func ensureTestUser(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	ctx := context.Background()
	// Create domain if needed
	_, _ = pool.Exec(ctx,
		`INSERT INTO domains (id, name, is_local) VALUES (88001, 'auditpkg.test', TRUE) ON CONFLICT DO NOTHING`)
	// Create user if needed
	_, err := pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		 VALUES (88001, 'audit_test_actor', 88001, 'actor@auditpkg.test', 'Audit Actor', TRUE)
		 ON CONFLICT (id) DO NOTHING`)
	if err != nil {
		t.Fatalf("ensureTestUser: %v", err)
	}
	return 88001
}

func TestWrite_RollsBackWithTx(t *testing.T) {
	pool := mustPool(t)
	ctx := context.Background()
	actorID := ensureTestUser(t, pool)

	// Count rows before
	var before int64
	if err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM admin_audit_log WHERE action = 'test.write_rollback'").Scan(&before); err != nil {
		t.Fatalf("count before: %v", err)
	}

	// Begin a tx, Write inside it, then ROLLBACK
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	e := audit.Entry{
		Actor:      actorID,
		Action:     "test.write_rollback",
		TargetType: "test",
		Notes:      "should be rolled back",
		Tier:       "core",
	}
	if err := audit.Write(ctx, tx, e); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("Write: %v", err)
	}
	// Roll back the transaction — the row should NOT persist
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	// Verify row count is unchanged
	var after int64
	if err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM admin_audit_log WHERE action = 'test.write_rollback'").Scan(&after); err != nil {
		t.Fatalf("count after: %v", err)
	}
	if after != before {
		t.Errorf("Write rolled back with tx: count before=%d after=%d, expected no change", before, after)
	}
}

func TestWriteAutonomous_SurvivesRolledBackTx(t *testing.T) {
	pool := mustPool(t)
	ctx := context.Background()
	actorID := ensureTestUser(t, pool)

	// Use a unique action so we can count precisely
	action := "test.autonomous_survives_rollback"

	// Count rows before
	var before int64
	if err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM admin_audit_log WHERE action = $1", action).Scan(&before); err != nil {
		t.Fatalf("count before: %v", err)
	}

	// Begin an outer tx that will be rolled back (simulates a denied escalation)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin outer tx: %v", err)
	}

	e := audit.Entry{
		Actor:      actorID,
		Action:     action,
		TargetType: "test",
		After:      json.RawMessage(`{"survived": true}`),
		Notes:      "must survive rollback",
		Tier:       "core",
	}

	// WriteAutonomous on pool — uses its OWN connection, commits independently
	if err := audit.WriteAutonomous(ctx, pool, e); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("WriteAutonomous: %v", err)
	}

	// Now roll back the outer tx (simulates a denied escalation)
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback outer: %v", err)
	}

	// The audit row MUST exist even though the outer tx was rolled back
	var after int64
	if err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM admin_audit_log WHERE action = $1", action).Scan(&after); err != nil {
		t.Fatalf("count after: %v", err)
	}
	if after != before+1 {
		t.Errorf("WriteAutonomous should survive rollback: count before=%d after=%d, expected +1", before, after)
	}

	// Cleanup: disable append-only trigger temporarily to delete test rows
	// (the trigger blocks DELETE on admin_audit_log in prod; for test cleanup we
	// disable it on the same connection momentarily — this is test-only code)
	_, _ = pool.Exec(ctx, "ALTER TABLE admin_audit_log DISABLE TRIGGER admin_audit_append_only")
	_, _ = pool.Exec(ctx, "DELETE FROM admin_audit_log WHERE action = $1", action)
	_, _ = pool.Exec(ctx, "ALTER TABLE admin_audit_log ENABLE TRIGGER admin_audit_append_only")
}
