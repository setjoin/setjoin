package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5"
	"setjoin.com/shared/testsupport"
)

// ── Dedicated gated SoD-mode handler (PUT /admin/dengbao/sod-mode) ────────────
//
// These tests are DB-backed (skip without DB_DSN). They drive the handler
// against a pgx.Tx that the test rolls back, so nothing persists in the shared
// test DB. Because the handler runs the precheck + flip via beginner.Begin(),
// passing a pgx.Tx makes the handler's "transaction" a SAVEPOINT nested inside
// the test's outer tx — committing it is harmless (the outer tx is rolled back
// at the end).

// seedDengbaoToggleOff ensures the dengbao.sod_mode row exists and is OFF inside
// the given tx.
func seedDengbaoToggleOff(t *testing.T, tx pgx.Tx) {
	t.Helper()
	_, err := tx.Exec(context.Background(),
		`INSERT INTO feature_toggles (key, enabled, updated_at)
		 VALUES ('dengbao.sod_mode', false, now())
		 ON CONFLICT (key) DO UPDATE SET enabled = false`)
	if err != nil {
		t.Fatalf("seed dengbao toggle: %v", err)
	}
}

func dengbaoEnabled(t *testing.T, tx pgx.Tx) bool {
	t.Helper()
	var enabled bool
	err := tx.QueryRow(context.Background(),
		`SELECT enabled FROM feature_toggles WHERE key = 'dengbao.sod_mode'`).Scan(&enabled)
	if err != nil {
		t.Fatalf("read dengbao toggle: %v", err)
	}
	return enabled
}

// neutralizeAllViolations removes every source of an admin_sod_precheck row
// inside the tx so the clean-path test sees a violation-free DB. It empties the
// role groups and the legacy-admin axis (both rolled back afterward).
func neutralizeAllViolations(t *testing.T, tx pgx.Tx) {
	t.Helper()
	ctx := context.Background()
	// Role groups drive super_admin_role / unclassifiable_perm / unclassified_role.
	// The wholesale assignment wipe trips trg_protect_last_super_admin (BZ064: the
	// last Super Admin cannot be removed) — that production guard is irrelevant to
	// this rolled-back fixture cleanup, so disable it for the truncate-equivalent.
	if _, err := tx.Exec(ctx, `ALTER TABLE admin_role_assignments DISABLE TRIGGER trg_protect_last_super_admin`); err != nil {
		t.Fatalf("disable last-SA trigger: %v", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM admin_role_assignments`); err != nil {
		t.Fatalf("clear assignments: %v", err)
	}
	// Flush V222's deferred final-state reachability checks before ALTER TABLE;
	// PostgreSQL refuses trigger DDL while that relation has pending events.
	if _, err := tx.Exec(ctx,
		`SET CONSTRAINTS trg_ca_reachability_assignments_validate IMMEDIATE`); err != nil {
		t.Fatalf("validate cleared assignment reachability: %v", err)
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE admin_role_assignments ENABLE TRIGGER trg_protect_last_super_admin`); err != nil {
		t.Fatalf("re-enable last-SA trigger: %v", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM admin_role_groups`); err != nil {
		t.Fatalf("clear role groups: %v", err)
	}
	// The legacy admin_role axis is GONE: the RBAC cut-over dropped users.admin_role
	// and admin_sod_precheck no longer emits legacy_admin_role rows, so there is no
	// legacy axis left to neutralize. is_admin is retained but no longer feeds the
	// precheck; clearing it here keeps the helper's "violation-free DB" intent
	// without depending on the dropped column.
	if _, err := tx.Exec(ctx, `UPDATE users SET is_admin = false`); err != nil {
		t.Fatalf("clear legacy admins: %v", err)
	}
}

func realUserID(t *testing.T, tx pgx.Tx) int64 {
	t.Helper()
	var id int64
	if err := tx.QueryRow(context.Background(), `SELECT MIN(id) FROM users`).Scan(&id); err != nil || id == 0 {
		t.Skip("no users in test DB — skipping SoD handler integration test")
	}
	return id
}

func putSodModeReq(enabled bool, userID int64) *http.Request {
	body, _ := json.Marshal(map[string]any{"enabled": enabled})
	req := httptest.NewRequest(http.MethodPut, "/admin/dengbao/sod-mode", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req.WithContext(ctxWithAdminUser(userID, "secadmin@example.com"))
}

// TestSodModeSetOnWithViolations: turning ON while the precheck reports
// violations must ROLL BACK (toggle stays OFF) and return the violation list
// (409). The shared test DB already has violating preset role groups, so we do
// NOT neutralize here.
func TestSodModeSetOnWithViolations(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)

	uid := realUserID(t, tx)
	seedDengbaoToggleOff(t, tx)

	// Sanity: there must be at least one violation for this test to be meaningful.
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM admin_sod_precheck()`).Scan(&n); err != nil {
		t.Fatalf("precheck count: %v", err)
	}
	if n == 0 {
		t.Skip("test DB has no SoD violations — cannot exercise the rollback path")
	}

	h := NewSodModeHandler(tx, testsupport.TestLogger())
	w := httptest.NewRecorder()
	h.Set(w, putSodModeReq(true, uid))

	if w.Code != http.StatusConflict {
		t.Fatalf("ON with violations: expected 409, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Violations []map[string]string `json:"violations"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode 409 body: %v", err)
	}
	if len(resp.Violations) == 0 {
		t.Fatal("ON with violations: response must include the violation list")
	}
	if dengbaoEnabled(t, tx) {
		t.Fatal("ON with violations: toggle must remain OFF after rollback (TOCTOU/precheck gate failed)")
	}
}

// TestSodModeSetOnClean: with a violation-free DB, turning ON flips the toggle
// to true AND writes an admin_audit_log row.
func TestSodModeSetOnClean(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)

	uid := realUserID(t, tx)
	seedDengbaoToggleOff(t, tx)
	neutralizeAllViolations(t, tx)

	// Re-resolve a user id (neutralize wiped is_admin but rows still exist).
	if err := tx.QueryRow(ctx, `SELECT MIN(id) FROM users`).Scan(&uid); err != nil {
		t.Fatalf("re-resolve uid: %v", err)
	}

	var before int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM admin_sod_precheck()`).Scan(&before); err != nil {
		t.Fatalf("precheck count: %v", err)
	}
	if before != 0 {
		t.Fatalf("neutralize failed: precheck still reports %d violations", before)
	}

	var auditBefore int
	tx.QueryRow(ctx, `SELECT count(*) FROM admin_audit_log WHERE action = 'sod_mode_enable'`).Scan(&auditBefore)

	h := NewSodModeHandler(tx, testsupport.TestLogger())
	w := httptest.NewRecorder()
	h.Set(w, putSodModeReq(true, uid))

	if w.Code != http.StatusOK && w.Code != http.StatusNoContent {
		t.Fatalf("ON clean: expected 200/204, got %d — body: %s", w.Code, w.Body.String())
	}
	if !dengbaoEnabled(t, tx) {
		t.Fatal("ON clean: toggle must be flipped to true")
	}
	var auditAfter int
	tx.QueryRow(ctx, `SELECT count(*) FROM admin_audit_log WHERE action = 'sod_mode_enable'`).Scan(&auditAfter)
	if auditAfter <= auditBefore {
		t.Fatalf("ON clean: an admin_audit_log 'sod_mode_enable' row must be written (before=%d after=%d)", auditBefore, auditAfter)
	}
}

// TestSodModeSetOffAlwaysSucceeds: turning OFF is unconditional and audited,
// even when the DB is full of violations.
func TestSodModeSetOffAlwaysSucceeds(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)

	uid := realUserID(t, tx)
	// Start ON so OFF is an observable change.
	_, err = tx.Exec(ctx,
		`INSERT INTO feature_toggles (key, enabled, updated_at)
		 VALUES ('dengbao.sod_mode', true, now())
		 ON CONFLICT (key) DO UPDATE SET enabled = true`)
	if err != nil {
		t.Fatalf("seed ON: %v", err)
	}

	var auditBefore int
	tx.QueryRow(ctx, `SELECT count(*) FROM admin_audit_log WHERE action = 'sod_mode_disable'`).Scan(&auditBefore)

	h := NewSodModeHandler(tx, testsupport.TestLogger())
	w := httptest.NewRecorder()
	h.Set(w, putSodModeReq(false, uid))

	if w.Code != http.StatusOK && w.Code != http.StatusNoContent {
		t.Fatalf("OFF: expected 200/204, got %d — body: %s", w.Code, w.Body.String())
	}
	if dengbaoEnabled(t, tx) {
		t.Fatal("OFF: toggle must be false")
	}
	var auditAfter int
	tx.QueryRow(ctx, `SELECT count(*) FROM admin_audit_log WHERE action = 'sod_mode_disable'`).Scan(&auditAfter)
	if auditAfter <= auditBefore {
		t.Fatalf("OFF: an admin_audit_log 'sod_mode_disable' row must be written (before=%d after=%d)", auditBefore, auditAfter)
	}
}
