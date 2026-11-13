// admin_ca_guard_test.go — CA-1 D8: machine guard asserting EVERY CA mutating
// reducer writes admin_audit_log AND PERFORMs ca_notify_policy_change.
//
// Two complementary arms:
//
//  1. Static reducer check (no DB): file-scan each mutating ca_*.sql for both
//     "admin_audit_log" and "ca_notify_policy_change" — fails if either is absent.
//     Read-only and infra reducers are in an explicit exempt list.
//
//  2. Handler-driven check (DB-backed): a single-connection pool with
//     app.capture_notify='on' so notify calls tee to _test_notify_log; drive a
//     representative mutating handler per reducer and assert (a) an
//     admin_audit_log row was written and (b) _test_notify_log has a row on the
//     conditional_access channel.
//
// A future CA write reducer that forgets audit/notify fails CI on arm 1.
// A future handler that forgets to call the reducer fails CI on arm 2.
//
// Run: go test ./internal/admin/ -run TestCAGuard
package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// ── arm 1: static file-scan ────────────────────────────────────────────────

// caReducerDir is the path to the CA reducer files relative to the module root.
// The test file lives in mailserver/internal/admin/; reducers are at mailserver/sql/reducers/.
const caReducerDir = "../../sql/reducers"

// caExemptReducers lists CA reducer files that are NOT required to have
// admin_audit_log + ca_notify_policy_change.  Each entry is a base filename.
//
// Exempt: read-only or infrastructure (not policy mutations).
var caExemptReducers = map[string]struct{}{
	// Read-only analytics:
	"ca_policy_impact.sql":   {},
	"ca_coverage_report.sql": {},
	// Guard (RAISES, does not mutate):
	"ca_lockout_guard.sql": {},
	// The choke point itself (contains app_notify, not ca_notify_policy_change):
	"ca_notify_policy_change.sql": {},
	// Append-only telemetry, not a policy mutation:
	"ca_signin_log_append.sql": {},
	// Retention prune, not a policy mutation:
	"ca_signin_log_prune.sql": {},
}

// TestCAGuardStaticReducerAuditNotify scans every ca_*.sql in the reducer
// directory and asserts that each MUTATING reducer contains:
//
//   - "admin_audit_log"      (direct audit INSERT)
//   - "ca_notify_policy_change"  (F2 choke-point call)
//
// Exempt files (read-only, guard, infra) are listed in caExemptReducers.
// A new mutating reducer that skips either side fails this test immediately.
func TestCAGuardStaticReducerAuditNotify(t *testing.T) {
	entries, err := os.ReadDir(caReducerDir)
	if err != nil {
		t.Fatalf("cannot read reducer dir %s: %v", caReducerDir, err)
	}

	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "ca_") || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		if _, exempt := caExemptReducers[e.Name()]; exempt {
			continue
		}

		path := filepath.Join(caReducerDir, e.Name())
		src, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s: cannot read: %v", e.Name(), err)
			continue
		}
		body := string(src)

		// Post-merge with main: audit writes route through the audit_write() choke
		// point (main's single-INSERT architecture). Either the direct table name
		// or an audit_write() call satisfies "writes audit in-txn".
		if !strings.Contains(body, "admin_audit_log") && !strings.Contains(body, "audit_write(") {
			t.Errorf("%s: MISSING audit write — every CA mutating reducer must write audit in-txn via audit_write() or admin_audit_log (L6)", e.Name())
		}
		if !strings.Contains(body, "ca_notify_policy_change") {
			t.Errorf("%s: MISSING ca_notify_policy_change call — every CA mutating reducer must notify via the F2 choke point", e.Name())
		}
		checked++
	}

	if checked == 0 {
		t.Fatalf("no ca_*.sql reducer files found in %s — check the path", caReducerDir)
	}
	t.Logf("static guard checked %d mutating CA reducer(s)", checked)
}

// ── arm 2: handler-driven check ───────────────────────────────────────────

// openSingleConnPool opens a pgxpool limited to 1 connection so that
// SET app.capture_notify='on' (session-scoped GUC) sticks for all handler calls.
// ponytail: MaxConns=1 on the config struct avoids DSN-string manipulation;
// skip/fatal policy delegates to testsupport.OpenTestPool (closes immediately after).
func openSingleConnPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	// Delegate skip/fatal policy (REQUIRE_DB, missing DB_DSN) to the shared helper.
	ref := testsupport.OpenTestPool(t)
	ref.Close() // only needed for the policy check; build our 1-conn pool below.

	cfg, err := pgxpool.ParseConfig(os.Getenv("DB_DSN"))
	if err != nil {
		t.Fatalf("pgxpool.ParseConfig: %v", err)
	}
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

// d8AdminUserID is the actor row used throughout the handler-driven guard arm.
const d8AdminUserID = int64(99081)

// ensureD8AdminUser seeds the domain+user rows needed for admin_audit_log FK.
func ensureD8AdminUser(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	_, _ = pool.Exec(ctx,
		`INSERT INTO domains (id, name, is_local) VALUES (99081, 'd8guard.test', TRUE) ON CONFLICT DO NOTHING`)
	_, _ = pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		 VALUES ($1, 'd8guard', 99081, 'd8guard@d8guard.test', 'D8 Guard', TRUE)
		 ON CONFLICT (id) DO NOTHING`, d8AdminUserID)
}

// auditCount returns the current count of admin_audit_log rows whose action
// starts with "ca_" — used to detect new writes without depending on a specific id.
func auditCount(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var n int64
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM admin_audit_log WHERE action LIKE 'ca_%'`,
	).Scan(&n); err != nil {
		t.Fatalf("auditCount: %v", err)
	}
	return n
}

// notifyCount returns the current count of _test_notify_log rows on the
// conditional_access channel.  Requires app.capture_notify='on' to be set first.
func notifyCount(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var n int64
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM _test_notify_log WHERE channel = 'conditional_access'`,
	).Scan(&n); err != nil {
		t.Fatalf("notifyCount: %v", err)
	}
	return n
}

// assertAuditAndNotify drives one mutating handler, then verifies:
//
//	(a) admin_audit_log gained at least one new ca_* row
//	(b) _test_notify_log gained at least one new conditional_access row
func assertAuditAndNotify(
	t *testing.T,
	pool *pgxpool.Pool,
	label string,
	before_audit, before_notify int64,
	call func(),
) {
	t.Helper()
	call()
	afterAudit := auditCount(t, pool)
	afterNotify := notifyCount(t, pool)
	if afterAudit <= before_audit {
		t.Errorf("%s: no new admin_audit_log row (before=%d after=%d)", label, before_audit, afterAudit)
	}
	if afterNotify <= before_notify {
		t.Errorf("%s: no new _test_notify_log row on conditional_access channel (before=%d after=%d)",
			label, before_notify, afterNotify)
	}
}

// adminReq returns an httptest.Request with d8AdminUserID auth context attached.
// ponytail: delegates auth injection to withAdminClaims (defined in admin_conditional_access_test.go,
// same package) so a future auth.Claims change only needs one edit.
func adminReq(method, target string, body []byte) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, target, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	return withAdminClaims(r, d8AdminUserID)
}

// TestCAGuardHandlerAuditNotify drives a representative mutating handler per
// reducer group and asserts both audit + notify fire for each call.
// DB-backed; skips without DB_DSN.
func TestCAGuardHandlerAuditNotify(t *testing.T) {
	pool := openSingleConnPool(t)
	ctx := context.Background()

	ensureD8AdminUser(t, pool)

	// Enable notify capture for the single pooled connection.
	if _, err := pool.Exec(ctx, "SET app.capture_notify = 'on'"); err != nil {
		t.Fatalf("SET app.capture_notify: %v", err)
	}

	// Seed break-glass so lockout guard doesn't trip on promote.
	_, _ = pool.Exec(ctx,
		`INSERT INTO system_config (key, value)
		 VALUES ('ca_break_glass_user_ids', $1::jsonb)
		 ON CONFLICT (key) DO UPDATE SET value = $1::jsonb`,
		fmt.Sprintf("[%d]", d8AdminUserID))
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key='ca_break_glass_user_ids'`)
	})

	// ── ca_policy_upsert (Create) ──────────────────────────────────────────
	caH := NewConditionalAccessHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	createBody, _ := json.Marshal(map[string]any{
		"name":       "d8-guard-create",
		"priority":   88801,
		"conditions": map[string]any{},
		"actions":    map[string]any{"action": "allow"},
	})
	ba, bn := auditCount(t, pool), notifyCount(t, pool)
	var createdID int64
	assertAuditAndNotify(t, pool, "ca_policy_upsert (Create)", ba, bn, func() {
		w := httptest.NewRecorder()
		caH.Create(w, adminReq(http.MethodPost, "/admin/conditional-access/policies", createBody))
		if w.Code != http.StatusCreated {
			t.Errorf("ca_policy_upsert Create: got %d, want 201; body=%s", w.Code, w.Body.String())
			return
		}
		var resp struct {
			ID int64 `json:"id"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		createdID = resp.ID
	})
	if createdID == 0 {
		t.Fatal("ca_policy_upsert Create: could not obtain created policy id — subsequent subtests depend on it")
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM conditional_access_policies WHERE id=$1`, createdID)
	})

	// ── ca_policy_reorder ─────────────────────────────────────────────────
	ba, bn = auditCount(t, pool), notifyCount(t, pool)
	reorderBody, _ := json.Marshal([]int64{createdID})
	assertAuditAndNotify(t, pool, "ca_policy_reorder (Reorder)", ba, bn, func() {
		w := httptest.NewRecorder()
		caH.Reorder(w, adminReq(http.MethodPost, "/admin/conditional-access/policies/reorder", reorderBody))
		if w.Code != http.StatusNoContent {
			t.Errorf("ca_policy_reorder: got %d, want 204; body=%s", w.Code, w.Body.String())
		}
	})

	// ── ca_policy_soft_delete ─────────────────────────────────────────────
	ba, bn = auditCount(t, pool), notifyCount(t, pool)
	assertAuditAndNotify(t, pool, "ca_policy_soft_delete (Delete)", ba, bn, func() {
		req := adminReq(http.MethodDelete,
			fmt.Sprintf("/admin/conditional-access/policies/%d", createdID), nil)
		req.SetPathValue("id", fmt.Sprint(createdID))
		w := httptest.NewRecorder()
		caH.Delete(w, req)
		if w.Code != http.StatusNoContent {
			t.Errorf("ca_policy_soft_delete: got %d, want 204; body=%s", w.Code, w.Body.String())
		}
	})

	// ── ca_policy_restore ─────────────────────────────────────────────────
	ba, bn = auditCount(t, pool), notifyCount(t, pool)
	assertAuditAndNotify(t, pool, "ca_policy_restore (Restore)", ba, bn, func() {
		req := adminReq(http.MethodPost,
			fmt.Sprintf("/admin/conditional-access/policies/%d/restore", createdID), nil)
		req.SetPathValue("id", fmt.Sprint(createdID))
		w := httptest.NewRecorder()
		caH.Restore(w, req)
		if w.Code != http.StatusNoContent {
			t.Errorf("ca_policy_restore: got %d, want 204; body=%s", w.Code, w.Body.String())
		}
	})

	// ── ca_policy_restore_from_audit ──────────────────────────────────────
	// Hard-delete first so an audit row exists to restore from.
	if _, err := pool.Exec(ctx, `SELECT ca_policy_delete($1, NULL::inet, $2)`,
		d8AdminUserID, createdID); err != nil {
		t.Fatalf("hard-delete setup for restore-from-audit: %v", err)
	}
	var auditID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM admin_audit_log WHERE target_type='conditional_access_policy' AND target_id=$1
		 ORDER BY id DESC LIMIT 1`, createdID).Scan(&auditID); err != nil {
		t.Fatalf("find audit row for restore-from-audit: %v", err)
	}

	rfaBody, _ := json.Marshal(map[string]any{"audit_id": auditID})
	ba, bn = auditCount(t, pool), notifyCount(t, pool)
	var restoredID int64
	assertAuditAndNotify(t, pool, "ca_policy_restore_from_audit (RestoreFromAudit)", ba, bn, func() {
		w := httptest.NewRecorder()
		caH.RestoreFromAudit(w, adminReq(http.MethodPost,
			"/admin/conditional-access/policies/restore-from-audit", rfaBody))
		if w.Code != http.StatusOK {
			t.Errorf("ca_policy_restore_from_audit: got %d, want 200; body=%s", w.Code, w.Body.String())
			return
		}
		var resp struct {
			ID int64 `json:"id"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		restoredID = resp.ID
	})
	if restoredID != 0 {
		t.Cleanup(func() {
			_, _ = pool.Exec(ctx, `DELETE FROM conditional_access_policies WHERE id=$1`, restoredID)
		})
	}

	// ── ca_break_glass_set (SetBreakGlass) ────────────────────────────────
	bgBody, _ := json.Marshal([]int64{d8AdminUserID})
	ba, bn = auditCount(t, pool), notifyCount(t, pool)
	assertAuditAndNotify(t, pool, "ca_break_glass_set (SetBreakGlass)", ba, bn, func() {
		w := httptest.NewRecorder()
		caH.SetBreakGlass(w, adminReq(http.MethodPut, "/admin/conditional-access/break-glass", bgBody))
		if w.Code != http.StatusNoContent {
			t.Errorf("ca_break_glass_set: got %d, want 204; body=%s", w.Code, w.Body.String())
		}
	})

	// ── ca_policy_promote ─────────────────────────────────────────────────
	// Need a report_only policy; re-seed since the restored one may be report_only.
	var promoteID int64
	if restoredID != 0 {
		// The restored policy is in report_only state (born from a report_only snapshot).
		if _, err := pool.Exec(ctx,
			`UPDATE conditional_access_policies SET state='report_only' WHERE id=$1`, restoredID); err == nil {
			promoteID = restoredID
		}
	}
	if promoteID == 0 {
		// Seed a fresh report_only policy.
		if err := pool.QueryRow(ctx,
			`INSERT INTO conditional_access_policies
			 (priority, name, description, state, scope_type, scope_target, conditions, actions, exclude_users, exclude_groups)
			 VALUES (88899,'d8-guard-promote','','report_only','global','','{}','{"action":"allow"}','[]','[]')
			 RETURNING id`).Scan(&promoteID); err != nil {
			t.Fatalf("seed promote policy: %v", err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(ctx, `DELETE FROM conditional_access_policies WHERE id=$1`, promoteID)
		})
	}

	ba, bn = auditCount(t, pool), notifyCount(t, pool)
	assertAuditAndNotify(t, pool, "ca_policy_promote (Promote)", ba, bn, func() {
		promBody, _ := json.Marshal(map[string]any{"confirm": true})
		req := adminReq(http.MethodPost,
			fmt.Sprintf("/admin/conditional-access/policies/%d/promote", promoteID), promBody)
		req.SetPathValue("id", fmt.Sprint(promoteID))
		w := httptest.NewRecorder()
		caH.Promote(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("ca_policy_promote: got %d, want 200; body=%s", w.Code, w.Body.String())
		}
	})

	// ── ca_named_location_set (NamedLocations.Create) ─────────────────────
	nlH := NewNamedLocationsHandler(pool, testsupport.TestLogger())
	nlBody, _ := json.Marshal(map[string]any{
		"name":       "d8-guard-location",
		"is_trusted": false,
		"cidrs":      []string{"192.0.2.0/24"}, // ip_ranges is NOT NULL; pass ≥1 CIDR
		"countries":  []string{"US"},           // countries is NOT NULL; pass ≥1 country
	})
	ba, bn = auditCount(t, pool), notifyCount(t, pool)
	var nlID int64
	assertAuditAndNotify(t, pool, "ca_named_location_set (NamedLocations.Create)", ba, bn, func() {
		w := httptest.NewRecorder()
		nlH.Create(w, adminReq(http.MethodPost, "/admin/conditional-access/named-locations", nlBody))
		if w.Code != http.StatusOK {
			t.Errorf("ca_named_location_set: got %d, want 200; body=%s", w.Code, w.Body.String())
			return
		}
		var resp struct {
			ID int64 `json:"id"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		nlID = resp.ID
	})
	if nlID != 0 {
		t.Cleanup(func() {
			_, _ = pool.Exec(ctx, `DELETE FROM named_locations WHERE id=$1`, nlID)
		})
	}

	// ── ca_auth_strength_set (AuthStrengths.Create) ───────────────────────
	asH := NewAuthStrengthsHandler(pool, testsupport.TestLogger())
	asBody, _ := json.Marshal(map[string]any{
		"slug":         "d8-guard-strength",
		"name":         "D8 Guard Strength",
		"combinations": [][]string{{"password", "totp"}},
		"min_acr":      "aal1", // required: must be aal1|aal2|aal3 — empty string fails CHECK
	})
	ba, bn = auditCount(t, pool), notifyCount(t, pool)
	var asID int64
	assertAuditAndNotify(t, pool, "ca_auth_strength_set (AuthStrengths.Create)", ba, bn, func() {
		w := httptest.NewRecorder()
		asH.Create(w, adminReq(http.MethodPost, "/admin/conditional-access/auth-strengths", asBody))
		if w.Code != http.StatusOK {
			t.Errorf("ca_auth_strength_set: got %d, want 200; body=%s", w.Code, w.Body.String())
			return
		}
		var resp struct {
			ID int64 `json:"id"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		asID = resp.ID
	})
	if asID != 0 {
		t.Cleanup(func() {
			_, _ = pool.Exec(ctx,
				`DELETE FROM auth_strengths WHERE id=$1 AND builtin=false`, asID)
		})
	}

	// ── ca_template_instantiate (Templates.Instantiate) ───────────────────
	tplH := NewCATemplatesHandler(pool, testsupport.TestLogger())
	ba, bn = auditCount(t, pool), notifyCount(t, pool)
	var tplPolicyID int64
	assertAuditAndNotify(t, pool, "ca_template_instantiate (Templates.Instantiate)", ba, bn, func() {
		req := adminReq(http.MethodPost,
			"/admin/conditional-access/templates/block-legacy-auth/instantiate", nil)
		req.SetPathValue("slug", "block-legacy-auth")
		w := httptest.NewRecorder()
		tplH.Instantiate(w, req)
		if w.Code != http.StatusCreated {
			t.Errorf("ca_template_instantiate: got %d, want 201; body=%s", w.Code, w.Body.String())
			return
		}
		var resp struct {
			ID int64 `json:"id"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		tplPolicyID = resp.ID
	})
	if tplPolicyID != 0 {
		t.Cleanup(func() {
			_, _ = pool.Exec(ctx, `DELETE FROM conditional_access_policies WHERE id=$1`, tplPolicyID)
		})
	}

	// ── ca_policy_import (Import) ─────────────────────────────────────────
	ieH := NewCAImportExportHandler(pool, testsupport.TestLogger())
	importDoc := map[string]any{
		"schemaVersion":   1,
		"policies":        []map[string]any{},
		"named_locations": []any{},
		"auth_strengths":  []any{},
	}
	importBody, _ := json.Marshal(importDoc)
	ba, bn = auditCount(t, pool), notifyCount(t, pool)
	assertAuditAndNotify(t, pool, "ca_policy_import (Import)", ba, bn, func() {
		req := adminReq(http.MethodPost, "/admin/conditional-access/import?mode=merge", importBody)
		w := httptest.NewRecorder()
		ieH.Import(w, req)
		// mode=merge with empty doc is a valid no-op that still writes audit+notify.
		if w.Code != http.StatusOK {
			t.Errorf("ca_policy_import: got %d, want 200; body=%s", w.Code, w.Body.String())
		}
	})
}
