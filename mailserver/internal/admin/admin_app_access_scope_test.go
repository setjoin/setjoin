package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/pgxutil"
)

// ── domain-scope IDOR regression suite (app passwords + app entitlements + CSV import) ──
//
// A domain-scoped admin (claims.DomainScope) must NOT be able to read or mutate
// app-passwords / app-entitlements of a user in a DIFFERENT domain, nor import a
// user into another domain. These tests seed two domains (A and B), each with a
// user, inject a request context scoped to domain A, and assert the domain-A
// admin cannot touch the domain-B target (404 / per-row reject) while it CAN for
// domain A — and that the cross-tenant row is byte-unchanged. All seeded rows are
// cleaned up in t.Cleanup (the shared helpers in admin_users_scope_test.go own
// the user/mailbox/domain seeding + teardown).

// seedAppPassword inserts an active app_password for the given user and returns
// its id. Cleanup removes it.
func seedAppPassword(t *testing.T, pool *pgxpool.Pool, userID int64, name string) int64 {
	t.Helper()
	ctx := context.Background()
	var apID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO app_passwords (user_id, name, token_hash)
		 VALUES ($1, $2, $3) RETURNING id`,
		userID, name, "$2a$10$apppwplaceholderhashvalueXXXXXXXXXXXXXXXXXXXXXXXXX",
	).Scan(&apID)
	if err != nil {
		t.Fatalf("seedAppPassword: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM app_passwords WHERE id = $1`, apID)
	})
	return apID
}

// adminClaimsCtx wraps a request context with an admin Claims (UserID) AND the
// given domain scope, the two context values the handlers consult.
func adminClaimsCtx(r *http.Request, adminUserID, scope int64) *http.Request {
	ctx := auth.ContextWithUser(r.Context(), &auth.Claims{UserID: adminUserID, IsAdmin: true})
	ctx = middleware.ContextWithDomainScope(ctx, scope)
	return r.WithContext(ctx)
}

// ── app passwords ───────────────────────────────────────────────────────────

// TestAppPasswords_DomainScope_ListForUser verifies a domain-A admin sees an
// empty app-password list for a domain-B user (R1 read isolation) but the real
// list for a domain-A user.
func TestAppPasswords_DomainScope_ListForUser(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewAppPasswordsHandler(pool, mailboxTestLogger())

	domA := ensureScopeTestDomain(t, pool, "scopea.example")
	domB := ensureScopeTestDomain(t, pool, "scopeb.example")
	userA := createScopeTestUser(t, pool, domA, "scopea.example")
	userB := createScopeTestUser(t, pool, domB, "scopeb.example")
	seedAppPassword(t, pool, userA, "a-key")
	seedAppPassword(t, pool, userB, "b-key")

	// Domain-A admin → domain-B user: must see an EMPTY list (no leak).
	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.SetPathValue("id", fmt.Sprintf("%d", userB))
	req = adminClaimsCtx(req, 1, domA)
	rec := httptest.NewRecorder()
	h.ListForUser(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ListForUser cross-domain: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var outB []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &outB); err != nil {
		t.Fatalf("decode cross-domain list: %v", err)
	}
	if len(outB) != 0 {
		t.Errorf("ListForUser leaked %d app password(s) of a domain-B user to a domain-A admin (IDOR)", len(outB))
	}

	// Domain-A admin → domain-A user: must see the real list.
	req = httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.SetPathValue("id", fmt.Sprintf("%d", userA))
	req = adminClaimsCtx(req, 1, domA)
	rec = httptest.NewRecorder()
	h.ListForUser(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ListForUser same-domain: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var outA []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &outA); err != nil {
		t.Fatalf("decode same-domain list: %v", err)
	}
	if len(outA) != 1 {
		t.Errorf("ListForUser same-domain: want 1 app password, got %d", len(outA))
	}
}

// TestAppPasswords_DomainScope_RevokeForUser verifies a domain-A admin cannot
// revoke a domain-B user's app password (404, row unchanged) but can revoke a
// domain-A user's.
func TestAppPasswords_DomainScope_RevokeForUser(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewAppPasswordsHandler(pool, mailboxTestLogger())

	domA := ensureScopeTestDomain(t, pool, "scopea.example")
	domB := ensureScopeTestDomain(t, pool, "scopeb.example")
	userA := createScopeTestUser(t, pool, domA, "scopea.example")
	userB := createScopeTestUser(t, pool, domB, "scopeb.example")
	apA := seedAppPassword(t, pool, userA, "a-key")
	apB := seedAppPassword(t, pool, userB, "b-key")
	// RevokeForUser writes an admin_audit_log row keyed by the admin's UserID
	// (FK → users); use a real seeded user as that admin.
	adminID := createScopeTestUser(t, pool, domA, "scopea.example")

	ctx := context.Background()

	// Domain-A admin → revoke domain-B app password: must be 404, row unchanged.
	req := httptest.NewRequest(http.MethodDelete, "/admin/users", nil)
	req.SetPathValue("userId", fmt.Sprintf("%d", userB))
	req.SetPathValue("apId", fmt.Sprintf("%d", apB))
	req = adminClaimsCtx(req, adminID, domA)
	rec := httptest.NewRecorder()
	h.RevokeForUser(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("RevokeForUser cross-domain: want 404, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var revokedB *string
	if err := pool.QueryRow(ctx, `SELECT revoked_at::text FROM app_passwords WHERE id = $1`, apB).Scan(&revokedB); err != nil {
		t.Fatalf("read cross-domain revoked_at: %v", err)
	}
	if revokedB != nil {
		t.Errorf("RevokeForUser cross-domain revoked the domain-B user's app password (IDOR): revoked_at=%v", *revokedB)
	}

	// Domain-A admin → revoke domain-A app password: must be 204, row revoked.
	req = httptest.NewRequest(http.MethodDelete, "/admin/users", nil)
	req.SetPathValue("userId", fmt.Sprintf("%d", userA))
	req.SetPathValue("apId", fmt.Sprintf("%d", apA))
	req = adminClaimsCtx(req, adminID, domA)
	rec = httptest.NewRecorder()
	h.RevokeForUser(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("RevokeForUser same-domain: want 204, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var revokedA *string
	if err := pool.QueryRow(ctx, `SELECT revoked_at::text FROM app_passwords WHERE id = $1`, apA).Scan(&revokedA); err != nil {
		t.Fatalf("read same-domain revoked_at: %v", err)
	}
	if revokedA == nil {
		t.Error("RevokeForUser same-domain did not revoke the domain-A user's app password")
	}
}

// ── app entitlements ─────────────────────────────────────────────────────────

// TestAppEntitlements_DomainScope_List verifies a domain-A admin reading a
// domain-B user's entitlements sees only default-allow (no explicit rows leaked),
// while a domain-A user's explicit row IS reflected.
func TestAppEntitlements_DomainScope_List(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewAppEntitlementHandler(pool, mailboxTestLogger())

	domA := ensureScopeTestDomain(t, pool, "scopea.example")
	domB := ensureScopeTestDomain(t, pool, "scopeb.example")
	userA := createScopeTestUser(t, pool, domA, "scopea.example")
	userB := createScopeTestUser(t, pool, domB, "scopeb.example")

	ctx := context.Background()
	// Give BOTH users an explicit calendar=false row.
	for _, uid := range []int64{userA, userB} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO user_app_entitlements (user_id, app, enabled) VALUES ($1, 'calendar', FALSE)
			 ON CONFLICT (user_id, app) DO UPDATE SET enabled = EXCLUDED.enabled`, uid); err != nil {
			t.Fatalf("seed entitlement for %d: %v", uid, err)
		}
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM user_app_entitlements WHERE user_id = ANY($1)`, []int64{userA, userB})
	})

	calendarEnabled := func(body []byte) (bool, bool) {
		var rows []appEntitlementRow
		if err := json.Unmarshal(body, &rows); err != nil {
			t.Fatalf("decode entitlements: %v", err)
		}
		for _, row := range rows {
			if row.App == "calendar" {
				return row.Enabled, true
			}
		}
		return false, false
	}

	// Domain-A admin → domain-B user: the explicit calendar=false must NOT leak;
	// the user falls back to default-allow (enabled=true).
	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.SetPathValue("id", fmt.Sprintf("%d", userB))
	req = adminClaimsCtx(req, 1, domA)
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("List cross-domain: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if enabled, ok := calendarEnabled(rec.Body.Bytes()); !ok || !enabled {
		t.Errorf("List cross-domain leaked domain-B explicit entitlement (IDOR): calendar enabled=%v ok=%v (want default-allow true)", enabled, ok)
	}

	// Domain-A admin → domain-A user: the explicit calendar=false IS reflected.
	req = httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.SetPathValue("id", fmt.Sprintf("%d", userA))
	req = adminClaimsCtx(req, 1, domA)
	rec = httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("List same-domain: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if enabled, ok := calendarEnabled(rec.Body.Bytes()); !ok || enabled {
		t.Errorf("List same-domain did not reflect domain-A explicit entitlement: calendar enabled=%v ok=%v (want false)", enabled, ok)
	}
}

// TestAppEntitlements_DomainScope_Set verifies a domain-A admin cannot toggle a
// domain-B user's entitlement (404, no row written) but can for a domain-A user.
func TestAppEntitlements_DomainScope_Set(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewAppEntitlementHandler(pool, mailboxTestLogger())

	domA := ensureScopeTestDomain(t, pool, "scopea.example")
	domB := ensureScopeTestDomain(t, pool, "scopeb.example")
	userA := createScopeTestUser(t, pool, domA, "scopea.example")
	userB := createScopeTestUser(t, pool, domB, "scopeb.example")
	// set_app_entitlement writes updated_by + admin_audit_log keyed by the admin's
	// UserID (FK → users); use a real seeded user as that admin.
	adminID := createScopeTestUser(t, pool, domA, "scopea.example")
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM user_app_entitlements WHERE user_id = ANY($1)`, []int64{userA, userB})
	})

	ctx := context.Background()

	// Domain-A admin → set domain-B user's contacts=false: must be 404 and write
	// NO row (the reducer never runs).
	req := httptest.NewRequest(http.MethodPut, "/admin/users", bytes.NewBufferString(`{"enabled":false}`))
	req.SetPathValue("id", fmt.Sprintf("%d", userB))
	req.SetPathValue("app", "contacts")
	req = adminClaimsCtx(req, adminID, domA)
	rec := httptest.NewRecorder()
	h.Set(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("Set cross-domain: want 404, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var rowsB int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM user_app_entitlements WHERE user_id = $1`, userB).Scan(&rowsB); err != nil {
		t.Fatalf("count cross-domain entitlement rows: %v", err)
	}
	if rowsB != 0 {
		t.Errorf("Set cross-domain wrote %d entitlement row(s) for the domain-B user (IDOR)", rowsB)
	}

	// Domain-A admin → set domain-A user's contacts=false: must be 204 and write
	// the row.
	req = httptest.NewRequest(http.MethodPut, "/admin/users", bytes.NewBufferString(`{"enabled":false}`))
	req.SetPathValue("id", fmt.Sprintf("%d", userA))
	req.SetPathValue("app", "contacts")
	req = adminClaimsCtx(req, adminID, domA)
	rec = httptest.NewRecorder()
	h.Set(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("Set same-domain: want 204, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var enabledA bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM user_app_entitlements WHERE user_id = $1 AND app = 'contacts'`, userA).Scan(&enabledA); err != nil {
		t.Fatalf("read same-domain entitlement: %v", err)
	}
	if enabledA {
		t.Error("Set same-domain did not write contacts=false for the domain-A user")
	}
}

// ── CSV import ───────────────────────────────────────────────────────────────

// buildCSVUpload constructs a multipart/form-data request body with a single
// "file" field carrying the given CSV content.
func buildCSVUpload(t *testing.T, csv string) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "import.csv")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := fw.Write([]byte(csv)); err != nil {
		t.Fatalf("write csv: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}
	return &buf, mw.FormDataContentType()
}

// TestImportCSV_DomainScope rejects a domain-A admin importing a domain-B user
// (per-row reject, partial success preserved) while accepting a domain-A user in
// the SAME upload.
func TestImportCSV_DomainScope(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: pool}, mailboxTestLogger(), nil, "", "")

	domA := ensureScopeTestDomain(t, pool, "scopea.example")
	// domB must exist so resolveLocalDomain resolves scopeb.example (it just
	// must not equal the domain scope) — the returned id is unused here.
	_ = ensureScopeTestDomain(t, pool, "scopeb.example")
	// The shared helper marks domains is_local via the default — make sure both
	// resolve as local for resolveLocalDomain (ensureScopeTestDomain inserts with
	// the table default is_local=TRUE).
	suffix := mailboxRandomSuffix(t)
	emailA := "csvimport-a-" + suffix + "@scopea.example"
	emailB := "csvimport-b-" + suffix + "@scopeb.example"
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `ALTER TABLE mailboxes DISABLE TRIGGER ALL`)
		pool.Exec(c, `DELETE FROM mailboxes WHERE email IN ($1, $2)`, emailA, emailB)
		pool.Exec(c, `ALTER TABLE mailboxes ENABLE TRIGGER ALL`)
		pool.Exec(c, `DELETE FROM users WHERE email IN ($1, $2)`, emailA, emailB)
	})

	csv := "email,password\n" +
		emailA + ",Sup3r-Str0ng-Pw!\n" +
		emailB + ",Sup3r-Str0ng-Pw!\n"
	body, contentType := buildCSVUpload(t, csv)

	req := httptest.NewRequest(http.MethodPost, "/admin/users/import", body)
	req.Header.Set("Content-Type", contentType)
	req = adminClaimsCtx(req, 1, domA)
	rec := httptest.NewRecorder()
	h.ImportCSV(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ImportCSV: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	var result struct {
		Created int `json:"created"`
		Failed  []struct {
			Row   int    `json:"row"`
			Email string `json:"email"`
			Error string `json:"error"`
		} `json:"failed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode import result: %v", err)
	}

	// Partial success: domain-A row created, domain-B row rejected per-row.
	if result.Created != 1 {
		t.Errorf("ImportCSV created = %d, want 1 (only the domain-A row)", result.Created)
	}
	var sawBReject bool
	for _, f := range result.Failed {
		if f.Email == emailB {
			sawBReject = true
			if f.Error != "email domain is not in your domain scope" {
				t.Errorf("ImportCSV domain-B reject reason = %q, want the domain-scope 403 reason", f.Error)
			}
		}
		if f.Email == emailA {
			t.Errorf("ImportCSV wrongly rejected the in-scope domain-A row: %q", f.Error)
		}
	}
	if !sawBReject {
		t.Error("ImportCSV did not reject the domain-B row (cross-domain IDOR import)")
	}

	// The cross-tenant row must NOT exist in the DB.
	ctx := context.Background()
	var bExists int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE email = $1`, emailB).Scan(&bExists); err != nil {
		t.Fatalf("count domain-B import: %v", err)
	}
	if bExists != 0 {
		t.Error("ImportCSV created the domain-B user despite the domain scope (IDOR)")
	}
	// The in-scope row must exist.
	var aExists int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE email = $1`, emailA).Scan(&aExists); err != nil {
		t.Fatalf("count domain-A import: %v", err)
	}
	if aExists != 1 {
		t.Errorf("ImportCSV did not create the in-scope domain-A user (count=%d)", aExists)
	}
}
