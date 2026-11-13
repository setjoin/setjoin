package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/testsupport"
)

// TestRequireReason is DB-backed: it reads audit_policy.reason_required_areas
// and writes a sensitive_action.reason_missing core row on rejection.
//
// Prerequisites: DB_DSN pointing at a loaded mailserver_test schema.
func TestRequireReason(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	// Seed: set reason_required_areas to {"roles","identity","audit"} for the test.
	_, err := pool.Exec(ctx,
		`UPDATE audit_policy SET reason_required_areas=ARRAY['roles','identity','audit'] WHERE id=1`)
	if err != nil {
		t.Fatalf("seed audit_policy: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx,
			`UPDATE audit_policy SET reason_required_areas='{}' WHERE id=1`)
	})

	// Use a real user from the test fixtures (admin_audit_log.user_id has FK → users).
	// 88002 = "actor@protection.test" seeded by _fixtures.sql.
	fixtureUserID := int64(88002)
	claims := &auth.Claims{
		UserID:      fixtureUserID,
		Email:       "actor@protection.test",
		IsAdmin:     true,
		Permissions: []string{"roles.manage"},
		Type:        jwtutil.TypeAccess,
	}

	// ── (a) in-scope area + missing X-Audit-Reason → 400 + reason_missing row ──

	t.Run("in-scope missing reason → 400 + audit row", func(t *testing.T) {
		// Use a timestamp anchor to count only rows written by THIS test run.
		// (admin_audit_log is append-only so we can't delete pre-existing rows.)
		var before time.Time
		_ = pool.QueryRow(ctx, `SELECT now()`).Scan(&before)

		req := httptest.NewRequest(http.MethodPost, "/admin/roles", nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
		w := httptest.NewRecorder()

		mw := RequireReason("roles.manage", pool)
		mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d — %s", w.Code, w.Body.String())
		}

		var count int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM admin_audit_log
			  WHERE action='sensitive_action.reason_missing' AND user_id=$1
			    AND occurred_at >= $2::timestamptz`,
			fixtureUserID, before,
		).Scan(&count); err != nil {
			t.Fatalf("count query: %v", err)
		}
		if count != 1 {
			t.Errorf("expected 1 reason_missing audit row, got %d", count)
		}
	})

	// ── (b) in-scope area + present X-Audit-Reason → 200, reason in context ────

	t.Run("in-scope with reason → 200 + reason in context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/admin/roles", nil)
		req.Header.Set("X-Audit-Reason", "quarterly access review")
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
		w := httptest.NewRecorder()

		var gotReason string
		mw := RequireReason("roles.manage", pool)
		mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotReason = ReasonFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d — %s", w.Code, w.Body.String())
		}
		if gotReason != "quarterly access review" {
			t.Errorf("expected reason in context, got %q", gotReason)
		}
	})

	// ── (c) out-of-scope area → passes, no extra entry, no reason needed ────────

	t.Run("out-of-scope area → passes without reason", func(t *testing.T) {
		var before time.Time
		_ = pool.QueryRow(ctx, `SELECT now()`).Scan(&before)

		req := httptest.NewRequest(http.MethodPost, "/admin/queue/requeue", nil)
		// No X-Audit-Reason header — should not be required.
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
		w := httptest.NewRecorder()

		mw := RequireReason("queue.write", pool) // "queue" not in reason_required_areas
		mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200 for out-of-scope area, got %d", w.Code)
		}

		var count int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM admin_audit_log
			  WHERE action='sensitive_action.reason_missing' AND user_id=$1
			    AND occurred_at >= $2::timestamptz`,
			fixtureUserID, before,
		).Scan(&count); err != nil {
			t.Fatalf("count query: %v", err)
		}
		if count != 0 {
			t.Errorf("expected 0 reason_missing rows for out-of-scope, got %d", count)
		}
	})
}
