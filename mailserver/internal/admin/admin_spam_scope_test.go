package admin

// TestSpamModel_ReachCheck is a DB-backed TDD test verifying that OU-scoped
// admins cannot mutate spam models for users outside their OU, and that a
// global/super actor can.
//
// Uses seedOUTestState (admin_roles_ou_test.go):
//   actorEngOUScoped (97901): assignment scope_type='ou', scope_id=97901 (/eng)
//   actorGlobal      (97902): assignment scope_type=NULL  (unconfined)
//   userEng          (97903): in /eng dept
//   userSales        (97905): in /sales dept — out of reach for eng-scoped actor
//
// All three spam-model mutation handlers (ResetModel, DisableModel, EnableModel)
// are covered: OU-scoped actor → /sales target → 403, global actor → pass.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

func TestSpamModel_ReachCheck(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewSpamHandler(pool, testsupport.TestLogger())

	// ── ResetModel ───────────────────────────────────────────────────────────

	t.Run("ResetModel/out-of-reach → 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/admin/spam/model/"+strconv.FormatInt(st.userSales, 10), nil)
		req.SetPathValue("userId", strconv.FormatInt(st.userSales, 10))
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
			UserID: st.actorEngOUScoped, IsAdmin: true, Permissions: permissions.AllPermissions,
		}))
		w := httptest.NewRecorder()
		h.ResetModel(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("ResetModel out-of-reach: want 403, got %d (body=%s)", w.Code, w.Body.String())
		}
	})

	t.Run("ResetModel/super → 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/admin/spam/model/"+strconv.FormatInt(st.userEng, 10), nil)
		req.SetPathValue("userId", strconv.FormatInt(st.userEng, 10))
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
			UserID: st.actorGlobal, IsAdmin: true, Permissions: permissions.AllPermissions,
		}))
		w := httptest.NewRecorder()
		h.ResetModel(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("ResetModel super: want 200, got %d (body=%s)", w.Code, w.Body.String())
		}
	})

	// ── DisableModel ─────────────────────────────────────────────────────────

	t.Run("DisableModel/out-of-reach → 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/admin/spam/model/"+strconv.FormatInt(st.userSales, 10)+"/disable", nil)
		req.SetPathValue("userId", strconv.FormatInt(st.userSales, 10))
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
			UserID: st.actorEngOUScoped, IsAdmin: true, Permissions: permissions.AllPermissions,
		}))
		w := httptest.NewRecorder()
		h.DisableModel(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("DisableModel out-of-reach: want 403, got %d (body=%s)", w.Code, w.Body.String())
		}
	})

	t.Run("DisableModel/super → 200", func(t *testing.T) {
		// seedOUTestState ON DELETE CASCADE cleans user_spam_model when the user
		// is deleted, so no extra cleanup is needed here.
		req := httptest.NewRequest(http.MethodPost, "/admin/spam/model/"+strconv.FormatInt(st.userEng, 10)+"/disable", nil)
		req.SetPathValue("userId", strconv.FormatInt(st.userEng, 10))
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
			UserID: st.actorGlobal, IsAdmin: true, Permissions: permissions.AllPermissions,
		}))
		w := httptest.NewRecorder()
		h.DisableModel(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("DisableModel super: want 200, got %d (body=%s)", w.Code, w.Body.String())
		}
	})

	// ── EnableModel ──────────────────────────────────────────────────────────

	t.Run("EnableModel/out-of-reach → 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/admin/spam/model/"+strconv.FormatInt(st.userSales, 10)+"/enable", nil)
		req.SetPathValue("userId", strconv.FormatInt(st.userSales, 10))
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
			UserID: st.actorEngOUScoped, IsAdmin: true, Permissions: permissions.AllPermissions,
		}))
		w := httptest.NewRecorder()
		h.EnableModel(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("EnableModel out-of-reach: want 403, got %d (body=%s)", w.Code, w.Body.String())
		}
	})

	t.Run("EnableModel/super → 200", func(t *testing.T) {
		// Pre-seed a row so the UPDATE has something to match (else 0 rows affected
		// but handler still returns 200 — acceptable; seeding makes the test more real).
		pool.Exec(context.Background(), // nolint:errcheck
			`INSERT INTO user_spam_model (user_id, model_bytes, sample_count, disabled)
			 VALUES ($1, '\x', 0, TRUE)
			 ON CONFLICT (user_id) DO UPDATE SET disabled = TRUE`, st.userEng)

		req := httptest.NewRequest(http.MethodPost, "/admin/spam/model/"+strconv.FormatInt(st.userEng, 10)+"/enable", nil)
		req.SetPathValue("userId", strconv.FormatInt(st.userEng, 10))
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
			UserID: st.actorGlobal, IsAdmin: true, Permissions: permissions.AllPermissions,
		}))
		w := httptest.NewRecorder()
		h.EnableModel(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("EnableModel super: want 200, got %d (body=%s)", w.Code, w.Body.String())
		}
	})
}
