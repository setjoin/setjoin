package admin

// TestSetFieldPolicy_ReachCheck is a DB-backed TDD test verifying that
// OU-scoped admins cannot set field policy for users outside their OU reach,
// and that a global actor succeeds.
//
// Uses seedOUTestState (admin_roles_ou_test.go):
//   actorEngOUScoped (97901): OU-scoped to /eng (dept 97901)
//   actorGlobal      (97902): unconfined (null scope)
//   userEng          (97903): in /eng — reachable for eng-scoped actor
//   userSales        (97905): in /sales — out of reach for eng-scoped actor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/config"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

func TestSetFieldPolicy_ReachCheck(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	// &config.Config{} — ADSyncEnabled=false, so no LDAP client is constructed.
	h := NewADHandler(pool, testsupport.TestLogger(), &config.Config{})

	// ── Case 1: OU-scoped actor → user in /sales → 403 ───────────────────────
	body1, _ := json.Marshal(map[string]any{"userId": st.userSales, "field": "displayName", "policy": "local_only"})
	req1 := httptest.NewRequest(http.MethodPost, "/admin/ad/field-policy", strings.NewReader(string(body1)))
	req1 = req1.WithContext(auth.ContextWithUser(req1.Context(), &auth.Claims{
		UserID: st.actorEngOUScoped, IsAdmin: true, Permissions: permissions.AllPermissions,
	}))
	w1 := httptest.NewRecorder()
	h.SetFieldPolicy(w1, req1)
	if w1.Code != http.StatusForbidden {
		t.Errorf("Case 1 (OU-scoped → /sales user): want 403, got %d (body=%s)", w1.Code, w1.Body.String())
	}

	// ── Case 2: global actor → user in /eng → 204 ────────────────────────────
	// field_policy.user_id → users.id ON DELETE CASCADE; seedOUTestState cleanup
	// deletes user 97903, which cascades and cleans this row automatically.
	body2, _ := json.Marshal(map[string]any{"userId": st.userEng, "field": "displayName", "policy": "local_only"})
	req2 := httptest.NewRequest(http.MethodPost, "/admin/ad/field-policy", strings.NewReader(string(body2)))
	req2 = req2.WithContext(auth.ContextWithUser(req2.Context(), &auth.Claims{
		UserID: st.actorGlobal, IsAdmin: true, Permissions: permissions.AllPermissions,
	}))
	w2 := httptest.NewRecorder()
	h.SetFieldPolicy(w2, req2)
	if w2.Code != http.StatusNoContent {
		t.Errorf("Case 2 (global → /eng user): want 204, got %d (body=%s)", w2.Code, w2.Body.String())
	}
	// Belt-and-suspenders cleanup in case the cascade doesn't fire in time.
	t.Cleanup(func() {
		pool.Exec(context.Background(), //nolint:errcheck
			`DELETE FROM field_policy WHERE user_id = $1 AND field = 'displayName'`, st.userEng)
	})
}
