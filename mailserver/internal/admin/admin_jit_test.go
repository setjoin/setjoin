package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

// jitTestEnableToggle turns the rbac.jit feature toggle ON for the duration of the test.
func jitTestEnableToggle(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`INSERT INTO feature_toggles (key, enabled) VALUES ('rbac.jit', true)
		 ON CONFLICT (key) DO UPDATE SET enabled = true`); err != nil {
		t.Fatalf("jitTestEnableToggle: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(),
			`UPDATE feature_toggles SET enabled = false WHERE key = 'rbac.jit'`)
	})
}

// jitTestSeedEligible inserts a user + eligible assignment for the named role.
// Returns (userID, roleGroupID). Cleanup is handled by seedUser.
func jitTestSeedEligible(t *testing.T, pool *pgxpool.Pool, roleName string) (int64, int64) {
	t.Helper()
	userID := seedUser(t, pool)
	ctx := context.Background()

	var groupID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM admin_role_groups WHERE name = $1`, roleName).Scan(&groupID); err != nil {
		t.Fatalf("jitTestSeedEligible lookup role %q: %v", roleName, err)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by, eligible)
		 VALUES ($1, $2, $1, true)
		 ON CONFLICT (user_id, role_group_id) DO UPDATE SET eligible = true`,
		userID, groupID); err != nil {
		t.Fatalf("jitTestSeedEligible INSERT assignment: %v", err)
	}
	return userID, groupID
}

// newJITHandler returns a JITHandler backed by a live test DB pool.
// toggles is nil — JIT gate lives in the DB reducer (feature_toggles table),
// so the Go handler does not need to pre-check it.
func newJITHandler(t *testing.T, pool *pgxpool.Pool) *JITHandler {
	t.Helper()
	return NewJITHandler(pool, testsupport.TestLogger(), nil)
}

// TestActivate_OwnEligible_200 — eligible assignment + toggle ON → 200 + activatedUntil.
func TestActivate_OwnEligible_200(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	jitTestEnableToggle(t, pool)
	userID, groupID := jitTestSeedEligible(t, pool, "Help Desk")
	h := newJITHandler(t, pool)

	body := `{"durationMinutes":60}`
	req := httptest.NewRequest("POST",
		"/admin/me/roles/"+strconv.FormatInt(groupID, 10)+"/activate",
		strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(groupID, 10))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: userID, Email: "jit@test.example", IsAdmin: true,
		Permissions: permissions.AllPermissions,
	}))
	w := httptest.NewRecorder()
	h.Activate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON decode: %v", err)
	}
	if _, ok := resp["activatedUntil"]; !ok {
		t.Error("response missing activatedUntil")
	}
}

// TestActivate_NotEligible_400 — no eligible assignment + toggle ON → 400 (BZ104).
func TestActivate_NotEligible_400(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	jitTestEnableToggle(t, pool)
	userID := seedUser(t, pool)

	ctx := context.Background()
	var groupID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM admin_role_groups WHERE name = 'Help Desk'`).Scan(&groupID); err != nil {
		t.Fatalf("lookup Help Desk: %v", err)
	}

	h := newJITHandler(t, pool)
	body := `{"durationMinutes":60}`
	req := httptest.NewRequest("POST",
		"/admin/me/roles/"+strconv.FormatInt(groupID, 10)+"/activate",
		strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(groupID, 10))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: userID, Email: "jit2@test.example", IsAdmin: false,
	}))
	w := httptest.NewRecorder()
	h.Activate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400 (BZ104 not-eligible): %s", w.Code, w.Body.String())
	}
}

// TestActivate_JustificationRequired_400 — eligible but justification missing → 400 (BZ105).
func TestActivate_JustificationRequired_400(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	jitTestEnableToggle(t, pool)
	userID, groupID := jitTestSeedEligible(t, pool, "Help Desk")

	// per-role policy: require_justification = true
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO admin_role_activation_policy (role_group_id, max_duration_minutes, require_justification)
		 VALUES ($1, 480, true)
		 ON CONFLICT (role_group_id) DO UPDATE SET require_justification = true`,
		groupID); err != nil {
		t.Fatalf("seed activation policy: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(),
			`DELETE FROM admin_role_activation_policy WHERE role_group_id = $1`, groupID)
	})

	h := newJITHandler(t, pool)
	body := `{"durationMinutes":60}` // no justification
	req := httptest.NewRequest("POST",
		"/admin/me/roles/"+strconv.FormatInt(groupID, 10)+"/activate",
		strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(groupID, 10))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: userID, Email: "jit3@test.example", IsAdmin: true,
		Permissions: permissions.AllPermissions,
	}))
	w := httptest.NewRecorder()
	h.Activate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400 (BZ105 justification required): %s", w.Code, w.Body.String())
	}
}

// TestActivate_ColdStart_SignalsRefresh — IsAdmin=false in JWT (token minted before eligibility)
// → 200 + tokenRefreshRequired:true so the webmail refreshes the token (D6).
func TestActivate_ColdStart_SignalsRefresh(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	jitTestEnableToggle(t, pool)
	userID, groupID := jitTestSeedEligible(t, pool, "Help Desk")

	h := newJITHandler(t, pool)
	body := `{"durationMinutes":60}`
	req := httptest.NewRequest("POST",
		"/admin/me/roles/"+strconv.FormatInt(groupID, 10)+"/activate",
		strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(groupID, 10))
	// IsAdmin=false: the live token predates the eligible assignment (cold-start).
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: userID, Email: "jit4@test.example", IsAdmin: false,
	}))
	w := httptest.NewRecorder()
	h.Activate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (cold-start): %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON decode: %v", err)
	}
	v, ok := resp["tokenRefreshRequired"]
	if !ok {
		t.Fatal("response missing tokenRefreshRequired (D6 cold-start signal)")
	}
	if b, ok2 := v.(bool); !ok2 || !b {
		t.Fatalf("tokenRefreshRequired = %v, want true", v)
	}
}

// TestDeactivate_200 — deactivate an active eligible assignment → 200.
func TestDeactivate_200(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	jitTestEnableToggle(t, pool)
	userID, groupID := jitTestSeedEligible(t, pool, "Help Desk")

	// Pre-activate so deactivate has something to clear.
	pool.Exec(context.Background(),
		`UPDATE admin_role_assignments SET activated_until = now() + interval '1 hour'
		 WHERE user_id = $1 AND role_group_id = $2`, userID, groupID)

	h := newJITHandler(t, pool)
	req := httptest.NewRequest("POST",
		"/admin/me/roles/"+strconv.FormatInt(groupID, 10)+"/deactivate", nil)
	req.SetPathValue("id", strconv.FormatInt(groupID, 10))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: userID, Email: "jit5@test.example", IsAdmin: true,
		Permissions: permissions.AllPermissions,
	}))
	w := httptest.NewRecorder()
	h.Deactivate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", w.Code, w.Body.String())
	}
}
