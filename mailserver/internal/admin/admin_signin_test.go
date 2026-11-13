package admin

// Admin sign-in reads are perm-gated and domain-scoped: an out-of-scope target → 404
// (indistinguishable from missing, no leak). secure-account attributes the admin actor.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/testsupport"
)

// seedSigninLoginEvent inserts a login_events row for the given user.
func seedSigninLoginEvent(t *testing.T, h *SignInHandler, userID int64) {
	t.Helper()
	_, err := h.pool.Exec(context.Background(),
		`INSERT INTO login_events (user_id, success, client, protocol, auth_method, occurred_at)
		 VALUES ($1, true, 'web', 'http', 'password', now())`, userID)
	if err != nil {
		t.Fatalf("seedSigninLoginEvent: %v", err)
	}
}

// seedSigninWebSession inserts a sessions row and returns its id.
func seedSigninWebSession(t *testing.T, h *SignInHandler, userID int64) string {
	t.Helper()
	var id string
	err := h.pool.QueryRow(context.Background(),
		`INSERT INTO sessions (user_id, expires_at, auth_method)
		 VALUES ($1, now() + interval '1 hour', 'password')
		 RETURNING id`, userID).Scan(&id)
	if err != nil {
		t.Fatalf("seedSigninWebSession: %v", err)
	}
	return id
}

// seedSigninOAuthToken inserts an oauth refresh token.
func seedSigninOAuthToken(t *testing.T, h *SignInHandler, userID int64) {
	t.Helper()
	hash := sha256.Sum256([]byte(fmt.Sprintf("signin-tok-%d", userID)))
	_, err := h.pool.Exec(context.Background(),
		`INSERT INTO oauth_tokens (user_id, client_id, token_hash, token_type, expires_at)
		 VALUES ($1, 'test-client', $2, 'refresh', now() + interval '1 day')`,
		userID, hash[:])
	if err != nil {
		t.Fatalf("seedSigninOAuthToken: %v", err)
	}
}

// As an admin WITHOUT users.read/audit.read → 403 on GET /admin/users/{id}/sign-ins.
// As an admin WITH the perm but target in another domain → 404.
// As an admin WITH the perm + in-domain target → 200 with that user's login_events rows.
// POST /admin/users/{id}/secure-account with users.password_reset → 200; the
//
//	admin_audit_log row attributes the ADMIN (p_actor=admin), not the target.
func TestAdminSignIn_PermAndDomainScope(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := testsupport.TestLogger()
	h := NewSignInHandler(pool, logger)

	domA := ensureScopeTestDomain(t, pool, "signina.test")
	domB := ensureScopeTestDomain(t, pool, "signinb.test")
	targetA := createScopeTestUser(t, pool, domA, "signina.test")
	_ = createScopeTestUser(t, pool, domB, "signinb.test")
	seedSigninLoginEvent(t, h, targetA)

	// --- 200: in-scope target, with auth perm ---
	req := httptest.NewRequest("GET", "/admin/users/"+fmt.Sprintf("%d", targetA)+"/sign-ins", nil)
	req.SetPathValue("id", fmt.Sprintf("%d", targetA))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 999, Email: "admin@signina.test"})
	ctx = middleware.ContextWithDomainScope(ctx, domA)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ListForUser(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 in-scope, got %d: %s", w.Code, w.Body.String())
	}

	// --- 404: out-of-scope target (domB user) seen from domA admin ---
	// We query for a user that belongs to domB while scoped to domA.
	// Use a non-existent ID to simulate: query a domB user via a domA scope.
	// We need a real domB user id:
	var domBUser int64
	pool.QueryRow(context.Background(),
		`SELECT id FROM users WHERE domain_id = $1 LIMIT 1`, domB).Scan(&domBUser)

	req2 := httptest.NewRequest("GET", "/admin/users/"+fmt.Sprintf("%d", domBUser)+"/sign-ins", nil)
	req2.SetPathValue("id", fmt.Sprintf("%d", domBUser))
	ctx2 := auth.ContextWithUser(req2.Context(), &auth.Claims{UserID: 999, Email: "admin@signina.test"})
	ctx2 = middleware.ContextWithDomainScope(ctx2, domA)
	req2 = req2.WithContext(ctx2)
	w2 := httptest.NewRecorder()
	h.ListForUser(w2, req2)
	if w2.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for out-of-scope target, got %d: %s", w2.Code, w2.Body.String())
	}
}

// EMPTY: an in-scope target with zero login_events returns items:[] (the UI renders
// security.admin.empty "No sign-ins recorded for {user}", not an error).
func TestAdminSignIn_EmptyInScope(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := testsupport.TestLogger()
	h := NewSignInHandler(pool, logger)

	domA := ensureScopeTestDomain(t, pool, "signine.test")
	targetA := createScopeTestUser(t, pool, domA, "signine.test")
	// No login events for targetA.

	req := httptest.NewRequest("GET", "/admin/users/"+fmt.Sprintf("%d", targetA)+"/sign-ins", nil)
	req.SetPathValue("id", fmt.Sprintf("%d", targetA))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 999})
	ctx = middleware.ContextWithDomainScope(ctx, domA)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ListForUser(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for empty in-scope, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Items) != 0 {
		t.Errorf("expected empty items, got %d", len(resp.Items))
	}
}

// 403 vs 404 distinctness: without the perm → 403 (security.admin.notPermitted);
// with the perm but out-of-scope → 404 (security.admin.notFound). Two different
// admin answers, two different UI states.
// NOTE: perm check happens in route middleware (not in handler); handler returns 404
// for scope miss. We test the handler's 404 path here; 403 is tested at the middleware layer.
func TestAdminSignIn_403VsScope404(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := testsupport.TestLogger()
	h := NewSignInHandler(pool, logger)

	domA := ensureScopeTestDomain(t, pool, "signinf.test")
	domB := ensureScopeTestDomain(t, pool, "signin403b.test")
	targetB := createScopeTestUser(t, pool, domB, "signin403b.test")

	// perm+foreign-domain target → 404 (scope gate in handler)
	req := httptest.NewRequest("GET", "/admin/users/"+fmt.Sprintf("%d", targetB)+"/sign-ins", nil)
	req.SetPathValue("id", fmt.Sprintf("%d", targetB))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 999})
	ctx = middleware.ContextWithDomainScope(ctx, domA)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ListForUser(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for perm+foreign-domain, got %d: %s", w.Code, w.Body.String())
	}
}

// ADMIN SECURE attribution + announce contract: the audit row attributes the admin
// actor, target's sessions/oauth are revoked, and target.must_change_password=true.
func TestAdminSignIn_SecureAttributesActorAndRevokes(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := testsupport.TestLogger()
	h := NewSignInHandler(pool, logger)

	domA := ensureScopeTestDomain(t, pool, "signins.test")
	// admin user (must exist in DB for the FK on admin_audit_log.user_id)
	adminUser := createScopeTestUser(t, pool, domA, "signins.test")
	targetUser := createScopeTestUser(t, pool, domA, "signins.test")

	// Seed target's sessions + oauth.
	seedSigninWebSession(t, h, targetUser)
	seedSigninOAuthToken(t, h, targetUser)

	// POST /admin/users/{id}/secure-account as admin
	req := httptest.NewRequest("POST", "/admin/users/"+fmt.Sprintf("%d", targetUser)+"/secure-account", strings.NewReader(""))
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.SetPathValue("id", fmt.Sprintf("%d", targetUser))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: adminUser, Email: "admin@signins.test"})
	ctx = middleware.ContextWithDomainScope(ctx, domA)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.SecureForUser(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	bg := context.Background()

	// target's web sessions must be gone
	var sessCount int
	pool.QueryRow(bg, `SELECT COUNT(*) FROM sessions WHERE user_id = $1`, targetUser).Scan(&sessCount)
	if sessCount != 0 {
		t.Errorf("target sessions not revoked: %d remaining", sessCount)
	}

	// target's oauth tokens must be revoked
	var oauthActive int
	pool.QueryRow(bg, `SELECT COUNT(*) FROM oauth_tokens WHERE user_id = $1 AND revoked_at IS NULL`, targetUser).Scan(&oauthActive)
	if oauthActive != 0 {
		t.Errorf("target oauth tokens not revoked: %d active", oauthActive)
	}

	// target.must_change_password must be true
	var mustChange bool
	pool.QueryRow(bg, `SELECT must_change_password FROM users WHERE id = $1`, targetUser).Scan(&mustChange)
	if !mustChange {
		t.Error("must_change_password not set on target")
	}

	// admin_audit_log must attribute the ADMIN, not the target
	var auditUserID int64
	var auditAction string
	pool.QueryRow(bg,
		`SELECT user_id, action FROM admin_audit_log
		 WHERE action = 'secure_account' AND target_id = $1
		 ORDER BY id DESC LIMIT 1`, targetUser).Scan(&auditUserID, &auditAction)
	if auditUserID != adminUser {
		t.Errorf("audit row user_id = %d, want admin %d", auditUserID, adminUser)
	}
	if auditAction != "secure_account" {
		t.Errorf("audit action = %q, want secure_account", auditAction)
	}
}
