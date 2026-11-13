package handlers

// Regression for two impersonation bugs uncovered by the RBAC cut-over:
//
//   - Finding 5: AdminImpersonate re-validated the actor (and read the target tier)
//     from the vestigial users.is_admin column, which is DEFAULT false and never set
//     by the grant path — so it 403'd every governed/SSO-provisioned admin (the only
//     kind the modern model produces). The actor here has users.is_admin = FALSE but
//     holds a governed assignment; pre-fix this returned 403.
//   - Finding 6: the impersonation token was delivered under a cookie named
//     "auth_token", which nothing reads (the gateway + authserver session use
//     "access_token"), so the impersonation session was silently never picked up.
//
// DB-backed (testsupport.OpenTestPool); skipped when the test DB is unset.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/testsupport"
)

func TestAdminImpersonate_GovernedAdmin_SetsAccessTokenCookie(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	// Actor: users.is_admin column FALSE (seedDerivationUser seeds it FALSE) but a
	// governed admin_role_assignments row (group 2 = user_admin) makes them an admin.
	actorID, actorEmail := seedDerivationUser(t, pool, ctx, "imp-actor", "irrelevant")
	defer cleanSSOActor(t, pool, ctx, actorID)
	grantGovernedAdmin(t, pool, ctx, actorID, 2)

	// Target: a strictly-less-privileged non-admin (no governed assignment).
	targetID, _ := seedDerivationUser(t, pool, ctx, "imp-target", "irrelevant")
	defer cleanSSOActor(t, pool, ctx, targetID)

	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	r := httptest.NewRequest(http.MethodPost, "/auth/admin/users/"+strconv.FormatInt(targetID, 10)+"/impersonate", nil)
	// The JWT claim is correctly derived at mint (isAdminExprSQL), so a governed
	// admin arrives with IsAdmin=true; the bug was the DB RE-validation reading the
	// raw column.
	r = r.WithContext(ContextWithUser(r.Context(), &token.Claims{UserID: actorID, Email: actorEmail, IsAdmin: true}))
	r.SetPathValue("id", strconv.FormatInt(targetID, 10))

	w := httptest.NewRecorder()
	h.AdminImpersonate(w, r)

	// Finding 5: a governed admin (column FALSE) must NOT be denied.
	if w.Code != http.StatusOK {
		t.Fatalf("governed admin impersonation must succeed (200), got %d (finding 5: actor gate read the vestigial users.is_admin column)", w.Code)
	}

	// Finding 6: the session cookie must be "access_token" (what the gateway reads),
	// never the dead "auth_token".
	var sawAccess, sawAuthToken bool
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case "access_token":
			sawAccess = true
			if c.Value == "" {
				t.Error("access_token cookie set with an empty value")
			}
		case "auth_token":
			sawAuthToken = true
		}
	}
	if !sawAccess {
		t.Error("impersonation must set the access_token cookie (the name the gateway reads)")
	}
	if sawAuthToken {
		t.Error("impersonation must not set the dead auth_token cookie (nothing reads it)")
	}
}

// TestAdminImpersonate_NonAdmin_Forbidden covers the two independent gates a
// non-privileged actor must fail:
//   - a claims-level non-admin (IsAdmin=false) is refused before any DB call
//     (the handler's first check).
//   - a STALE/spoofed claim asserting IsAdmin=true for an actor who the DB
//     shows holds neither a governed admin_role_assignments row nor
//     users.is_admin=true is refused by the defense-in-depth DB re-validation
//     (the comment above AdminImpersonate: "JWT may be stale if admin was
//     demoted/disabled").
//
// In both cases the target must never receive an impersonation token: no
// access_token cookie is set on the response.
func TestAdminImpersonate_NonAdmin_Forbidden(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	actorID, actorEmail := seedDerivationUser(t, pool, ctx, "imp-nonadmin", "irrelevant")
	defer cleanSSOActor(t, pool, ctx, actorID)
	targetID, _ := seedDerivationUser(t, pool, ctx, "imp-nonadmin-target", "irrelevant")
	defer cleanSSOActor(t, pool, ctx, targetID)

	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	newReq := func(isAdmin bool) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/auth/admin/users/"+strconv.FormatInt(targetID, 10)+"/impersonate", nil)
		r = r.WithContext(ContextWithUser(r.Context(), &token.Claims{UserID: actorID, Email: actorEmail, IsAdmin: isAdmin}))
		r.SetPathValue("id", strconv.FormatInt(targetID, 10))
		return r
	}

	t.Run("claims say non-admin", func(t *testing.T) {
		w := httptest.NewRecorder()
		h.AdminImpersonate(w, newReq(false))
		if w.Code != http.StatusForbidden {
			t.Fatalf("non-admin claims: expected 403, got %d", w.Code)
		}
		for _, c := range w.Result().Cookies() {
			if c.Name == "access_token" {
				t.Fatal("non-admin claims must never receive an access_token cookie")
			}
		}
	})

	t.Run("stale claims say admin but DB has no admin authority", func(t *testing.T) {
		// actorID has no admin_role_assignments row and users.is_admin=FALSE
		// (seedDerivationUser's default) — the DB re-validation must catch a
		// forged/stale token that claims IsAdmin=true.
		w := httptest.NewRecorder()
		h.AdminImpersonate(w, newReq(true))
		if w.Code != http.StatusForbidden {
			t.Fatalf("stale admin claims with no DB authority: expected 403, got %d", w.Code)
		}
		for _, c := range w.Result().Cookies() {
			if c.Name == "access_token" {
				t.Fatal("an actor with no DB-side admin authority must never receive an access_token cookie")
			}
		}
	})
}

// TestAdminImpersonate_PeerGovernedAdmin_EscalationDenied is the end-to-end
// (HTTP handler + real DB) counterpart to TestImpersonationRank_NoUpwardOrEqual
// in auth_security_test.go, which only exercises the isolated rank function.
// Two governed admins holding the SAME non-super role group sit at equal rank
// (3) per the handler's no-upward-or-equal rule, so neither may impersonate the
// other. Asserts the 403, that no access_token cookie is issued, and that the
// refusal is audited (admin_impersonate_denied / privilege_escalation) — the
// handler's explicit defense against a lateral admin-to-admin takeover.
func TestAdminImpersonate_PeerGovernedAdmin_EscalationDenied(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	actorID, actorEmail := seedDerivationUser(t, pool, ctx, "imp-peer-actor", "irrelevant")
	defer cleanSSOActor(t, pool, ctx, actorID)
	targetID, _ := seedDerivationUser(t, pool, ctx, "imp-peer-target", "irrelevant")
	defer cleanSSOActor(t, pool, ctx, targetID)

	// group 2 = user_admin builtin (seeded by V010) — both actor and target hold
	// the SAME non-super governed role, so both resolve to rank 3 (equal).
	grantGovernedAdmin(t, pool, ctx, actorID, 2)
	grantGovernedAdmin(t, pool, ctx, targetID, 2)

	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	r := httptest.NewRequest(http.MethodPost, "/auth/admin/users/"+strconv.FormatInt(targetID, 10)+"/impersonate", nil)
	r = r.WithContext(ContextWithUser(r.Context(), &token.Claims{UserID: actorID, Email: actorEmail, IsAdmin: true}))
	r.SetPathValue("id", strconv.FormatInt(targetID, 10))

	w := httptest.NewRecorder()
	h.AdminImpersonate(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("peer governed admin: expected 403 (no-upward-or-equal), got %d", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "access_token" {
			t.Fatal("a denied escalation attempt must never receive an access_token cookie")
		}
	}

	var reason string
	err := pool.QueryRow(ctx,
		`SELECT metadata->>'reason' FROM audit_log
		  WHERE user_id = $1 AND event_type = 'admin_impersonate_denied'
		  ORDER BY id DESC LIMIT 1`,
		actorID,
	).Scan(&reason)
	if err != nil {
		t.Fatalf("expected an admin_impersonate_denied audit row for actor %d: %v", actorID, err)
	}
	if reason != "privilege_escalation" {
		t.Errorf("audit reason = %q, want %q", reason, "privilege_escalation")
	}
}
