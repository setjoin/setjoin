package admin

// Tests for ADHandler.SetPrincipal (POST /admin/ad/principal): the audited,
// INTENTIONAL krb5_principal change. Every sync/provisioning path refuses to
// rewrite the Kerberos/SPNEGO SSO identity of an existing user (the Go
// always-local-only floor + the provision_account UPDATE fence), so this
// endpoint is the single sanctioned writer — it must gate on a live
// identity.write assignment with reach over the target (resolved in the
// reducer, not from JWT claims), reject empty principals, write the new value,
// and record the old→new change in admin_audit_log via the shared audit_write
// choke in the SAME transaction.
//
// Uses seedOUTestState (admin_roles_ou_test.go):
//   actorEngOUScoped (97901): OU-scoped to /eng
//   actorGlobal      (97902): unconfined (null scope)
//   userEng          (97903): in /eng — reachable for the global actor
//   userSales        (97905): in /sales — out of reach for the eng-scoped actor

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

func TestSetPrincipal_AuditedIntentionalChange(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	// The reducer resolves authority from live DB rows, not the JWT claims the
	// handler tests inject — the global actor needs a persisted identity.write
	// assignment for the Case 4 mutation to be authorized.
	grantIdentityWrite(t, pool, st.actorGlobal, 0)
	// &config.Config{} — ADSyncEnabled=false, so no LDAP client is constructed.
	h := NewADHandler(pool, testsupport.TestLogger(), &config.Config{})

	// ── Case 1: no authenticated actor → 401 ─────────────────────────────────
	body1, _ := json.Marshal(map[string]any{"userId": st.userEng, "krb5Principal": "u@REALM"})
	req1 := httptest.NewRequest(http.MethodPost, "/admin/ad/principal", strings.NewReader(string(body1)))
	w1 := httptest.NewRecorder()
	h.SetPrincipal(w1, req1)
	if w1.Code != http.StatusUnauthorized {
		t.Errorf("Case 1 (no actor): want 401, got %d (body=%s)", w1.Code, w1.Body.String())
	}

	// ── Case 2: OU-scoped actor → user in /sales → 403 (unauthorized) ────────
	body2, _ := json.Marshal(map[string]any{"userId": st.userSales, "krb5Principal": "u@REALM"})
	req2 := httptest.NewRequest(http.MethodPost, "/admin/ad/principal", strings.NewReader(string(body2)))
	req2 = req2.WithContext(auth.ContextWithUser(req2.Context(), &auth.Claims{
		UserID: st.actorEngOUScoped, IsAdmin: true, Permissions: permissions.AllPermissions,
	}))
	w2 := httptest.NewRecorder()
	h.SetPrincipal(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Errorf("Case 2 (OU-scoped → /sales user): want 403, got %d (body=%s)", w2.Code, w2.Body.String())
	}

	// ── Case 3: empty krb5Principal → 400 ────────────────────────────────────
	body3, _ := json.Marshal(map[string]any{"userId": st.userEng, "krb5Principal": "   "})
	req3 := httptest.NewRequest(http.MethodPost, "/admin/ad/principal", strings.NewReader(string(body3)))
	req3 = req3.WithContext(auth.ContextWithUser(req3.Context(), &auth.Claims{
		UserID: st.actorGlobal, IsAdmin: true, Permissions: permissions.AllPermissions,
	}))
	w3 := httptest.NewRecorder()
	h.SetPrincipal(w3, req3)
	if w3.Code != http.StatusBadRequest {
		t.Errorf("Case 3 (blank principal): want 400, got %d (body=%s)", w3.Code, w3.Body.String())
	}

	// ── Case 4: global actor performs the intentional change ─────────────────
	// Seed a known OLD principal directly (bypassing the endpoint — e.g. the
	// value the user was originally provisioned with), then change it via
	// SetPrincipal and require 204 + the new value + an old→new audit row.
	oldPrincipal := "user-eng@LEGACY.REALM"
	newPrincipal := "user-eng@CORP.EXAMPLE.COM"
	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET krb5_principal = $1 WHERE id = $2`, oldPrincipal, st.userEng); err != nil {
		t.Fatalf("seed old principal: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), //nolint:errcheck
			`UPDATE users SET krb5_principal = NULL WHERE id IN ($1, $2)`, st.userEng, st.userSales)
	})

	body4, _ := json.Marshal(map[string]any{"userId": st.userEng, "krb5Principal": newPrincipal})
	req4 := httptest.NewRequest(http.MethodPost, "/admin/ad/principal", strings.NewReader(string(body4)))
	req4 = req4.WithContext(auth.ContextWithUser(req4.Context(), &auth.Claims{
		UserID: st.actorGlobal, IsAdmin: true, Permissions: permissions.AllPermissions,
	}))
	w4 := httptest.NewRecorder()
	h.SetPrincipal(w4, req4)
	if w4.Code != http.StatusNoContent {
		t.Fatalf("Case 4 (global → /eng user): want 204, got %d (body=%s)", w4.Code, w4.Body.String())
	}

	var stored string
	if err := pool.QueryRow(context.Background(),
		`SELECT krb5_principal FROM users WHERE id = $1`, st.userEng).Scan(&stored); err != nil {
		t.Fatalf("read principal after change: %v", err)
	}
	if stored != newPrincipal {
		t.Errorf("krb5_principal = %q, want %q", stored, newPrincipal)
	}

	// The audit row carries the actor, the target, and BOTH the old and new
	// principal (old→new), written in the same transaction as the change.
	// (Earlier runs may have left rows for these fixed IDs — take the newest.)
	var before, after string
	if err := pool.QueryRow(context.Background(), `
		SELECT COALESCE(before_state->>'krb5_principal', ''),
		       COALESCE(after_state->>'krb5_principal', '')
		  FROM admin_audit_log
		 WHERE action = 'ad_krb5_principal_change' AND user_id = $1 AND target_id = $2
		 ORDER BY id DESC LIMIT 1`,
		st.actorGlobal, st.userEng).Scan(&before, &after); err != nil {
		t.Fatalf("read ad_krb5_principal_change audit row: %v", err)
	}
	if before != oldPrincipal || after != newPrincipal {
		t.Errorf("audit old→new = %q→%q, want %q→%q", before, after, oldPrincipal, newPrincipal)
	}
}
