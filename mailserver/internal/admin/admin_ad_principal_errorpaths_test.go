package admin

// Handler-level error-path coverage for the AD identity seam:
//
//   - SetFieldPolicy rejects policy="ad_managed" on krb5_principal with 400:
//     the Kerberos/SPNEGO SSO identity carries a code-level always-local-only
//     floor in the sync engines and the provision_account reducer's UPDATE
//     branch, so an 'ad_managed' row could never take effect. The ONLY
//     sanctioned principal change is SetPrincipal below.
//   - SetPrincipal fast-path input validation: malformed JSON → 400, missing
//     userId → 400 (both before any DB access).
//   - SetPrincipal fast-path reach query failure (e.g. closed/unavailable
//     pool) → 500, never a fail-open.
//   - SetPrincipal reducer BZ061 → 403: an actor the fast-path admin_can_reach
//     admits (the seed's global NULL-scope Help Desk assignment) but whose
//     assignment carries NO identity.write is denied by the reducer's in-lock
//     admin_can_manage_with_permission re-check, the principal stays
//     unchanged, and no audit row is written.
//   - SetPrincipal unknown target → 404 from the plain current-principal read
//     (a NULL-scope assignment reaches even a nonexistent user id, so the
//     fast path passes and the read misses).
//
// Uses seedOUTestState (admin_roles_ou_test.go):
//   actorGlobal (97902): unconfined Help Desk assignment — reach without
//   identity.write; userEng (97903): reachable target.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/config"
	"setjoin.com/mailserver/internal/ldaputil"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

// newPrincipalReq builds an authenticated POST /admin/ad/principal request
// with a raw body (so malformed-JSON cases stay expressible).
func newPrincipalReq(t *testing.T, rawBody string, actorID int64) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/admin/ad/principal", strings.NewReader(rawBody))
	if actorID != 0 {
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
			UserID: actorID, IsAdmin: true, Permissions: permissions.AllPermissions,
		}))
	}
	return req
}

// TestSetPrincipal_RequestValidation pins the 400 arms that run before any
// database access: a body that does not decode, and a body without a positive
// userId.
func TestSetPrincipal_RequestValidation(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewADHandler(pool, testsupport.TestLogger(), &config.Config{})

	t.Run("malformed JSON body is rejected with 400", func(t *testing.T) {
		w := httptest.NewRecorder()
		h.SetPrincipal(w, newPrincipalReq(t, `{"userId":`, st.actorGlobal))
		if w.Code != http.StatusBadRequest {
			t.Errorf("malformed JSON: want 400, got %d (body=%s)", w.Code, w.Body.String())
		}
	})

	t.Run("missing userId is rejected with 400", func(t *testing.T) {
		w := httptest.NewRecorder()
		h.SetPrincipal(w, newPrincipalReq(t, `{"userId":0,"krb5Principal":"u@REALM"}`, st.actorGlobal))
		if w.Code != http.StatusBadRequest {
			t.Errorf("userId=0: want 400, got %d (body=%s)", w.Code, w.Body.String())
		}
	})

	t.Run("negative userId is rejected with 400", func(t *testing.T) {
		w := httptest.NewRecorder()
		h.SetPrincipal(w, newPrincipalReq(t, `{"userId":-5,"krb5Principal":"u@REALM"}`, st.actorGlobal))
		if w.Code != http.StatusBadRequest {
			t.Errorf("userId<0: want 400, got %d (body=%s)", w.Code, w.Body.String())
		}
	})
}

// TestSetPrincipal_ClosedPoolFastPathFailsClosed pins the 500 on the fast-path
// admin_can_reach query: when the pool is unavailable the endpoint must fail
// closed with "database error", never fall through to the mutation.
func TestSetPrincipal_ClosedPoolFastPathFailsClosed(t *testing.T) {
	closed := testsupport.OpenTestPool(t)
	closed.Close() // OpenTestPool's cleanup Close is idempotent
	h := NewADHandler(closed, testsupport.TestLogger(), &config.Config{})

	body, _ := json.Marshal(map[string]any{"userId": 97903, "krb5Principal": "closed-pool@REALM"})
	w := httptest.NewRecorder()
	h.SetPrincipal(w, newPrincipalReq(t, string(body), 97902))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("closed pool: want 500, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestSetFieldPolicy_Krb5PrincipalAlwaysLocalOnly pins the explicit 400 for
// policy="ad_managed" on krb5_principal: accepting it would write a row the
// sync floor makes a silent no-op that reads like the principal is
// directory-managed.
func TestSetFieldPolicy_Krb5PrincipalAlwaysLocalOnly(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewADHandler(pool, testsupport.TestLogger(), &config.Config{})

	body, _ := json.Marshal(map[string]any{
		"userId": st.userEng,
		"field":  ldaputil.FieldKrb5Principal,
		"policy": "ad_managed",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/ad/field-policy", strings.NewReader(string(body)))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: st.actorGlobal, IsAdmin: true, Permissions: permissions.AllPermissions,
	}))
	w := httptest.NewRecorder()
	h.SetFieldPolicy(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("ad_managed on krb5_principal: want 400, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestSetPrincipal_ReachedButNoIdentityWriteIsForbidden drives the reducer's
// BZ061 → 403 mapping through the handler: the fast-path admin_can_reach admits
// the global NULL-scope Help Desk assignment (reach), but that assignment does
// NOT carry identity.write, so ad_principal_set's in-lock
// admin_can_manage_with_permission re-check denies the change. The principal
// must stay unchanged and no audit row may appear.
func TestSetPrincipal_ReachedButNoIdentityWriteIsForbidden(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	// Deliberately NO grantIdentityWrite for st.actorGlobal: the missing
	// permission axis is the case under test.
	h := NewADHandler(pool, testsupport.TestLogger(), &config.Config{})
	ctx := context.Background()

	const oldPrincipal = "no-iw@LEGACY.REALM"
	if _, err := pool.Exec(ctx,
		`UPDATE users SET krb5_principal = $1 WHERE id = $2`, oldPrincipal, st.userEng); err != nil {
		t.Fatalf("seed old principal: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, //nolint:errcheck
			`UPDATE users SET krb5_principal = NULL WHERE id = $1`, st.userEng)
	})

	auditsBefore := countPrincipalChangeAudits(t, pool, st.actorGlobal, st.userEng)

	body, _ := json.Marshal(map[string]any{"userId": st.userEng, "krb5Principal": "no-iw@NEW.REALM"})
	w := httptest.NewRecorder()
	h.SetPrincipal(w, newPrincipalReq(t, string(body), st.actorGlobal))
	if w.Code != http.StatusForbidden {
		t.Fatalf("reach-without-identity.write: want 403 (reducer BZ061), got %d (body=%s)",
			w.Code, w.Body.String())
	}

	var stored string
	if err := pool.QueryRow(ctx,
		`SELECT krb5_principal FROM users WHERE id = $1`, st.userEng).Scan(&stored); err != nil {
		t.Fatalf("read principal after denial: %v", err)
	}
	if stored != oldPrincipal {
		t.Errorf("krb5_principal = %q, want unchanged %q (denied actor must not mutate)", stored, oldPrincipal)
	}
	if after := countPrincipalChangeAudits(t, pool, st.actorGlobal, st.userEng); after != auditsBefore {
		t.Errorf("audit rows for denied change: before=%d after=%d, want unchanged", auditsBefore, after)
	}
}

// TestSetPrincipal_UnknownTargetUserNotFound pins the 404 from the plain
// current-principal read: a NULL-scope assignment satisfies admin_can_reach
// without consulting the target row, so a nonexistent userId passes the fast
// path and is reported 404 by the miss on users.krb5_principal.
func TestSetPrincipal_UnknownTargetUserNotFound(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewADHandler(pool, testsupport.TestLogger(), &config.Config{})

	const ghostUserID = 987654321 // no such user
	body, _ := json.Marshal(map[string]any{"userId": ghostUserID, "krb5Principal": "ghost@REALM"})
	w := httptest.NewRecorder()
	h.SetPrincipal(w, newPrincipalReq(t, string(body), st.actorGlobal))
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown target: want 404, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestSetPrincipal_ReducerUnexpectedFailureIs500 pins the defensive default arm
// of the reducer error switch: an error that is neither BZ060 nor BZ061 must
// map to 500 "database error" (logged), never collapse into a misleading 4xx.
// The reducer is made unavailable by temporarily renaming it — the exact shape
// a real outage produces — and restored by t.Cleanup before any later test
// runs. The database is this test run's disposable schema DB and the rename
// preserves the function's OID and definition.
func TestSetPrincipal_ReducerUnexpectedFailureIs500(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedOUTestState(t)
	h := NewADHandler(pool, testsupport.TestLogger(), &config.Config{})
	ctx := context.Background()

	const (
		fnSig    = "ad_principal_set(bigint,bigint,text,text,inet)"
		fnHidden = "ad_principal_set_cov_gap_hidden"
	)
	if _, err := pool.Exec(ctx, `ALTER FUNCTION `+fnSig+` RENAME TO `+fnHidden); err != nil {
		t.Fatalf("temporarily hide ad_principal_set: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx,
			`ALTER FUNCTION `+fnHidden+`(bigint,bigint,text,text,inet) RENAME TO ad_principal_set`); err != nil {
			t.Errorf("restore ad_principal_set: %v", err)
		}
	})

	// grantIdentityWrite: the denial under test is the DEFAULT arm, so the
	// BZ061 permission gate must pass and the failure must come from the
	// reducer being unavailable.
	grantIdentityWrite(t, pool, st.actorGlobal, 0)
	if _, err := pool.Exec(ctx,
		`UPDATE users SET krb5_principal = $1 WHERE id = $2`, "outage@LEGACY.REALM", st.userEng); err != nil {
		t.Fatalf("seed old principal: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, //nolint:errcheck
			`UPDATE users SET krb5_principal = NULL WHERE id = $1`, st.userEng)
	})

	body, _ := json.Marshal(map[string]any{"userId": st.userEng, "krb5Principal": "outage@NEW.REALM"})
	w := httptest.NewRecorder()
	h.SetPrincipal(w, newPrincipalReq(t, string(body), st.actorGlobal))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("unavailable reducer: want 500, got %d (body=%s)", w.Code, w.Body.String())
	}
}
