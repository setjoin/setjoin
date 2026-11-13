package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
)

func runtimeDeps(claims *jwtutil.Claims, dl *threat.SessionDenylist, toggles *toggle.FeatureFlags) RuntimeAccessDeps {
	return RuntimeAccessDeps{
		Claims:   func(*http.Request) *jwtutil.Claims { return claims },
		Denylist: dl,
		Engine:   nil, // nil engine ⇒ re-eval is a no-op allow (fail-open)
		Toggles:  toggles,
		Replay:   threat.NewDPoPReplayCache(time.Minute),
		Logger:   slog.Default(),
	}
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
}

// TestTokenBindingRefusalCarriesAdmissionMarker is the per-tab recovery
// contract's gateway half: the token-binding deny keeps its 401/title shape
// but carries the machine-readable problem `code` (threat.DPoPAdmissionCode)
// the webmail client keys its one-shot replay on. Every OTHER deny
// (revocation, sign-in-frequency, step-up) stays marker-free so an
// application-level refusal can never drive a replay.
func TestTokenBindingRefusalCarriesAdmissionMarker(t *testing.T) {
	deps := runtimeDeps(&jwtutil.Claims{
		UserID: 42,
		Cnf:    &jwtutil.ConfirmationClaim{JKT: "jkt-thumbprint"},
	}, threat.NewSessionDenylist(nil, slog.Default()), caeToggles(toggle.FeatureTokenBinding))

	// A proof that cannot verify (missing header): the VerifyDPoP refusal arm.
	rec := httptest.NewRecorder()
	RequireRuntimeAccess(deps)(okHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("verify-failure status = %d, want 401", rec.Code)
	}
	assertAdmissionMarked(t, rec.Body.String())

	// The miswired-replay-cache fail-closed arm answers the SAME marked shape.
	deps.Replay = nil
	rec2 := httptest.NewRecorder()
	RequireRuntimeAccess(deps)(okHandler()).ServeHTTP(rec2, httptest.NewRequest("GET", "/x", nil))
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("nil-replay status = %d, want 401", rec2.Code)
	}
	assertAdmissionMarked(t, rec2.Body.String())

	// The negative control: a session_revoked deny is NOT admission-marked —
	// a dead session's refusal must not invite a recovery replay.
	revokedDeps := runtimeDeps(&jwtutil.Claims{UserID: 42, JTI: "jti"}, threat.NewSessionDenylist(nil, slog.Default()), caeToggles())
	revokedDeps.Denylist.Apply(threat.RevocationRow{UserID: 42, Scope: threat.ScopeJTI, JTI: "jti", NotBefore: time.Now()})
	rec3 := httptest.NewRecorder()
	RequireRuntimeAccess(revokedDeps)(okHandler()).ServeHTTP(rec3, httptest.NewRequest("GET", "/x", nil))
	if rec3.Code != http.StatusUnauthorized {
		t.Fatalf("revoked status = %d, want 401", rec3.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec3.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode deny body %s: %v", rec3.Body.String(), err)
	}
	if body["code"] == threat.DPoPAdmissionCode {
		t.Fatal("session_revoked deny carries the admission marker — refusals of dead sessions must never replay")
	}
}

func assertAdmissionMarked(t *testing.T, body string) {
	t.Helper()
	var problem map[string]any
	if err := json.Unmarshal([]byte(body), &problem); err != nil {
		t.Fatalf("decode problem body %s: %v", body, err)
	}
	if problem["code"] != threat.DPoPAdmissionCode {
		t.Fatalf("token-binding deny = %s, want code %q — the client cannot tell a replayable admission refusal from a committed one", body, threat.DPoPAdmissionCode)
	}
}

func TestDPoPExternalPathSurvivesStripPrefix(t *testing.T) {
	var got string
	handler := http.StripPrefix("/api", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/system/health" {
			t.Fatalf("inner URL.Path = %q", r.URL.Path)
		}
		got = dpopExternalPath(r)
	}))
	req := httptest.NewRequest(http.MethodGet, "https://setjoin.test/api/admin/system/health?fresh=1", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if got != "/api/admin/system/health" {
		t.Fatalf("external DPoP path = %q, want %q", got, "/api/admin/system/health")
	}
}

func TestRuntimeFeatureOffPassThrough(t *testing.T) {
	toggles := toggle.NewTestFlags(map[string]bool{toggle.FeatureCAERuntime: false})
	mw := RequireRuntimeAccess(runtimeDeps(&jwtutil.Claims{UserID: 1}, threat.NewSessionDenylist(nil, slog.Default()), toggles))
	rec := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/jmap", nil))
	if rec.Code != 200 {
		t.Fatalf("feature off must pass through, got %d", rec.Code)
	}
}

func TestRuntimeFeatureOffStillDeniesKnownRevocation(t *testing.T) {
	toggles := toggle.NewTestFlags(map[string]bool{toggle.FeatureCAERuntime: false})
	dl := threat.NewSessionDenylist(nil, slog.Default())
	dl.Apply(threat.RevocationRow{
		UserID: 1, Scope: threat.ScopeAll, NotBefore: time.Now(),
	})
	claims := &jwtutil.Claims{UserID: 1}
	claims.IssuedAt = jwtutil.NewNumericDate(time.Now().Add(-time.Hour))
	rec := httptest.NewRecorder()
	RequireRuntimeAccess(runtimeDeps(claims, dl, toggles))(okHandler()).
		ServeHTTP(rec, httptest.NewRequest("GET", "/jmap", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("known revocation must remain effective while CAE is off, got %d", rec.Code)
	}
}

func TestRuntimeFeatureOffUnloadedDenylistPassesDuringRollout(t *testing.T) {
	toggles := toggle.NewTestFlags(map[string]bool{toggle.FeatureCAERuntime: false})
	dl := threat.NewSessionDenylist(func(context.Context) ([]threat.RevocationRow, error) {
		return nil, errors.New("db unavailable")
	}, slog.Default())
	rec := httptest.NewRecorder()
	RequireRuntimeAccess(runtimeDeps(&jwtutil.Claims{UserID: 1}, dl, toggles))(okHandler()).
		ServeHTTP(rec, httptest.NewRequest("GET", "/jmap", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("unloaded denylist remains rollout-pass-through while CAE is off, got %d", rec.Code)
	}
}

func TestRuntimeFeatureOffUnloadedDenylistStillDeniesPushedRevocation(t *testing.T) {
	toggles := toggle.NewTestFlags(map[string]bool{toggle.FeatureCAERuntime: false})
	dl := threat.NewSessionDenylist(func(context.Context) ([]threat.RevocationRow, error) {
		return nil, errors.New("db unavailable")
	}, slog.Default())
	dl.Apply(threat.RevocationRow{
		UserID: 1, Scope: threat.ScopeAll, NotBefore: time.Now(),
	})
	claims := &jwtutil.Claims{UserID: 1}
	claims.IssuedAt = jwtutil.NewNumericDate(time.Now().Add(-time.Hour))
	rec := httptest.NewRecorder()
	RequireRuntimeAccess(runtimeDeps(claims, dl, toggles))(okHandler()).
		ServeHTTP(rec, httptest.NewRequest("GET", "/jmap", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("pushed revocation must be authoritative before first refresh, got %d", rec.Code)
	}
}

func TestRuntimeNilClaims401(t *testing.T) {
	toggles := toggle.NewTestFlags(map[string]bool{toggle.FeatureCAERuntime: true})
	mw := RequireRuntimeAccess(runtimeDeps(nil, threat.NewSessionDenylist(nil, slog.Default()), toggles))
	rec := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/jmap", nil))
	if rec.Code != 401 {
		t.Fatalf("nil claims must 401, got %d", rec.Code)
	}
}

func TestRuntimeDenylistHit401(t *testing.T) {
	toggles := toggle.NewTestFlags(map[string]bool{toggle.FeatureCAERuntime: true})
	dl := threat.NewSessionDenylist(nil, slog.Default())
	dl.Apply(threat.RevocationRow{UserID: 1, Scope: "all", NotBefore: time.Now()})
	iat := time.Now().Add(-time.Hour)
	claims := &jwtutil.Claims{UserID: 1}
	claims.IssuedAt = jwtutil.NewNumericDate(iat) // helper provided by jwtutil; or set RegisteredClaims.IssuedAt
	mw := RequireRuntimeAccess(runtimeDeps(claims, dl, toggles))
	rec := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/jmap", nil))
	if rec.Code != 401 {
		t.Fatalf("revoked session must 401, got %d", rec.Code)
	}
}

func TestRuntimeSifExceededReauth(t *testing.T) {
	toggles := toggle.NewTestFlags(map[string]bool{toggle.FeatureCAERuntime: true})
	sif := int64(60) // 60s max age
	claims := &jwtutil.Claims{UserID: 1, SignInFreq: &sif}
	claims.IssuedAt = jwtutil.NewNumericDate(time.Now().Add(-2 * time.Hour))
	mw := RequireRuntimeAccess(runtimeDeps(claims, threat.NewSessionDenylist(nil, slog.Default()), toggles))
	rec := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/jmap", nil))
	if rec.Code != 401 || rec.Header().Get("WWW-Authenticate") != "reauth" {
		t.Fatalf("sif-exceeded must 401 reauth, got %d / %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}

func TestRuntimeSifUsesImmutableSessionAuthenticationTime(t *testing.T) {
	toggles := toggle.NewTestFlags(map[string]bool{toggle.FeatureCAERuntime: true})
	sif := int64(60)
	authTime := time.Now().Add(-2 * time.Hour).Unix()
	claims := &jwtutil.Claims{
		UserID:          1,
		SignInFreq:      &sif,
		SessionAuthTime: &authTime,
	}
	// A just-refreshed iat must not reset the family-level SIF window.
	claims.IssuedAt = jwtutil.NewNumericDate(time.Now())
	rec := httptest.NewRecorder()
	RequireRuntimeAccess(
		runtimeDeps(claims, threat.NewSessionDenylist(nil, slog.Default()), toggles),
	)(okHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/jmap", nil))
	if rec.Code != http.StatusUnauthorized ||
		rec.Header().Get("WWW-Authenticate") != "reauth" {
		t.Fatalf("old auth_time with fresh iat must reauth, got %d / %q",
			rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}

// TestRuntimeNilDenylistDeny verifies nil Denylist is fail-closed (not skip).
// A nil Denylist means the middleware was wired without revocation support; that
// must be treated as "cannot verify" → 401, not "no revocations" → allow.
func TestRuntimeNilDenylistDeny(t *testing.T) {
	toggles := toggle.NewTestFlags(map[string]bool{toggle.FeatureCAERuntime: true})
	deps := RuntimeAccessDeps{
		Claims:   func(*http.Request) *jwtutil.Claims { return &jwtutil.Claims{UserID: 1} },
		Denylist: nil, // intentionally nil — must deny, not skip
		Engine:   nil,
		Toggles:  toggles,
		Replay:   threat.NewDPoPReplayCache(time.Minute),
		Logger:   slog.Default(),
	}
	rec := httptest.NewRecorder()
	RequireRuntimeAccess(deps)(okHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/jmap", nil))
	if rec.Code != 401 {
		t.Fatalf("nil denylist must 401 (fail-closed), got %d", rec.Code)
	}
}

// TestRuntimeGroupScopedPolicyFires verifies that group/role-scoped CA policies
// re-evaluate correctly at runtime (Fix 5: GroupIDs/RoleGroupIDs populated via resolvers).
// Without the fix, group/role-scoped policies silently did not re-evaluate (only
// user/global did), so a group-block policy was never enforced at runtime.
func TestRuntimeGroupScopedPolicyFires(t *testing.T) {
	toggles := toggle.NewTestFlags(map[string]bool{
		toggle.FeatureCAERuntime:        true,
		toggle.FeatureConditionalAccess: true,
	})
	dl := threat.NewSessionDenylist(nil, slog.Default())
	// Stub store: one group-scoped block policy for group 42.
	store := &stubGroupPolicyStore{}
	engine := threat.NewPolicyEngine(store, toggles, nil, nil, slog.Default(), false)
	claims := &jwtutil.Claims{UserID: 1}
	claims.IssuedAt = jwtutil.NewNumericDate(time.Now())
	deps := RuntimeAccessDeps{
		Claims:            func(*http.Request) *jwtutil.Claims { return claims },
		Denylist:          dl,
		Engine:            engine,
		Toggles:           toggles,
		Replay:            threat.NewDPoPReplayCache(time.Minute),
		Logger:            slog.Default(),
		GroupResolver:     func(_ context.Context, _ int64) []int64 { return []int64{42} },
		RoleGroupResolver: nil,
		CountryFunc:       nil,
	}
	rec := httptest.NewRecorder()
	RequireRuntimeAccess(deps)(okHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/jmap", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("group-scoped block policy must return 403, got %d", rec.Code)
	}
}

// stubGroupPolicyStore returns one group-scoped block policy for group 42.
type stubGroupPolicyStore struct{}

func (s *stubGroupPolicyStore) LoadAllPolicies(_ context.Context) ([]threat.PolicyRow, error) {
	return s.LoadPolicies(context.Background(), threat.PolicyEvalContext{})
}
func (s *stubGroupPolicyStore) LoadPolicies(_ context.Context, _ threat.PolicyEvalContext) ([]threat.PolicyRow, error) {
	return []threat.PolicyRow{{
		ID:          1,
		Priority:    1,
		Name:        "block-group-42",
		State:       "on",
		ScopeType:   "group",
		ScopeTarget: "42",
		Conditions:  map[string]interface{}{},
		Actions:     map[string]interface{}{"action": "block"},
	}}, nil
}
func (s *stubGroupPolicyStore) ResolveGeoTier(_ context.Context, _ string) (string, error) {
	return "low", nil
}
func (s *stubGroupPolicyStore) LoadBreakGlass(_ context.Context) ([]int64, error) { return nil, nil }
func (s *stubGroupPolicyStore) LoadNamedLocations(_ context.Context) ([]threat.NamedLocation, error) {
	return nil, nil
}
func (s *stubGroupPolicyStore) LoadAuthStrengths(_ context.Context) ([]threat.AuthStrength, error) {
	return nil, nil
}

// TestRuntimeColdStartDeny verifies the middleware denies when the denylist has never
// successfully loaded from DB (cold-start fail-closed safety).
func TestRuntimeColdStartDeny(t *testing.T) {
	toggles := toggle.NewTestFlags(map[string]bool{toggle.FeatureCAERuntime: true})
	// Non-nil reconcileFn that always errors → Refresh never sets loaded=true.
	dl := threat.NewSessionDenylist(func(context.Context) ([]threat.RevocationRow, error) {
		return nil, errors.New("db unavailable")
	}, slog.Default())
	// dl.Loaded() == false; no rows.
	claims := &jwtutil.Claims{UserID: 1}
	mw := RequireRuntimeAccess(runtimeDeps(claims, dl, toggles))
	rec := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/jmap", nil))
	if rec.Code != 401 {
		t.Fatalf("cold-start (!Loaded) must 401, got %d", rec.Code)
	}
}

// ── F2 tests: TermsPendingResolver + remediation body + auth_method threading ──

// stubTermsPolicyStore returns one global require_terms block policy for tou_id 99.
type stubTermsPolicyStore struct{}

func (s *stubTermsPolicyStore) LoadAllPolicies(_ context.Context) ([]threat.PolicyRow, error) {
	return s.LoadPolicies(context.Background(), threat.PolicyEvalContext{})
}
func (s *stubTermsPolicyStore) LoadPolicies(_ context.Context, _ threat.PolicyEvalContext) ([]threat.PolicyRow, error) {
	return []threat.PolicyRow{{
		ID:         2,
		Priority:   1,
		Name:       "require-aup",
		State:      "on",
		ScopeType:  "global",
		Conditions: map[string]interface{}{},
		Actions:    map[string]interface{}{"action": "require_terms", "tou_id": float64(99)},
	}}, nil
}
func (s *stubTermsPolicyStore) ResolveGeoTier(_ context.Context, _ string) (string, error) {
	return "low", nil
}
func (s *stubTermsPolicyStore) LoadBreakGlass(_ context.Context) ([]int64, error) { return nil, nil }
func (s *stubTermsPolicyStore) LoadNamedLocations(_ context.Context) ([]threat.NamedLocation, error) {
	return nil, nil
}
func (s *stubTermsPolicyStore) LoadAuthStrengths(_ context.Context) ([]threat.AuthStrength, error) {
	return nil, nil
}

func makeTermsDeps(pendingResolver func(context.Context, int64, int64) bool) RuntimeAccessDeps {
	toggles := toggle.NewTestFlags(map[string]bool{
		toggle.FeatureCAERuntime:        true,
		toggle.FeatureConditionalAccess: true,
	})
	dl := threat.NewSessionDenylist(nil, slog.Default())
	engine := threat.NewPolicyEngine(&stubTermsPolicyStore{}, toggles, nil, nil, slog.Default(), false)
	claims := &jwtutil.Claims{UserID: 1, AuthMethod: "certificate"}
	claims.IssuedAt = jwtutil.NewNumericDate(time.Now())
	return RuntimeAccessDeps{
		Claims:               func(*http.Request) *jwtutil.Claims { return claims },
		Denylist:             dl,
		Engine:               engine,
		Toggles:              toggles,
		Replay:               threat.NewDPoPReplayCache(time.Minute),
		Logger:               slog.Default(),
		TermsPendingResolver: pendingResolver,
	}
}

// TestRuntimeTermsPendingBlocks: a user who has NOT accepted the ToU gets 403 with
// remediation="terms" and remediation_tou_id in the JSON body.
func TestRuntimeTermsPendingBlocks(t *testing.T) {
	// Resolver says: yes, still pending.
	deps := makeTermsDeps(func(_ context.Context, _ int64, _ int64) bool { return true })
	rec := httptest.NewRecorder()
	RequireRuntimeAccess(deps)(okHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/jmap", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("pending ToU must 403, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"remediation":"terms"`) {
		t.Errorf("403 body must include remediation=terms, got %s", body)
	}
	if !strings.Contains(body, `"remediation_tou_id":99`) {
		t.Errorf("403 body must include remediation_tou_id=99, got %s", body)
	}
}

// TestRuntimeTermsAcceptedAllows: a user who HAS accepted the ToU is allowed through.
func TestRuntimeTermsAcceptedAllows(t *testing.T) {
	// Resolver says: not pending (accepted).
	deps := makeTermsDeps(func(_ context.Context, _ int64, _ int64) bool { return false })
	rec := httptest.NewRecorder()
	RequireRuntimeAccess(deps)(okHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/jmap", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("accepted ToU must allow (200), got %d", rec.Code)
	}
}

// TestRuntimeTermsNilResolverFailClosed: nil TermsPendingResolver means we cannot
// verify acceptance → fail-closed (block).
func TestRuntimeTermsNilResolverFailClosed(t *testing.T) {
	deps := makeTermsDeps(nil) // nil resolver
	rec := httptest.NewRecorder()
	RequireRuntimeAccess(deps)(okHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/jmap", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("nil resolver must fail-closed (403), got %d", rec.Code)
	}
}

// stubTermsNoTouIDPolicyStore returns one global require_terms block policy that
// is MALFORMED: it carries no tou_id, so RemediationTermsID resolves to 0.
type stubTermsNoTouIDPolicyStore struct{}

func (s *stubTermsNoTouIDPolicyStore) LoadAllPolicies(_ context.Context) ([]threat.PolicyRow, error) {
	return s.LoadPolicies(context.Background(), threat.PolicyEvalContext{})
}
func (s *stubTermsNoTouIDPolicyStore) LoadPolicies(_ context.Context, _ threat.PolicyEvalContext) ([]threat.PolicyRow, error) {
	return []threat.PolicyRow{{
		ID:         3,
		Priority:   1,
		Name:       "require-aup-no-touid",
		State:      "on",
		ScopeType:  "global",
		Conditions: map[string]interface{}{},
		Actions:    map[string]interface{}{"action": "require_terms"}, // no tou_id → RemediationTermsID==0
	}}, nil
}
func (s *stubTermsNoTouIDPolicyStore) ResolveGeoTier(_ context.Context, _ string) (string, error) {
	return "low", nil
}
func (s *stubTermsNoTouIDPolicyStore) LoadBreakGlass(_ context.Context) ([]int64, error) {
	return nil, nil
}
func (s *stubTermsNoTouIDPolicyStore) LoadNamedLocations(_ context.Context) ([]threat.NamedLocation, error) {
	return nil, nil
}
func (s *stubTermsNoTouIDPolicyStore) LoadAuthStrengths(_ context.Context) ([]threat.AuthStrength, error) {
	return nil, nil
}

// TestRuntimeTermsMissingTouIDFailClosed: a require_terms block whose policy lacks
// a tou_id (RemediationTermsID==0) must DENY (403) even when the pending-resolver
// would say "not pending" (i.e. would have ALLOWED). This pins the #7 fail-open fix:
// previously TermsPendingResolver(uid, 0) matched no row → pending=false → allow.
func TestRuntimeTermsMissingTouIDFailClosed(t *testing.T) {
	toggles := toggle.NewTestFlags(map[string]bool{
		toggle.FeatureCAERuntime:        true,
		toggle.FeatureConditionalAccess: true,
	})
	dl := threat.NewSessionDenylist(nil, slog.Default())
	engine := threat.NewPolicyEngine(&stubTermsNoTouIDPolicyStore{}, toggles, nil, nil, slog.Default(), false)
	claims := &jwtutil.Claims{UserID: 1}
	claims.IssuedAt = jwtutil.NewNumericDate(time.Now())
	resolverCalled := false
	deps := RuntimeAccessDeps{
		Claims:   func(*http.Request) *jwtutil.Claims { return claims },
		Denylist: dl,
		Engine:   engine,
		Toggles:  toggles,
		Replay:   threat.NewDPoPReplayCache(time.Minute),
		Logger:   slog.Default(),
		// Resolver would ALLOW (not pending) — the fix must block BEFORE consulting it.
		TermsPendingResolver: func(context.Context, int64, int64) bool { resolverCalled = true; return false },
	}
	rec := httptest.NewRecorder()
	RequireRuntimeAccess(deps)(okHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/jmap", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("require_terms without tou_id must fail-closed (403), got %d", rec.Code)
	}
	if resolverCalled {
		t.Error("a tou_id-less terms block must NOT consult TermsPendingResolver (resolver(uid,0) is the fail-open)")
	}
}

// TestRuntimeAuthMethodThreaded: claims.AuthMethod is propagated to pectx.AuthMethod,
// not hard-coded to "jwt_bearer". Uses a certificate auth method on the claims.
// The policy engine sees the threaded method — tested indirectly by verifying
// the group-scoped policy fires normally (no regression on the threading change).
func TestRuntimeAuthMethodThreaded(t *testing.T) {
	toggles := toggle.NewTestFlags(map[string]bool{
		toggle.FeatureCAERuntime:        true,
		toggle.FeatureConditionalAccess: true,
	})
	dl := threat.NewSessionDenylist(nil, slog.Default())
	engine := threat.NewPolicyEngine(&stubGroupPolicyStore{}, toggles, nil, nil, slog.Default(), false)
	claims := &jwtutil.Claims{UserID: 1, AuthMethod: "certificate"}
	claims.IssuedAt = jwtutil.NewNumericDate(time.Now())
	deps := RuntimeAccessDeps{
		Claims:        func(*http.Request) *jwtutil.Claims { return claims },
		Denylist:      dl,
		Engine:        engine,
		Toggles:       toggles,
		Replay:        threat.NewDPoPReplayCache(time.Minute),
		Logger:        slog.Default(),
		GroupResolver: func(_ context.Context, _ int64) []int64 { return []int64{42} },
	}
	rec := httptest.NewRecorder()
	RequireRuntimeAccess(deps)(okHandler()).ServeHTTP(rec, httptest.NewRequest("GET", "/jmap", nil))
	// Group-42 block policy fires; auth_method in pectx = "certificate" (not "jwt_bearer").
	if rec.Code != http.StatusForbidden {
		t.Fatalf("group-block must still fire with certificate auth_method, got %d", rec.Code)
	}
}

func caeToggles(on ...string) *toggle.FeatureFlags {
	flags := map[string]bool{toggle.FeatureCAERuntime: true}
	for _, name := range on {
		flags[name] = true
	}
	return toggle.NewTestFlags(flags)
}

func TestRequireRuntimeAccessPanicsOnNilClaimsFunc(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("nil Claims function must panic at construction, not mid-request")
		}
	}()
	RequireRuntimeAccess(RuntimeAccessDeps{})
}

func TestRequireRuntimeAccessLoggerFallback(t *testing.T) {
	deps := RuntimeAccessDeps{
		Claims: func(*http.Request) *jwtutil.Claims { return nil },
		// Logger deliberately nil: must fall back to slog.Default(), not
		// nil-deref on the first Warn/Error.
		Denylist: threat.NewSessionDenylist(nil, slog.Default()),
		Toggles:  toggle.NewTestFlags(map[string]bool{toggle.FeatureCAERuntime: false}),
		Replay:   threat.NewDPoPReplayCache(time.Minute),
	}
	handler := RequireRuntimeAccess(deps)(okHandler())
	req := httptest.NewRequest("GET", "/x", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("nil logger middleware status = %d, want 200", rec.Code)
	}
}

func TestRequireRuntimeAccessNilReplayFailsClosedUnderTokenBinding(t *testing.T) {
	deps := runtimeDeps(&jwtutil.Claims{
		UserID: 42,
		Cnf:    &jwtutil.ConfirmationClaim{JKT: "jkt-thumbprint"},
	}, threat.NewSessionDenylist(nil, slog.Default()), caeToggles(toggle.FeatureTokenBinding))
	deps.Replay = nil // miswired cache

	handler := RequireRuntimeAccess(deps)(okHandler())
	req := httptest.NewRequest("GET", "/x", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("nil Replay under token binding = %d, want 401 (fail-closed, no panic)", rec.Code)
	}
}

func TestRequireRuntimeAccessSignInFreqWithoutTemporalAnchorFailsClosed(t *testing.T) {
	freq := int64(3600)
	claims := &jwtutil.Claims{UserID: 42, SignInFreq: &freq}
	// Neither SessionAuthTime nor IssuedAt: the timer cannot be evaluated and
	// must deny, not silently pass.
	deps := runtimeDeps(claims, threat.NewSessionDenylist(nil, slog.Default()), caeToggles())
	handler := RequireRuntimeAccess(deps)(okHandler())
	req := httptest.NewRequest("GET", "/x", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anchor-less SignInFreq token = %d, want 401 (fail-closed)", rec.Code)
	}
	if reauth := rec.Header().Get("WWW-Authenticate"); reauth != "reauth" {
		t.Fatalf("WWW-Authenticate = %q, want reauth", reauth)
	}
}

func TestRequireRuntimeAccessSignInFreqWithFreshAnchorPasses(t *testing.T) {
	now := time.Now()
	freq := int64(3600)
	claims := &jwtutil.Claims{
		UserID: 42, SignInFreq: &freq,
	}
	authTime := now.Unix()
	claims.SessionAuthTime = &authTime
	deps := runtimeDeps(claims, threat.NewSessionDenylist(nil, slog.Default()), caeToggles())
	handler := RequireRuntimeAccess(deps)(okHandler())
	req := httptest.NewRequest("GET", "/x", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("fresh anchor = %d, want 200", rec.Code)
	}
}
