package handlers

// mfa_possession_test.go — the C1 possession-proof issuance family
// (possession scheme v7 §3/§3.2, §4.2).
//
// Covered:
//   - TestPossessionEndpointsAdmission: the §3.2 T1/T2 wire contract — 401
//     with nothing presented, bearer-first precedence, stale-cookie
//     fall-through to a valid mfa_token member, access-typed member tokens
//     refused, strict application/json (415), scope/operation parity,
//     target_ref rules, C2/C3 refusals naming the password path.
//   - TestLockedFinishRefusesBothAssertionKinds: a locked webauthn_uv budget
//     refuses finish 429 WITHOUT evaluating the assertion and WITHOUT
//     consuming the ceremony (the v7 corrected §1.7/§3.2 order).
//   - TestForeignOriginCannotReplaceAssertionCeremony: the r5 CSRF closure —
//     foreign-origin begins cannot delete/replace a live ceremony; positive
//     controls for same-origin replace and the headerless native passthrough.
//   - TestTargetedRevocationBindingAtIssuance: revoke targets bind AT
//     ISSUANCE on every applicable issuer, with the single 400 invalid_target
//     refusal shape and the ownership SELECT scoped to the admission user.
//   - TestBearerOnlyWebAuthnRegisterRefused, TestWrongTargetRefusedAtDelete,
//     TestCrossAccountCeremonyRefused, TestNativeDeviceRegisterGated,
//     TestImpersonationRefusedAtPossessionEndpoints, and the generation-kill
//     propagation (§1.8).
//
// NOT covered here (needs a software WebAuthn authenticator; recorded in the
// task report): cryptographically valid UV assertions through finish — the
// finish path past verification (grant issuance halves) is exercised by the
// mfa_pending C1 bootstrap flow only at the storage layer.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"fmt"
	"net/http"
	"net/http/httptest"
	"setjoin.com/authserver/internal/authn"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/middleware"
	"setjoin.com/shared/pwhash"
)

func newPossessionHarness(t *testing.T) *AuthHandler {
	t.Helper()
	pool := enrollmentHandlerPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	passkey, err := authn.NewPasskeyProvider(pool, "localhost", "SetJoin", "http://localhost:8080")
	if err != nil {
		t.Fatalf("build passkey provider: %v", err)
	}
	return NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger(), Passkey: passkey})
}

// seedUVPasskey inserts a live UV-capable credential (C1 classification).
func seedUVPasskey(t *testing.T, h *AuthHandler, userID int64, idHex string, uv bool) []byte {
	t.Helper()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("credential id entropy: %v", err)
	}
	if idHex != "" {
		raw, _ = base64.RawURLEncoding.DecodeString(idHex)
	}
	pub := make([]byte, 64)
	if _, err := rand.Read(pub); err != nil {
		t.Fatalf("public key entropy: %v", err)
	}
	if _, err := h.pool.Exec(context.Background(),
		`INSERT INTO passkey_credentials (id, user_id, public_key, attestation_type, sign_count, uv_capable)
		 VALUES ($1, $2, $3, 'none', 0, $4)`, raw, userID, pub, uv,
	); err != nil {
		t.Fatalf("seed passkey credential: %v", err)
	}
	return raw
}

func newPossessionUser(t *testing.T, h *AuthHandler, label string, uvPasskey bool) (int64, *token.Claims) {
	t.Helper()
	pool := h.pool
	userID := seedLocalUser(t, pool, fmt.Sprintf("poss-%s-%d@example.test", label, time.Now().UnixNano()))
	if uvPasskey {
		seedUVPasskey(t, h, userID, "", true)
	}
	return userID, removalClaims(userID, "poss-jti-"+fmt.Sprint(userID))
}

// postPossession posts a JSON body with optional headers, bypassing the mux.
func postPossession(h *AuthHandler, path string, payload map[string]any, headers map[string]string, claims *token.Claims) *httptest.ResponseRecorder {
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if claims != nil {
		req = req.WithContext(ContextWithUser(req.Context(), claims))
	}
	rr := httptest.NewRecorder()
	switch path {
	case "/auth/mfa/possession/totp":
		h.MFAPossessionTOTP(rr, req)
	case "/auth/mfa/possession/webauthn/begin":
		h.MFAPossessionWebAuthnBegin(rr, req)
	case "/auth/mfa/possession/webauthn/finish":
		h.MFAPossessionWebAuthnFinish(rr, req)
	case "/auth/mfa/reauth":
		h.MFAReauthBegin(rr, req)
	default:
		panic("unknown path " + path)
	}
	return rr
}

// TestPossessionEndpointsAdmission is the v7 §4.2 named test: the §3.2 T1/T2
// wire contract across the three possession endpoints.
func TestPossessionEndpointsAdmission(t *testing.T) {
	h := newPossessionHarness(t)
	jwtP := h.jwt

	t.Run("nothing presented at begin: 401", func(t *testing.T) {
		rr := postPossession(h, "/auth/mfa/possession/webauthn/begin",
			map[string]any{"operation": "recovery.regenerate"}, nil, nil)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d body %s, want 401", rr.Code, rr.Body.String())
		}
	})

	t.Run("access-typed token in the mfa_token member: 401 (type parity)", func(t *testing.T) {
		access, err := jwtP.IssueAccess(42, "x@example.test", false)
		if err != nil {
			t.Fatalf("issue access: %v", err)
		}
		rr := postPossession(h, "/auth/mfa/possession/webauthn/begin",
			map[string]any{"operation": "recovery.regenerate", "mfa_token": access}, nil, nil)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d body %s, want 401 (an access token never substitutes for the bearer)", rr.Code, rr.Body.String())
		}
	})

	t.Run("bearer-first precedence: member ignored under a valid bearer", func(t *testing.T) {
		userID, claims := newPossessionUser(t, h, "prec", true)
		bearer, err := jwtP.IssueAccess(userID, claims.Email, false)
		if err != nil {
			t.Fatalf("issue bearer: %v", err)
		}
		// A garbage mfa_token member MUST be ignored, not fall through.
		rr := postPossession(h, "/auth/mfa/possession/webauthn/begin",
			map[string]any{"operation": "recovery.regenerate", "mfa_token": "garbage"},
			map[string]string{"Authorization": "Bearer " + bearer}, nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d body %s, want 200 (session admission; member ignored)", rr.Code, rr.Body.String())
		}
		var row struct {
			scope string
		}
		if err := h.pool.QueryRow(context.Background(),
			`SELECT token_scope FROM webauthn_ceremonies WHERE user_id = $1`, userID,
		).Scan(&row.scope); err != nil || row.scope != "session" {
			t.Fatalf("ceremony scope = %q (%v), want session", row.scope, err)
		}
	})

	t.Run("stale cookie falls through to a valid mfa_token member (Mode B)", func(t *testing.T) {
		userID, _ := newPossessionUser(t, h, "fallthrough", true)
		pending, err := jwtP.IssueMFAPending(userID, "fallthrough@example.test")
		if err != nil {
			t.Fatalf("issue mfa_pending: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/auth/mfa/possession/webauthn/begin",
			strings.NewReader(`{"operation":"bootstrap.totp.enroll","mfa_token":"`+pending+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "access_token", Value: "stale-invalid-cookie"})
		rr := httptest.NewRecorder()
		h.MFAPossessionWebAuthnBegin(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d body %s, want 200 (the normal pre-session bootstrap state)", rr.Code, rr.Body.String())
		}
		pendingClaims, err := jwtP.Validate(pending)
		if err != nil {
			t.Fatalf("validate pending: %v", err)
		}
		var jti string
		if err := h.pool.QueryRow(context.Background(),
			`SELECT session_jti FROM webauthn_ceremonies WHERE user_id = $1`, userID,
		).Scan(&jti); err != nil || jti != pendingClaims.JTI {
			t.Fatalf("ceremony jti = %q (%v), want the pending JTI", jti, err)
		}
	})

	t.Run("strict media type: missing or non-JSON Content-Type is 415", func(t *testing.T) {
		for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded"} {
			req := httptest.NewRequest(http.MethodPost, "/auth/mfa/possession/webauthn/begin",
				strings.NewReader(`{"operation":"recovery.regenerate"}`))
			if ct != "" {
				req.Header.Set("Content-Type", ct)
			}
			rr := httptest.NewRecorder()
			RequireJSONContentType(http.HandlerFunc(h.MFAPossessionWebAuthnBegin)).ServeHTTP(rr, req)
			if rr.Code != http.StatusUnsupportedMediaType {
				t.Fatalf("Content-Type %q: status = %d, want 415", ct, rr.Code)
			}
			if !strings.Contains(rr.Body.String(), "unsupported_media_type") {
				t.Fatalf("body %s missing the 415 slug", rr.Body.String())
			}
		}
	})

	t.Run("scope/operation parity", func(t *testing.T) {
		userID, claims := newPossessionUser(t, h, "parity", true)
		pending, err := jwtP.IssueMFAPending(userID, claims.Email)
		if err != nil {
			t.Fatalf("issue mfa_pending: %v", err)
		}
		// mfa_pending + non-bootstrap operation → 400 invalid_operation.
		rr := postPossession(h, "/auth/mfa/possession/webauthn/begin",
			map[string]any{"operation": "recovery.regenerate", "mfa_token": pending}, nil, nil)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid_operation") {
			t.Fatalf("status = %d body %s, want 400 invalid_operation", rr.Code, rr.Body.String())
		}
		// Session bearer + bootstrap operation → 400 invalid_operation.
		bearer, err := jwtP.IssueAccess(userID, claims.Email, false)
		if err != nil {
			t.Fatalf("issue bearer: %v", err)
		}
		rr = postPossession(h, "/auth/mfa/possession/webauthn/begin",
			map[string]any{"operation": "bootstrap.totp.enroll"},
			map[string]string{"Authorization": "Bearer " + bearer}, nil)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid_operation") {
			t.Fatalf("status = %d body %s, want 400 invalid_operation", rr.Code, rr.Body.String())
		}
	})

	t.Run("begin without operation: 400 (after a valid admission)", func(t *testing.T) {
		userID, claims := newPossessionUser(t, h, "noop", true)
		bearer, err := jwtP.IssueAccess(userID, claims.Email, false)
		if err != nil {
			t.Fatalf("issue bearer: %v", err)
		}
		rr := postPossession(h, "/auth/mfa/possession/webauthn/begin",
			map[string]any{}, map[string]string{"Authorization": "Bearer " + bearer}, nil)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid_operation") {
			t.Fatalf("status = %d body %s, want 400 invalid_operation", rr.Code, rr.Body.String())
		}
	})

	t.Run("target_ref rules at begin", func(t *testing.T) {
		userID, claims := newPossessionUser(t, h, "target", true)
		bearer, err := jwtP.IssueAccess(userID, claims.Email, false)
		if err != nil {
			t.Fatalf("issue bearer: %v", err)
		}
		hdr := map[string]string{"Authorization": "Bearer " + bearer}
		// webauthn.revoke WITHOUT target_ref → 400.
		rr := postPossession(h, "/auth/mfa/possession/webauthn/begin",
			map[string]any{"operation": "webauthn.revoke"}, hdr, nil)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid_target") {
			t.Fatalf("status = %d body %s, want 400 invalid_target", rr.Code, rr.Body.String())
		}
		// target_ref on a target-less operation → 400.
		rr = postPossession(h, "/auth/mfa/possession/webauthn/begin",
			map[string]any{"operation": "recovery.regenerate", "target_ref": "AAAA"}, hdr, nil)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid_target") {
			t.Fatalf("status = %d body %s, want 400 invalid_target", rr.Code, rr.Body.String())
		}
		// malformed target_ref → 400 invalid_target (single refusal shape).
		rr = postPossession(h, "/auth/mfa/possession/webauthn/begin",
			map[string]any{"operation": "webauthn.revoke", "target_ref": "!!!not-base64url!!!"}, hdr, nil)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid_target") {
			t.Fatalf("status = %d body %s, want 400 invalid_target", rr.Code, rr.Body.String())
		}
	})

	t.Run("non-C1 cohort at begin: 403 possession_proof_required", func(t *testing.T) {
		userID, claims := newPossessionUser(t, h, "c2", false)
		// C2: push-only factor holder.
		if _, err := h.pool.Exec(context.Background(),
			`UPDATE users SET push_mfa_enabled = TRUE WHERE id = $1`, userID); err != nil {
			t.Fatalf("seed push factor: %v", err)
		}
		bearer, err := jwtP.IssueAccess(userID, claims.Email, false)
		if err != nil {
			t.Fatalf("issue bearer: %v", err)
		}
		rr := postPossession(h, "/auth/mfa/possession/webauthn/begin",
			map[string]any{"operation": "recovery.regenerate"},
			map[string]string{"Authorization": "Bearer " + bearer}, nil)
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), PossessionRequiredCode) {
			t.Fatalf("status = %d body %s, want 403 %s", rr.Code, rr.Body.String(), PossessionRequiredCode)
		}
	})

	t.Run("possession/totp for a C3 account: 403 naming the password path", func(t *testing.T) {
		_, claims := newPossessionUser(t, h, "c3", false)
		rr := postPossession(h, "/auth/mfa/possession/totp",
			map[string]any{"operation": "recovery.regenerate", "code": "123456"}, nil, claims)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d body %s, want 403", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), MFAReauthChallengePath) || strings.Contains(rr.Body.String(), ReauthRequiredCode) {
			t.Fatalf("refusal %s must name the PASSWORD path, not reauth_required", rr.Body.String())
		}
	})
}

// TestLockedFinishRefusesBothAssertionKinds is the v7-named acceptance case:
// with the webauthn_uv budget locked, finish answers 429 WITHOUT evaluating
// the assertion (valid and invalid assertions are refused alike) and the
// ceremony row is NOT consumed — the §1.7 guard fails, state stays
// CEREMONY_LIVE.
func TestLockedFinishRefusesBothAssertionKinds(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUser(t, h, "locked", true)
	// The finish endpoint resolves admission from the WIRE (dual admission),
	// so present a real bearer and bind the fixture ceremony to ITS jti.
	bearer, err := h.jwt.IssueAccess(userID, claims.Email, false)
	if err != nil {
		t.Fatalf("issue bearer: %v", err)
	}
	bearerClaims, err := h.jwt.Validate(bearer)
	if err != nil {
		t.Fatalf("validate bearer: %v", err)
	}

	// A live management-assertion ceremony for the session (fixture — the
	// begin arm created it under the same invariants).
	if _, err := h.pool.Exec(context.Background(),
		`INSERT INTO webauthn_ceremonies
		   (challenge_hash, user_id, kind, operation, target_ref, session_jti, token_scope, refresh_family_id, expires_at)
		 VALUES ('locked-chash', $1, 'management_assertion', 'recovery.regenerate', NULL, $2, 'session', NULL, now() + interval '5 minutes')`,
		userID, bearerClaims.JTI); err != nil {
		t.Fatalf("seed ceremony: %v", err)
	}
	// Lock the webauthn_uv budget.
	if _, err := h.pool.Exec(context.Background(),
		`UPDATE users SET possession_webauthn_failed_attempts = 5,
		                  possession_webauthn_locked_until = now() + interval '15 minutes'
		  WHERE id = $1`, userID); err != nil {
		t.Fatalf("lock budget: %v", err)
	}

	for name, body := range map[string]string{
		"invalid assertion":  `{"operation":"recovery.regenerate","not":"an assertion"}`,
		"assertion-ish body": `{"operation":"recovery.regenerate","id":"AA","response":{}}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/auth/mfa/possession/webauthn/finish",
			strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+bearer)
		rr := httptest.NewRecorder()
		h.MFAPossessionWebAuthnFinish(rr, req)
		if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("%s: status = %d body %s, want 429", name, rr.Code, rr.Body.String())
		}
		// The ceremony row is NOT consumed.
		var live bool
		if err := h.pool.QueryRow(context.Background(),
			`SELECT EXISTS (SELECT 1 FROM webauthn_ceremonies WHERE challenge_hash = 'locked-chash')`,
		).Scan(&live); err != nil || !live {
			t.Fatalf("%s: ceremony consumed by a locked refusal (%v)", name, err)
		}
	}
}

// TestForeignOriginCannotReplaceAssertionCeremony is the r5 finding 2 closure
// (v7 §4.2): foreign-origin begins cannot delete or replace a live
// management-assertion ceremony, with positive controls for both admission
// modes' documented behavior.
func TestForeignOriginCannotReplaceAssertionCeremony(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUser(t, h, "csrf", true)
	bearer, err := h.jwt.IssueAccess(userID, claims.Email, false)
	if err != nil {
		t.Fatalf("issue bearer: %v", err)
	}
	// The begin handler behind the CSRF middleware (the v7 mount).
	csrfBegin := middleware.CSRF(RequireJSONContentType(http.HandlerFunc(h.MFAPossessionWebAuthnBegin)))

	post := func(headers map[string]string, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/auth/mfa/possession/webauthn/begin", strings.NewReader(body))
		req.Host = "example.test" // the client-facing host the Origin tuple compares against
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rr := httptest.NewRecorder()
		csrfBegin.ServeHTTP(rr, req)
		return rr
	}
	sameOrigin := map[string]string{
		"Content-Type":  "application/json",
		"Origin":        "http://example.test",
		"Authorization": "Bearer " + bearer,
	}

	// C₁: the victim's live ceremony.
	rr := post(sameOrigin, `{"operation":"recovery.regenerate"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("same-origin begin (positive control): status = %d body %s", rr.Code, rr.Body.String())
	}
	var originalHash string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT challenge_hash FROM webauthn_ceremonies WHERE user_id = $1`, userID,
	).Scan(&originalHash); err != nil {
		t.Fatalf("read ceremony: %v", err)
	}

	// (a) A foreign-origin request carrying the victim's ambient cookie: the
	// middleware denies (403 csrf_failed) and C₁ is STILL LIVE — nothing
	// deleted or replaced.
	foreign := map[string]string{
		"Content-Type": "application/json",
		"Origin":       "https://evil.example",
		"Cookie":       "access_token=" + bearer,
	}
	rr = post(foreign, `{"operation":"recovery.regenerate"}`)
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "csrf_failed") {
		t.Fatalf("(a) status = %d body %s, want 403 csrf_failed", rr.Code, rr.Body.String())
	}
	var stillHash string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT challenge_hash FROM webauthn_ceremonies WHERE user_id = $1`, userID,
	).Scan(&stillHash); err != nil || stillHash != originalHash {
		t.Fatalf("(a) ceremony replaced by a foreign origin: %q vs %q (%v)", stillHash, originalHash, err)
	}

	// (b) Origin/Referer absent + Sec-Fetch-Site: cross-site → 403, C₁ live.
	crossSite := map[string]string{
		"Content-Type":   "application/json",
		"Sec-Fetch-Site": "cross-site",
		"Cookie":         "access_token=" + bearer,
	}
	rr = post(crossSite, `{"operation":"recovery.regenerate"}`)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("(b) status = %d body %s, want 403", rr.Code, rr.Body.String())
	}
	if err := h.pool.QueryRow(context.Background(),
		`SELECT challenge_hash FROM webauthn_ceremonies WHERE user_id = $1`, userID,
	).Scan(&stillHash); err != nil || stillHash != originalHash {
		t.Fatalf("(b) ceremony replaced: %q vs %q", stillHash, originalHash)
	}

	// (c) The same foreign-origin request admitted by a presented mfa_token:
	// the middleware is admission-agnostic — 403.
	pending, err := h.jwt.IssueMFAPending(userID, claims.Email)
	if err != nil {
		t.Fatalf("issue mfa_pending: %v", err)
	}
	rr = post(map[string]string{
		"Content-Type": "application/json",
		"Origin":       "https://evil.example",
	}, `{"operation":"bootstrap.totp.enroll","mfa_token":"`+pending+`"}`)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("(c) status = %d body %s, want 403 (admission-agnostic CSRF)", rr.Code, rr.Body.String())
	}

	// Positive control: the SAME-ORIGIN begin MAY replace C₁ (delete-prior).
	rr = post(sameOrigin, `{"operation":"recovery.regenerate"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("same-origin replace: status = %d body %s", rr.Code, rr.Body.String())
	}
	var replacedHash string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT challenge_hash FROM webauthn_ceremonies WHERE user_id = $1`, userID,
	).Scan(&replacedHash); err != nil || replacedHash == originalHash {
		t.Fatalf("legitimate replace did not rotate the ceremony: %q vs %q", replacedHash, originalHash)
	}

	// Positive control: the headerless native mfa_token begin passes via the
	// documented passthrough (no Origin/Referer/Sec-Fetch-Site at all).
	nativePending, err := h.jwt.IssueMFAPending(userID, claims.Email)
	if err != nil {
		t.Fatalf("issue native mfa_pending: %v", err)
	}
	rr = post(map[string]string{"Content-Type": "application/json"},
		`{"operation":"bootstrap.totp.enroll","mfa_token":"`+nativePending+`"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("headerless native Mode B begin: status = %d body %s, want 200 (passthrough)", rr.Code, rr.Body.String())
	}
}

// TestTargetedRevocationBindingAtIssuance covers the v6/r5 binding contract
// at the issuance surfaces, plus the v7 §3.2 T3.4 assertion-pair subtests
// (opus r1 finding 2): begin binds the target on the CEREMONY row, finish
// re-derives it and RE-VALIDATES ownership+live INSIDE the fenced finish
// transaction.
func TestTargetedRevocationBindingAtIssuance(t *testing.T) {
	h := newPossessionHarness(t)

	t.Run("password path binds the target and the DELETE consumes it", func(t *testing.T) {
		userID, claims := newPossessionUser(t, h, "revpwd", false)
		credID := seedUVPasskey(t, h, userID, "", false)
		target := base64.RawURLEncoding.EncodeToString(credID)
		password := "correct-horse-battery"
		if err := h.pool.QueryRow(context.Background(),
			`UPDATE users SET password_hash = $1 WHERE id = $2 RETURNING password_hash`,
			mustHash(t, password), userID,
		).Scan(new(string)); err != nil {
			t.Fatalf("seed password: %v", err)
		}
		// C2 password grant with the revoke target bound AT ISSUANCE.
		rr := postPossession(h, "/auth/mfa/reauth",
			map[string]any{"operation": "webauthn.revoke", "password": password, "target_ref": target},
			nil, claims)
		if rr.Code != http.StatusOK {
			t.Fatalf("reauth status = %d body %s", rr.Code, rr.Body.String())
		}
		var out struct {
			ReauthToken string `json:"reauth_token"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		var op string
		var targetRef *string
		if err := h.pool.QueryRow(context.Background(),
			`SELECT operation, target_ref FROM mfa_reauth_step_ups WHERE user_id = $1`, userID,
		).Scan(&op, &targetRef); err != nil || op != "webauthn.revoke" || targetRef == nil || *targetRef != target {
			t.Fatalf("grant = {%q %v} (%v), want {webauthn.revoke %s}", op, targetRef, err, target)
		}
		// The DELETE consumes the grant byte-bound to {id}.
		del := httptest.NewRequest(http.MethodDelete, "/auth/webauthn/credential/"+target, nil)
		del.SetPathValue("id", target)
		del.Header.Set(ReauthTokenHeader, out.ReauthToken)
		del = del.WithContext(ContextWithUser(del.Context(), claims))
		drr := httptest.NewRecorder()
		h.WebAuthnRevokeCredential(drr, del)
		if drr.Code != http.StatusNoContent {
			t.Fatalf("delete status = %d body %s, want 204", drr.Code, drr.Body.String())
		}
		var revoked bool
		if err := h.pool.QueryRow(context.Background(),
			`SELECT revoked_at IS NOT NULL FROM passkey_credentials WHERE user_id = $1`, userID,
		).Scan(&revoked); err != nil || !revoked {
			t.Fatalf("credential not revoked (%v)", err)
		}
		var gen int64
		if err := h.pool.QueryRow(context.Background(),
			`SELECT factor_generation FROM users WHERE id = $1`, userID,
		).Scan(&gen); err != nil || gen != 1 {
			t.Fatalf("factor_generation = %d (%v), want 1 (the revocation bump)", gen, err)
		}
	})

	t.Run("ownership SELECT is user-scoped: foreign and revoked targets refuse", func(t *testing.T) {
		owner, _ := newPossessionUser(t, h, "revown", false)
		seedUVPasskey(t, h, owner, "", false)
		attacker, attackerClaims := newPossessionUser(t, h, "revatk", false)
		// The attacker holds one LIVE credential of their own...
		ownLive := seedUVPasskey(t, h, attacker, "", false)
		// ...and one REVOKED one.
		ownRevoked := seedUVPasskey(t, h, attacker, "", false)
		if _, err := h.pool.Exec(context.Background(),
			`UPDATE passkey_credentials SET revoked_at = now() WHERE id = $1`, ownRevoked); err != nil {
			t.Fatalf("revoke fixture: %v", err)
		}
		password := "correct-horse-battery"
		if _, err := h.pool.Exec(context.Background(),
			`UPDATE users SET password_hash = $1 WHERE id = $2`, mustHash(t, password), attacker); err != nil {
			t.Fatalf("seed password: %v", err)
		}
		// The FOREIGN credential id, presented by the attacker → 400.
		foreign := base64.RawURLEncoding.EncodeToString(seedForeignID(t, h, owner))
		rr := postPossession(h, "/auth/mfa/reauth",
			map[string]any{"operation": "webauthn.revoke", "password": password, "target_ref": foreign},
			nil, attackerClaims)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid_target") {
			t.Fatalf("foreign target: status = %d body %s, want 400 invalid_target", rr.Code, rr.Body.String())
		}
		// The attacker's OWN REVOKED credential refuses with the SAME shape.
		rr = postPossession(h, "/auth/mfa/reauth",
			map[string]any{"operation": "webauthn.revoke", "password": password, "target_ref": base64.RawURLEncoding.EncodeToString(ownRevoked)},
			nil, attackerClaims)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid_target") {
			t.Fatalf("revoked target: status = %d body %s, want 400 invalid_target", rr.Code, rr.Body.String())
		}
		_ = ownLive
	})

	t.Run("possession/totp binds the target on the C1 totp path", func(t *testing.T) {
		userID, claims := newPossessionUser(t, h, "revtotp", false)
		if _, err := h.pool.Exec(context.Background(),
			`UPDATE users SET totp_enabled = TRUE WHERE id = $1`, userID); err != nil {
			t.Fatalf("seed totp: %v", err)
		}
		credID := seedUVPasskey(t, h, userID, "", false)
		target := base64.RawURLEncoding.EncodeToString(credID)
		// A grant proven by the enabled TOTP (the enabled-secret verify runs
		// against users.totp_secret_enc — fixture an enabled secret).
		if _, err := h.pool.Exec(context.Background(),
			`UPDATE users SET totp_secret_enc = pgp_sym_encrypt($2, current_setting('app.encryption_key'))
			  WHERE id = $1`, userID, removalTestSecret); err != nil {
			t.Fatalf("seed totp secret: %v", err)
		}
		code, err := totp.GenerateCode(removalTestSecret, time.Now())
		if err != nil {
			t.Fatalf("generate code: %v", err)
		}
		rr := postPossession(h, "/auth/mfa/possession/totp",
			map[string]any{"operation": "webauthn.revoke", "code": code, "target_ref": target}, nil, claims)
		if rr.Code != http.StatusOK {
			t.Fatalf("possession/totp status = %d body %s, want 200", rr.Code, rr.Body.String())
		}
		var targetRef *string
		if err := h.pool.QueryRow(context.Background(),
			`SELECT target_ref FROM mfa_reauth_step_ups WHERE user_id = $1`, userID,
		).Scan(&targetRef); err != nil || targetRef == nil || *targetRef != target {
			t.Fatalf("totp grant target = %v (%v), want %s", targetRef, err, target)
		}
	})

	// --- §3.2 T3.4: the assertion-pair subtests (software authenticator) ---
	// The account proves with a UV passkey (the prover) and revokes a
	// DIFFERENT credential (the target). Each subtest owns its harness.
	newRevocationPair := func(t *testing.T, label string) (h2 *AuthHandler, userID int64, auth *softwareAuthenticator, target, bearer string) {
		t.Helper()
		h2 = newPossessionHarness(t)
		var err error
		auth, err = newSoftwareAuthenticator("localhost", "http://localhost:8080")
		if err != nil {
			t.Fatalf("%s: software authenticator: %v", label, err)
		}
		userID, claims0 := newPossessionUserWithEmail(t, h2, label, false)
		email := claims0.Email
		seedEnabledTOTP(t, h2, userID) // C1
		seedAuthenticatorCredential(t, h2, userID, auth, true)
		targetBytes := seedUVPasskey(t, h2, userID, "", false)
		target = base64.RawURLEncoding.EncodeToString(targetBytes)
		bearer, err = h2.jwt.IssueAccess(userID, email, false)
		if err != nil {
			t.Fatalf("%s: issue bearer: %v", label, err)
		}
		return h2, userID, auth, target, bearer
	}

	beginRevoke := func(t *testing.T, h2 *AuthHandler, bearer, target string) string {
		t.Helper()
		br := postPossession(h2, "/auth/mfa/possession/webauthn/begin",
			map[string]any{"operation": "webauthn.revoke", "target_ref": target},
			map[string]string{"Authorization": "Bearer " + bearer}, nil)
		if br.Code != http.StatusOK {
			t.Fatalf("begin status = %d body %s, want 200", br.Code, br.Body.String())
		}
		var options struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
			} `json:"publicKey"`
		}
		if err := json.Unmarshal(br.Body.Bytes(), &options); err != nil || options.PublicKey.Challenge == "" {
			t.Fatalf("begin options %s (%v)", br.Body.String(), err)
		}
		return options.PublicKey.Challenge
	}

	t.Run("assertion pair: begin binds the target, finish copies it to the grant and the DELETE consumes it", func(t *testing.T) {
		h2, userID, auth, target, bearer := newRevocationPair(t, "revpair")
		hdrs := map[string]string{"Authorization": "Bearer " + bearer}

		// Begin binds operation + target on the CEREMONY row (§1.4/§3.2 T3.3).
		challenge := beginRevoke(t, h2, bearer, target)
		var ceremonyOp string
		var ceremonyTarget *string
		if err := h2.pool.QueryRow(context.Background(),
			`SELECT operation, target_ref FROM webauthn_ceremonies WHERE user_id = $1 AND kind = 'management_assertion'`, userID,
		).Scan(&ceremonyOp, &ceremonyTarget); err != nil || ceremonyOp != "webauthn.revoke" || ceremonyTarget == nil || *ceremonyTarget != target {
			t.Fatalf("ceremony = {%q %v} (%v), want {webauthn.revoke %s}", ceremonyOp, ceremonyTarget, err, target)
		}

		// Finish with the UV assertion + the SAME operation/target → the
		// grant carries the ceremony's binding.
		assertion, err := auth.AssertionResponse(challenge, nil)
		if err != nil {
			t.Fatalf("assertion: %v", err)
		}
		fr := postPossessionFinishHdrs(h2, "/auth/mfa/possession/webauthn/finish", assertion,
			map[string]string{"operation": "webauthn.revoke", "target_ref": target}, hdrs)
		if fr.Code != http.StatusOK {
			t.Fatalf("finish status = %d body %s, want 200", fr.Code, fr.Body.String())
		}
		var out struct {
			ReauthToken string `json:"reauth_token"`
		}
		_ = json.Unmarshal(fr.Body.Bytes(), &out)
		var grantOp string
		var grantTarget *string
		var proofMethod string
		var proving []byte
		if err := h2.pool.QueryRow(context.Background(),
			`SELECT operation, target_ref, proof_method, proving_factor_id
			   FROM mfa_reauth_step_ups WHERE user_id = $1`, userID,
		).Scan(&grantOp, &grantTarget, &proofMethod, &proving); err != nil ||
			grantOp != "webauthn.revoke" || grantTarget == nil || *grantTarget != target ||
			proofMethod != "webauthn_uv" || string(proving) != string(auth.credID) {
			t.Fatalf("grant = {%q %v %q %x} (%v), want the ceremony-bound webauthn_uv grant", grantOp, grantTarget, proofMethod, proving, err)
		}

		// The DELETE consumes the grant byte-bound to the same target —
		// presented on the SAME session that proved (the grant's {JTI,
		// family} binding is the bearer's).
		bearerClaims, err := h2.jwt.Validate(bearer)
		if err != nil {
			t.Fatalf("validate bearer: %v", err)
		}
		del := httptest.NewRequest(http.MethodDelete, "/auth/webauthn/credential/"+target, nil)
		del.SetPathValue("id", target)
		del.Header.Set(ReauthTokenHeader, out.ReauthToken)
		del = del.WithContext(ContextWithUser(del.Context(), bearerClaims))
		drr := httptest.NewRecorder()
		h2.WebAuthnRevokeCredential(drr, del)
		if drr.Code != http.StatusNoContent {
			t.Fatalf("delete status = %d body %s, want 204", drr.Code, drr.Body.String())
		}
		if n := countGrantsFor(t, h2, userID); n != 0 {
			t.Fatalf("grant rows = %d after the DELETE, want 0 (consumed)", n)
		}
	})

	t.Run("assertion finish naming another operation than the ceremony: 400 operation_mismatch, no grant", func(t *testing.T) {
		h2, userID, auth, target, bearer := newRevocationPair(t, "revopmis")
		challenge := beginRevoke(t, h2, bearer, target)
		assertion, err := auth.AssertionResponse(challenge, nil)
		if err != nil {
			t.Fatalf("assertion: %v", err)
		}
		fr := postPossessionFinishHdrs(h2, "/auth/mfa/possession/webauthn/finish", assertion,
			map[string]string{"operation": "recovery.regenerate", "target_ref": target},
			map[string]string{"Authorization": "Bearer " + bearer})
		if fr.Code != http.StatusBadRequest || !strings.Contains(fr.Body.String(), "operation_mismatch") {
			t.Fatalf("finish status = %d body %s, want 400 operation_mismatch", fr.Code, fr.Body.String())
		}
		if n := countGrantsFor(t, h2, userID); n != 0 {
			t.Fatalf("operation_mismatch refusal minted %d grant rows", n)
		}
	})

	t.Run("assertion finish naming another target than the ceremony: 400 target_mismatch, no grant", func(t *testing.T) {
		h2, userID, auth, target, bearer := newRevocationPair(t, "revtgtmis")
		otherBytes := seedUVPasskey(t, h2, userID, "", false)
		other := base64.RawURLEncoding.EncodeToString(otherBytes)
		challenge := beginRevoke(t, h2, bearer, target)
		assertion, err := auth.AssertionResponse(challenge, nil)
		if err != nil {
			t.Fatalf("assertion: %v", err)
		}
		fr := postPossessionFinishHdrs(h2, "/auth/mfa/possession/webauthn/finish", assertion,
			map[string]string{"operation": "webauthn.revoke", "target_ref": other},
			map[string]string{"Authorization": "Bearer " + bearer})
		if fr.Code != http.StatusBadRequest || !strings.Contains(fr.Body.String(), "target_mismatch") {
			t.Fatalf("finish status = %d body %s, want 400 target_mismatch", fr.Code, fr.Body.String())
		}
		if n := countGrantsFor(t, h2, userID); n != 0 {
			t.Fatalf("target_mismatch refusal minted %d grant rows", n)
		}
	})

	t.Run("credential revoked between begin and finish: the fenced finish revalidates and refuses, no grant", func(t *testing.T) {
		h2, userID, auth, target, bearer := newRevocationPair(t, "revbtwn")
		challenge := beginRevoke(t, h2, bearer, target)
		// The target dies AFTER begin bound it, BEFORE finish.
		targetBytes, err := base64.RawURLEncoding.DecodeString(target)
		if err != nil {
			t.Fatalf("decode target: %v", err)
		}
		if _, err := h2.pool.Exec(context.Background(),
			`UPDATE passkey_credentials SET revoked_at = now() WHERE id = $1`, targetBytes,
		); err != nil {
			t.Fatalf("revoke fixture: %v", err)
		}
		assertion, err := auth.AssertionResponse(challenge, nil)
		if err != nil {
			t.Fatalf("assertion: %v", err)
		}
		fr := postPossessionFinishHdrs(h2, "/auth/mfa/possession/webauthn/finish", assertion,
			map[string]string{"operation": "webauthn.revoke", "target_ref": target},
			map[string]string{"Authorization": "Bearer " + bearer})
		if fr.Code != http.StatusBadRequest || !strings.Contains(fr.Body.String(), "invalid_target") {
			t.Fatalf("finish status = %d body %s, want 400 invalid_target (§3.2 T3.4 in-tx recheck)", fr.Code, fr.Body.String())
		}
		if n := countGrantsFor(t, h2, userID); n != 0 {
			t.Fatalf("revoked-target finish minted %d grant rows, want 0", n)
		}
		if n := countRegistrationAudits(t, h2, userID); n != 0 {
			t.Fatalf("unexpected audits: %d", n)
		}
	})
}

// TestWrongTargetRefusedAtDelete pins §1.1's byte-equality consumption: a
// webauthn.revoke grant bound to K refuses the DELETE for a different {id},
// and the dead proof is deleted by the mismatch refusal.
func TestWrongTargetRefusedAtDelete(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUser(t, h, "wrongtgt", false)
	seedUVPasskey(t, h, userID, "", false)
	seedUVPasskey(t, h, userID, "", false)
	rows := queryCredTargets(t, h, userID)
	if len(rows) < 2 {
		t.Fatalf("fixture needs two credentials, got %d", len(rows))
	}
	bound, other := rows[0], rows[1]
	tok := seedSessionGrant(t, h, userID, claims.JTI, "webauthn.revoke", &bound, "password", nil)

	del := httptest.NewRequest(http.MethodDelete, "/auth/webauthn/credential/"+other, nil)
	del.SetPathValue("id", other)
	del.Header.Set(ReauthTokenHeader, tok)
	del = del.WithContext(ContextWithUser(del.Context(), claims))
	rr := httptest.NewRecorder()
	h.WebAuthnRevokeCredential(rr, del)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d body %s, want 403 (target mismatch)", rr.Code, rr.Body.String())
	}
	var n int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM mfa_reauth_step_ups WHERE user_id = $1`, userID,
	).Scan(&n); err != nil || n != 0 {
		t.Fatalf("mismatch refusal left the dead grant: %d rows (%v)", n, err)
	}
	var revoked int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM passkey_credentials WHERE user_id = $1 AND revoked_at IS NOT NULL`, userID,
	).Scan(&revoked); err != nil || revoked != 0 {
		t.Fatalf("credential revoked on a mismatched target: %d", revoked)
	}
}

// TestCrossAccountCeremonyRefused: user B's session cannot resolve user A's
// ceremony (the {user, kind, scope, JTI} predicates, §1.4).
func TestCrossAccountCeremonyRefused(t *testing.T) {
	h := newPossessionHarness(t)
	userA, _ := newPossessionUser(t, h, "victim", true)
	userB, claimsB := newPossessionUser(t, h, "attacker", true)
	if _, err := h.pool.Exec(context.Background(),
		`INSERT INTO webauthn_ceremonies
		   (challenge_hash, user_id, kind, operation, session_jti, token_scope, expires_at)
		 VALUES ('victim-chash', $1, 'management_assertion', 'recovery.regenerate', 'victim-jti', 'session', now() + interval '5 minutes')`,
		userA); err != nil {
		t.Fatalf("seed ceremony: %v", err)
	}
	// The finish endpoint resolves admission from the WIRE: B presents a
	// real (valid!) bearer — it just cannot resolve A's ceremony.
	bearerB, err := h.jwt.IssueAccess(userB, claimsB.Email, false)
	if err != nil {
		t.Fatalf("issue bearer B: %v", err)
	}
	rr := postPossession(h, "/auth/mfa/possession/webauthn/finish",
		map[string]any{"operation": "recovery.regenerate"},
		map[string]string{"Authorization": "Bearer " + bearerB}, nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d body %s, want 403 (no ceremony for B)", rr.Code, rr.Body.String())
	}
	var n int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM webauthn_ceremonies WHERE user_id = $1`, userA,
	).Scan(&n); err != nil || n != 1 {
		t.Fatalf("victim ceremony disturbed: %d rows (%v)", n, err)
	}
	_ = userB
}

// TestBearerOnlyWebAuthnRegisterRefused is the owner decision's negative case
// (§4.2): register begin without a live grant answers the typed 403.
func TestBearerOnlyWebAuthnRegisterRefused(t *testing.T) {
	h := newPossessionHarness(t)
	_, claims := newPossessionUser(t, h, "beareronly", true)
	req := httptest.NewRequest(http.MethodGet, "/auth/webauthn/register/begin", nil)
	req = req.WithContext(ContextWithUser(req.Context(), claims))
	rr := httptest.NewRecorder()
	h.WebAuthnRegisterBegin(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("begin status = %d body %s, want 403 reauth_required", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), ReauthRequiredCode) {
		t.Fatalf("body %s missing %q", rr.Body.String(), ReauthRequiredCode)
	}
}

// TestImpersonationRefusedAtPossessionEndpoints: AdminActorID bearers are
// refused unconditionally at issuance AND the gated arms (§1.7 last row).
// The impersonated BEARER rides the wire so the dual-admission endpoints see
// exactly what an impersonated session presents.
func TestImpersonationRefusedAtPossessionEndpoints(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUser(t, h, "imp", true)
	bearer, err := h.jwt.IssueImpersonation(userID, claims.Email, 7, "standard")
	if err != nil {
		t.Fatalf("issue impersonated bearer: %v", err)
	}
	authHdr := map[string]string{"Authorization": "Bearer " + bearer}
	// The parsed-claims shape requireAuth would attach in the context.
	impersonatedClaims := *claims
	admin := int64(7)
	impersonatedClaims.AdminActorID = &admin

	for name, do := range map[string]func() *httptest.ResponseRecorder{
		"reauth": func() *httptest.ResponseRecorder {
			return postPossession(h, "/auth/mfa/reauth",
				map[string]any{"operation": "recovery.regenerate", "password": "x"}, authHdr, &impersonatedClaims)
		},
		"possession/totp": func() *httptest.ResponseRecorder {
			return postPossession(h, "/auth/mfa/possession/totp",
				map[string]any{"operation": "recovery.regenerate", "code": "1"}, authHdr, &impersonatedClaims)
		},
		"begin": func() *httptest.ResponseRecorder {
			return postPossession(h, "/auth/mfa/possession/webauthn/begin",
				map[string]any{"operation": "recovery.regenerate"}, authHdr, nil)
		},
		"finish": func() *httptest.ResponseRecorder {
			return postPossession(h, "/auth/mfa/possession/webauthn/finish",
				map[string]any{"operation": "recovery.regenerate"}, authHdr, nil)
		},
		"backup-codes": func() *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodPost, "/auth/backup-codes/generate", strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(ContextWithUser(req.Context(), &impersonatedClaims))
			rr := httptest.NewRecorder()
			h.GenerateBackupCodes(rr, req)
			return rr
		},
		"device/register native": func() *httptest.ResponseRecorder {
			key, genErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if genErr != nil {
				t.Fatal(genErr)
			}
			body := fmt.Sprintf(`{"provider":"apns","push_token":"tok","device_public_key":%q}`,
				hex.EncodeToString(elliptic.Marshal(elliptic.P256(), key.X, key.Y)))
			req := httptest.NewRequest(http.MethodPost, "/auth/device/register", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(ContextWithUser(req.Context(), &impersonatedClaims))
			rr := httptest.NewRecorder()
			h.DeviceRegister(rr, req)
			return rr
		},
	} {
		rr := do()
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s: status = %d body %s, want 403 (impersonated refusal)", name, rr.Code, rr.Body.String())
		}
	}
	_ = claims
}

// TestNativeDeviceRegisterGated pins the §3 distinction: native providers
// need a grant; the webpush subscription does not.
func TestNativeDeviceRegisterGated(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUser(t, h, "device", false)
	_ = userID

	// webpush: NOT gated.
	webpush := httptest.NewRequest(http.MethodPost, "/auth/device/register",
		strings.NewReader(`{"provider":"webpush","push_token":"{\"endpoint\":\"https://push.example/sub\"}"}`))
	webpush.Header.Set("Content-Type", "application/json")
	webpush = webpush.WithContext(ContextWithUser(webpush.Context(), claims))
	rr := httptest.NewRecorder()
	h.DeviceRegister(rr, webpush)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("webpush register status = %d body %s, want 204 (subscriptions are not gated)", rr.Code, rr.Body.String())
	}

	// native (apns): gated — without a grant, typed 403.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	validKey := hex.EncodeToString(elliptic.Marshal(elliptic.P256(), privKey.X, privKey.Y))
	native := httptest.NewRequest(http.MethodPost, "/auth/device/register",
		strings.NewReader(`{"provider":"apns","push_token":"tok","device_public_key":"`+validKey+`"}`))
	_ = err
	native.Header.Set("Content-Type", "application/json")
	native = native.WithContext(ContextWithUser(native.Context(), claims))
	nrr := httptest.NewRecorder()
	h.DeviceRegister(nrr, native)
	if nrr.Code != http.StatusForbidden {
		t.Fatalf("native register without grant status = %d body %s, want 403 reauth_required", nrr.Code, nrr.Body.String())
	}
	if !strings.Contains(nrr.Body.String(), ReauthRequiredCode) {
		t.Fatalf("body %s missing %q", nrr.Body.String(), ReauthRequiredCode)
	}
}

// TestFirstFactorPasswordGrantInvalidAfterPossessionEnrolls pins §2.5/§1.8:
// a live C3 password grant dies when the account's first possession factor
// is gained (the promotion's generation bump), with the active grant refusing.
func TestFirstFactorPasswordGrantInvalidAfterPossessionEnrolls(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUser(t, h, "c3die", false)
	// Bound the fixture grant to the CURRENT generation.
	var gen int64
	if err := h.pool.QueryRow(context.Background(),
		`SELECT factor_generation FROM users WHERE id = $1`, userID).Scan(&gen); err != nil {
		t.Fatalf("read generation: %v", err)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	sum := sha256SumHex(hexEncode(raw))
	if _, err := h.pool.Exec(context.Background(),
		`INSERT INTO mfa_reauth_step_ups
		   (token_hash, user_id, session_jti, operation, proof_method,
		    bound_factor_generation, token_scope, refresh_family_id, expires_at)
		 VALUES ($1, $2, $3, 'recovery.regenerate', 'password', $4, 'session', NULL, now() + interval '5 minutes')`,
		sum, userID, claims.JTI, gen,
	); err != nil {
		t.Fatalf("seed C3 grant: %v", err)
	}
	// The account gains its first possession factor via the gated promotion
	// (any §1.8 mutation commits G+1).
	if _, err := h.pool.Exec(context.Background(),
		`UPDATE users SET totp_enabled = TRUE, factor_generation = factor_generation + 1 WHERE id = $1`,
		userID); err != nil {
		t.Fatalf("gain factor: %v", err)
	}
	// The old-grant consumption refuses under the fence.
	gr := httptest.NewRequest(http.MethodPost, "/auth/backup-codes/generate", strings.NewReader(`{}`))
	gr.Header.Set("Content-Type", "application/json")
	gr.Header.Set(ReauthTokenHeader, hexEncode(raw))
	gr = gr.WithContext(ContextWithUser(gr.Context(), claims))
	rr := httptest.NewRecorder()
	h.GenerateBackupCodes(rr, gr)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d body %s, want 403 (generation-bumped grant is DEAD)", rr.Code, rr.Body.String())
	}
}

// mustHash hashes a fixture password with the shared pwhash seam.
func mustHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := pwhash.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	return hash
}

// sha256SumHex is the store-side token hash for fixtures.
func sha256SumHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hexEncode(b []byte) string { return hex.EncodeToString(b) }

// seedForeignID seeds a credential owned by userID and returns its raw id.
func seedForeignID(t *testing.T, h *AuthHandler, userID int64) []byte {
	t.Helper()
	return seedUVPasskey(t, h, userID, "", false)
}

// queryCredTargets lists the base64url credential ids of a user's live rows.
func queryCredTargets(t *testing.T, h *AuthHandler, userID int64) []string {
	t.Helper()
	rows, err := h.pool.Query(context.Background(),
		`SELECT id FROM passkey_credentials WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at`, userID)
	if err != nil {
		t.Fatalf("list credentials: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id []byte
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan credential: %v", err)
		}
		out = append(out, base64.RawURLEncoding.EncodeToString(id))
	}
	return out
}

// seedSessionGrant inserts a full session-scope grant fixture and returns the
// raw token to present.
func seedSessionGrant(t *testing.T, h *AuthHandler, userID int64, jti, operation string, target *string, proofMethod string, proving []byte) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("grant entropy: %v", err)
	}
	tok := hexEncode(raw)
	family := any(nil)
	if _, err := h.pool.Exec(context.Background(),
		`DELETE FROM mfa_reauth_step_ups WHERE user_id = $1`, userID); err != nil {
		t.Fatalf("seed grant cleanup: %v", err)
	}
	if _, err := h.pool.Exec(context.Background(),
		`INSERT INTO mfa_reauth_step_ups
		   (token_hash, user_id, session_jti, operation, target_ref,
		    proof_method, proving_factor_id, bound_factor_generation,
		    token_scope, refresh_family_id, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7,
		         (SELECT factor_generation FROM users WHERE id = $2),
		         'session', $8, now() + interval '5 minutes')`,
		sha256SumHex(tok), userID, jti, operation, target,
		proofMethod, proving, family,
	); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	return tok
}
