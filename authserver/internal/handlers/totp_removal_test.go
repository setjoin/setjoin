package handlers

// De-enrollment lifecycle tests for med-webmail-mfa-lifecycle-001
// (D-MAILSERVER-WEBMAIL-SRC-ROUTES-SETTINGS-001).
//
// Covered here, per the package's proposedTests contract:
//
//   - decision-table cases 1 and 2 remove the factor with correct step-up and
//     typed confirmation (password + current TOTP code; password + recovery
//     code when the authenticator is lost);
//   - missing/wrong step-up, a replayed step-up token, a foreign-session
//     token, and a concurrent double-submission are refused with the factor
//     intact;
//   - a missing or invalid CSRF token is refused before the handler runs;
//   - no unauthenticated /auth/totp/remove* route exists: both routes are
//     mounted exactly as authserverd mounts them (requireAuth + CSRF), and
//     the chain refuses unauthenticated calls;
//   - case 3 (authenticator lost, no recovery codes) is refused on the
//     self-service path with the factor intact;
//   - audit events exist for successes and refusals — including authenticated
//     malformed-body attempts, which must never bypass the audit trail — and
//     lockout bookkeeping follows the existing authn failure policy.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"setjoin.com/authserver/internal/token"
	sharedauth "setjoin.com/shared/auth"
	sharedmw "setjoin.com/shared/middleware"
	"setjoin.com/shared/pwhash"
)

// requireRemovalTestAuth mirrors internal/middleware.RequireAuth for these
// tests. The real middleware cannot be imported here (it imports this package
// for ContextWithUser — a test import cycle), so the exact seam sequence is
// composed instead: BearerAuthenticator.Authenticate → ContextWithUser, with
// the same status mapping (ErrWrongTokenType → 403, otherwise 401 with a
// WWW-Authenticate challenge).
func requireRemovalTestAuth(authn sharedauth.Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := authn.Authenticate(r.Context(), r)
			if err != nil {
				if errors.Is(err, token.ErrWrongTokenType) {
					http.Error(w, "Invalid token type", http.StatusForbidden)
					return
				}
				w.Header().Set("WWW-Authenticate", `Bearer realm="authserver"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(ContextWithUser(r.Context(), claims)))
		})
	}
}

// removalTestSecret is a valid base32 TOTP secret; codes are generated from it
// per test.
const removalTestSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

// seedRemovalUser seeds a local user with a working password and, when
// withFactor is set, an ENABLED TOTP factor encrypted under the test key.
// Recovery codes are stored bcrypt-hashed exactly as authn.GenerateBackupCodes
// does. Cleanup of the users row is handled by seedLocalUser.
func seedRemovalUser(
	t *testing.T, pool *pgxpool.Pool, email, password string, withFactor bool, recoveryCodes []string,
) int64 {
	t.Helper()
	userID := seedLocalUser(t, pool, email)
	ctx := context.Background()

	hash, err := pwhash.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if !withFactor {
		if _, err := pool.Exec(ctx,
			`UPDATE users SET password_hash = $1, totp_enabled = FALSE WHERE id = $2`,
			hash, userID); err != nil {
			t.Fatalf("seed removal user: %v", err)
		}
		return userID
	}

	hashedCodes := []string{}
	for _, code := range recoveryCodes {
		h, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.MinCost)
		if err != nil {
			t.Fatalf("hash recovery code: %v", err)
		}
		hashedCodes = append(hashedCodes, string(h))
	}

	if _, err := pool.Exec(ctx,
		`UPDATE users SET password_hash = $1,
		                   totp_secret_enc = pgp_sym_encrypt($2, current_setting('app.encryption_key')),
		                   totp_enabled = TRUE,
		                   totp_enabled_at = now(),
		                   totp_backup_codes_enc = $3
		 WHERE id = $4`,
		hash, removalTestSecret, hashedCodes, userID); err != nil {
		t.Fatalf("seed removal user: %v", err)
	}
	return userID
}

func removalUserState(t *testing.T, pool *pgxpool.Pool, userID int64) (enabled bool, hasSecret bool, codeCount int) {
	t.Helper()
	var secret []byte
	var codes []string
	if err := pool.QueryRow(context.Background(),
		`SELECT totp_enabled, totp_secret_enc, COALESCE(totp_backup_codes_enc, '{}')
		   FROM users WHERE id = $1`, userID,
	).Scan(&enabled, &secret, &codes); err != nil {
		t.Fatalf("read user state: %v", err)
	}
	return enabled, secret != nil, len(codes)
}

func removalAuditCount(t *testing.T, pool *pgxpool.Pool, userID int64, action string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_audit_log WHERE user_id = $1 AND action = $2`,
		userID, action,
	).Scan(&n); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return n
}

// removalClaims mints the context claims RequireAuth would attach; jti is the
// access-session binding the step-up token is pinned to.
func removalClaims(userID int64, jti string) *token.Claims {
	return &token.Claims{
		UserID: userID,
		Email:  fmt.Sprintf("u%d@example.test", userID),
		Type:   token.TypeAccess,
		JTI:    jti,
	}
}

// postRemoval posts JSON to a removal handler with authenticated claims in the
// request context (the middleware-attached shape), bypassing the mux wrappers.
func postRemoval(
	t *testing.T, path string, payload map[string]any, claims *token.Claims, handler http.HandlerFunc,
) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal %s payload: %v", path, err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if claims != nil {
		req = req.WithContext(ContextWithUser(req.Context(), claims))
	}
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

// postRemovalRaw posts a raw (not necessarily valid JSON) body to a removal
// handler with authenticated claims in the request context — the malformed-body
// ingress cases postRemoval's marshalled payloads cannot express.
func postRemovalRaw(
	t *testing.T, path, rawBody string, claims *token.Claims, handler http.HandlerFunc,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(rawBody))
	req.Header.Set("Content-Type", "application/json")
	if claims != nil {
		req = req.WithContext(ContextWithUser(req.Context(), claims))
	}
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

// removalHarness bundles one seeded enabled-factor user with its handlers and
// the session jti the step-up token binds to.
type removalHarness struct {
	t        *testing.T
	pool     *pgxpool.Pool
	beginH   http.HandlerFunc
	confirmH http.HandlerFunc
	userID   int64
	jti      string
}

func newRemovalHarness(t *testing.T, recoveryCodes []string) *removalHarness {
	t.Helper()
	pool := enrollmentHandlerPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	email := fmt.Sprintf("totp-remove-%d@example.test", time.Now().UnixNano())
	userID := seedRemovalUser(t, pool, email, "correct-horse-battery", true, recoveryCodes)
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
	return &removalHarness{
		t:        t,
		pool:     pool,
		beginH:   h.TOTPRemovalBegin,
		confirmH: h.TOTPRemovalConfirm,
		userID:   userID,
		jti:      "sess-" + fmt.Sprint(userID),
	}
}

func (rh *removalHarness) begin(password, code string) (stepUpToken string, status int) {
	rh.t.Helper()
	rec := postRemoval(rh.t, "/auth/totp/remove/begin",
		map[string]any{"password": password, "code": code},
		removalClaims(rh.userID, rh.jti), rh.beginH)
	var out struct {
		StepUpToken string `json:"step_up_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.StepUpToken, rec.Code
}

func (rh *removalHarness) confirm(jti, stepUpToken, confirm string) int {
	rh.t.Helper()
	return postRemoval(rh.t, "/auth/totp/remove",
		map[string]any{"step_up_token": stepUpToken, "confirm": confirm},
		removalClaims(rh.userID, jti), rh.confirmH).Code
}

func (rh *removalHarness) factorIntact() {
	rh.t.Helper()
	enabled, hasSecret, codeCount := removalUserState(rh.t, rh.pool, rh.userID)
	if !enabled || !hasSecret || codeCount == 0 {
		rh.t.Fatalf("factor must remain intact: enabled=%v hasSecret=%v codes=%d", enabled, hasSecret, codeCount)
	}
}

func TestTOTPRemoval_DecisionTable_DB(t *testing.T) {
	t.Run("case 1: password plus current TOTP code removes factor and recovery codes", func(t *testing.T) {
		pool := enrollmentHandlerPool(t)
		ensureEnrollmentLocalDomain(t, pool)
		email := fmt.Sprintf("totp-remove-c1-%d@example.test", time.Now().UnixNano())
		userID := seedRemovalUser(t, pool, email, "correct-horse-battery", true, []string{"aaa11111", "bbb22222"})
		h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
		jti := "sess-case1"

		code, err := totp.GenerateCode(removalTestSecret, time.Now())
		if err != nil {
			t.Fatalf("generate TOTP code: %v", err)
		}
		begin := postRemoval(t, "/auth/totp/remove/begin",
			map[string]any{"password": "correct-horse-battery", "code": code},
			removalClaims(userID, jti), h.TOTPRemovalBegin)
		if begin.Code != http.StatusOK {
			t.Fatalf("begin (case 1) status = %d body %s, want 200", begin.Code, begin.Body.String())
		}
		var beginBody struct {
			StepUpToken string `json:"step_up_token"`
			ExpiresIn   int    `json:"expires_in"`
		}
		if err := json.Unmarshal(begin.Body.Bytes(), &beginBody); err != nil || beginBody.StepUpToken == "" {
			t.Fatalf("begin body = %s (%v), want step_up_token", begin.Body.String(), err)
		}

		confirm := postRemoval(t, "/auth/totp/remove",
			map[string]any{"step_up_token": beginBody.StepUpToken, "confirm": "REMOVE"},
			removalClaims(userID, jti), h.TOTPRemovalConfirm)
		if confirm.Code != http.StatusNoContent {
			t.Fatalf("confirm (case 1) status = %d body %s, want 204", confirm.Code, confirm.Body.String())
		}

		enabled, hasSecret, codeCount := removalUserState(t, pool, userID)
		if enabled || hasSecret || codeCount != 0 {
			t.Fatalf("factor not fully removed: enabled=%v hasSecret=%v codes=%d", enabled, hasSecret, codeCount)
		}
		if got := removalAuditCount(t, pool, userID, "totp_removed"); got != 1 {
			t.Fatalf("totp_removed audit rows = %d, want 1", got)
		}
		if got := removalAuditCount(t, pool, userID, "totp_removal_step_up_authorized"); got != 1 {
			t.Fatalf("step-up audit rows = %d, want 1", got)
		}
	})

	t.Run("case 2: authenticator lost, recovery code steps up", func(t *testing.T) {
		rh := newRemovalHarness(t, []string{"rec99999"})
		tok, status := rh.begin("correct-horse-battery", "rec99999")
		if status != http.StatusOK || tok == "" {
			t.Fatalf("begin (case 2) status = %d token %q, want 200 + token", status, tok)
		}
		if got := rh.confirm(rh.jti, tok, "REMOVE"); got != http.StatusNoContent {
			t.Fatalf("confirm (case 2) status = %d, want 204", got)
		}
		enabled, hasSecret, codeCount := removalUserState(t, rh.pool, rh.userID)
		if enabled || hasSecret || codeCount != 0 {
			t.Fatalf("case 2 factor not fully removed: enabled=%v hasSecret=%v codes=%d", enabled, hasSecret, codeCount)
		}
	})

	t.Run("case 3: authenticator lost, no recovery codes: refused with factor intact", func(t *testing.T) {
		pool := enrollmentHandlerPool(t)
		ensureEnrollmentLocalDomain(t, pool)
		email := fmt.Sprintf("totp-remove-c3-%d@example.test", time.Now().UnixNano())
		userID := seedRemovalUser(t, pool, email, "correct-horse-battery", true, nil)
		h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

		begin := postRemoval(t, "/auth/totp/remove/begin",
			map[string]any{"password": "correct-horse-battery", "code": "000000"},
			removalClaims(userID, "sess-case3"), h.TOTPRemovalBegin)
		if begin.Code != http.StatusUnauthorized {
			t.Fatalf("begin (case 3) status = %d, want 401 refusal", begin.Code)
		}
		enabled, hasSecret, _ := removalUserState(t, pool, userID)
		if !enabled || !hasSecret {
			t.Fatalf("case 3 factor must stay intact: enabled=%v hasSecret=%v", enabled, hasSecret)
		}
		if got := removalAuditCount(t, pool, userID, "totp_removal_step_up_refused"); got != 1 {
			t.Fatalf("case 3 refusal audit rows = %d, want 1", got)
		}
	})
}

func TestTOTPRemoval_RefusalsKeepFactor_DB(t *testing.T) {
	rh := newRemovalHarness(t, []string{"rec77777"})

	// Wrong password never reaches the factor decision.
	if _, status := rh.begin("wrong-password", "anything"); status != http.StatusForbidden {
		t.Fatalf("wrong password status = %d, want 403", status)
	}
	rh.factorIntact()

	// Wrong typed confirmation: refused, factor intact.
	tokGood, status := rh.begin("correct-horse-battery", "rec77777")
	if status != http.StatusOK {
		t.Fatalf("begin with recovery code status = %d, want 200", status)
	}
	if got := rh.confirm(rh.jti, tokGood, "remove"); got != http.StatusBadRequest {
		t.Fatalf("mistyped confirmation status = %d, want 400", got)
	}
	rh.factorIntact()

	// Missing step-up token.
	if got := rh.confirm(rh.jti, "", "REMOVE"); got != http.StatusForbidden {
		t.Fatalf("missing step-up token status = %d, want 403", got)
	}
	rh.factorIntact()

	// Garbage step-up token.
	if got := rh.confirm(rh.jti, "not-a-token", "REMOVE"); got != http.StatusForbidden {
		t.Fatalf("garbage step-up token status = %d, want 403", got)
	}
	rh.factorIntact()

	// Foreign-session token: issued on rh.jti, consumed on another session.
	tokSession, _ := rh.begin("correct-horse-battery", "rec77777")
	if got := rh.confirm("other-session", tokSession, "REMOVE"); got != http.StatusForbidden {
		t.Fatalf("foreign-session step-up token status = %d, want 403", got)
	}
	rh.factorIntact()

	// Replay: first successful removal consumes the token; a second use is
	// refused and cannot double-remove anything.
	tokReplay, _ := rh.begin("correct-horse-battery", "rec77777")
	if got := rh.confirm(rh.jti, tokReplay, "REMOVE"); got != http.StatusNoContent {
		t.Fatalf("first confirm status = %d, want 204", got)
	}
	if got := rh.confirm(rh.jti, tokReplay, "REMOVE"); got != http.StatusForbidden {
		t.Fatalf("replayed step-up token status = %d, want 403", got)
	}
	if got := removalAuditCount(t, rh.pool, rh.userID, "totp_removed"); got != 1 {
		t.Fatalf("totp_removed audit rows after replay = %d, want 1", got)
	}

	// Refusals are audited (decision refusals + token refusals).
	if got := removalAuditCount(t, rh.pool, rh.userID, "totp_removal_refused"); got < 3 {
		t.Fatalf("totp_removal_refused audit rows = %d, want >= 3", got)
	}
	if got := removalAuditCount(t, rh.pool, rh.userID, "totp_removal_step_up_refused"); got < 1 {
		t.Fatalf("totp_removal_step_up_refused audit rows = %d, want >= 1", got)
	}
}

func TestTOTPRemoval_LockoutPolicyApplies_DB(t *testing.T) {
	pool := enrollmentHandlerPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	email := fmt.Sprintf("totp-remove-lock-%d@example.test", time.Now().UnixNano())
	userID := seedRemovalUser(t, pool, email, "correct-horse-battery", true, nil)
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	rec := postRemoval(t, "/auth/totp/remove/begin",
		map[string]any{"password": "correct-horse-battery", "code": "000000"},
		removalClaims(userID, "sess-lock"), h.TOTPRemovalBegin)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code status = %d, want 401", rec.Code)
	}
	// The existing authn failure policy must have recorded the attempt.
	var attempts int
	if err := pool.QueryRow(context.Background(),
		`SELECT totp_failed_attempts FROM users WHERE id = $1`, userID).Scan(&attempts); err != nil {
		t.Fatalf("read attempts: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("totp_failed_attempts = %d after one wrong code, want 1 (existing lockout policy)", attempts)
	}
}

func TestTOTPRemoval_UnauthenticatedRouteAbsence_DB(t *testing.T) {
	// No unauthenticated /auth/totp/remove* route exists: both mounts are the
	// exact requireAuth + CSRF chain authserverd registers, and that chain
	// refuses a call with no bearer session before any handler logic runs.
	pool := enrollmentHandlerPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
	jwt := newTestJWT()
	requireAuth := requireRemovalTestAuth(token.NewBearerAuthenticator(jwt))

	mux := http.NewServeMux()
	mux.Handle("POST /auth/totp/remove/begin", requireAuth(sharedmw.CSRF(http.HandlerFunc(h.TOTPRemovalBegin))))
	mux.Handle("POST /auth/totp/remove", requireAuth(sharedmw.CSRF(http.HandlerFunc(h.TOTPRemovalConfirm))))

	for _, path := range []string{"/auth/totp/remove", "/auth/totp/remove/begin"} {
		req := httptest.NewRequest(http.MethodPost, path, http.NoBody)
		req.Header.Set("Origin", "https://mail.example.com")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated POST %s status = %d, want 401", path, rec.Code)
		}
	}
}

func TestTOTPRemoval_CSRFCheckedAtMux_DB(t *testing.T) {
	pool := enrollmentHandlerPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	email := fmt.Sprintf("totp-remove-csrf-%d@example.test", time.Now().UnixNano())
	userID := seedRemovalUser(t, pool, email, "correct-horse-battery", true, []string{"rec55555"})
	jwt := newTestJWT()
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: jwt, Logger: discardLogger()})
	requireAuth := requireRemovalTestAuth(token.NewBearerAuthenticator(jwt))

	// BOTH removal routes are mounted behind the same requireAuth + CSRF chain
	// authserverd registers, and the cross-origin rejection is proven on each
	// of them (A5: the /begin arm alone does not evidence the /remove arm).
	mux := http.NewServeMux()
	mux.Handle("POST /auth/totp/remove/begin", requireAuth(sharedmw.CSRF(http.HandlerFunc(h.TOTPRemovalBegin))))
	mux.Handle("POST /auth/totp/remove", requireAuth(sharedmw.CSRF(http.HandlerFunc(h.TOTPRemovalConfirm))))

	access, err := jwt.IssueAccess(userID, email, false)
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}

	for _, path := range []string{"/auth/totp/remove/begin", "/auth/totp/remove"} {
		// Cross-site Origin: the CSRF middleware must deny before the handler runs.
		req := httptest.NewRequest(http.MethodPost, path, http.NoBody)
		req.Header.Set("Authorization", "Bearer "+access)
		req.Header.Set("Origin", "https://attacker.example.net")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("cross-origin POST %s status = %d body %s, want 403", path, rec.Code, rec.Body.String())
		}

		// Positive control: a same-origin request passes the CSRF fence and
		// reaches the handler (its empty body yields the bounded decoder's 400,
		// not the CSRF 403) — proving the 403s above are the CSRF arm, not the
		// middleware denying everything.
		sameOrigin := httptest.NewRequest(http.MethodPost, path, http.NoBody)
		sameOrigin.Header.Set("Authorization", "Bearer "+access)
		sameOrigin.Header.Set("Origin", "http://"+sameOrigin.Host)
		sameRec := httptest.NewRecorder()
		mux.ServeHTTP(sameRec, sameOrigin)
		if sameRec.Code == http.StatusForbidden {
			t.Fatalf("same-origin POST %s was CSRF-denied; the fence must only reject cross-origin requests", path)
		}
		if sameRec.Code != http.StatusBadRequest {
			t.Fatalf("same-origin POST %s status = %d body %s, want 400 (handler reached, empty body)", path, sameRec.Code, sameRec.Body.String())
		}
	}

	enabled, hasSecret, codeCount := removalUserState(t, pool, userID)
	if !enabled || !hasSecret || codeCount != 1 {
		t.Fatalf("factor must remain intact after CSRF refusals: enabled=%v hasSecret=%v codes=%d", enabled, hasSecret, codeCount)
	}
}

// TestTOTPRemoval_MalformedBodyRefusalsAudited_DB proves the every-attempt
// contract on the ingress edge: an authenticated request whose body fails the
// bounded decode is still a de-enrollment attempt — it must be refused with the
// decoder's 400 AND audited through the same refusal channel, never silently
// dropped before the trail.
func TestTOTPRemoval_MalformedBodyRefusalsAudited_DB(t *testing.T) {
	rh := newRemovalHarness(t, []string{"rec22222"})

	cases := []struct {
		name    string
		body    string
		path    string
		handler http.HandlerFunc
		action  string
	}{
		{"begin truncated JSON", `{"password":"x"`, "/auth/totp/remove/begin", rh.beginH, "totp_removal_step_up_refused"},
		{"begin empty body", "", "/auth/totp/remove/begin", rh.beginH, "totp_removal_step_up_refused"},
		{"confirm truncated JSON", `{"step_up_token":"x"`, "/auth/totp/remove", rh.confirmH, "totp_removal_refused"},
		{"confirm empty body", "", "/auth/totp/remove", rh.confirmH, "totp_removal_refused"},
	}

	before := map[string]int{
		"totp_removal_step_up_refused": removalAuditCount(t, rh.pool, rh.userID, "totp_removal_step_up_refused"),
		"totp_removal_refused":         removalAuditCount(t, rh.pool, rh.userID, "totp_removal_refused"),
	}

	for _, tc := range cases {
		rec := postRemovalRaw(t, tc.path, tc.body, removalClaims(rh.userID, rh.jti), tc.handler)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d body %s, want 400", tc.name, rec.Code, rec.Body.String())
		}
		if got := removalAuditCount(t, rh.pool, rh.userID, tc.action); got != before[tc.action]+1 {
			t.Fatalf("%s: %s audit rows = %d, want exactly %d (the malformed attempt must be audited)",
				tc.name, tc.action, got, before[tc.action]+1)
		}
		before[tc.action]++ // later cases accumulate on the same action counter
	}

	// None of the malformed attempts may have touched the factor.
	rh.factorIntact()
	if got := removalAuditCount(t, rh.pool, rh.userID, "totp_removed"); got != 0 {
		t.Fatalf("totp_removed audit rows = %d, want 0 after malformed-body attempts", got)
	}
}

func TestTOTPRemoval_ConcurrentDoubleSubmission_DB(t *testing.T) {
	rh := newRemovalHarness(t, []string{"rec33333"})
	tok, status := rh.begin("correct-horse-battery", "rec33333")
	if status != http.StatusOK || tok == "" {
		t.Fatalf("begin status = %d token %q, want 200 + token", status, tok)
	}

	var wg sync.WaitGroup
	statuses := make([]int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			statuses[slot] = rh.confirm(rh.jti, tok, "REMOVE")
		}(i)
	}
	wg.Wait()

	successes, refusals := 0, 0
	for _, s := range statuses {
		switch s {
		case http.StatusNoContent:
			successes++
		case http.StatusForbidden:
			refusals++
		default:
			t.Fatalf("unexpected concurrent confirm status %d", s)
		}
	}
	if successes != 1 || refusals != 1 {
		t.Fatalf("concurrent double-submission statuses = %v, want exactly one 204 and one 403", statuses)
	}
	if got := removalAuditCount(t, rh.pool, rh.userID, "totp_removed"); got != 1 {
		t.Fatalf("totp_removed audit rows = %d, want exactly 1", got)
	}
	enabled, _, _ := removalUserState(t, rh.pool, rh.userID)
	if enabled {
		t.Fatal("factor must be removed exactly once")
	}
}
