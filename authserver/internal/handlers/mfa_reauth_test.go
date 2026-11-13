package handlers

// First-factor possession gate — the reauth/possession + gated-arm contract
// (possession scheme v7; supersedes the ER5 s07 first-factor step-up tests
// this file carried).
//
// REVISED DELIBERATELY per v7 §4 (r1 fix plan 5): the pre-gate tests that
// expected UNGATED factor-holder enrollment (push-only "keeps the ungated
// posture"), password-only regeneration for C1 accounts, and the
// current_totp_code replace arm are rewritten to the gated contract — every
// factor-set mutation now requires a fresh proof grant (owner decision (a)),
// C1 accounts are refused the password path with the method-aware 403, and
// TOTP setup stages a pending enrollment (enrollment_id) instead of
// overwriting the active factor.
//
// Covered here:
//
//   - POST /auth/mfa/reauth: password proof issues a single-use,
//     session-bound grant carrying the DECLARED operation; wrong passwords
//     are refused and audited (the password budget commits the failure);
//     C1 accounts receive possession_proof_required naming the possession
//     endpoints; re-issuance replaces the prior grant.
//   - /auth/totp/setup + /auth/totp/confirm: the grant is peeked at setup
//     (with one-time enrollment binding) and consumed at confirm; stale/
//     expired/foreign-session/replayed proofs answer the typed 403
//     reauth_required; the ACTIVE factor is untouched until confirm.
//   - /auth/backup-codes/generate: gated for EVERY account (operation
//     recovery.regenerate); C1 accounts must prove possession.
//   - Fail-closed behavior on DB failures; every refusal audited.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/pwhash"
)

// reauthStepupHarness bundles one seeded user with the shared handler set
// and the session jti the grant binds to.
type reauthStepupHarness struct {
	t        *testing.T
	pool     *pgxpool.Pool
	userID   int64
	jti      string
	password string
	h        *AuthHandler
}

// seedStepupUser seeds a local user with a working password and, per mode,
// either no factor ("none"), an ENABLED TOTP factor ("totp"), or only
// push MFA enabled ("push"). Cleanup of the users row is handled by
// seedLocalUser; mfa_reauth_step_ups rows cascade.
func seedStepupUser(t *testing.T, pool *pgxpool.Pool, email, password, mode string) int64 {
	t.Helper()
	userID := seedLocalUser(t, pool, email)
	hash, err := pwhash.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	ctx := context.Background()
	switch mode {
	case "totp":
		if _, err := pool.Exec(ctx,
			`UPDATE users SET password_hash = $1,
			                   totp_secret_enc = pgp_sym_encrypt($2, current_setting('app.encryption_key')),
			                   totp_enabled = TRUE,
			                   totp_enabled_at = now()
			 WHERE id = $3`,
			hash, removalTestSecret, userID); err != nil {
			t.Fatalf("seed stepup user (totp): %v", err)
		}
	case "push":
		if _, err := pool.Exec(ctx,
			`UPDATE users SET password_hash = $1, push_mfa_enabled = TRUE WHERE id = $2`,
			hash, userID); err != nil {
			t.Fatalf("seed stepup user (push): %v", err)
		}
	default:
		if _, err := pool.Exec(ctx,
			`UPDATE users SET password_hash = $1 WHERE id = $2`,
			hash, userID); err != nil {
			t.Fatalf("seed stepup user: %v", err)
		}
	}
	return userID
}

func newReauthStepupHarness(t *testing.T, mode string) *reauthStepupHarness {
	t.Helper()
	pool := enrollmentHandlerPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	email := fmt.Sprintf("mfa-reauth-%d@example.test", time.Now().UnixNano())
	userID := seedStepupUser(t, pool, email, "correct-horse-battery", mode)
	return &reauthStepupHarness{
		t:        t,
		pool:     pool,
		userID:   userID,
		jti:      "sess-reauth-" + fmt.Sprint(userID),
		password: "correct-horse-battery",
		h:        NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()}),
	}
}

func (rh *reauthStepupHarness) claims() *token.Claims {
	return removalClaims(rh.userID, rh.jti)
}

// postJSON posts a JSON body to a handler with authenticated claims in the
// request context (the middleware-attached shape), bypassing the mux wrappers.
func (rh *reauthStepupHarness) postJSON(path string, payload map[string]any, claims *token.Claims, handler http.HandlerFunc) *httptest.ResponseRecorder {
	rh.t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		rh.t.Fatalf("marshal %s payload: %v", path, err)
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

// getJSON issues a GET (with an optional JSON body — the setup arm reads the
// X-MFA-Reauth header or a body member) with authenticated claims in the
// request context.
func (rh *reauthStepupHarness) getJSON(path string, payload map[string]any, claims *token.Claims, handler http.HandlerFunc) *httptest.ResponseRecorder {
	rh.t.Helper()
	var req *http.Request
	if payload == nil {
		req = httptest.NewRequest(http.MethodGet, path, nil)
	} else {
		body, err := json.Marshal(payload)
		if err != nil {
			rh.t.Fatalf("marshal %s payload: %v", path, err)
		}
		req = httptest.NewRequest(http.MethodGet, path, bytes.NewReader(body))
	}
	req.Header.Set("Content-Type", "application/json")
	if claims != nil {
		req = req.WithContext(ContextWithUser(req.Context(), claims))
	}
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

// beginReauth runs the challenge endpoint (password proof for a C2/C3
// account — the C1 refusal is asserted separately) and returns the
// reauth_token. The operation is REQUIRED by the v7 contract.
func (rh *reauthStepupHarness) beginReauth(password, operation string) (string, int) {
	rh.t.Helper()
	rec := rh.postJSON(MFAReauthChallengePath,
		map[string]any{"password": password, "operation": operation}, rh.claims(), rh.h.MFAReauthBegin)
	var out struct {
		ReauthToken string `json:"reauth_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.ReauthToken, rec.Code
}

// setup runs the setup arm as the harness user (token via the header, the
// transport a real GET uses).
func (rh *reauthStepupHarness) setup(reauthToken string) *httptest.ResponseRecorder {
	rh.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/totp/setup", nil)
	if reauthToken != "" {
		req.Header.Set(ReauthTokenHeader, reauthToken)
	}
	req = req.WithContext(ContextWithUser(req.Context(), rh.claims()))
	rr := httptest.NewRecorder()
	rh.h.TOTPSetup(rr, req)
	return rr
}

// confirm runs the confirm arm as the harness user; enrollmentID is the
// setup-issued identifier the v7 contract requires.
func (rh *reauthStepupHarness) confirm(code, reauthToken, enrollmentID string) *httptest.ResponseRecorder {
	payload := map[string]any{"code": code, "enrollment_id": enrollmentID}
	if reauthToken != "" {
		payload["reauth_token"] = reauthToken
	}
	return rh.postJSON("/auth/totp/confirm", payload, rh.claims(), rh.h.TOTPConfirm)
}

// generate runs the recovery-regeneration arm as the harness user.
func (rh *reauthStepupHarness) generate(reauthToken string) *httptest.ResponseRecorder {
	payload := map[string]any{}
	if reauthToken != "" {
		payload["reauth_token"] = reauthToken
	}
	return rh.postJSON("/auth/backup-codes/generate", payload, rh.claims(), rh.h.GenerateBackupCodes)
}

// setupBody extracts the provisioning URI + enrollment_id from a 200 setup.
func setupBody(t *testing.T, rec *httptest.ResponseRecorder) (uri, enrollmentID string) {
	t.Helper()
	var body struct {
		ProvisioningURI string `json:"provisioning_uri"`
		EnrollmentID    string `json:"enrollment_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.ProvisioningURI == "" || body.EnrollmentID == "" {
		t.Fatalf("setup body = %s (%v), want provisioning_uri + enrollment_id", rec.Body.String(), err)
	}
	u, err := url.Parse(body.ProvisioningURI)
	if err != nil {
		t.Fatalf("parse provisioning uri: %v", err)
	}
	secret := u.Query().Get("secret")
	if secret == "" {
		t.Fatalf("provisioning uri %q carries no secret", body.ProvisioningURI)
	}
	return body.ProvisioningURI, body.EnrollmentID
}

// provisioningSecret extracts the pending secret from a 200 setup body.
func provisioningSecret(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	uri, _ := setupBody(t, rec)
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse provisioning uri: %v", err)
	}
	return u.Query().Get("secret")
}

// seedGrant inserts a FULL grant tuple directly (bypassing issuance) — the
// fixture device the v7 acceptance matrix uses for C1 proofs (whose grant
// cannot be minted through the password endpoint) and for old-row states.
// Returns the raw token to present.
func (rh *reauthStepupHarness) seedGrant(operation string, opts map[string]any) string {
	rh.t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		rh.t.Fatalf("seed grant entropy: %v", err)
	}
	token := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	proofMethod := authn.ProofMethodPassword
	var provingFactorID any
	var targetRef any
	family := any(nil)
	sessionJTI := rh.jti
	ttlSecs := int(MFAReauthStepUpTTL.Seconds())
	if opts != nil {
		if v, ok := opts["proof_method"].(string); ok {
			proofMethod = v
		}
		if v, ok := opts["target_ref"].(string); ok {
			targetRef = v
		}
		if v, ok := opts["family"].(string); ok {
			family = v
		}
		if v, ok := opts["jti"].(string); ok {
			sessionJTI = v
		}
		if v, ok := opts["ttl_secs"].(int); ok {
			ttlSecs = v
		}
		if v, ok := opts["proving_factor_id"].([]byte); ok {
			provingFactorID = v
		}
	}
	_, err := rh.pool.Exec(context.Background(),
		`DELETE FROM mfa_reauth_step_ups WHERE user_id = $1`, rh.userID)
	if err != nil {
		rh.t.Fatalf("seed grant cleanup: %v", err)
	}
	_, err = rh.pool.Exec(context.Background(),
		`INSERT INTO mfa_reauth_step_ups
		   (token_hash, user_id, session_jti, operation, target_ref,
		    proof_method, proving_factor_id, bound_factor_generation,
		    token_scope, refresh_family_id, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7,
		         (SELECT factor_generation FROM users WHERE id = $2),
		         'session', $8, now() + make_interval(secs => $9))`,
		hex.EncodeToString(sum[:]), rh.userID, sessionJTI, operation, targetRef,
		proofMethod, provingFactorID, family, ttlSecs,
	)
	if err != nil {
		rh.t.Fatalf("seed grant: %v", err)
	}
	return token
}

// factorState reports the account's TOTP enabled flag and recovery-code count.
func (rh *reauthStepupHarness) factorState() (enabled bool, codeCount int) {
	rh.t.Helper()
	var codes []string
	if err := rh.pool.QueryRow(context.Background(),
		`SELECT COALESCE(totp_enabled, FALSE), COALESCE(totp_backup_codes_enc, '{}')
		   FROM users WHERE id = $1`, rh.userID,
	).Scan(&enabled, &codes); err != nil {
		rh.t.Fatalf("read factor state: %v", err)
	}
	return enabled, len(codes)
}

// reauthAuditCount counts admin_audit_log rows for one action.
func (rh *reauthStepupHarness) reauthAuditCount(action string) int {
	rh.t.Helper()
	var n int
	if err := rh.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_audit_log WHERE user_id = $1 AND action = $2`,
		rh.userID, action,
	).Scan(&n); err != nil {
		rh.t.Fatalf("count audit rows: %v", err)
	}
	return n
}

// expireReauthTokens forces every live grant of the harness user past its
// expiry — the "stale proof" arm without waiting out the TTL.
func (rh *reauthStepupHarness) expireReauthTokens() {
	rh.t.Helper()
	if _, err := rh.pool.Exec(context.Background(),
		`UPDATE mfa_reauth_step_ups SET expires_at = now() - interval '1 second' WHERE user_id = $1`,
		rh.userID); err != nil {
		rh.t.Fatalf("expire reauth tokens: %v", err)
	}
}

// assertReauthRequired verifies a response carries the full typed 403
// reauth_required problem contract: problem+json content type, the RFC 7807
// Type URI, the machine-readable code, the remediation action, and the
// challenge path in the Detail — never a silent failure.
func assertReauthRequired(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d body %s, want 403 reauth_required", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Fatalf("content type = %q, want application/problem+json", got)
	}
	var body struct {
		Type        string `json:"type"`
		Status      int    `json:"status"`
		Detail      string `json:"detail"`
		Code        string `json:"code"`
		Remediation string `json:"remediation"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode problem body: %v (%s)", err, rec.Body.String())
	}
	if body.Type != reauthRequiredProblemType {
		t.Errorf("problem type = %q, want %q", body.Type, reauthRequiredProblemType)
	}
	if body.Status != http.StatusForbidden {
		t.Errorf("problem status = %d, want 403", body.Status)
	}
	if body.Code != ReauthRequiredCode {
		t.Errorf("problem code = %q, want %q", body.Code, ReauthRequiredCode)
	}
	if body.Remediation != reauthRemediation {
		t.Errorf("problem remediation = %q, want %q", body.Remediation, reauthRemediation)
	}
	if !strings.Contains(body.Detail, MFAReauthChallengePath) {
		t.Errorf("problem detail %q does not name the challenge path %q", body.Detail, MFAReauthChallengePath)
	}
}

// -- POST /auth/mfa/reauth (the password issuance path, C2/C3) --

func TestMFAReauthChallenge_DB(t *testing.T) {
	t.Run("wrong password refused and audited", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		rec := rh.postJSON(MFAReauthChallengePath,
			map[string]any{"password": "wrong-password", "operation": "recovery.regenerate"}, rh.claims(), rh.h.MFAReauthBegin)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d body %s, want 403", rec.Code, rec.Body.String())
		}
		if got := rh.reauthAuditCount("mfa_reauth_refused"); got != 1 {
			t.Fatalf("mfa_reauth_refused audit rows = %d, want 1", got)
		}
		// The evaluated failure commits toward the §2.3 password budget.
		var attempts int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT possession_password_failed_attempts FROM users WHERE id = $1`, rh.userID,
		).Scan(&attempts); err != nil || attempts != 1 {
			t.Fatalf("possession_password_failed_attempts = %d (%v), want 1", attempts, err)
		}
	})

	t.Run("missing password refused and audited", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		rec := rh.postJSON(MFAReauthChallengePath, map[string]any{"operation": "recovery.regenerate"}, rh.claims(), rh.h.MFAReauthBegin)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d body %s, want 400", rec.Code, rec.Body.String())
		}
		if got := rh.reauthAuditCount("mfa_reauth_refused"); got != 1 {
			t.Fatalf("mfa_reauth_refused audit rows = %d, want 1", got)
		}
	})

	t.Run("missing operation refused 400 invalid_operation", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		rec := rh.postJSON(MFAReauthChallengePath, map[string]any{"password": rh.password}, rh.claims(), rh.h.MFAReauthBegin)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_operation") {
			t.Fatalf("status = %d body %s, want 400 invalid_operation", rec.Code, rec.Body.String())
		}
	})

	t.Run("bootstrap operation is mfa_pending-scope only", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		rec := rh.postJSON(MFAReauthChallengePath,
			map[string]any{"password": rh.password, "operation": "bootstrap.totp.enroll"}, rh.claims(), rh.h.MFAReauthBegin)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_operation") {
			t.Fatalf("status = %d body %s, want 400 invalid_operation (scope parity)", rec.Code, rec.Body.String())
		}
	})

	t.Run("fresh password issues session-bound grant bound to the declared operation", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		tok, status := rh.beginReauth(rh.password, "recovery.regenerate")
		if status != http.StatusOK || tok == "" {
			t.Fatalf("begin status = %d token %q, want 200 + token", status, tok)
		}
		if got := rh.reauthAuditCount("mfa_reauth_authorized"); got != 1 {
			t.Fatalf("mfa_reauth_authorized audit rows = %d, want 1", got)
		}
		var sessionJTI, operation, scope string
		var fam *string
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT session_jti, operation, token_scope, refresh_family_id
			   FROM mfa_reauth_step_ups WHERE user_id = $1`, rh.userID,
		).Scan(&sessionJTI, &operation, &scope, &fam); err != nil {
			t.Fatalf("read grant row: %v", err)
		}
		if sessionJTI != rh.jti || operation != "recovery.regenerate" || scope != "session" || fam != nil {
			t.Fatalf("grant tuple = {%q,%q,%q,%v}, want {%q,recovery.regenerate,session,nil}", sessionJTI, operation, scope, fam, rh.jti)
		}
		// Success resets the password budget in the same issuance transaction.
		var attempts int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT possession_password_failed_attempts FROM users WHERE id = $1`, rh.userID,
		).Scan(&attempts); err != nil || attempts != 0 {
			t.Fatalf("budget not reset on success: %d (%v)", attempts, err)
		}
	})

	t.Run("re-issuance replaces the prior grant", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		old, _ := rh.beginReauth(rh.password, "recovery.regenerate")
		fresh, _ := rh.beginReauth(rh.password, "recovery.regenerate")
		if old == fresh {
			t.Fatal("re-issuance returned the same token")
		}
		var n int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM mfa_reauth_step_ups WHERE user_id = $1`, rh.userID,
		).Scan(&n); err != nil || n != 1 {
			t.Fatalf("live grant rows = %d (%v), want 1 (one-live-row rule)", n, err)
		}
		// The old token's hash no longer matches any row.
		oldHash := authn.ReauthTokenHash(old)
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM mfa_reauth_step_ups WHERE token_hash = $1`, oldHash,
		).Scan(&n); err != nil || n != 0 {
			t.Fatalf("old grant survived re-issuance (%v)", err)
		}
	})

	t.Run("C1 password proof refused with the method-aware 403 naming the possession endpoints", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "totp")
		rec := rh.postJSON(MFAReauthChallengePath,
			map[string]any{"password": rh.password, "operation": "recovery.regenerate"}, rh.claims(), rh.h.MFAReauthBegin)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d body %s, want 403", rec.Code, rec.Body.String())
		}
		for _, want := range []string{PossessionRequiredCode, "/auth/mfa/possession/totp", "/auth/mfa/possession/webauthn/begin"} {
			if !strings.Contains(rec.Body.String(), want) {
				t.Fatalf("C1 refusal body %s missing %q", rec.Body.String(), want)
			}
		}
		var n int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM mfa_reauth_step_ups WHERE user_id = $1`, rh.userID,
		).Scan(&n); err != nil || n != 0 {
			t.Fatalf("C1 password refusal minted a grant (%v)", err)
		}
	})

	t.Run("unauthenticated request: 401 before anything else", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		rec := rh.postJSON(MFAReauthChallengePath,
			map[string]any{"password": rh.password, "operation": "recovery.regenerate"}, nil, rh.h.MFAReauthBegin)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d body %s, want 401", rec.Code, rec.Body.String())
		}
	})

	t.Run("malformed body: 400 and audited (every-attempt contract)", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		req := httptest.NewRequest(http.MethodPost, MFAReauthChallengePath, strings.NewReader("{not-json"))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(ContextWithUser(req.Context(), rh.claims()))
		rr := httptest.NewRecorder()
		rh.h.MFAReauthBegin(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d body %s, want 400", rr.Code, rr.Body.String())
		}
		if got := rh.reauthAuditCount("mfa_reauth_refused"); got != 1 {
			t.Fatalf("mfa_reauth_refused audit rows = %d, want 1", got)
		}
	})

	t.Run("password lookup failure fails closed with 500, never as invalid password", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		// A second, closed pool stands in for a DB outage; the harness pool
		// stays open so cleanup still runs.
		closed := enrollmentHandlerPool(t)
		closed.Close()
		h := NewAuthHandler(AuthHandlerConfig{Pool: closed, JWT: newTestJWT(), Logger: discardLogger()})
		rec := rh.postJSON(MFAReauthChallengePath,
			map[string]any{"password": rh.password, "operation": "recovery.regenerate"}, rh.claims(), h.MFAReauthBegin)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d body %s, want 500 (a DB outage is not an invalid password)", rec.Code, rec.Body.String())
		}
	})
}

// -- GET /auth/totp/setup + POST /auth/totp/confirm under the gate --

func TestTOTPSetup_PossessionGate_DB(t *testing.T) {
	t.Run("no factor + no proof: typed 403 reauth_required, audited, active factor untouched", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		assertReauthRequired(t, rh.setup(""))
		if got := rh.reauthAuditCount("mfa_reauth_refused"); got != 1 {
			t.Fatalf("mfa_reauth_refused audit rows = %d, want 1", got)
		}
		var pending int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM totp_pending_enrollments WHERE user_id = $1`, rh.userID,
		).Scan(&pending); err != nil || pending != 0 {
			t.Fatalf("pending enrollment staged without proof (err=%v)", err)
		}
	})

	t.Run("fresh proof proceeds, stages the pending row, and the grant survives (peek)", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		tok, status := rh.beginReauth(rh.password, "totp.enroll")
		if status != http.StatusOK {
			t.Fatalf("begin status = %d", status)
		}
		first := rh.setup(tok)
		if first.Code != http.StatusOK {
			t.Fatalf("setup with fresh proof: status = %d body %s, want 200", first.Code, first.Body.String())
		}
		_, enrollmentID := setupBody(t, first)
		// RESUME: the same grant + same JTI re-derives the SAME enrollment.
		second := rh.setup(tok)
		if second.Code != http.StatusOK {
			t.Fatalf("second setup (resume): status = %d body %s, want 200", second.Code, second.Body.String())
		}
		_, resumeID := setupBody(t, second)
		if resumeID != enrollmentID {
			t.Fatalf("resume minted a new enrollment id %q, want %q", resumeID, enrollmentID)
		}
		// The grant is still live (peek, non-consuming) and now bound.
		var bound bool
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT target_ref IS NOT NULL FROM mfa_reauth_step_ups WHERE user_id = $1`, rh.userID,
		).Scan(&bound); err != nil || !bound {
			t.Fatalf("grant not bound after setup (%v)", err)
		}
	})

	t.Run("ACTIVE factor untouched until confirm: users row keeps no staged secret", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "totp")
		// C1 account: prove via a seeded totp-proof grant (the possession
		// endpoints mint these; fixture here).
		tok := rh.seedGrant("totp.replace", map[string]any{"proof_method": "totp"})
		rec := rh.setup(tok)
		if rec.Code != http.StatusOK {
			t.Fatalf("setup status = %d body %s, want 200", rec.Code, rec.Body.String())
		}
		secret := provisioningSecret(t, rec)
		if secret == removalTestSecret {
			t.Fatal("setup staged the ACTIVE secret as the pending secret")
		}
		enabled, _ := rh.factorState()
		if !enabled {
			t.Fatal("setup disturbed the active factor")
		}
	})

	t.Run("stale (expired) proof: typed 403", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		tok, _ := rh.beginReauth(rh.password, "totp.enroll")
		rh.expireReauthTokens()
		assertReauthRequired(t, rh.setup(tok))
	})

	t.Run("foreign-session proof: typed 403", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		tok, _ := rh.beginReauth(rh.password, "totp.enroll")
		req := httptest.NewRequest(http.MethodGet, "/auth/totp/setup", nil)
		req.Header.Set(ReauthTokenHeader, tok)
		req = req.WithContext(ContextWithUser(req.Context(), removalClaims(rh.userID, rh.jti+"-other")))
		rr := httptest.NewRecorder()
		rh.h.TOTPSetup(rr, req)
		assertReauthRequired(t, rr)
	})

	t.Run("wrong-operation grant at the setup arm: refusal deletes the dead proof", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		tok := rh.seedGrant("recovery.regenerate", nil) // presentable only at generate
		assertReauthRequired(t, rh.setup(tok))
		var n int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM mfa_reauth_step_ups WHERE user_id = $1`, rh.userID,
		).Scan(&n); err != nil || n != 0 {
			t.Fatalf("mismatch refusal left the dead grant in place: %d rows (%v)", n, err)
		}
	})

	t.Run("gate lookup failure fails closed with 500, never an ungated arm", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		closed := enrollmentHandlerPool(t)
		closed.Close()
		h := NewAuthHandler(AuthHandlerConfig{Pool: closed, JWT: newTestJWT(), Logger: discardLogger()})
		rec := rh.postJSON("/auth/totp/confirm",
			map[string]any{"code": "123456", "enrollment_id": "00000000-0000-0000-0000-000000000000", "reauth_token": "deadbeef"}, rh.claims(), h.TOTPConfirm)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d body %s, want 500 (fail closed, never silently ungated)", rec.Code, rec.Body.String())
		}
	})

	t.Run("factor-holder accounts are gated TOO (revised: no ungated posture)", func(t *testing.T) {
		for _, mode := range []string{"totp", "push"} {
			rh := newReauthStepupHarness(t, mode)
			rec := rh.setup("")
			assertReauthRequired(t, rec)
		}
	})
}

func TestTOTPConfirm_PossessionGate_DB(t *testing.T) {
	t.Run("full fresh flow: proof, setup, code, confirm activates + consumes + bumps generation", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		tok, _ := rh.beginReauth(rh.password, "totp.enroll")
		setup := rh.setup(tok)
		if setup.Code != http.StatusOK {
			t.Fatalf("setup status = %d body %s, want 200", setup.Code, setup.Body.String())
		}
		secret := provisioningSecret(t, setup)
		_, enrollmentID := setupBody(t, setup)
		var genBefore int64
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT factor_generation FROM users WHERE id = $1`, rh.userID,
		).Scan(&genBefore); err != nil {
			t.Fatalf("read generation: %v", err)
		}
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatalf("generate code: %v", err)
		}
		rec := rh.confirm(code, tok, enrollmentID)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("confirm status = %d body %s, want 204", rec.Code, rec.Body.String())
		}
		enabled, _ := rh.factorState()
		if !enabled {
			t.Fatal("factor not enabled after confirm")
		}
		var genAfter int64
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT factor_generation FROM users WHERE id = $1`, rh.userID,
		).Scan(&genAfter); err != nil {
			t.Fatalf("read generation: %v", err)
		}
		if genAfter != genBefore+1 {
			t.Fatalf("factor_generation = %d, want %d (the promotion bump)", genAfter, genBefore+1)
		}
		var pending, grants int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT (SELECT count(*) FROM totp_pending_enrollments WHERE user_id = $1),
			        (SELECT count(*) FROM mfa_reauth_step_ups WHERE user_id = $1)`, rh.userID,
		).Scan(&pending, &grants); err != nil || pending != 0 || grants != 0 {
			t.Fatalf("promotion left artifacts: pending=%d grants=%d (%v)", pending, grants, err)
		}
		// Replay: the grant is consumed and the generation advanced — the
		// typed 403 is the one honest answer (revised from the pre-gate 401).
		replay := rh.confirm(code, tok, enrollmentID)
		assertReauthRequired(t, replay)
	})

	t.Run("valid code WITHOUT proof: typed 403, factor NOT enabled", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		tok, _ := rh.beginReauth(rh.password, "totp.enroll")
		setup := rh.setup(tok)
		secret := provisioningSecret(t, setup)
		_, enrollmentID := setupBody(t, setup)
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatalf("generate code: %v", err)
		}
		// Confirm without the token: typed 403, factor untouched, audit row.
		assertReauthRequired(t, rh.confirm(code, "", enrollmentID))
		if enabled, _ := rh.factorState(); enabled {
			t.Fatal("factor enabled without a fresh proof")
		}
		if got := rh.reauthAuditCount("mfa_reauth_refused"); got == 0 {
			t.Fatal("confirm refusal not audited")
		}
	})

	t.Run("stale proof with valid code: typed 403, factor NOT enabled", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		tok, _ := rh.beginReauth(rh.password, "totp.enroll")
		setup := rh.setup(tok)
		secret := provisioningSecret(t, setup)
		_, enrollmentID := setupBody(t, setup)
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatalf("generate code: %v", err)
		}
		rh.expireReauthTokens()
		assertReauthRequired(t, rh.confirm(code, tok, enrollmentID))
		if enabled, _ := rh.factorState(); enabled {
			t.Fatal("factor enabled with a stale proof")
		}
	})

	t.Run("wrong enrollment_id: refusal deletes the grant, factor untouched", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		tok, _ := rh.beginReauth(rh.password, "totp.enroll")
		setup := rh.setup(tok)
		secret := provisioningSecret(t, setup)
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatalf("generate code: %v", err)
		}
		rec := rh.confirm(code, tok, "00000000-0000-0000-0000-000000000000")
		assertReauthRequired(t, rec)
		if enabled, _ := rh.factorState(); enabled {
			t.Fatal("factor enabled on a mismatched binding")
		}
		var n int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM mfa_reauth_step_ups WHERE user_id = $1`, rh.userID,
		).Scan(&n); err != nil || n != 0 {
			t.Fatalf("tuple mismatch did not delete the dead grant: %d (%v)", n, err)
		}
	})

	// r8 (§1.7): a DEAD STAGED ROW behind a live, correctly-bound grant is the
	// tuple-mismatch refusal whose cleanup the handler performs itself — and
	// that cleanup must COMMIT. The pre-r8 code deleted the grant in-transaction
	// and returned into the deferred rollback, resurrecting the burned proof.
	t.Run("dead staged row: refusal cleanup COMMITS — grant durably gone", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		tok, _ := rh.beginReauth(rh.password, "totp.enroll")
		setup := rh.setup(tok)
		secret := provisioningSecret(t, setup)
		_, enrollmentID := setupBody(t, setup)
		// Kill the staged row outside any handler transaction: the grant is
		// live and bound to enrollmentID (the peek succeeds), but the
		// confirm's staged-row read resolves nothing.
		if _, err := rh.pool.Exec(context.Background(),
			`DELETE FROM totp_pending_enrollments WHERE user_id = $1`, rh.userID,
		); err != nil {
			t.Fatalf("kill staged row: %v", err)
		}
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatalf("generate code: %v", err)
		}
		rec := rh.confirm(code, tok, enrollmentID)
		assertReauthRequired(t, rec)
		// Durable absence: this pool read is a FRESH transaction after the
		// handler returned — zero rows is the committed state, not the
		// in-transaction view.
		var grants int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM mfa_reauth_step_ups WHERE user_id = $1`, rh.userID,
		).Scan(&grants); err != nil || grants != 0 {
			t.Fatalf("refusal cleanup did not commit: %d grant row(s) survive the returned refusal (%v)", grants, err)
		}
		if enabled, _ := rh.factorState(); enabled {
			t.Fatal("factor enabled on a dead staged row")
		}
		// The refusal audit rides the SAME committed transaction.
		if got := rh.reauthAuditCount("mfa_reauth_refused"); got != 1 {
			t.Fatalf("mfa_reauth_refused audit rows = %d, want 1 (audit committed with the cleanup)", got)
		}
	})

	t.Run("invalid code leaves the grant and pending row intact", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		tok, _ := rh.beginReauth(rh.password, "totp.enroll")
		setup := rh.setup(tok)
		_, enrollmentID := setupBody(t, setup)
		rec := rh.confirm("000000", tok, enrollmentID)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d body %s, want 401 (invalid code)", rec.Code, rec.Body.String())
		}
		var n int
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM mfa_reauth_step_ups WHERE user_id = $1`, rh.userID,
		).Scan(&n); err != nil || n != 1 {
			t.Fatalf("invalid code burned the grant: %d rows (%v)", n, err)
		}
	})
}

// -- POST /auth/backup-codes/generate: gated for EVERY account --

func TestGenerateBackupCodes_ReauthGate_DB(t *testing.T) {
	t.Run("no proof: typed 403, no codes minted", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		assertReauthRequired(t, rh.generate(""))
		if _, count := rh.factorState(); count != 0 {
			t.Fatalf("recovery codes minted without proof: %d", count)
		}
		if got := rh.reauthAuditCount("mfa_reauth_refused"); got != 1 {
			t.Fatalf("mfa_reauth_refused audit rows = %d, want 1", got)
		}
	})

	t.Run("malformed body: typed 403 (tolerant decode, never a silent 400)", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		req := httptest.NewRequest(http.MethodPost, "/auth/backup-codes/generate", bytes.NewReader([]byte("not-json")))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(ContextWithUser(req.Context(), rh.claims()))
		rr := httptest.NewRecorder()
		rh.h.GenerateBackupCodes(rr, req)
		assertReauthRequired(t, rr)
	})

	t.Run("fresh proof mints codes, consumes the grant, bumps the generation (replay refused)", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		tok, _ := rh.beginReauth(rh.password, "recovery.regenerate")
		var genBefore int64
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT factor_generation FROM users WHERE id = $1`, rh.userID,
		).Scan(&genBefore); err != nil {
			t.Fatalf("read generation: %v", err)
		}
		rec := rh.generate(tok)
		if rec.Code != http.StatusOK {
			t.Fatalf("generate with fresh proof: status = %d body %s, want 200", rec.Code, rec.Body.String())
		}
		var body struct {
			BackupCodes []string `json:"backup_codes"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body.BackupCodes) != 10 {
			t.Fatalf("backup_codes = %s (%v), want 10 codes", rec.Body.String(), err)
		}
		if _, count := rh.factorState(); count != 10 {
			t.Fatalf("stored recovery codes = %d, want 10", count)
		}
		var genAfter int64
		if err := rh.pool.QueryRow(context.Background(),
			`SELECT factor_generation FROM users WHERE id = $1`, rh.userID,
		).Scan(&genAfter); err != nil {
			t.Fatalf("read generation: %v", err)
		}
		if genAfter != genBefore+1 {
			t.Fatalf("factor_generation = %d, want %d", genAfter, genBefore+1)
		}
		assertReauthRequired(t, rh.generate(tok))
	})

	t.Run("account WITH a factor is gated too (regeneration replaces every code)", func(t *testing.T) {
		// C1 (TOTP) account: password grants are refused at issuance, so the
		// proof is a totp-proof grant (fixture — the possession endpoints
		// mint these).
		rh := newReauthStepupHarness(t, "totp")
		assertReauthRequired(t, rh.generate(""))
		tok := rh.seedGrant("recovery.regenerate", map[string]any{"proof_method": "totp"})
		if rec := rh.generate(tok); rec.Code != http.StatusOK {
			t.Fatalf("generate with possession proof on factor account: status = %d body %s, want 200", rec.Code, rec.Body.String())
		}
	})

	t.Run("stale proof: typed 403", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		tok, _ := rh.beginReauth(rh.password, "recovery.regenerate")
		rh.expireReauthTokens()
		assertReauthRequired(t, rh.generate(tok))
	})

	t.Run("token consumption failure fails closed with 500, no codes minted", func(t *testing.T) {
		rh := newReauthStepupHarness(t, "none")
		closed := enrollmentHandlerPool(t)
		closed.Close()
		h := NewAuthHandler(AuthHandlerConfig{Pool: closed, JWT: newTestJWT(), Logger: discardLogger()})
		rec := rh.postJSON("/auth/backup-codes/generate", map[string]any{"reauth_token": "deadbeef"}, rh.claims(), h.GenerateBackupCodes)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d body %s, want 500 (fail closed)", rec.Code, rec.Body.String())
		}
		if _, count := rh.factorState(); count != 0 {
			t.Fatalf("recovery codes minted despite gate failure: %d", count)
		}
	})
}

// -- contract constants + the grant-store failure contract --

func TestMFAReauthChallengePathIsStable(t *testing.T) {
	// The challenge path and problem members are part of the client-visible
	// contract (named in the 403 problem Detail and wired in authserverd);
	// they must never drift.
	if MFAReauthChallengePath != "/auth/mfa/reauth" {
		t.Fatalf("challenge path = %q, want /auth/mfa/reauth", MFAReauthChallengePath)
	}
	if ReauthRequiredCode != "reauth_required" {
		t.Fatalf("problem code = %q, want reauth_required", ReauthRequiredCode)
	}
	if reauthRemediation != "reauth" {
		t.Fatalf("remediation = %q, want reauth", reauthRemediation)
	}
	if MFAReauthStepUpTTL != 5*time.Minute {
		t.Fatalf("ttl = %v, want 5m (mirrors TOTPRemovalStepUpTTL)", MFAReauthStepUpTTL)
	}
	// The typed problem really renders the full 403 contract.
	req := httptest.NewRequest(http.MethodGet, "/auth/totp/setup", nil)
	rec := httptest.NewRecorder()
	writeReauthRequired(rec, req)
	assertReauthRequired(t, rec)
}

// The grant-store lookup failure contract (revised from the removed
// peekMFAReauth/consumeMFAReauth helpers): a DB failure is a WRAPPED error —
// never the refusal sentinel (fail closed means 500, not 403) — and a
// missing row is exactly ErrGrantRequired.
func TestGrantStoreFailureContract_DB(t *testing.T) {
	rh := newReauthStepupHarness(t, "none")
	family := ""
	pred := authn.GrantPredicate{
		TokenHash:     "deadbeef",
		UserID:        rh.userID,
		SessionJTI:    rh.jti,
		Operation:     "recovery.regenerate",
		TargetBound:   false,
		TokenScope:    "session",
		FamilyBound:   true,
		RefreshFamily: &family,
	}
	if _, err := authn.PeekGrant(context.Background(), rh.pool, pred); !errors.Is(err, authn.ErrGrantRequired) {
		t.Fatalf("PeekGrant missing row: err=%v, want ErrGrantRequired", err)
	}
	if _, err := authn.ConsumeGrant(context.Background(), rh.pool, pred); !errors.Is(err, authn.ErrGrantRequired) {
		t.Fatalf("ConsumeGrant missing row: err=%v, want ErrGrantRequired", err)
	}

	closed := enrollmentHandlerPool(t)
	closed.Close()
	if _, err := authn.PeekGrant(context.Background(), closed, pred); err == nil || errors.Is(err, authn.ErrGrantRequired) {
		t.Fatalf("PeekGrant closed pool: err=%v, want a wrapped lookup error", err)
	}
	if _, err := authn.ConsumeGrant(context.Background(), closed, pred); err == nil || errors.Is(err, authn.ErrGrantRequired) {
		t.Fatalf("ConsumeGrant closed pool: err=%v, want a wrapped lookup error", err)
	}
}
