package handlers

// possession_gate_arms_test.go — fail-closed arm coverage for the possession
// endpoints (mfa_possession.go) and the gated webauthn register/revoke/list
// arms (webauthn.go). The acceptance matrix and happy paths live in
// mfa_possession_test.go / possession_acceptance_test.go /
// webauthn_register_gate_test.go; this file drives the arms those suites do
// not reach:
//
//   - admission and request-validation refusals (no bearer, impersonated,
//     malformed body, missing members, unknown operations);
//   - fail-closed 500s on every statement failure the arms touch, injected
//     with the established mechanisms: closed pool (tx begin / reads),
//     BEFORE-trigger faults scoped to the fixture user (ceremony create,
//     grant insert, credential persist, generation bump, §2.3 increments),
//     deferred constraint triggers for COMMIT-failure arms, and the
//     'infinity' timestamptz scan fault for *time.Time budget reads;
//   - durable-revocation refusals (a revoked jti turns every gated arm into
//     the typed reauth_required answer);
//   - ceremony tuple enforcement at finish (target_ref byte equality) and
//     the single-use consume contract.
//
// Every test asserts the OBSERVABLE outcome — status contract, no grant, no
// ceremony consumption, counters preserved — never merely line execution.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/authserver/internal/token"
)

// --- shared arms fixtures ---

// errReader is a body that fails mid-read (the transport-level read fault).
type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

// armsImpersonated returns a copy of claims carrying an admin actor — the
// impersonated-bearer shape requireAuth would attach.
func armsImpersonated(claims *token.Claims) *token.Claims {
	imp := *claims
	actor := int64(7)
	imp.AdminActorID = &actor
	return &imp
}

// armsIssueBearer mints an access bearer for the fixture identity.
func armsIssueBearer(t *testing.T, h *AuthHandler, userID int64, email string) string {
	t.Helper()
	bearer, err := h.jwt.IssueAccess(userID, email, false)
	if err != nil {
		t.Fatalf("issue access bearer: %v", err)
	}
	return bearer
}

// armsRevokeJTI seeds a durable jti-scope revocation so the in-transaction
// recheck refuses the presented session.
func armsRevokeJTI(t *testing.T, h *AuthHandler, userID int64, jti string) {
	t.Helper()
	if _, err := h.pool.Exec(context.Background(),
		`INSERT INTO session_revocations (user_id, scope, jti, reason, expires_at)
		 VALUES ($1, 'jti', $2, 'possession-gate-arms fixture', now() + interval '1 hour')`, userID, jti,
	); err != nil {
		t.Fatalf("seed jti revocation: %v", err)
	}
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM session_revocations WHERE user_id = $1 AND scope = 'jti' AND jti = $2`, userID, jti)
	})
}

// armsFaultTrigger installs a user-scoped RAISE trigger and drops it at
// cleanup (the seedFaultTrigger mechanism, table passed explicitly).
func armsFaultTrigger(t *testing.T, h *AuthHandler, fn, trig, table, timing, whenSQL string) {
	t.Helper()
	if _, err := h.pool.Exec(context.Background(), fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $fn$
		BEGIN
		  RAISE EXCEPTION 'injected fault (%%s)', TG_NAME;
		END $fn$;
		CREATE TRIGGER %s %s ON %s
		FOR EACH ROW WHEN (%s) EXECUTE FUNCTION %s()`,
		fn, trig, timing, table, whenSQL, fn)); err != nil {
		t.Fatalf("install arms fault trigger on %s: %v", table, err)
	}
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS `+trig+` ON `+table)
		_, _ = h.pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+fn+`()`)
	})
}

// armsDeferredCommitFault installs a DEFERRED constraint trigger that raises
// at COMMIT (the commit-failure seam; 40001 serializable-failure code).
// timing selects AFTER UPDATE (users) or AFTER INSERT (append-only tables);
// an INSERT trigger's WHEN clause may not reference OLD values.
func armsDeferredCommitFault(t *testing.T, h *AuthHandler, fn, trig, table, timing, whenSQL string) {
	t.Helper()
	if _, err := h.pool.Exec(context.Background(), fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $fn$
		BEGIN
		  RAISE EXCEPTION 'injected commit failure' USING ERRCODE='40001';
		END $fn$;
		CREATE CONSTRAINT TRIGGER %s %s ON %s
		DEFERRABLE INITIALLY DEFERRED
		FOR EACH ROW WHEN (%s) EXECUTE FUNCTION %s()`,
		fn, trig, timing, table, whenSQL, fn)); err != nil {
		t.Fatalf("install deferred commit fault on %s: %v", table, err)
	}
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS `+trig+` ON `+table)
		_, _ = h.pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+fn+`()`)
	})
}

// armsParkBudget sets a possession budget column to the given SQL expression
// (e.g. "now() + interval '10 min'" for a lock, "'infinity'" for a read
// fault) and resets it to NULL at cleanup.
func armsParkBudget(t *testing.T, h *AuthHandler, column, sqlExpr string, userID int64) {
	t.Helper()
	if _, err := h.pool.Exec(context.Background(),
		`UPDATE users SET `+column+` = `+sqlExpr+` WHERE id = $1`, userID); err != nil {
		t.Fatalf("park %s: %v", column, err)
	}
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`UPDATE users SET `+column+` = NULL WHERE id = $1`, userID)
	})
}

// armsGrantSeed inserts one session-scope grant row directly and returns the
// raw token (the fixture device for gated arms whose grants are not minted
// through public flows).
func armsGrantSeed(t *testing.T, h *AuthHandler, userID int64, jti, operation, proofMethod string, target *string) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := armsRandRead(raw); err != nil {
		t.Fatalf("seed grant entropy: %v", err)
	}
	tok := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(tok))
	if _, err := h.pool.Exec(context.Background(),
		`DELETE FROM mfa_reauth_step_ups WHERE user_id = $1`, userID); err != nil {
		t.Fatalf("seed grant cleanup: %v", err)
	}
	if _, err := h.pool.Exec(context.Background(), `
		INSERT INTO mfa_reauth_step_ups
		  (token_hash, user_id, session_jti, operation, target_ref,
		   proof_method, bound_factor_generation, token_scope, refresh_family_id, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6,
		         (SELECT factor_generation FROM users WHERE id = $2),
		         'session', 'F', now() + interval '5 minutes')`,
		hex.EncodeToString(sum[:]), userID, jti, operation, target, proofMethod,
	); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	return tok
}

func armsPostTOTP(h *AuthHandler, payload map[string]any, headers map[string]string, claims *token.Claims) *httptest.ResponseRecorder {
	return postPossession(h, "/auth/mfa/possession/totp", payload, headers, claims)
}

func armsPostBegin(h *AuthHandler, payload map[string]any, headers map[string]string, claims *token.Claims) *httptest.ResponseRecorder {
	return postPossession(h, "/auth/mfa/possession/webauthn/begin", payload, headers, claims)
}

func armsPostFinishBody(h *AuthHandler, body string, headers map[string]string, claims *token.Claims) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/possession/webauthn/finish", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if claims != nil {
		req = req.WithContext(ContextWithUser(req.Context(), claims))
	}
	rr := httptest.NewRecorder()
	h.MFAPossessionWebAuthnFinish(rr, req)
	return rr
}

// --- mfa_possession.go arms ---

// armsLegacyPasskey satisfies the handler passkeyProvider seam WITHOUT the
// management-assertion ceremony methods — the configuration posture of an
// embedder that wired WebAuthn login before the possession gate existed.
type armsLegacyPasskey struct{}

func (armsLegacyPasskey) BeginRegistration(context.Context, int64) ([]byte, []byte, error) {
	return nil, nil, errors.New("arms legacy provider: not implemented")
}

func (armsLegacyPasskey) FinishRegistration(context.Context, int64, []byte, *http.Request) error {
	return errors.New("arms legacy provider: not implemented")
}

func (armsLegacyPasskey) BeginLogin(context.Context, string) (int64, []byte, []byte, error) {
	return 0, nil, nil, errors.New("arms legacy provider: not implemented")
}

func (armsLegacyPasskey) FinishLogin(context.Context, int64, []byte, *http.Request) error {
	return errors.New("arms legacy provider: not implemented")
}

func (armsLegacyPasskey) NameCredential(context.Context, []byte, int64, string) error {
	return errors.New("arms legacy provider: not implemented")
}

func (armsLegacyPasskey) RevokeCredential(context.Context, []byte, int64) error {
	return errors.New("arms legacy provider: not implemented")
}

func TestPossessionWebAuthnUnavailableWithoutCeremonySeam(t *testing.T) {
	pool := enrollmentHandlerPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	// The passkey seam is present but does NOT implement the ceremony
	// interface: once the wire admission succeeds, ceremonyProvider returns
	// nil and the endpoints answer 404 — the unconfigured-ceremony posture.
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
	h.passkey = &armsLegacyPasskey{}
	userID, claims := newPossessionUser(t, h, "arms-noprov", true)
	bearer := armsIssueBearer(t, h, userID, claims.Email)
	hdrs := map[string]string{"Authorization": "Bearer " + bearer}
	if rr := armsPostBegin(h, map[string]any{"operation": "recovery.regenerate"}, hdrs, claims); rr.Code != http.StatusNotFound {
		t.Fatalf("begin without ceremony seam = %d body %s, want 404", rr.Code, rr.Body.String())
	}
	if rr := armsPostFinishBody(h, `{"operation":"recovery.regenerate"}`, hdrs, claims); rr.Code != http.StatusNotFound {
		t.Fatalf("finish without ceremony seam = %d, want 404", rr.Code)
	}
}

func TestPossessionFinishBodyFaultArms(t *testing.T) {
	h := newPossessionHarness(t)

	// A body that fails mid-read is a 400 — the raw bytes never decode.
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/possession/webauthn/finish", errReader{err: fmt.Errorf("injected read failure")})
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.MFAPossessionWebAuthnFinish(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("finish with erroring body = %d, want 400", rr.Code)
	}

	// A body that reads but does not parse is the same refusal shape.
	if rr := armsPostFinishBody(h, "{not-json", nil, nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("finish with unparseable body = %d, want 400", rr.Code)
	}
	// The response is a problem document naming the decode failure.
	if !strings.Contains(rr.Body.String(), "invalid JSON") {
		t.Fatalf("finish decode refusal body = %s, want the invalid-JSON problem", rr.Body.String())
	}
}

func TestPossessionTOTPRequestValidationArms(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUser(t, h, "arms-val", false)
	_ = userID

	// Nothing presented: the bearer funnel writes the uniform 401.
	if rr := armsPostTOTP(h, map[string]any{"operation": "recovery.regenerate"}, nil, nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("totp arm without a bearer = %d, want 401", rr.Code)
	}

	// Unparseable body: 400 before any validation.
	bad := httptest.NewRequest(http.MethodPost, "/auth/mfa/possession/totp", strings.NewReader("{not-json"))
	bad.Header.Set("Content-Type", "application/json")
	bad = bad.WithContext(ContextWithUser(bad.Context(), claims))
	brr := httptest.NewRecorder()
	h.MFAPossessionTOTP(brr, bad)
	if brr.Code != http.StatusBadRequest {
		t.Fatalf("totp arm with unparseable body = %d, want 400", brr.Code)
	}

	// Unknown operation: the T1 parity gate refuses before the code is read.
	if rr := armsPostTOTP(h, map[string]any{"operation": "not-an-operation", "code": "000000"}, nil, claims); rr.Code != http.StatusBadRequest {
		t.Fatalf("totp arm with unknown operation = %d body %s, want 400", rr.Code, rr.Body.String())
	}
	// Missing code: the evaluated proof needs the code member.
	if rr := armsPostTOTP(h, map[string]any{"operation": "recovery.regenerate"}, nil, claims); rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "code is required") {
		t.Fatalf("totp arm without code = %d body %s, want 400 naming the code", rr.Code, rr.Body.String())
	}
}

func TestPossessionTOTPFailClosedArms(t *testing.T) {
	userID, claims, closed, open := armsTOTPFailClosedFixture(t, "arms-totp-failclosed")

	// (a) A closed pool fails the issuance tx at Begin: 500, no grant.
	if rr := armsPostTOTP(closed, map[string]any{"operation": "recovery.regenerate", "code": "000000"}, nil, claims); rr.Code != http.StatusInternalServerError {
		t.Fatalf("totp arm with closed pool = %d, want 500", rr.Code)
	}
	if n := countGrantsFor(t, open, userID); n != 0 {
		t.Fatalf("grant rows after closed-pool attempt = %d, want 0", n)
	}
}

// armsTOTPFailClosedFixture builds the (a) closed-pool and (b) live handlers
// plus an enabled-TOTP C1 fixture.
func armsTOTPFailClosedFixture(t *testing.T, label string) (int64, *token.Claims, *AuthHandler, *AuthHandler) {
	t.Helper()
	open := newPossessionHarness(t)
	userID, claims := newPossessionUserWithEmail(t, open, label, false)
	seedEnabledTOTP(t, open, userID)

	closed := enrollmentHandlerPool(t)
	ensureEnrollmentLocalDomain(t, closed)
	closed.Close()
	return userID, claims, NewAuthHandler(AuthHandlerConfig{Pool: closed, JWT: newTestJWT(), Logger: discardLogger()}), open
}

func TestPossessionTOTPFenceFaultArms(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUserWithEmail(t, h, "arms-totp-fence", false)
	seedEnabledTOTP(t, h, userID)

	// Person-fence fault: the fence FUNCTION is replaced for this user only,
	// restoring the captured definition at cleanup.
	var original string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT pg_get_functiondef('identity_auth_person_fence(bigint)'::regprocedure)`).Scan(&original); err != nil {
		t.Fatalf("capture original fence: %v", err)
	}
	if _, err := h.pool.Exec(context.Background(), fmt.Sprintf(`CREATE OR REPLACE FUNCTION identity_auth_person_fence(p_user_id BIGINT) RETURNS void
		LANGUAGE plpgsql AS $fn$
		BEGIN
		  IF p_user_id = %d THEN
		    RAISE EXCEPTION 'injected person fence failure';
		  END IF;
		  PERFORM pg_advisory_xact_lock(hashtextextended('identity-person:'||p_user_id::text, 0));
		END $fn$;`, userID)); err != nil {
		t.Fatalf("install fence fault: %v", err)
	}
	t.Cleanup(func() {
		if _, err := h.pool.Exec(context.Background(), original); err != nil {
			t.Errorf("restore identity_auth_person_fence: %v", err)
		}
	})

	if rr := armsPostTOTP(h, map[string]any{"operation": "recovery.regenerate", "code": "000000"}, nil, claims); rr.Code != http.StatusInternalServerError {
		t.Fatalf("totp arm under fence fault = %d, want 500", rr.Code)
	}
	if n := countGrantsFor(t, h, userID); n != 0 {
		t.Fatalf("grant rows under fence fault = %d, want 0", n)
	}
}

func TestPossessionTOTPUsersFenceDeletedUserArm(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUserWithEmail(t, h, "arms-totp-deleted", false)
	seedEnabledTOTP(t, h, userID)
	if _, err := h.pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID); err != nil {
		t.Fatalf("delete fixture user: %v", err)
	}
	// The users fence observes the missing row and fails closed; the person
	// fence (an advisory lock) passes, proving the refusal is the FENCE arm.
	if rr := armsPostTOTP(h, map[string]any{"operation": "recovery.regenerate", "code": "000000"}, nil, claims); rr.Code != http.StatusInternalServerError {
		t.Fatalf("totp arm for a deleted user = %d, want 500", rr.Code)
	}
}

func TestPossessionTOTPTargetOwnershipArm(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUserWithEmail(t, h, "arms-totp-target", false)
	seedEnabledTOTP(t, h, userID)
	code, err := totp.GenerateCode(removalTestSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// A syntactically valid target that no credential owns: the §3.2 T4
	// ownership check inside the issuance tx refuses with the single 400.
	foreign := "QUFBQUFBQUFBQUFBQUFBQQ" // base64url("AAAAAAAAAAAAAAAA")
	if rr := armsPostTOTP(h, map[string]any{"operation": "webauthn.revoke", "code": code, "target_ref": foreign}, nil, claims); rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid_target") {
		t.Fatalf("totp arm with foreign target = %d body %s, want 400 invalid_target", rr.Code, rr.Body.String())
	}
	if n := countGrantsFor(t, h, userID); n != 0 {
		t.Fatalf("grant rows after foreign target = %d, want 0", n)
	}
}

func TestPossessionTOTPEvaluatedFailureCommitFault(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUserWithEmail(t, h, "arms-totp-commit", false)
	seedEnabledTOTP(t, h, userID)

	// A deferred constraint trigger fires at COMMIT after the evaluated
	// failure's bookkeeping increment: the refusal commit fails, the handler
	// must answer 500 and the tx must roll back the increment.
	armsDeferredCommitFault(t, h, "arms_totp_eval_commit_fault", "arms_totp_eval_commit_trig", "users", "AFTER UPDATE",
		"NEW.id = "+itoaInt(userID)+" AND NEW.totp_failed_attempts = OLD.totp_failed_attempts + 1")

	if rr := armsPostTOTP(h, map[string]any{"operation": "recovery.regenerate", "code": "000000"}, nil, claims); rr.Code != http.StatusInternalServerError {
		t.Fatalf("faulted evaluated-failure commit = %d, want 500", rr.Code)
	}
	at, lock := readTOTPBudget(t, h, userID)
	if at != 0 || lock != nil {
		t.Fatalf("counter after faulted refusal = %d/%v, want exactly 0/nil (the increment rolled back)", at, lock)
	}
	if n := countGrantsFor(t, h, userID); n != 0 {
		t.Fatalf("grant rows after faulted refusal = %d, want 0", n)
	}
}

func TestPossessionTOTPSuccessGrantCommitFault(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUserWithEmail(t, h, "arms-totp-grant-commit", false)
	seedEnabledTOTP(t, h, userID)
	if _, err := h.pool.Exec(context.Background(),
		`UPDATE users SET totp_failed_attempts = 4 WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}

	// A deferred trigger on the grant INSERT fires at COMMIT after the valid
	// proof's budget reset: the whole success must roll back — no grant, and
	// the counter stays parked at 4.
	armsDeferredCommitFault(t, h, "arms_totp_grant_commit_fault", "arms_totp_grant_commit_trig", "mfa_reauth_step_ups", "AFTER INSERT",
		"NEW.user_id = "+itoaInt(userID))

	code, err := totp.GenerateCode(removalTestSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rr := armsPostTOTP(h, map[string]any{"operation": "recovery.regenerate", "code": code}, nil, claims); rr.Code != http.StatusInternalServerError {
		t.Fatalf("faulted success commit = %d, want 500", rr.Code)
	}
	at, lock := readTOTPBudget(t, h, userID)
	if at != 4 || lock != nil {
		t.Fatalf("counter after faulted success = %d/%v, want exactly 4/nil (the reset rolled back)", at, lock)
	}
	if n := countGrantsFor(t, h, userID); n != 0 {
		t.Fatalf("grant rows after faulted success = %d, want 0", n)
	}
}

func itoaInt(n int64) string { return fmt.Sprintf("%d", n) }

func TestPossessionBeginGuardArms(t *testing.T) {
	h := newPossessionHarness(t)

	t.Run("impersonated bearer refused", func(t *testing.T) {
		userID, claims := newPossessionUser(t, h, "arms-beg-imp", true)
		// Admission reads the WIRE: the impersonated bearer itself is what the
		// endpoint sees, so the refusal must fire on its claims.
		impBearer, err := h.jwt.IssueImpersonation(userID, claims.Email, 7, "standard")
		if err != nil {
			t.Fatalf("issue impersonated bearer: %v", err)
		}
		hdrs := map[string]string{"Authorization": "Bearer " + impBearer}
		if rr := armsPostBegin(h, map[string]any{"operation": "recovery.regenerate"}, hdrs, claims); rr.Code != http.StatusForbidden {
			t.Fatalf("begin with impersonated bearer = %d, want 403", rr.Code)
		}
		var ceremonies int
		if err := h.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM webauthn_ceremonies WHERE user_id = $1`, userID).Scan(&ceremonies); err != nil || ceremonies != 0 {
			t.Fatalf("ceremony rows after impersonated begin = %d (%v), want 0", ceremonies, err)
		}
	})

	t.Run("revoked jti answers the typed reauth_required", func(t *testing.T) {
		userID, claims := newPossessionUser(t, h, "arms-beg-revoked", true)
		bearer := armsIssueBearer(t, h, userID, claims.Email)
		// Admission reads the wire: the recheck keys on the ADMITTED bearer's
		// JTI, so revoke exactly that identity.
		wireClaims, err := h.jwt.Validate(bearer)
		if err != nil {
			t.Fatalf("validate fixture bearer: %v", err)
		}
		armsRevokeJTI(t, h, userID, wireClaims.JTI)
		rr := armsPostBegin(h, map[string]any{"operation": "recovery.regenerate"},
			map[string]string{"Authorization": "Bearer " + bearer}, claims)
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), ReauthRequiredCode) {
			t.Fatalf("begin with revoked jti = %d body %s, want 403 reauth_required", rr.Code, rr.Body.String())
		}
		var ceremonies int
		if err := h.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM webauthn_ceremonies WHERE user_id = $1`, userID).Scan(&ceremonies); err != nil || ceremonies != 0 {
			t.Fatalf("ceremony rows after revoked begin = %d (%v), want 0", ceremonies, err)
		}
	})

	t.Run("non-C1 cohort refused with the possession-required contract", func(t *testing.T) {
		userID, claims := newPossessionUser(t, h, "arms-beg-c3", false)
		bearer := armsIssueBearer(t, h, userID, claims.Email)
		rr := armsPostBegin(h, map[string]any{"operation": "recovery.regenerate"},
			map[string]string{"Authorization": "Bearer " + bearer}, claims)
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), PossessionRequiredCode) {
			t.Fatalf("begin for a zero-factor account = %d body %s, want 403 possession required", rr.Code, rr.Body.String())
		}
	})

	t.Run("locked webauthn budget refuses 429 without minting", func(t *testing.T) {
		userID, claims := newPossessionUser(t, h, "arms-beg-locked", true)
		bearer := armsIssueBearer(t, h, userID, claims.Email)
		armsParkBudget(t, h, "possession_webauthn_locked_until", "now() + interval '10 min'", userID)
		rr := armsPostBegin(h, map[string]any{"operation": "recovery.regenerate"},
			map[string]string{"Authorization": "Bearer " + bearer}, claims)
		if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("begin under lock = %d, want 429", rr.Code)
		}
	})

	t.Run("faulted budget read fails closed with 500", func(t *testing.T) {
		userID, claims := newPossessionUser(t, h, "arms-beg-readfault", true)
		bearer := armsIssueBearer(t, h, userID, claims.Email)
		armsParkBudget(t, h, "possession_webauthn_locked_until", "'infinity'::timestamptz", userID)
		rr := armsPostBegin(h, map[string]any{"operation": "recovery.regenerate"},
			map[string]string{"Authorization": "Bearer " + bearer}, claims)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("begin with faulted budget read = %d, want 500", rr.Code)
		}
	})

	t.Run("foreign revoke target refuses at begin", func(t *testing.T) {
		userID, claims := newPossessionUser(t, h, "arms-beg-target", true)
		bearer := armsIssueBearer(t, h, userID, claims.Email)
		foreign := "QUFBQUFBQUFBQUFBQUFBQQ"
		rr := armsPostBegin(h, map[string]any{"operation": "webauthn.revoke", "target_ref": foreign},
			map[string]string{"Authorization": "Bearer " + bearer}, claims)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid_target") {
			t.Fatalf("begin with foreign target = %d body %s, want 400 invalid_target", rr.Code, rr.Body.String())
		}
	})
}

func TestPossessionBeginFailClosedArms(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUser(t, h, "arms-beg-fail", true)
	bearer := armsIssueBearer(t, h, userID, claims.Email)
	hdrs := map[string]string{"Authorization": "Bearer " + bearer}
	payload := map[string]any{"operation": "recovery.regenerate"}

	t.Run("closed pool fails the begin tx", func(t *testing.T) {
		closed := enrollmentHandlerPool(t)
		ensureEnrollmentLocalDomain(t, closed)
		closed.Close()
		ch := NewAuthHandler(AuthHandlerConfig{Pool: closed, JWT: newTestJWT(), Logger: discardLogger(), Passkey: h.passkey.(*authn.PasskeyProvider)})
		if rr := armsPostBegin(ch, payload, hdrs, claims); rr.Code != http.StatusInternalServerError {
			t.Fatalf("begin with closed pool = %d, want 500", rr.Code)
		}
	})

	t.Run("person fence fault fails closed", func(t *testing.T) {
		var original string
		if err := h.pool.QueryRow(context.Background(),
			`SELECT pg_get_functiondef('identity_auth_person_fence(bigint)'::regprocedure)`).Scan(&original); err != nil {
			t.Fatalf("capture original fence: %v", err)
		}
		if _, err := h.pool.Exec(context.Background(), fmt.Sprintf(`CREATE OR REPLACE FUNCTION identity_auth_person_fence(p_user_id BIGINT) RETURNS void
			LANGUAGE plpgsql AS $fn$
			BEGIN
			  IF p_user_id = %d THEN
			    RAISE EXCEPTION 'injected begin fence failure';
			  END IF;
			  PERFORM pg_advisory_xact_lock(hashtextextended('identity-person:'||p_user_id::text, 0));
			END $fn$;`, userID)); err != nil {
			t.Fatalf("install fence fault: %v", err)
		}
		t.Cleanup(func() {
			if _, err := h.pool.Exec(context.Background(), original); err != nil {
				t.Errorf("restore fence: %v", err)
			}
		})
		if rr := armsPostBegin(h, payload, hdrs, claims); rr.Code != http.StatusInternalServerError {
			t.Fatalf("begin under fence fault = %d, want 500", rr.Code)
		}
	})

	t.Run("deleted user fails the users fence", func(t *testing.T) {
		dID, dClaims := newPossessionUser(t, h, "arms-beg-del", true)
		dBearer := armsIssueBearer(t, h, dID, dClaims.Email)
		if _, err := h.pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, dID); err != nil {
			t.Fatal(err)
		}
		rr := armsPostBegin(h, payload, map[string]string{"Authorization": "Bearer " + dBearer}, dClaims)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("begin for a deleted user = %d, want 500", rr.Code)
		}
	})

	t.Run("disabled user fails the assertion options mint", func(t *testing.T) {
		// The UV-capable user load rides the begin tx and filters
		// enabled = TRUE: a disabled account fails the options mint AFTER the
		// cohort/budget guards passed — the fail-closed 500.
		disID, disClaims := newPossessionUser(t, h, "arms-beg-disabled", true)
		disBearer := armsIssueBearer(t, h, disID, disClaims.Email)
		if _, err := h.pool.Exec(context.Background(),
			`UPDATE users SET enabled = FALSE WHERE id = $1`, disID); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = h.pool.Exec(context.Background(), `UPDATE users SET enabled = TRUE WHERE id = $1`, disID)
		})
		rr := armsPostBegin(h, payload, map[string]string{"Authorization": "Bearer " + disBearer}, disClaims)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("begin for a disabled user = %d, want 500", rr.Code)
		}
	})

	t.Run("faulted ceremony create fails closed", func(t *testing.T) {
		armsFaultTrigger(t, h, "arms_begin_ceremony_fault", "arms_begin_ceremony_trig", "webauthn_ceremonies", "BEFORE INSERT",
			"NEW.user_id = "+itoaInt(userID))
		if rr := armsPostBegin(h, payload, hdrs, claims); rr.Code != http.StatusInternalServerError {
			t.Fatalf("begin with faulted ceremony create = %d, want 500", rr.Code)
		}
	})

	t.Run("faulted begin commit rolls back the ceremony", func(t *testing.T) {
		armsDeferredCommitFault(t, h, "arms_begin_commit_fault", "arms_begin_commit_trig", "webauthn_ceremonies", "AFTER INSERT",
			"NEW.user_id = "+itoaInt(userID))
		if rr := armsPostBegin(h, payload, hdrs, claims); rr.Code != http.StatusInternalServerError {
			t.Fatalf("begin with faulted commit = %d, want 500", rr.Code)
		}
		var ceremonies int
		if err := h.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM webauthn_ceremonies WHERE user_id = $1`, userID).Scan(&ceremonies); err != nil || ceremonies != 0 {
			t.Fatalf("ceremony rows after faulted commit = %d (%v), want 0 (rolled back)", ceremonies, err)
		}
	})
}

func TestPossessionFinishCeremonyArms(t *testing.T) {
	h := newPossessionHarness(t)

	t.Run("faulted ceremony lookup fails closed", func(t *testing.T) {
		userID, _ := newPossessionUser(t, h, "arms-fin-lookup", true)
		pending, err := h.jwt.IssueMFAPending(userID, "arms-fin-lookup@example.test")
		if err != nil {
			t.Fatal(err)
		}
		closed := enrollmentHandlerPool(t)
		ensureEnrollmentLocalDomain(t, closed)
		closed.Close()
		ch := NewAuthHandler(AuthHandlerConfig{Pool: closed, JWT: newTestJWT(), Logger: discardLogger(), Passkey: h.passkey.(*authn.PasskeyProvider)})
		rr := armsPostFinishBody(ch, `{"operation":"bootstrap.totp.enroll","mfa_token":"`+pending+`"}`, nil, nil)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("finish with faulted ceremony lookup = %d body %s, want 500", rr.Code, rr.Body.String())
		}
	})

	t.Run("finish target_ref must byte-equal the ceremony binding", func(t *testing.T) {
		userID, claims := newPossessionUser(t, h, "arms-fin-target", true)
		seedEnabledTOTP(t, h, userID)
		credID := seedUVPasskey(t, h, userID, "", true)
		target := armsB64URL(credID)
		bearer := armsIssueBearer(t, h, userID, claims.Email)
		hdrs := map[string]string{"Authorization": "Bearer " + bearer}
		tok := armsGrantSeed(t, h, userID, claims.JTI, "webauthn.revoke", "totp", &target)

		// begin binds the ceremony to the revoke target...
		br := armsPostBegin(h, map[string]any{"operation": "webauthn.revoke", "target_ref": target}, hdrs, claims)
		if br.Code != http.StatusOK {
			t.Fatalf("revoke begin = %d body %s, want 200", br.Code, br.Body.String())
		}
		// ...and the finish MUST present the same target: absent → 400.
		fr := armsPostFinishBody(h, `{"operation":"webauthn.revoke"}`,
			map[string]string{"Authorization": "Bearer " + bearer, ReauthTokenHeader: ""}, claims)
		_ = tok
		if fr.Code != http.StatusBadRequest || !strings.Contains(fr.Body.String(), "target_mismatch") {
			t.Fatalf("finish without the ceremony target = %d body %s, want 400 target_mismatch", fr.Code, fr.Body.String())
		}
		// A plain ceremony rejects a PRESENTED target just the same.
		br2 := armsPostBegin(h, map[string]any{"operation": "recovery.regenerate"}, hdrs, claims)
		if br2.Code != http.StatusOK {
			t.Fatalf("plain begin = %d body %s, want 200", br2.Code, br2.Body.String())
		}
		fr2 := armsPostFinishBody(h, `{"operation":"recovery.regenerate","target_ref":"`+target+`"}`,
			map[string]string{"Authorization": "Bearer " + bearer}, claims)
		if fr2.Code != http.StatusBadRequest || !strings.Contains(fr2.Body.String(), "target_mismatch") {
			t.Fatalf("plain finish with a target = %d body %s, want 400 target_mismatch", fr2.Code, fr2.Body.String())
		}
	})

	t.Run("impersonated finish refused after the ceremony checks", func(t *testing.T) {
		userID, claims := newPossessionUser(t, h, "arms-fin-imp", true)
		bearer := armsIssueBearer(t, h, userID, claims.Email)
		br := armsPostBegin(h, map[string]any{"operation": "recovery.regenerate"},
			map[string]string{"Authorization": "Bearer " + bearer}, claims)
		if br.Code != http.StatusOK {
			t.Fatalf("begin = %d body %s, want 200", br.Code, br.Body.String())
		}
		// The finish presents the IMPERSONATED bearer on the wire: admission
		// succeeds, then the unconditional impersonation refusal fires.
		impBearer, err := h.jwt.IssueImpersonation(userID, claims.Email, 7, "standard")
		if err != nil {
			t.Fatalf("issue impersonated bearer: %v", err)
		}
		fr := armsPostFinishBody(h, `{"operation":"recovery.regenerate"}`,
			map[string]string{"Authorization": "Bearer " + impBearer}, claims)
		if fr.Code != http.StatusForbidden {
			t.Fatalf("finish with impersonated bearer = %d body %s, want 403", fr.Code, fr.Body.String())
		}
		// The ceremony survives: the refusal is impersonation, not consumption.
		var ceremonies int
		if err := h.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM webauthn_ceremonies WHERE user_id = $1 AND kind = 'management_assertion'`, userID).Scan(&ceremonies); err != nil || ceremonies != 1 {
			t.Fatalf("ceremony rows after impersonated finish = %d (%v), want 1 (not consumed)", ceremonies, err)
		}
	})
}

func armsB64URL(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	out := make([]byte, 0, (len(b)*8+5)/6)
	var buf, bits int
	for _, c := range b {
		buf = buf<<8 | int(c)
		bits += 8
		for bits >= 6 {
			bits -= 6
			out = append(out, alphabet[buf>>bits&0x3f])
		}
	}
	if bits > 0 {
		out = append(out, alphabet[buf<<(6-bits)&0x3f])
	}
	return string(out)
}

func armsRandRead(b []byte) (int, error) {
	for i := range b {
		b[i] = byte(i*7 + 3)
	}
	return len(b), nil
}

func TestPossessionFinishFailClosedArms(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUser(t, h, "arms-fin-fail", true)
	bearer := armsIssueBearer(t, h, userID, claims.Email)
	hdrs := map[string]string{"Authorization": "Bearer " + bearer}
	finishBody := `{"operation":"recovery.regenerate"}`

	liveCeremony := func(t *testing.T) {
		t.Helper()
		br := armsPostBegin(h, map[string]any{"operation": "recovery.regenerate"}, hdrs, claims)
		if br.Code != http.StatusOK {
			t.Fatalf("begin = %d body %s, want 200", br.Code, br.Body.String())
		}
	}

	t.Run("person fence fault fails the finish closed", func(t *testing.T) {
		liveCeremony(t)
		var original string
		if err := h.pool.QueryRow(context.Background(),
			`SELECT pg_get_functiondef('identity_auth_person_fence(bigint)'::regprocedure)`).Scan(&original); err != nil {
			t.Fatal(err)
		}
		if _, err := h.pool.Exec(context.Background(), fmt.Sprintf(`CREATE OR REPLACE FUNCTION identity_auth_person_fence(p_user_id BIGINT) RETURNS void
			LANGUAGE plpgsql AS $fn$
			BEGIN
			  IF p_user_id = %d THEN
			    RAISE EXCEPTION 'injected finish fence failure';
			  END IF;
			  PERFORM pg_advisory_xact_lock(hashtextextended('identity-person:'||p_user_id::text, 0));
			END $fn$;`, userID)); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = h.pool.Exec(context.Background(), original)
		})
		if rr := armsPostFinishBody(h, finishBody, hdrs, claims); rr.Code != http.StatusInternalServerError {
			t.Fatalf("finish under fence fault = %d, want 500", rr.Code)
		}
	})

	t.Run("revoked jti refuses the finish with the typed 403", func(t *testing.T) {
		rID, rClaims := newPossessionUser(t, h, "arms-fin-revoked", true)
		rBearer := armsIssueBearer(t, h, rID, rClaims.Email)
		rHdrs := map[string]string{"Authorization": "Bearer " + rBearer}
		if br := armsPostBegin(h, map[string]any{"operation": "recovery.regenerate"}, rHdrs, rClaims); br.Code != http.StatusOK {
			t.Fatalf("begin = %d, want 200", br.Code)
		}
		// The finish recheck keys on the ADMITTED bearer's JTI (the ceremony
		// is bound to it) — revoke that identity after the begin.
		wireClaims, err := h.jwt.Validate(rBearer)
		if err != nil {
			t.Fatalf("validate fixture bearer: %v", err)
		}
		armsRevokeJTI(t, h, rID, wireClaims.JTI)
		rr := armsPostFinishBody(h, finishBody, rHdrs, rClaims)
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), ReauthRequiredCode) {
			t.Fatalf("finish with revoked jti = %d body %s, want 403 reauth_required", rr.Code, rr.Body.String())
		}
		var ceremonies int
		if err := h.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM webauthn_ceremonies WHERE user_id = $1 AND kind = 'management_assertion'`, rID).Scan(&ceremonies); err != nil || ceremonies != 1 {
			t.Fatalf("ceremony rows after revoked finish = %d (%v), want 1 (not consumed)", ceremonies, err)
		}
	})

	t.Run("faulted budget read fails the finish closed", func(t *testing.T) {
		fID, fClaims := newPossessionUser(t, h, "arms-fin-readfault", true)
		fBearer := armsIssueBearer(t, h, fID, fClaims.Email)
		fHdrs := map[string]string{"Authorization": "Bearer " + fBearer}
		if br := armsPostBegin(h, map[string]any{"operation": "recovery.regenerate"}, fHdrs, fClaims); br.Code != http.StatusOK {
			t.Fatalf("begin = %d, want 200", br.Code)
		}
		armsParkBudget(t, h, "possession_webauthn_locked_until", "'infinity'::timestamptz", fID)
		if rr := armsPostFinishBody(h, finishBody, fHdrs, fClaims); rr.Code != http.StatusInternalServerError {
			t.Fatalf("finish with faulted budget read = %d, want 500", rr.Code)
		}
	})
}

// --- webauthn.go (gated register / revoke / list) arms ---

func TestWebAuthnRegisterBeginAdmissionArms(t *testing.T) {
	h := newRegisterHarness(t)
	userID, email, claims := seedC1UserWithPassword(t, h, "arms-regb", nil)

	t.Run("unauthenticated begin is refused", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/webauthn/register/begin", nil)
		rr := httptest.NewRecorder()
		h.WebAuthnRegisterBegin(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("register begin without claims = %d, want 401", rr.Code)
		}
	})

	t.Run("impersonated context claims are refused unconditionally", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/webauthn/register/begin", nil)
		req = req.WithContext(ContextWithUser(req.Context(), armsImpersonated(claims)))
		rr := httptest.NewRecorder()
		h.WebAuthnRegisterBegin(rr, req)
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "impersonation_forbidden") {
			t.Fatalf("register begin with impersonated claims = %d body %s, want 403", rr.Code, rr.Body.String())
		}
	})
	_ = email
	_ = userID
}

func TestWebAuthnRegisterBeginResumeArms(t *testing.T) {
	h := newRegisterHarness(t)
	userID, email, claims := seedC1UserWithPassword(t, h, "arms-regb-resume", nil)

	// First begin (registerChallenge seeds the live webauthn.register grant
	// and returns ITS raw token): binds the grant to the ceremony's challenge.
	_, _, tok, _ := registerChallenge(t, h, userID, claims.JTI, email)

	// RESUME: a second begin with the SAME bound grant answers 200
	// {"status":"bound"} — no second ceremony, no re-binding.
	req := httptest.NewRequest(http.MethodGet, "/auth/webauthn/register/begin", nil)
	req.Header.Set(ReauthTokenHeader, tok)
	req = req.WithContext(ContextWithUser(req.Context(), claims))
	rr := httptest.NewRecorder()
	h.WebAuthnRegisterBegin(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "bound") {
		t.Fatalf("resume begin = %d body %s, want 200 bound", rr.Code, rr.Body.String())
	}
	var ceremonies int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM webauthn_ceremonies WHERE user_id = $1 AND kind = 'registration'`, userID).Scan(&ceremonies); err != nil || ceremonies != 1 {
		t.Fatalf("ceremony rows after resume = %d (%v), want 1", ceremonies, err)
	}

	// Bound grant with a DEAD ceremony: the fail-closed 409 — re-prove.
	if _, err := h.pool.Exec(context.Background(),
		`DELETE FROM webauthn_ceremonies WHERE user_id = $1 AND kind = 'registration'`, userID); err != nil {
		t.Fatal(err)
	}
	rr2 := httptest.NewRecorder()
	h.WebAuthnRegisterBegin(rr2, req)
	if rr2.Code != http.StatusConflict || !strings.Contains(rr2.Body.String(), "proof_already_bound") {
		t.Fatalf("resume with dead ceremony = %d body %s, want 409 proof_already_bound", rr2.Code, rr2.Body.String())
	}
}

func TestWebAuthnRegisterBeginFaultArms(t *testing.T) {
	h := newRegisterHarness(t)
	userID, _, claims := seedC1UserWithPassword(t, h, "arms-regb-fault", nil)
	seedEnabledTOTP(t, h, userID)

	t.Run("faulted one-time binding fails closed", func(t *testing.T) {
		tok := seedSessionGrant(t, h, userID, claims.JTI, "webauthn.register", nil, "totp", nil)
		armsFaultTrigger(t, h, "arms_reg_bind_fault", "arms_reg_bind_trig", "mfa_reauth_step_ups", "BEFORE UPDATE",
			"NEW.user_id = "+itoaInt(userID)+" AND OLD.target_ref IS NULL")
		req := httptest.NewRequest(http.MethodGet, "/auth/webauthn/register/begin", nil)
		req.Header.Set(ReauthTokenHeader, tok)
		req = req.WithContext(ContextWithUser(req.Context(), claims))
		rr := httptest.NewRecorder()
		h.WebAuthnRegisterBegin(rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("begin with faulted binding = %d, want 500", rr.Code)
		}
		var target *string
		if err := h.pool.QueryRow(context.Background(),
			`SELECT target_ref FROM mfa_reauth_step_ups WHERE user_id = $1`, userID).Scan(&target); err != nil || target != nil {
			t.Fatalf("target_ref after faulted bind = %v (%v), want NULL (nothing half-bound)", target, err)
		}
	})

	t.Run("faulted ceremony create fails closed", func(t *testing.T) {
		tok := seedSessionGrant(t, h, userID, claims.JTI, "webauthn.register", nil, "totp", nil)
		armsFaultTrigger(t, h, "arms_reg_ceremony_fault", "arms_reg_ceremony_trig", "webauthn_ceremonies", "BEFORE INSERT",
			"NEW.user_id = "+itoaInt(userID))
		req := httptest.NewRequest(http.MethodGet, "/auth/webauthn/register/begin", nil)
		req.Header.Set(ReauthTokenHeader, tok)
		req = req.WithContext(ContextWithUser(req.Context(), claims))
		rr := httptest.NewRecorder()
		h.WebAuthnRegisterBegin(rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("begin with faulted ceremony create = %d, want 500", rr.Code)
		}
	})

	t.Run("faulted begin commit leaves nothing bound", func(t *testing.T) {
		tok := seedSessionGrant(t, h, userID, claims.JTI, "webauthn.register", nil, "totp", nil)
		armsDeferredCommitFault(t, h, "arms_reg_commit_fault", "arms_reg_commit_trig", "webauthn_ceremonies", "AFTER INSERT",
			"NEW.user_id = "+itoaInt(userID))
		req := httptest.NewRequest(http.MethodGet, "/auth/webauthn/register/begin", nil)
		req.Header.Set(ReauthTokenHeader, tok)
		req = req.WithContext(ContextWithUser(req.Context(), claims))
		rr := httptest.NewRecorder()
		h.WebAuthnRegisterBegin(rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("begin with faulted commit = %d, want 500", rr.Code)
		}
		var ceremonies, grants int
		if err := h.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM webauthn_ceremonies WHERE user_id = $1`, userID).Scan(&ceremonies); err != nil || ceremonies != 0 {
			t.Fatalf("ceremony rows after faulted commit = %d (%v), want 0", ceremonies, err)
		}
		if err := h.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM mfa_reauth_step_ups WHERE user_id = $1`, userID).Scan(&grants); err != nil || grants != 1 {
			t.Fatalf("grant rows after faulted commit = %d (%v), want 1 (unconsumed, binding rolled back)", grants, err)
		}
	})
}

// armsRegisterFixture drives a register begin and returns the challenge, the
// session cookie value, the grant token the begin bound, and a fresh
// attestation for the challenge.
func armsRegisterFixture(t *testing.T, h *AuthHandler, userID int64, email string, claimsJTI string) (challenge, cookie, tok string, att []byte, authr *softwareAuthenticator) {
	t.Helper()
	authr, err := newSoftwareAuthenticator("localhost", "http://localhost:8080")
	if err != nil {
		t.Fatalf("software authenticator: %v", err)
	}
	challenge, cookie, tok, _ = registerChallenge(t, h, userID, claimsJTI, email)
	att, err = authr.AttestationResponse(challenge)
	if err != nil {
		t.Fatalf("attestation: %v", err)
	}
	return challenge, cookie, tok, att, authr
}

func TestWebAuthnRegisterFinishRequestArms(t *testing.T) {
	h := newRegisterHarness(t)
	userID, email, claims := seedC1UserWithPassword(t, h, "arms-regf-req", nil)
	seedEnabledTOTP(t, h, userID)
	var cookie, tok string

	// A live begin/cookie pair for the transport-refusal subtests below; the
	// presented token value is irrelevant to those arms (refused earlier).
	_, cookie, tok, _, _ = armsRegisterFixture(t, h, userID, email, claims.JTI)

	t.Run("missing session cookie refused", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/webauthn/register/finish", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(ContextWithUser(req.Context(), claims))
		rr := httptest.NewRecorder()
		h.WebAuthnRegisterFinish(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "missing session cookie") {
			t.Fatalf("finish without cookie = %d body %s, want 400", rr.Code, rr.Body.String())
		}
	})

	t.Run("garbage session cookie refused", func(t *testing.T) {
		rr := postRegisterFinish(h, userID, claims.JTI, email, "F", "not-a-valid-cookie", []byte(`{}`), tok, "")
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid session cookie") {
			t.Fatalf("finish with garbage cookie = %d body %s, want 400", rr.Code, rr.Body.String())
		}
	})

	t.Run("oversized attestation body refused", func(t *testing.T) {
		// The finish buffers the attestation itself under the mount cap: a body
		// beyond it must fail the buffer read with the same 400 shape.
		big := make([]byte, webauthnRegistrationBodyLimit+1)
		for i := range big {
			big[i] = 'a'
		}
		rr := postRegisterFinish(h, userID, claims.JTI, email, "F", cookie, big, tok, "")
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid request body") {
			t.Fatalf("finish with oversized body = %d body %s, want 400", rr.Code, rr.Body.String())
		}
	})
}

func TestWebAuthnRegisterFinishConsumableFaultArms(t *testing.T) {
	h := newRegisterHarness(t)
	userID, email, claims := seedC1UserWithPassword(t, h, "arms-regf-fault", nil)
	seedEnabledTOTP(t, h, userID)

	t.Run("registration verification failure consumed nothing", func(t *testing.T) {
		challenge, cookie, tok, _, _ := armsRegisterFixture(t, h, userID, email, claims.JTI)
		// An attestation over a DIFFERENT challenge fails verification —
		// before any consumption. The seeded grant carries a NULL family, so
		// the finish presents "" (any refusal here is verification's 400, not
		// the §1.7 family mismatch).
		other, err := newSoftwareAuthenticator("localhost", "http://localhost:8080")
		if err != nil {
			t.Fatal(err)
		}
		attOther, err := other.AttestationResponse(challenge + "tampered")
		if err != nil {
			t.Fatal(err)
		}
		rr := postRegisterFinish(h, userID, claims.JTI, email, "", cookie, attOther, tok, "")
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "registration failed") {
			t.Fatalf("finish with tampered attestation = %d body %s, want 400 registration failed", rr.Code, rr.Body.String())
		}
		if n := countRegisteredCredentials(t, h, userID); n != 0 {
			t.Fatalf("credentials after failed verification = %d, want 0 (nothing persisted)", n)
		}
	})

	t.Run("missing ceremony answers the typed reauth_required", func(t *testing.T) {
		_, cookie, tok, att, _ := armsRegisterFixture(t, h, userID, email, claims.JTI)
		// The ceremony row dies between begin and finish.
		if _, err := h.pool.Exec(context.Background(),
			`DELETE FROM webauthn_ceremonies WHERE user_id = $1 AND kind = 'registration'`, userID); err != nil {
			t.Fatal(err)
		}
		rr := postRegisterFinish(h, userID, claims.JTI, email, "F", cookie, att, tok, "")
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), ReauthRequiredCode) {
			t.Fatalf("finish without ceremony = %d body %s, want 403 reauth_required", rr.Code, rr.Body.String())
		}
	})

	t.Run("faulted ceremony consume fails closed", func(t *testing.T) {
		_, cookie, tok, att, _ := armsRegisterFixture(t, h, userID, email, claims.JTI)
		armsFaultTrigger(t, h, "arms_regf_consume_fault", "arms_regf_consume_trig", "webauthn_ceremonies", "BEFORE DELETE",
			"OLD.user_id = "+itoaInt(userID))
		rr := postRegisterFinish(h, userID, claims.JTI, email, "F", cookie, att, tok, "")
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("finish with faulted consume = %d, want 500", rr.Code)
		}
	})

	t.Run("faulted credential persist rolls the finish back", func(t *testing.T) {
		_, cookie, tok, att, _ := armsRegisterFixture(t, h, userID, email, claims.JTI)
		armsFaultTrigger(t, h, "arms_regf_persist_fault", "arms_regf_persist_trig", "passkey_credentials", "BEFORE INSERT",
			"NEW.user_id = "+itoaInt(userID))
		rr := postRegisterFinish(h, userID, claims.JTI, email, "", cookie, att, tok, "")
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("finish with faulted persist = %d, want 500", rr.Code)
		}
		if n := countRegisteredCredentials(t, h, userID); n != 0 {
			t.Fatalf("credentials after faulted persist = %d, want 0 (the insert rolled back)", n)
		}
	})

	t.Run("faulted generation bump rolls the finish back", func(t *testing.T) {
		_, cookie, tok, att, _ := armsRegisterFixture(t, h, userID, email, claims.JTI)
		G := readFactorGeneration(t, h, userID)
		armsFaultTrigger(t, h, "arms_regf_bump_fault", "arms_regf_bump_trig", "users", "BEFORE UPDATE",
			"NEW.id = "+itoaInt(userID)+" AND NEW.factor_generation = OLD.factor_generation + 1")
		rr := postRegisterFinish(h, userID, claims.JTI, email, "", cookie, att, tok, "")
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("finish with faulted bump = %d, want 500", rr.Code)
		}
		if got := readFactorGeneration(t, h, userID); got != G {
			t.Fatalf("factor_generation after faulted bump = %d, want %d (rolled back)", got, G)
		}
	})

	t.Run("faulted finish commit persists nothing", func(t *testing.T) {
		_, cookie, tok, att, _ := armsRegisterFixture(t, h, userID, email, claims.JTI)
		armsDeferredCommitFault(t, h, "arms_regf_commit_fault", "arms_regf_commit_trig", "admin_audit_log", "AFTER INSERT",
			"NEW.user_id = "+itoaInt(userID)+" AND NEW.action = 'passkey_registered'")
		rr := postRegisterFinish(h, userID, claims.JTI, email, "", cookie, att, tok, "")
		if rr.Code != http.StatusInternalServerError {
			var ceremonies, grants int
			var enabled bool
			_ = h.pool.QueryRow(context.Background(),
				`SELECT count(*) FROM webauthn_ceremonies WHERE user_id = $1`, userID).Scan(&ceremonies)
			_ = h.pool.QueryRow(context.Background(),
				`SELECT count(*) FROM mfa_reauth_step_ups WHERE user_id = $1`, userID).Scan(&grants)
			_ = h.pool.QueryRow(context.Background(),
				`SELECT COALESCE(totp_enabled, FALSE) FROM users WHERE id = $1`, userID).Scan(&enabled)
			t.Fatalf("finish with faulted commit = %d body %s want 500 (diag: ceremonies=%d grants=%d totp_enabled=%v)", rr.Code, rr.Body.String(), ceremonies, grants, enabled)
		}
		if n := countRegisteredCredentials(t, h, userID); n != 0 {
			t.Fatalf("credentials after faulted commit = %d, want 0", n)
		}
	})
}

func TestWebAuthnRevokeArms(t *testing.T) {
	h := newRegisterHarness(t)
	userID, _, claims := seedC1UserWithPassword(t, h, "arms-revoke", nil)
	seedEnabledTOTP(t, h, userID)
	credID := seedUVPasskey(t, h, userID, "", true)
	target := base64.RawURLEncoding.EncodeToString(credID)

	revokeReq := func(t *testing.T, credIDParam, reauthToken string, ctxClaims *token.Claims) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodDelete, "/auth/webauthn/credentials/"+credIDParam, nil)
		req.SetPathValue("id", credIDParam)
		if reauthToken != "" {
			req.Header.Set(ReauthTokenHeader, reauthToken)
		}
		if ctxClaims != nil {
			req = req.WithContext(ContextWithUser(req.Context(), ctxClaims))
		}
		rr := httptest.NewRecorder()
		h.WebAuthnRevokeCredential(rr, req)
		return rr
	}

	t.Run("impersonated bearer refused unconditionally", func(t *testing.T) {
		tok := seedSessionGrant(t, h, userID, claims.JTI, "webauthn.revoke", &target, "totp", nil)
		rr := revokeReq(t, target, tok, armsImpersonated(claims))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("revoke with impersonated claims = %d, want 403", rr.Code)
		}
		var revoked *time.Time
		if err := h.pool.QueryRow(context.Background(),
			`SELECT revoked_at FROM passkey_credentials WHERE id = $1`, credID).Scan(&revoked); err != nil || revoked != nil {
			t.Fatalf("credential revoked_at after impersonated revoke = %v (%v), want NULL", revoked, err)
		}
	})

	t.Run("malformed credential id refused", func(t *testing.T) {
		tok := seedSessionGrant(t, h, userID, claims.JTI, "webauthn.revoke", &target, "totp", nil)
		rr := revokeReq(t, "!!!not-base64!!!", tok, claims)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("revoke with malformed id = %d, want 400", rr.Code)
		}
	})

	t.Run("already-revoked target answers the single 400", func(t *testing.T) {
		// Revoke the credential out-of-band, then prove a FRESH grant bound to
		// the (now dead) target at the CURRENT generation: consumption
		// succeeds, the revocation statement matches zero live rows, and the
		// handler answers the single 400 refusal.
		if _, err := h.pool.Exec(context.Background(),
			`UPDATE passkey_credentials SET revoked_at = now() WHERE id = $1`, credID); err != nil {
			t.Fatal(err)
		}
		tok := seedSessionGrant(t, h, userID, claims.JTI, "webauthn.revoke", &target, "totp", nil)
		rr := revokeReq(t, target, tok, claims)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "credential not found or already revoked") {
			t.Fatalf("revoke of a dead credential = %d body %s, want 400", rr.Code, rr.Body.String())
		}
		// The dead-target refusal is NON-burning: the handler writes the 400
		// and the deferred rollback restores the consumed grant (the client
		// may re-target), so exactly the seeded grant survives.
		if n := countGrantsFor(t, h, userID); n != 1 {
			t.Fatalf("grant rows after dead-target revoke = %d, want 1 (the refusal never burns the proof)", n)
		}
	})

	t.Run("faulted revocation update fails closed", func(t *testing.T) {
		// A fresh live credential to target.
		liveID := seedUVPasskey(t, h, userID, "", true)
		liveTarget := base64.RawURLEncoding.EncodeToString(liveID)
		tok := seedSessionGrant(t, h, userID, claims.JTI, "webauthn.revoke", &liveTarget, "totp", nil)
		armsFaultTrigger(t, h, "arms_revoke_update_fault", "arms_revoke_update_trig", "passkey_credentials", "BEFORE UPDATE",
			"NEW.id = decode('"+hexEncode(liveID)+"','hex') AND OLD.revoked_at IS NULL")
		rr := revokeReq(t, liveTarget, tok, claims)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("revoke with faulted update = %d, want 500", rr.Code)
		}
	})

	t.Run("faulted cleanup fails the revoke closed", func(t *testing.T) {
		liveID := seedUVPasskey(t, h, userID, "", true)
		liveTarget := base64.RawURLEncoding.EncodeToString(liveID)
		tok := seedSessionGrant(t, h, userID, claims.JTI, "webauthn.revoke", &liveTarget, "totp", nil)
		// A second outstanding grant proven by the SAME credential (the §2.5
		// cleanup's target): the fault fires only for ITS delete, never for
		// the presented webauthn.revoke consumption.
		if _, err := h.pool.Exec(context.Background(), `
			INSERT INTO mfa_reauth_step_ups
			  (token_hash, user_id, session_jti, operation, target_ref,
			   proof_method, proving_factor_id, bound_factor_generation,
			   token_scope, refresh_family_id, expires_at)
			 VALUES ($1, $2, $3, 'recovery.regenerate', NULL, 'totp', $4,
			         (SELECT factor_generation FROM users WHERE id = $2),
			         'session', 'F', now() + interval '5 minutes')`,
			sha256SumHex("arms-revoke-cleanup-token"), userID, claims.JTI+"-cleanup", liveID); err != nil {
			t.Fatalf("seed cleanup grant: %v", err)
		}
		armsFaultTrigger(t, h, "arms_revoke_cleanup_fault", "arms_revoke_cleanup_trig", "mfa_reauth_step_ups", "BEFORE DELETE",
			"OLD.user_id = "+itoaInt(userID)+" AND OLD.operation <> 'webauthn.revoke'")
		rr := revokeReq(t, liveTarget, tok, claims)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("revoke with faulted cleanup = %d, want 500", rr.Code)
		}
	})

	t.Run("faulted generation bump rolls the revoke back", func(t *testing.T) {
		liveID := seedUVPasskey(t, h, userID, "", true)
		liveTarget := base64.RawURLEncoding.EncodeToString(liveID)
		tok := seedSessionGrant(t, h, userID, claims.JTI, "webauthn.revoke", &liveTarget, "totp", nil)
		G := readFactorGeneration(t, h, userID)
		armsFaultTrigger(t, h, "arms_revoke_bump_fault", "arms_revoke_bump_trig", "users", "BEFORE UPDATE",
			"NEW.id = "+itoaInt(userID)+" AND NEW.factor_generation = OLD.factor_generation + 1")
		rr := revokeReq(t, liveTarget, tok, claims)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("revoke with faulted bump = %d, want 500", rr.Code)
		}
		if got := readFactorGeneration(t, h, userID); got != G {
			t.Fatalf("factor_generation after faulted revoke = %d, want %d (rolled back)", got, G)
		}
	})

	t.Run("faulted audit insert rolls the revoke back", func(t *testing.T) {
		liveID := seedUVPasskey(t, h, userID, "", true)
		liveTarget := base64.RawURLEncoding.EncodeToString(liveID)
		tok := seedSessionGrant(t, h, userID, claims.JTI, "webauthn.revoke", &liveTarget, "totp", nil)
		armsFaultTrigger(t, h, "arms_revoke_audit_fault", "arms_revoke_audit_trig", "admin_audit_log", "BEFORE INSERT",
			"NEW.user_id = "+itoaInt(userID)+" AND NEW.action = 'passkey_revoked'")
		rr := revokeReq(t, liveTarget, tok, claims)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("revoke with faulted audit = %d, want 500", rr.Code)
		}
		var revoked *time.Time
		if err := h.pool.QueryRow(context.Background(),
			`SELECT revoked_at FROM passkey_credentials WHERE id = $1`, liveID).Scan(&revoked); err != nil || revoked != nil {
			t.Fatalf("credential revoked after faulted audit = %v (%v), want NULL (rolled back)", revoked, err)
		}
	})

	t.Run("faulted revoke commit persists nothing", func(t *testing.T) {
		liveID := seedUVPasskey(t, h, userID, "", true)
		liveTarget := base64.RawURLEncoding.EncodeToString(liveID)
		tok := seedSessionGrant(t, h, userID, claims.JTI, "webauthn.revoke", &liveTarget, "totp", nil)
		armsDeferredCommitFault(t, h, "arms_revoke_commit_fault", "arms_revoke_commit_trig", "admin_audit_log", "AFTER INSERT",
			"NEW.user_id = "+itoaInt(userID)+" AND NEW.action = 'passkey_revoked'")
		rr := revokeReq(t, liveTarget, tok, claims)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("revoke with faulted commit = %d, want 500", rr.Code)
		}
		var revoked *time.Time
		if err := h.pool.QueryRow(context.Background(),
			`SELECT revoked_at FROM passkey_credentials WHERE id = $1`, liveID).Scan(&revoked); err != nil || revoked != nil {
			t.Fatalf("credential revoked after faulted commit = %v (%v), want NULL (rolled back)", revoked, err)
		}
	})
}

func TestWebAuthnListCredentialsArms(t *testing.T) {
	h := newRegisterHarness(t)
	userID, _, claims := seedC1UserWithPassword(t, h, "arms-list", nil)
	seedUVPasskey(t, h, userID, "", true)

	req := httptest.NewRequest(http.MethodGet, "/auth/webauthn/credentials", nil)
	req = req.WithContext(ContextWithUser(req.Context(), claims))
	rr := httptest.NewRecorder()
	h.WebAuthnListCredentials(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("credential list = %d body %s, want 200", rr.Code, rr.Body.String())
	}
	var listed struct {
		Credentials []struct {
			UVCapable bool `json:"uv_capable"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &listed); err != nil || len(listed.Credentials) != 1 {
		t.Fatalf("credential list body %s (%v), want exactly the seeded credential", rr.Body.String(), err)
	}
	if !listed.Credentials[0].UVCapable {
		t.Fatal("credential list lost the persisted uv_capable flag (the §1.2 cohort input)")
	}
}
