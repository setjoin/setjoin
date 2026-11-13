package handlers

// possession_statement_fault_test.go — the §4.1 statement-level fault tests
// through the REAL handlers (r2 defect 5c), using the established
// trigger-injection precedent (guest_invite_test.go):
//
//   - TestBudgetBookkeepingFaultRefusesAndPreserves: a fault injected at the
//     named budget statement INSIDE the issuance/finish transaction → 500,
//     NO grant, and the counter/lock state EXACTLY as before the attempt
//     (fail-closed + preserved; the transactional rollback carries nothing
//     partial).
//   - TestGrantAuditFaultRollsBackAll: a fault at the §2.4 success-audit
//     INSERT rolls back the mutation, the grant/ceremony consumption, the
//     generation bump AND the audit — nothing partial commits.
//
// Triggers are scoped to the fixture user (WHEN clause) and dropped in
// t.Cleanup, so no other test or parcel observes them.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// seedFaultTrigger installs a trigger that RAISES when stmt fires for the
// given user, and drops it (and its function) at cleanup. fn and trig must
// be unique per call site.
func seedFaultTrigger(t *testing.T, h *AuthHandler, fn, trig, createSQL string) {
	t.Helper()
	if _, err := h.pool.Exec(context.Background(), createSQL); err != nil {
		t.Fatalf("install fault trigger: %v", err)
	}
	t.Cleanup(func() {
		h.pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS `+trig+` ON `+triggerTable(trig))
		h.pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+fn+`()`)
	})
}

// triggerTable maps the test's trigger names to their tables (kept explicit —
// the cleanup must target the same table the trigger was created on).
func triggerTable(trig string) string {
	switch trig {
	case "fault_possession_webauthn_increment":
		return "users"
	case "fault_totp_increment":
		return "users"
	case "fault_totp_reset":
		return "users"
	case "fault_grant_insert":
		return "mfa_reauth_step_ups"
	case "fault_register_audit":
		return "admin_audit_log"
	}
	panic("unknown trigger " + trig)
}

func TestBudgetBookkeepingFaultRefusesAndPreserves(t *testing.T) {
	h := newPossessionHarness(t)
	ctx := context.Background()

	// C1 fixture with an enabled TOTP secret, one enrolled UV credential
	// (BeginLogin requires at least one live credential), and a session
	// bearer.
	userID, claims := newPossessionUserWithEmail(t, h, "fault-budget", true)
	seedEnabledTOTP(t, h, userID)
	bearer, err := h.jwt.IssueAccess(userID, claims.Email, false)
	if err != nil {
		t.Fatalf("issue bearer: %v", err)
	}

	// A LIVE management-assertion ceremony through the real begin (session
	// admission): the finish below will evaluate an INVALID assertion against
	// it.
	beginReq := httptest.NewRequest(http.MethodPost, "/auth/mfa/possession/webauthn/begin",
		strings.NewReader(`{"operation":"recovery.regenerate"}`))
	beginReq.Header.Set("Content-Type", "application/json")
	beginReq.Header.Set("Authorization", "Bearer "+bearer)
	beginRR := httptest.NewRecorder()
	h.MFAPossessionWebAuthnBegin(beginRR, beginReq)
	if beginRR.Code != http.StatusOK {
		t.Fatalf("begin status = %d body %s, want 200", beginRR.Code, beginRR.Body.String())
	}

	before := readWebAuthnBudget(t, h, userID)
	// Fault at the §2.3 webauthn_uv increment statement (the evaluated-failure
	// bookkeeping inside the finish transaction).
	uid := strconv.FormatInt(userID, 10)
	seedFaultTrigger(t, h,
		"possession_fault_webauthn_increment", "fault_possession_webauthn_increment",
		`CREATE FUNCTION possession_fault_webauthn_increment() RETURNS trigger AS $fn$
		 BEGIN
		   RAISE EXCEPTION 'injected budget bookkeeping failure';
		 END $fn$ LANGUAGE plpgsql`)
	if _, err := h.pool.Exec(ctx, `
		CREATE TRIGGER fault_possession_webauthn_increment
		BEFORE UPDATE OF possession_webauthn_failed_attempts ON users
		FOR EACH ROW WHEN (NEW.id = `+uid+` AND NEW.possession_webauthn_failed_attempts = OLD.possession_webauthn_failed_attempts + 1)
		EXECUTE FUNCTION possession_fault_webauthn_increment()`); err != nil {
		t.Fatalf("create increment trigger: %v", err)
	}

	// Finish with an assertion that PARSES but cannot verify against the
	// ceremony (wrong challenge) — the evaluated-failure path whose increment
	// is now faulted. (The machinery-vs-observation split, r7: an
	// UNPARSEABLE body would answer 400 invalid_request without ever
	// reaching the counter, so this fixture must be a well-formed assertion
	// that is merely WRONG.)
	cdJSON := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"type":"webauthn.get","challenge":"wrong","origin":"http://localhost:8080"}`))
	authData := base64.RawURLEncoding.EncodeToString(make([]byte, 37)) // rpIdHash(32)+flags(1)+counter(4)
	body := `{"id":"dGVzdA","rawId":"dGVzdA","type":"public-key",` +
		`"response":{"authenticatorData":"` + authData + `","clientDataJSON":"` + cdJSON + `","signature":"AA","userHandle":null},` +
		`"operation":"recovery.regenerate"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/possession/webauthn/finish", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	rr := httptest.NewRecorder()
	h.MFAPossessionWebAuthnFinish(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("faulted finish status = %d body %s, want 500 (TOTPBookkeepingError-grade refusal)", rr.Code, rr.Body.String())
	}
	after := readWebAuthnBudget(t, h, userID)
	if after.Attempts != before.Attempts || (after.LockedUntil == nil) != (before.LockedUntil == nil) {
		t.Fatalf("budget disturbed by the faulted attempt: before %+v after %+v — the rollback must preserve exact state", before, after)
	}
	// The ceremony was NOT consumed (the guard failed, state stays live).
	var ceremonies int
	if err := h.pool.QueryRow(ctx,
		`SELECT count(*) FROM webauthn_ceremonies WHERE user_id = $1 AND kind = 'management_assertion'`, userID,
	).Scan(&ceremonies); err != nil || ceremonies != 1 {
		t.Fatalf("management_assertion rows = %d (%v), want 1 — the faulted finish must not consume the ceremony", ceremonies, err)
	}
	// And NO grant was issued.
	if n := countGrantsFor(t, h, userID); n != 0 {
		t.Fatalf("grant rows = %d after the faulted finish, want 0", n)
	}
}

// webAuthnBudgetState is the possession webauthn_uv counter pair.
type webAuthnBudgetState struct {
	Attempts    int
	LockedUntil *time.Time
}

func readWebAuthnBudget(t *testing.T, h *AuthHandler, userID int64) webAuthnBudgetState {
	t.Helper()
	var s webAuthnBudgetState
	if err := h.pool.QueryRow(context.Background(),
		`SELECT COALESCE(possession_webauthn_failed_attempts, 0), possession_webauthn_locked_until FROM users WHERE id = $1`,
		userID).Scan(&s.Attempts, &s.LockedUntil); err != nil {
		t.Fatalf("read webauthn budget: %v", err)
	}
	return s
}

// TestTOTPBudgetFaultAtIncrementRefusesAndPreserves runs the same fail-closed
// check through the TOTP issuance arm: a faulted counter increment inside the
// §2.3 one-cycle yields 500 with the counters EXACTLY as before (the §2.3
// caller table's TOTPBookkeepingError mapping through the REAL handler).
func TestTOTPBudgetFaultAtIncrementRefusesAndPreserves(t *testing.T) {
	h := newPossessionHarness(t)
	ctx := context.Background()

	userID, claims := newPossessionUserWithEmail(t, h, "fault-totpbudget", false)
	seedEnabledTOTP(t, h, userID)

	beforeAt, beforeLock := readTOTPBudget(t, h, userID)
	if beforeAt != 0 || beforeLock != nil {
		t.Fatalf("fixture budget not clean: %d %v", beforeAt, beforeLock)
	}

	uid := strconv.FormatInt(userID, 10)
	seedFaultTrigger(t, h,
		"possession_fault_totp_increment", "fault_totp_increment",
		`CREATE FUNCTION possession_fault_totp_increment() RETURNS trigger AS $fn$
		 BEGIN
		   RAISE EXCEPTION 'injected totp budget bookkeeping failure';
		 END $fn$ LANGUAGE plpgsql`)
	if _, err := h.pool.Exec(ctx, `
		CREATE TRIGGER fault_totp_increment
		BEFORE UPDATE OF totp_failed_attempts ON users
		FOR EACH ROW WHEN (NEW.id = `+uid+` AND NEW.totp_failed_attempts = OLD.totp_failed_attempts + 1)
		EXECUTE FUNCTION possession_fault_totp_increment()`); err != nil {
		t.Fatalf("create totp increment trigger: %v", err)
	}

	rr := postPossession(h, "/auth/mfa/possession/totp",
		map[string]any{"operation": "recovery.regenerate", "code": "000000"}, nil, claims)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("faulted issuance status = %d body %s, want 500", rr.Code, rr.Body.String())
	}
	afterAt, afterLock := readTOTPBudget(t, h, userID)
	if afterAt != 0 || afterLock != nil {
		t.Fatalf("totp budget disturbed: %d %v — the faulted cycle rolled back, state must be exactly as before", afterAt, afterLock)
	}
	if n := countGrantsFor(t, h, userID); n != 0 {
		t.Fatalf("grant rows = %d after the faulted issuance, want 0", n)
	}
}

// TestGrantInsertFaultIssuesNothing (the §4.1 budget-family fault at the
// grant statement itself): a fault injected at the grant INSERT inside a
// SUCCESSFUL proof's issuance transaction → 500, NO grant, and the verified
// proof's counter reset rolls back WITH it (no accepted-alongside-a-reset-
// error state).
func TestGrantInsertFaultIssuesNothing(t *testing.T) {
	h := newPossessionHarness(t)
	ctx := context.Background()

	userID, claims := newPossessionUserWithEmail(t, h, "fault-grant", false)
	seedEnabledTOTP(t, h, userID)
	// Park the counter at 4 so the success path's reset is a REAL statement
	// (UPDATE users SET totp_failed_attempts = 0) whose rollback is visible.
	if _, err := h.pool.Exec(ctx,
		`UPDATE users SET totp_failed_attempts = 4 WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}

	seedFaultTrigger(t, h,
		"possession_fault_grant_insert", "fault_grant_insert",
		`CREATE FUNCTION possession_fault_grant_insert() RETURNS trigger AS $fn$
		 BEGIN
		   RAISE EXCEPTION 'injected grant issuance failure';
		 END $fn$ LANGUAGE plpgsql`)
	uid := strconv.FormatInt(userID, 10)
	if _, err := h.pool.Exec(ctx, `
		CREATE TRIGGER fault_grant_insert
		BEFORE INSERT ON mfa_reauth_step_ups
		FOR EACH ROW WHEN (NEW.user_id = `+uid+`)
		EXECUTE FUNCTION possession_fault_grant_insert()`); err != nil {
		t.Fatalf("create grant trigger: %v", err)
	}

	code, err := totp.GenerateCode(removalTestSecret, time.Now())
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	rr := postPossession(h, "/auth/mfa/possession/totp",
		map[string]any{"operation": "recovery.regenerate", "code": code}, nil, claims)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("faulted issuance status = %d body %s, want 500", rr.Code, rr.Body.String())
	}
	if n := countGrantsFor(t, h, userID); n != 0 {
		t.Fatalf("grant rows = %d after the faulted grant INSERT, want 0 — a faulted mint must not half-issue", n)
	}
	// The counter reset rolled back WITH the grant: still 4, never 0.
	afterAt, afterLock := readTOTPBudget(t, h, userID)
	if afterAt != 4 || afterLock != nil {
		t.Fatalf("counter after the faulted success = %d %v, want 4/nil (reset rolled back with the grant)", afterAt, afterLock)
	}
}

// TestGrantAuditFaultRollsBackAll is the §4.1 named case through the REAL
// registration finish: a fault at the §2.4 success-audit INSERT rolls back
// the credential persistence, the ceremony+grant consumption, the generation
// bump AND the audit — nothing partial commits — and the SAME finish then
// succeeds once the fault is removed (no consumed-but-uncommitted state).
func TestGrantAuditFaultRollsBackAll(t *testing.T) {
	// The register harness carries the cookie key the wa_reg_sess transport
	// encrypts with.
	h := newRegisterHarness(t)
	authr, err := newSoftwareAuthenticator("localhost", "http://localhost:8080")
	if err != nil {
		t.Fatalf("software authenticator: %v", err)
	}
	userID, claims := newPossessionUserWithEmail(t, h, "fault-audit", false)
	seedEnabledTOTP(t, h, userID)
	claims.FamilyID = "F"

	// Public flows to a ready registration finish: TOTP proof → register
	// grant → begin binds the grant and creates the ceremony.
	proofCode, err := totp.GenerateCode(removalTestSecret, time.Now())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	ir := postPossession(h, "/auth/mfa/possession/totp",
		map[string]any{"operation": "webauthn.register", "code": proofCode}, nil, claims)
	if ir.Code != http.StatusOK {
		t.Fatalf("issuance status = %d body %s, want 200", ir.Code, ir.Body.String())
	}
	var issuance struct {
		ReauthToken string `json:"reauth_token"`
	}
	if err := json.Unmarshal(ir.Body.Bytes(), &issuance); err != nil || issuance.ReauthToken == "" {
		t.Fatalf("issuance body %s (%v)", ir.Body.String(), err)
	}
	challenge, sessCookie := registerBegin(t, h, userID, claims, issuance.ReauthToken)
	att, err := authr.AttestationResponse(challenge)
	if err != nil {
		t.Fatalf("attestation: %v", err)
	}

	// The §2.4 audit fault.
	uid := strconv.FormatInt(userID, 10)
	seedFaultTrigger(t, h,
		"possession_fault_register_audit", "fault_register_audit",
		`CREATE FUNCTION possession_fault_register_audit() RETURNS trigger AS $fn$
		 BEGIN
		   RAISE EXCEPTION 'injected audit failure';
		 END $fn$ LANGUAGE plpgsql`)
	if _, err := h.pool.Exec(context.Background(), `
		CREATE TRIGGER fault_register_audit
		BEFORE INSERT ON admin_audit_log
		FOR EACH ROW WHEN (NEW.user_id = `+uid+` AND NEW.action = 'passkey_registered')
		EXECUTE FUNCTION possession_fault_register_audit()`); err != nil {
		t.Fatalf("create audit trigger: %v", err)
	}

	dr := postRegisterFinish(h, userID, claims.JTI, claims.Email, "F", sessCookie, att, issuance.ReauthToken, "")
	if dr.Code != http.StatusInternalServerError {
		t.Fatalf("faulted finish status = %d body %s, want 500", dr.Code, dr.Body.String())
	}

	// NOTHING partial committed.
	if n := countRegisteredCredentials(t, h, userID); n != 0 {
		t.Fatalf("credentials = %d after the faulted finish, want 0 — the mutation must roll back with the audit", n)
	}
	if gen := readFactorGeneration(t, h, userID); gen != 0 {
		t.Fatalf("factor_generation = %d after the faulted finish, want 0 — the bump rolls back with the audit", gen)
	}
	if n := countRegistrationAudits(t, h, userID); n != 0 {
		t.Fatalf("audit rows = %d after the faulted finish, want 0", n)
	}
	if n := countGrantsFor(t, h, userID); n != 1 {
		t.Fatalf("grant rows = %d after the faulted finish, want 1 — consumption rolls back with the audit", n)
	}
	var ceremonies int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM webauthn_ceremonies WHERE user_id = $1 AND kind = 'registration'`, userID,
	).Scan(&ceremonies); err != nil || ceremonies != 1 {
		t.Fatalf("registration ceremony rows = %d (%v), want 1 — the single-use delete rolls back with the audit", ceremonies, err)
	}

	// Fault removed (t.Cleanup runs at test end, so drop early here): the
	// SAME ceremony + grant complete — proving the faulted attempt consumed
	// nothing.
	if _, err := h.pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS fault_register_audit ON admin_audit_log`); err != nil {
		t.Fatal(err)
	}
	att2, err := authr.AttestationResponse(challenge)
	if err != nil {
		t.Fatalf("attestation 2: %v", err)
	}
	er := postRegisterFinish(h, userID, claims.JTI, claims.Email, "F", sessCookie, att2, issuance.ReauthToken, "")
	if er.Code != http.StatusCreated {
		t.Fatalf("retry finish status = %d body %s, want 201 — the faulted attempt must have consumed nothing", er.Code, er.Body.String())
	}
	if n := countRegisteredCredentials(t, h, userID); n != 1 {
		t.Fatalf("credentials after the retry = %d, want 1", n)
	}
}

// seedTOTPLockReadFault parks totp_locked_until at 'infinity' for the fixture
// user: pgx refuses to scan an infinite timestamptz into *time.Time, so the
// §2.3 step-1 budget READ fails for THIS user only — a statement-fault
// injection for the read that triggers cannot reach. Cleanup restores NULL.
func seedTOTPLockReadFault(t *testing.T, h *AuthHandler, userID int64) {
	t.Helper()
	if _, err := h.pool.Exec(context.Background(),
		`UPDATE users SET totp_locked_until = 'infinity'::timestamptz WHERE id = $1`, userID,
	); err != nil {
		t.Fatalf("seed budget-read fault: %v", err)
	}
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`UPDATE users SET totp_locked_until = NULL WHERE id = $1`, userID)
	})
}

// TestTOTPBudgetReadFaultRefusedThroughEveryCallerMapping covers the §2.3
// caller table's budget-READ row (r3 acceptance F-iii): when the cycle's
// step-1 lock-state read ERRORS (the historical read was fail-OPEN — an error
// read as "unlocked" — the repair made it fail CLOSED as TOTPBookkeepingError),
// EVERY shared-cycle caller must refuse 500 with the budget EXACTLY as before,
// no tokens, no grants.
func TestTOTPBudgetReadFaultRefusedThroughEveryCallerMapping(t *testing.T) {
	h := newPossessionHarness(t)
	ctx := context.Background()

	userID, claims := newPossessionUserWithEmail(t, h, "fault-budgetread", false)
	seedEnabledTOTP(t, h, userID)
	if _, err := h.pool.Exec(ctx,
		`UPDATE users SET totp_failed_attempts = 2,
		                  password_hash = $2 WHERE id = $1`,
		userID, mustHash(t, "correct-horse-battery"),
	); err != nil {
		t.Fatal(err)
	}
	seedTOTPLockReadFault(t, h, userID)

	pending, err := h.jwt.IssueMFAPending(userID, claims.Email)
	if err != nil {
		t.Fatalf("issue mfa pending: %v", err)
	}

	// login: TOTPVerify → the read fault is the cycle's first statement →
	// 500 "internal error"; no tokens minted.
	rr := httptest.NewRequest(http.MethodPost, "/auth/totp/verify",
		strings.NewReader(`{"mfa_token":"`+pending+`","code":"000000"}`))
	rr.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.TOTPVerify(w, rr)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("login: status = %d body %s, want 500 (bookkeeping refusal)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "access_token") {
		t.Fatal("login: a faulted budget read must never mint tokens")
	}

	// forgot-password: 500 with the NO-enumeration mapping (no constant-time
	// delay theater on infrastructure failure — a bare internal error).
	fv := httptest.NewRequest(http.MethodPost, "/auth/forgot-password/verify",
		strings.NewReader(`{"email":"`+claims.Email+`","code":"000000"}`))
	fv.Header.Set("Content-Type", "application/json")
	fw := httptest.NewRecorder()
	h.ForgotPasswordVerify(fw, fv)
	if fw.Code != http.StatusInternalServerError {
		t.Fatalf("forgot-password: status = %d body %s, want 500 (bookkeeping refusal)", fw.Code, fw.Body.String())
	}

	// removal: BeginTOTPRemoval's cycle read faults → the default (500) arm,
	// never a factor mutation.
	rv := httptest.NewRequest(http.MethodPost, "/auth/totp/removal/begin",
		strings.NewReader(`{"password":"correct-horse-battery","code":"000000"}`))
	rv.Header.Set("Content-Type", "application/json")
	rv = rv.WithContext(ContextWithUser(rv.Context(), claims))
	rw := httptest.NewRecorder()
	h.TOTPRemovalBegin(rw, rv)
	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("removal: status = %d body %s, want 500 (bookkeeping refusal)", rw.Code, rw.Body.String())
	}
	if strings.Contains(rw.Body.String(), "step_up_token") {
		t.Fatal("removal: a faulted budget read must never mint a step-up token")
	}

	// possession issuance: the fourth §2.3 caller (r2's increment-fault arm,
	// now with the READ fault).
	ir := postPossession(h, "/auth/mfa/possession/totp",
		map[string]any{"operation": "recovery.regenerate", "code": "000000"}, nil, claims)
	if ir.Code != http.StatusInternalServerError {
		t.Fatalf("possession issuance: status = %d body %s, want 500 (bookkeeping refusal)", ir.Code, ir.Body.String())
	}
	if n := countGrantsFor(t, h, userID); n != 0 {
		t.Fatalf("grant rows = %d after faulted calls, want 0", n)
	}

	// The budget is EXACTLY as before the faulted calls: 2 evaluated failures
	// (parked) and the fault marker untouched — the cycle rolled back, and no
	// caller treated the failed read as an unlocked budget. (The marker reads
	// through a text cast: scanning 'infinity' is itself the fault.)
	var at int
	var lockText *string
	if err := h.pool.QueryRow(ctx,
		`SELECT totp_failed_attempts, totp_locked_until::text FROM users WHERE id = $1`, userID,
	).Scan(&at, &lockText); err != nil {
		t.Fatal(err)
	}
	if at != 2 {
		t.Fatalf("counter = %d after the faulted calls, want exactly 2 (preserved)", at)
	}
	if lockText == nil || *lockText != "infinity" {
		t.Fatalf("fault marker disturbed: %v, want infinity (the faulted calls never wrote the budget)", lockText)
	}
}

// TestTOTPBudgetResetFaultAtSuccessRefusesAndPreserves covers the §2.3
// caller table's budget-RESET row (r3 acceptance F-iii): a fault injected at
// the success-path reset (`UPDATE ... SET totp_failed_attempts = 0`) inside a
// VALID code's cycle → the cycle is bookkeeping-failed → the login caller
// answers 500, mints NO tokens, and the counter/lock are EXACTLY as before —
// the successful verification never half-applies.
func TestTOTPBudgetResetFaultAtSuccessRefusesAndPreserves(t *testing.T) {
	h := newPossessionHarness(t)
	ctx := context.Background()

	userID, claims := newPossessionUserWithEmail(t, h, "fault-budgetreset", false)
	seedEnabledTOTP(t, h, userID)
	// Park at 4 so the success path's reset is a REAL rewrite (4 → 0).
	if _, err := h.pool.Exec(ctx,
		`UPDATE users SET totp_failed_attempts = 4 WHERE id = $1`, userID,
	); err != nil {
		t.Fatal(err)
	}

	seedFaultTrigger(t, h,
		"possession_fault_totp_reset", "fault_totp_reset",
		`CREATE OR REPLACE FUNCTION possession_fault_totp_reset() RETURNS trigger AS $fn$
		 BEGIN
		   RAISE EXCEPTION 'injected totp budget reset failure';
		 END $fn$ LANGUAGE plpgsql`)
	uid := strconv.FormatInt(userID, 10)
	if _, err := h.pool.Exec(ctx, `
		DROP TRIGGER IF EXISTS fault_totp_reset ON users;
		CREATE TRIGGER fault_totp_reset
		BEFORE UPDATE OF totp_failed_attempts ON users
		FOR EACH ROW WHEN (NEW.id = `+uid+` AND NEW.totp_failed_attempts = 0 AND OLD.totp_failed_attempts <> 0)
		EXECUTE FUNCTION possession_fault_totp_reset()`); err != nil {
		t.Fatalf("create reset trigger: %v", err)
	}

	pending, err := h.jwt.IssueMFAPending(userID, claims.Email)
	if err != nil {
		t.Fatalf("issue mfa pending: %v", err)
	}
	// A VALID code: the cycle must reach the success-path reset whose
	// statement is faulted (an invalid code would fail at verify instead).
	validCode, err := totp.GenerateCode(removalTestSecret, time.Now())
	if err != nil {
		t.Fatalf("valid code: %v", err)
	}
	rr := httptest.NewRequest(http.MethodPost, "/auth/totp/verify",
		strings.NewReader(`{"mfa_token":"`+pending+`","code":"`+validCode+`"}`))
	rr.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.TOTPVerify(w, rr)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("faulted reset: status = %d body %s, want 500 (bookkeeping refusal)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "access_token") {
		t.Fatal("a faulted reset must never mint tokens — the verification never half-applies")
	}

	at, lock := readTOTPBudget(t, h, userID)
	if at != 4 || lock != nil {
		t.Fatalf("budget disturbed by the faulted reset: %d %v, want exactly 4/nil (rolled back)", at, lock)
	}
}

// triggerTableEntry registers a table name for a new trigger (triggerTable
// must know every fault trigger's table so cleanup targets the right one).
// fault_totp_reset is already mapped to users by the r3 reset-fault test; the
// reset-fault callers below reuse that trigger through their REAL handlers.

// TestTOTPBudgetResetFaultThroughEveryCaller extends the §2.3 caller table's
// budget-RESET row (r4 acceptance F-a) beyond the login arm: the success-path
// reset (`UPDATE ... SET totp_failed_attempts = 0` from a non-zero counter) is
// faulted ONCE, and a VALID code is then driven through ALL FOUR shared-cycle
// callers' REAL handlers — login (TOTPVerify), forgot-password
// (ForgotPasswordVerify), removal (TOTPRemovalBegin) and possession issuance
// (MFAPossessionTOTP). Every caller must fail CLOSED with its mapped 500, mint
// NO artifact (tokens, reset_token, step-up token, grant), and leave the
// counter/lock EXACTLY as parked — a successful verification never half-applies
// through any caller.
func TestTOTPBudgetResetFaultThroughEveryCaller(t *testing.T) {
	h := newPossessionHarness(t)
	ctx := context.Background()

	userID, claims := newPossessionUserWithEmail(t, h, "fault-reset-all", false)
	seedEnabledTOTP(t, h, userID)
	if _, err := h.pool.Exec(ctx,
		`UPDATE users SET totp_failed_attempts = 4,
		                  password_hash = $2 WHERE id = $1`,
		userID, mustHash(t, "correct-horse-battery"),
	); err != nil {
		t.Fatal(err)
	}
	// The forgot-password verify consumes the per-account recovery budget and
	// rides the per-IP enum guard: run this test against its own fresh guard so
	// the global limiter's state cannot leak in.
	withEnumGuard(t, 100, time.Minute)

	seedFaultTrigger(t, h,
		"possession_fault_totp_reset", "fault_totp_reset",
		`CREATE OR REPLACE FUNCTION possession_fault_totp_reset() RETURNS trigger AS $fn$
		 BEGIN
		   RAISE EXCEPTION 'injected totp budget reset failure';
		 END $fn$ LANGUAGE plpgsql`)
	uid := strconv.FormatInt(userID, 10)
	if _, err := h.pool.Exec(ctx, `
		DROP TRIGGER IF EXISTS fault_totp_reset ON users;
		CREATE TRIGGER fault_totp_reset
		BEFORE UPDATE OF totp_failed_attempts ON users
		FOR EACH ROW WHEN (NEW.id = `+uid+` AND NEW.totp_failed_attempts = 0 AND OLD.totp_failed_attempts <> 0)
		EXECUTE FUNCTION possession_fault_totp_reset()`); err != nil {
		t.Fatalf("create reset trigger: %v", err)
	}

	validCode := func() string {
		code, err := totp.GenerateCode(removalTestSecret, time.Now())
		if err != nil {
			t.Fatalf("valid code: %v", err)
		}
		return code
	}
	assertPreserved := func(stage string) {
		t.Helper()
		at, lock := readTOTPBudget(t, h, userID)
		if at != 4 || lock != nil {
			t.Fatalf("%s: budget disturbed by the faulted reset: %d %v, want exactly 4/nil (rolled back)", stage, at, lock)
		}
		if n := countGrantsFor(t, h, userID); n != 0 {
			t.Fatalf("%s: grant rows = %d, want 0", stage, n)
		}
	}

	// (1) login: TOTPVerify with a VALID code reaches the faulted reset.
	pending, err := h.jwt.IssueMFAPending(userID, claims.Email)
	if err != nil {
		t.Fatalf("issue mfa pending: %v", err)
	}
	w := httptest.NewRecorder()
	h.TOTPVerify(w, httptest.NewRequest(http.MethodPost, "/auth/totp/verify",
		strings.NewReader(`{"mfa_token":"`+pending+`","code":"`+validCode()+`"}`)))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("login: status = %d body %s, want 500 (bookkeeping refusal)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "access_token") {
		t.Fatal("login: a faulted reset must never mint tokens")
	}
	assertPreserved("login")

	// (2) forgot-password: the same cycle drives its TOTP branch.
	fw := httptest.NewRecorder()
	h.ForgotPasswordVerify(fw, httptest.NewRequest(http.MethodPost, "/auth/forgot-password/verify",
		strings.NewReader(`{"email":"`+claims.Email+`","code":"`+validCode()+`"}`)))
	if fw.Code != http.StatusInternalServerError {
		t.Fatalf("forgot-password: status = %d body %s, want 500 (bookkeeping refusal)", fw.Code, fw.Body.String())
	}
	if strings.Contains(fw.Body.String(), "reset_token") {
		t.Fatal("forgot-password: a faulted reset must never mint a reset token — no half-applied verification")
	}
	assertPreserved("forgot-password")

	// (3) removal: BeginTOTPRemoval's cycle (password already validated).
	rw := httptest.NewRecorder()
	removalReq := httptest.NewRequest(http.MethodPost, "/auth/totp/removal/begin",
		strings.NewReader(`{"password":"correct-horse-battery","code":"`+validCode()+`"}`))
	removalReq.Header.Set("Content-Type", "application/json")
	removalReq = removalReq.WithContext(ContextWithUser(removalReq.Context(), claims))
	h.TOTPRemovalBegin(rw, removalReq)
	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("removal: status = %d body %s, want 500 (bookkeeping refusal)", rw.Code, rw.Body.String())
	}
	if strings.Contains(rw.Body.String(), "step_up_token") {
		t.Fatal("removal: a faulted reset must never mint a step-up token")
	}
	assertPreserved("removal")

	// (4) possession issuance: the §2.3 ONE cycle inside the issuance tx.
	ir := postPossession(h, "/auth/mfa/possession/totp",
		map[string]any{"operation": "recovery.regenerate", "code": validCode()}, nil, claims)
	if ir.Code != http.StatusInternalServerError {
		t.Fatalf("possession issuance: status = %d body %s, want 500 (bookkeeping refusal)", ir.Code, ir.Body.String())
	}
	assertPreserved("possession-issuance")
}
