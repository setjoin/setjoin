package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/testsupport"
)

func TestHashTokenHex(t *testing.T) {
	got := token.HashTokenHex("hello")
	if len(got) != 64 {
		t.Errorf("HashTokenHex length = %d, want 64", len(got))
	}
	if token.HashTokenHex("hello") != got {
		t.Error("HashTokenHex is not deterministic")
	}
	if token.HashTokenHex("world") == got {
		t.Error("different inputs produced same hash")
	}
}

// discardLogger returns a no-op slog logger so handlers that log on failure paths
// do not panic in tests.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// withEnumGuard swaps the process-wide enumIPGuard for a fresh limiter with the
// given budget for the duration of the test, then restores it. This keeps the
// per-IP-limit tests fast and independent of other tests sharing the global.
func withEnumGuard(t *testing.T, limit int, window time.Duration) {
	t.Helper()
	prev := enumIPGuard
	enumIPGuard = authn.NewIPRateLimiter(limit, window)
	t.Cleanup(func() { enumIPGuard = prev })
}

func postJSON(handler http.HandlerFunc, ip string, body map[string]string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":40000"
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

// ── Enumeration: nonexistent vs existing indistinguishable (begin decoy) ─────

// TestForgotPasswordBegin_DecoyResponseUniform proves the begin decoy path (taken
// for a non-existent / unreachable / no-MFA account) returns the EXACT uniform
// body {"method":"totp","message":<generic>} with 200 — byte-identical to what a
// real TOTP account's begin returns. With a closed pool, resolveForgotPasswordMethod
// returns nil (lookup fails), so this exercises the decoy branch directly.
//
// Against the OLD code (which returned method "none" / a different message / a
// 404 for accounts with no MFA or that did not exist) the body or status differed
// by existence — the enumeration oracle this closes.
func TestForgotPasswordBegin_DecoyResponseUniform(t *testing.T) {
	withEnumGuard(t, 100, time.Minute)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool:   createClosedPool(t),
		JWT:    newTestJWT(),
		Logger: discardLogger(),
	})

	rr := postJSON(h.ForgotPasswordBegin, "203.0.113.1", map[string]string{"email": "ghost@example.com"})
	if rr.Code != http.StatusOK {
		t.Fatalf("decoy must return 200 (indistinguishable from a real TOTP account), got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if resp["method"] != "totp" {
		t.Errorf("decoy method = %q, want \"totp\" (must match a real TOTP account)", resp["method"])
	}
	if resp["message"] != msgForgotPasswordGeneric {
		t.Errorf("decoy message = %q, want the generic message", resp["message"])
	}
	// The decoy must NOT leak existence via extra keys (e.g. a nonce only a real
	// push account would carry).
	if _, ok := resp["nonce"]; ok {
		t.Error("decoy response must not include a nonce — that would distinguish it from a non-push account")
	}
	if len(resp) != 2 {
		t.Errorf("decoy body has %d keys, want exactly {method,message}: %v", len(resp), resp)
	}
}

// TestForgotPasswordBegin_TwoEmailsIndistinguishable feeds two different
// non-existent emails and asserts the responses are byte-identical, so an
// attacker cannot tell accounts apart by the begin response.
func TestForgotPasswordBegin_TwoEmailsIndistinguishable(t *testing.T) {
	withEnumGuard(t, 100, time.Minute)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool:   createClosedPool(t),
		JWT:    newTestJWT(),
		Logger: discardLogger(),
	})

	a := postJSON(h.ForgotPasswordBegin, "203.0.113.2", map[string]string{"email": "alice@example.com"})
	b := postJSON(h.ForgotPasswordBegin, "203.0.113.3", map[string]string{"email": "nobody@nowhere.example"})

	if a.Code != b.Code {
		t.Errorf("status differs by email: %d vs %d", a.Code, b.Code)
	}
	if a.Body.String() != b.Body.String() {
		t.Errorf("body differs by email:\n  a=%s\n  b=%s", a.Body.String(), b.Body.String())
	}
}

// ── Per-IP rate limit triggers (shared seam) ────────────────────────────────

// TestForgotPasswordBegin_PerIPLimit proves the shared enumIPGuard caps grinding:
// after the budget is spent from one IP, further requests get a uniform 429. This
// is the per-IP limit the prior wave was missing on forgot-password.
func TestForgotPasswordBegin_PerIPLimit(t *testing.T) {
	withEnumGuard(t, 3, time.Minute)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool:   createClosedPool(t),
		JWT:    newTestJWT(),
		Logger: discardLogger(),
	})

	const ip = "198.51.100.10"
	for i := 0; i < 3; i++ {
		rr := postJSON(h.ForgotPasswordBegin, ip, map[string]string{"email": "x@example.com"})
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d within budget: got %d, want 200", i+1, rr.Code)
		}
	}
	rr := postJSON(h.ForgotPasswordBegin, ip, map[string]string{"email": "x@example.com"})
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("over-budget request: got %d, want 429", rr.Code)
	}

	// A different IP retains its own budget — the limit is per source IP.
	other := postJSON(h.ForgotPasswordBegin, "198.51.100.11", map[string]string{"email": "x@example.com"})
	if other.Code != http.StatusOK {
		t.Errorf("a fresh IP must still be served: got %d", other.Code)
	}
}

// TestForgotPasswordVerify_PerIPLimit proves the SIBLING verify endpoint shares
// the same per-IP cap, so the brute-force surface is closed there too.
func TestForgotPasswordVerify_PerIPLimit(t *testing.T) {
	withEnumGuard(t, 3, time.Minute)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool:   createClosedPool(t),
		JWT:    newTestJWT(),
		Logger: discardLogger(),
	})

	const ip = "198.51.100.20"
	body := map[string]string{"email": "x@example.com", "code": "000000"}
	for i := 0; i < 3; i++ {
		rr := postJSON(h.ForgotPasswordVerify, ip, body)
		// Closed pool => user resolves nil => uniform 401, but within budget.
		if rr.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d within budget unexpectedly 429", i+1)
		}
	}
	rr := postJSON(h.ForgotPasswordVerify, ip, body)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("over-budget verify: got %d, want 429", rr.Code)
	}
}

// ── Source-level guard: TOTP path routes through the lockout seam ────────────

// TestForgotPasswordVerify_TOTPUsesLockoutSeam is the structural proof for fix 3:
// ForgotPasswordVerify's TOTP branch must go through authn.VerifyTOTPWithLockout
// (which enforces the 5-failure lock), NOT the bare authn.VerifyTOTP that the OLD
// code called (which bypassed the lockout). This fails against the old code.
func TestForgotPasswordVerify_TOTPUsesLockoutSeam(t *testing.T) {
	body := handlerFuncBody(t, "forgot_password.go", "ForgotPasswordVerify")
	if !strings.Contains(body, "VerifyTOTPWithLockout") {
		t.Error("ForgotPasswordVerify's TOTP path must use authn.VerifyTOTPWithLockout to inherit the lockout")
	}
	// The bare VerifyTOTP (no lockout) must NOT be called directly here.
	if callsIdentInHandler(t, "forgot_password.go", "ForgotPasswordVerify", "VerifyTOTP") {
		t.Error("ForgotPasswordVerify must not call the bare VerifyTOTP (it bypasses the 5-failure lockout)")
	}
}

// ── Source-level guard: push path routes through the lockout seam ────────────

// TestForgotPasswordVerify_PushUsesLockoutSeam is the structural proof for the
// forgot-password push hardening: the push branch must go through the
// per-account lockout seam (VerifyChallengeWithLockout — 5 failed answers →
// account-level 429, mirroring the TOTP branch) and must NOT call the bare
// VerifyChallenge, whose per-challenge burn an attacker resets by minting fresh
// challenges. ForgotPasswordBegin must stamp its challenges with the recovery
// purpose so the seam only accepts challenges minted by this flow.
func TestForgotPasswordVerify_PushUsesLockoutSeam(t *testing.T) {
	body := handlerFuncBody(t, "forgot_password.go", "ForgotPasswordVerify")
	if !strings.Contains(body, "VerifyChallengeWithLockout") {
		t.Error("ForgotPasswordVerify's push path must use VerifyChallengeWithLockout to inherit the per-account lockout")
	}
	if callsIdentInHandler(t, "forgot_password.go", "ForgotPasswordVerify", "VerifyChallenge") {
		t.Error("ForgotPasswordVerify must not call the bare VerifyChallenge (its per-challenge burn is reset by fresh challenges; the account lockout is the control)")
	}
	if !strings.Contains(body, "PushVerifyLocked") {
		t.Error("ForgotPasswordVerify must map PushVerifyLocked to the 429 lockout response")
	}
	beginBody := handlerFuncBody(t, "forgot_password.go", "ForgotPasswordBegin")
	if !strings.Contains(beginBody, "ForgotPasswordChallengePurpose") {
		t.Error("ForgotPasswordBegin must stamp its push challenge with authn.ForgotPasswordChallengePurpose so the verify seam can bind it")
	}
}

// ── Reset: admin-ness for password policy is DERIVED, not the dead column ─────

// TestForgotPasswordReset_DerivesAdminForPolicy is the regression for the audit
// fix: ForgotPasswordReset now selects the password policy with the DERIVED
// is_admin (isAdminExprSQL) instead of the vestigial users.is_admin column. That
// column is DEFAULT-FALSE for every governed admin (the grant path never sets it),
// so the old raw read applied the WEAKER non-admin policy to admins on the reset
// path. This runs the exact query the handler now runs and asserts a governed
// admin (users.is_admin FALSE + unexpired assignment) derives TRUE. DB-backed;
// skipped when DB_DSN is unset.
//
// (The stricter-password 400-vs-200 end-to-end assertion is not expressible today:
// validate_password's p_is_admin param is currently inert, so no password passes
// the non-admin policy yet fails the admin one. This is the plan's sanctioned
// smallest alternative — it proves the handler derives admin-ness correctly, the
// property the fix restores.)
func TestForgotPasswordReset_DerivesAdminForPolicy(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID, _ := seedDerivationUser(t, pool, ctx, "deriv-fpwd", "irrelevant")
	defer cleanSSOActor(t, pool, ctx, userID)
	grantGovernedAdmin(t, pool, ctx, userID, 2) // group 2 = user_admin builtin

	var isAdmin bool
	if err := pool.QueryRow(ctx,
		`SELECT `+isAdminExprSQL+` FROM users WHERE id = $1`, userID,
	).Scan(&isAdmin); err != nil {
		t.Fatalf("derive is_admin: %v", err)
	}
	if !isAdmin {
		t.Fatal("forgot-password reset must derive is_admin=TRUE for a governed admin (users.is_admin is FALSE); the old raw-column read applied the weaker non-admin password policy")
	}

	// Negative: a user with NO governed assignment derives FALSE — proves the
	// assignment, not a constant, drives the value.
	plainID, _ := seedDerivationUser(t, pool, ctx, "deriv-fpwd-none", "irrelevant")
	defer cleanSSOActor(t, pool, ctx, plainID)
	if err := pool.QueryRow(ctx,
		`SELECT `+isAdminExprSQL+` FROM users WHERE id = $1`, plainID,
	).Scan(&isAdmin); err != nil {
		t.Fatalf("derive is_admin (no assignment): %v", err)
	}
	if isAdmin {
		t.Fatal("a user with no governed admin_role_assignments row must derive is_admin=FALSE")
	}
}

func TestForgotPasswordResetRejectsDisabledIdentityAtMintFence(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ensureEnrollmentLocalDomain(t, pool)
	ctx := context.Background()
	email := "forgot-reset-fence-" + randSuffix() + "@example.com"
	userID := seedLocalUser(t, pool, email)
	if _, err := pool.Exec(ctx,
		`UPDATE users SET enabled=FALSE WHERE id=$1`, userID,
	); err != nil {
		t.Fatal(err)
	}
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
	})
	resetToken, err := h.jwt.IssuePasswordReset(userID, email)
	if err != nil {
		t.Fatal(err)
	}
	rec := postJSON(h.ForgotPasswordReset, "203.0.113.42", map[string]string{
		"email":        email,
		"reset_token":  resetToken,
		"new_password": "Fenced-Reset-Passw0rd!",
	})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled reset status=%d, want 503: %s",
			rec.Code, rec.Body.String())
	}
}

// ── Push recovery lockout: account-level 429 after 5 failed answers ──────────

// forgotPasswordBegin returns the begin response body for an email.
func forgotPasswordBegin(t *testing.T, h *AuthHandler, ip, email string) map[string]string {
	t.Helper()
	rr := postJSON(h.ForgotPasswordBegin, ip, map[string]string{"email": email})
	if rr.Code != http.StatusOK {
		t.Fatalf("begin: status %d body %s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode begin body: %v", err)
	}
	return resp
}

// challengeCodeFor reads the correct number-match answer for a nonce straight
// from the challenge row (the code is only secret from the wire, not the DB).
func challengeCodeFor(t *testing.T, pool *pgxpool.Pool, userID int64, nonce string) string {
	t.Helper()
	var code string
	if err := pool.QueryRow(context.Background(),
		`SELECT challenge_code FROM push_mfa_challenges WHERE user_id = $1 AND nonce = decode($2, 'hex')
		 ORDER BY created_at DESC LIMIT 1`, userID, nonce,
	).Scan(&code); err != nil {
		t.Fatalf("read challenge code: %v", err)
	}
	return code
}

// wrongAnswerFor returns a definitely-wrong number-match answer for code.
func wrongAnswerFor(code string) string {
	if code == "00" {
		return "01"
	}
	return "00"
}

// TestForgotPasswordVerify_PushLockout429_AccountLevel is the end-to-end proof
// of the push recovery lockout: five failed number-match answers across
// DISTINCT fresh challenges lock the ACCOUNT, and the next verify returns the
// 429 lockout response EVEN WITH the correct answer — the property the
// per-challenge burn-at-3 could never provide. Before the lock trips, wrong
// answers get the uniform 401; the locked response differs only by the 429
// status with the same lockout text the TOTP branch returns.
func TestForgotPasswordVerify_PushLockout429_AccountLevel(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	withEnumGuard(t, 100, time.Minute)
	ensureEnrollmentLocalDomain(t, pool)
	ctx := context.Background()

	email := "push-lockout-e2e-" + randSuffix() + "@example.com"
	userID := seedLocalUser(t, pool, email)
	if _, err := pool.Exec(ctx,
		`UPDATE users SET push_mfa_enabled = TRUE, totp_enabled = FALSE WHERE id = $1`, userID,
	); err != nil {
		t.Fatalf("enroll push mfa: %v", err)
	}
	provider := authn.NewNumberMatchPushProvider(ctx, pool, nil, "", "", discardLogger())
	h := NewAuthHandler(AuthHandlerConfig{
		Pool:    pool,
		JWT:     newTestJWT(),
		Logger:  discardLogger(),
		PushMFA: provider,
	})

	const ip = "203.0.113.77"

	// Mint the per-user maximum of 3 fresh challenges (GenerateChallenge caps
	// at 3 per 5 minutes) and confirm each is stamped with the recovery
	// purpose — the binding the verify seam enforces.
	var nonces [3]string
	for i := 0; i < 3; i++ {
		resp := forgotPasswordBegin(t, h, ip, email)
		if resp["method"] != "push" {
			t.Fatalf("begin %d: method = %q, want push", i+1, resp["method"])
		}
		if resp["nonce"] == "" {
			t.Fatalf("begin %d: no nonce in response", i+1)
		}
		nonces[i] = resp["nonce"]
	}
	var purpose string
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(session_id, '') FROM push_mfa_challenges WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1`,
		userID,
	).Scan(&purpose); err != nil {
		t.Fatalf("read challenge purpose: %v", err)
	}
	if purpose != authn.ForgotPasswordChallengePurpose {
		t.Fatalf("challenge session_id = %q, want the recovery purpose %q", purpose, authn.ForgotPasswordChallengePurpose)
	}

	verify := func(nonce, answer string) *httptest.ResponseRecorder {
		return postJSON(h.ForgotPasswordVerify, ip, map[string]string{
			"email": email, "nonce": nonce, "answer": answer,
		})
	}

	// Four wrong answers across the first two challenges: uniform 401.
	for _, tc := range []struct{ nonce string }{{nonces[0]}, {nonces[0]}, {nonces[1]}, {nonces[1]}} {
		code := challengeCodeFor(t, pool, userID, tc.nonce)
		rr := verify(tc.nonce, wrongAnswerFor(code))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("wrong answer: status %d, want 401: %s", rr.Code, rr.Body.String())
		}
		if body := rr.Body.String(); !strings.Contains(body, "invalid verification code") {
			t.Fatalf("wrong answer body = %s, want the uniform invalid-code error", body)
		}
	}

	// The FIFTH failure (fresh third challenge) trips the account lock; this
	// response is still the uniform 401.
	code := challengeCodeFor(t, pool, userID, nonces[2])
	if rr := verify(nonces[2], wrongAnswerFor(code)); rr.Code != http.StatusUnauthorized {
		t.Fatalf("fifth failure: status %d, want 401: %s", rr.Code, rr.Body.String())
	}

	// The SIXTH attempt is refused with the 429 lockout EVEN WITH the correct
	// answer for a live challenge — no verification is attempted.
	rr := verify(nonces[2], code)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("locked verify with correct code: status %d, want 429: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode 429 body: %v", err)
	}
	if resp["error"] != msgAccountLocked {
		t.Fatalf("locked body error = %q, want %q (the TOTP branch's lockout text)", resp["error"], msgAccountLocked)
	}
	// The lock is account-level: a DIFFERENT account is not locked.
	other := "push-lockout-other-" + randSuffix() + "@example.com"
	otherID := seedLocalUser(t, pool, other)
	if _, err := pool.Exec(ctx,
		`UPDATE users SET push_mfa_enabled = TRUE, totp_enabled = FALSE WHERE id = $1`, otherID,
	); err != nil {
		t.Fatalf("enroll push mfa (other): %v", err)
	}
	otherResp := forgotPasswordBegin(t, h, "203.0.113.78", other)
	otherCode := challengeCodeFor(t, pool, otherID, otherResp["nonce"])
	if rr := postJSON(h.ForgotPasswordVerify, "203.0.113.78", map[string]string{
		"email": other, "nonce": otherResp["nonce"], "answer": otherCode,
	}); rr.Code != http.StatusOK {
		t.Fatalf("a different account must not inherit the lock: status %d: %s", rr.Code, rr.Body.String())
	}
}

// TestForgotPasswordVerify_PushSuccessIssuesResetToken proves the seam's
// accepted path end-to-end: a purpose-stamped challenge answered correctly
// issues the reset token — the lockout must not break legitimate recovery.
func TestForgotPasswordVerify_PushSuccessIssuesResetToken(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	withEnumGuard(t, 100, time.Minute)
	ensureEnrollmentLocalDomain(t, pool)
	ctx := context.Background()

	email := "push-recovery-ok-" + randSuffix() + "@example.com"
	userID := seedLocalUser(t, pool, email)
	if _, err := pool.Exec(ctx,
		`UPDATE users SET push_mfa_enabled = TRUE, totp_enabled = FALSE WHERE id = $1`, userID,
	); err != nil {
		t.Fatalf("enroll push mfa: %v", err)
	}
	provider := authn.NewNumberMatchPushProvider(ctx, pool, nil, "", "", discardLogger())
	h := NewAuthHandler(AuthHandlerConfig{
		Pool:    pool,
		JWT:     newTestJWT(),
		Logger:  discardLogger(),
		PushMFA: provider,
	})

	resp := forgotPasswordBegin(t, h, "203.0.113.79", email)
	if resp["nonce"] == "" {
		t.Fatal("begin returned no nonce for a push account")
	}
	code := challengeCodeFor(t, pool, userID, resp["nonce"])
	rr := postJSON(h.ForgotPasswordVerify, "203.0.113.79", map[string]string{
		"email": email, "nonce": resp["nonce"], "answer": code,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("correct answer: status %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode verify body: %v", err)
	}
	if body["reset_token"] == "" {
		t.Fatalf("verify response missing reset_token: %s", rr.Body.String())
	}
}

// ── Push lockout bookkeeping error: logged, request proceeds uniformly ───────

// failingLockoutPushProvider is a ChallengeProvider whose lockout seam always
// fails its bookkeeping: VerifyChallengeWithLockout returns the fail-closed
// PushVerifyInvalid outcome PLUS a non-nil error, the shape the real seam
// returns when the lock-state read, purpose probe, or challenge transaction
// fails transiently (authn push_lockout.go). It records whether the seam was
// consulted so the test proves the handler reached the target branch.
type failingLockoutPushProvider struct {
	bookkeepingErr error
	seamConsulted  bool
}

func (f *failingLockoutPushProvider) Name() string { return "push" }

func (f *failingLockoutPushProvider) Available(context.Context, int64) bool { return true }

func (f *failingLockoutPushProvider) GenerateChallenge(context.Context, int64, string) (*authn.ChallengeResponse, error) {
	return nil, errors.New("GenerateChallenge not used by this test")
}

func (f *failingLockoutPushProvider) VerifyChallenge(context.Context, int64, string, string) error {
	return errors.New("VerifyChallenge not used by this test")
}

// VerifyChallengeWithLockout implements the pushRecoveryVerifier seam the
// forgot-password push branch type-asserts, failing bookkeeping every time.
func (f *failingLockoutPushProvider) VerifyChallengeWithLockout(context.Context, int64, string, string) (authn.PushVerifyOutcome, error) {
	f.seamConsulted = true
	return authn.PushVerifyInvalid, f.bookkeepingErr
}

// TestForgotPasswordVerify_PushLockoutBookkeepingErrorProceedsUniformly pins the
// push branch's bookkeeping-error contract: when VerifyChallengeWithLockout
// returns a non-nil error alongside its fail-closed invalid outcome, the
// handler LOGS the error and continues down the uniform failure path — the
// response is the byte-standard 401 "invalid verification code", never a 500
// and never a lockout 429 (a transient DB failure must not read as a lock or
// an internal fault on this pre-auth endpoint).
func TestForgotPasswordVerify_PushLockoutBookkeepingErrorProceedsUniformly(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	withEnumGuard(t, 100, time.Minute)
	ensureEnrollmentLocalDomain(t, pool)
	ctx := context.Background()

	email := "push-bookkeeping-" + randSuffix() + "@example.com"
	userID := seedLocalUser(t, pool, email)
	if _, err := pool.Exec(ctx,
		`UPDATE users SET push_mfa_enabled = TRUE, totp_enabled = FALSE WHERE id = $1`, userID,
	); err != nil {
		t.Fatalf("enroll push mfa: %v", err)
	}
	provider := &failingLockoutPushProvider{
		bookkeepingErr: errors.New("injected lockout bookkeeping failure"),
	}
	h := NewAuthHandler(AuthHandlerConfig{
		Pool:    pool,
		JWT:     newTestJWT(),
		Logger:  discardLogger(),
		PushMFA: provider,
	})

	rr := postJSON(h.ForgotPasswordVerify, "203.0.113.91", map[string]string{
		"email": email, "nonce": "00ff", "answer": "42",
	})
	if !provider.seamConsulted {
		t.Fatal("the push lockout seam was never consulted — the test did not reach the target branch")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("bookkeeping error: status %d, want the uniform 401 (log-and-continue, never a 500): %s",
			rr.Code, rr.Body.String())
	}
	if body := rr.Body.String(); !strings.Contains(body, "invalid verification code") {
		t.Fatalf("body = %s, want the uniform invalid-code error", body)
	}
}

// ── TOTP lockout: 5 wrong codes within the window → 429 account-locked ───────

// wrongTOTPCode returns a code that is wrong for the secret across the ENTIRE
// validation window (current period ± the ±1 skew), recomputed per attempt so
// a 30 s window rollover mid-test cannot make a stale submission accidentally
// valid.
func wrongTOTPCode(t *testing.T, secret string) string {
	t.Helper()
	for _, candidate := range []string{"000000", "000001", "000002"} {
		clash := false
		for _, offset := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
			code, err := totp.GenerateCode(secret, time.Now().Add(offset))
			if err != nil {
				t.Fatalf("generate candidate code: %v", err)
			}
			if code == candidate {
				clash = true
				break
			}
		}
		if !clash {
			return candidate
		}
	}
	t.Fatal("no wrong code candidate available")
	return ""
}

// TestForgotPasswordVerify_TOTPLockout429_AccountLevel is the end-to-end proof
// of the forgot-password TOTP lockout: five wrong codes submitted through the
// endpoint (each answered with the uniform 401 — the fifth failure trips the
// DB-backed account lock but the seam still reports invalid for it, so the
// lock binds from the NEXT attempt) persist totp_failed_attempts = 5 with a
// future totp_locked_until on the user row, and the SIXTH attempt is refused
// with the 429 {"error": msgAccountLocked} lockout body WITHOUT any
// verification being attempted — the only response on this endpoint allowed
// to differ from the uniform invalid-code 401.
func TestForgotPasswordVerify_TOTPLockout429_AccountLevel(t *testing.T) {
	// The GUC-carrying pool: GenerateTOTPSecret and the verify path both run
	// pgp_sym_encrypt/decrypt under app.encryption_key.
	pool := enrollmentHandlerPool(t)
	withEnumGuard(t, 100, time.Minute)
	ensureEnrollmentLocalDomain(t, pool)
	ctx := context.Background()

	email := "totp-lockout-fpwd-" + randSuffix() + "@example.com"
	userID := seedLocalUser(t, pool, email)
	uri, err := authn.GenerateTOTPSecret(ctx, pool, userID, email, "setjoin-test")
	if err != nil {
		t.Fatalf("seed totp secret: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE users SET totp_enabled = TRUE, push_mfa_enabled = FALSE WHERE id = $1`, userID,
	); err != nil {
		t.Fatalf("enable totp: %v", err)
	}
	key, err := otp.NewKeyFromURL(uri)
	if err != nil {
		t.Fatalf("parse provisioning uri: %v", err)
	}

	h := NewAuthHandler(AuthHandlerConfig{
		Pool:   pool,
		JWT:    newTestJWT(),
		Logger: discardLogger(),
	})

	const ip = "203.0.113.92"
	verify := func() *httptest.ResponseRecorder {
		return postJSON(h.ForgotPasswordVerify, ip, map[string]string{
			"email": email, "code": wrongTOTPCode(t, key.Secret()),
		})
	}

	// Five wrong answers: every one gets the uniform 401 (never a 429 yet).
	for i := 0; i < 5; i++ {
		if rr := verify(); rr.Code != http.StatusUnauthorized {
			t.Fatalf("wrong answer %d: status %d, want the uniform 401: %s", i+1, rr.Code, rr.Body.String())
		}
	}

	// The lock tripped in the DB: 5 recorded failures and a future lock.
	var failedAttempts int
	var lockedUntil time.Time
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(totp_failed_attempts, 0), COALESCE(totp_locked_until, now())
		   FROM users WHERE id = $1`, userID,
	).Scan(&failedAttempts, &lockedUntil); err != nil {
		t.Fatalf("read lockout state: %v", err)
	}
	if failedAttempts != 5 || !lockedUntil.After(time.Now()) {
		t.Fatalf("after 5 failures: attempts=%d locked_until=%v, want 5 + a future lock (the DB-backed account lock must have tripped)",
			failedAttempts, lockedUntil)
	}

	// The SIXTH attempt is refused with the 429 lockout body.
	rr := verify()
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("locked attempt: status %d, want 429: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode 429 body: %v", err)
	}
	if resp["error"] != msgAccountLocked {
		t.Fatalf("locked body error = %q, want %q", resp["error"], msgAccountLocked)
	}
}

// ── AST helpers ─────────────────────────────────────────────────────────────

func handlerFuncBody(t *testing.T, file, name string) string {
	t.Helper()
	fset := gotoken.NewFileSet()
	src, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	for _, d := range src.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name {
			continue
		}
		var sb strings.Builder
		ast.Inspect(fn, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.BasicLit:
				sb.WriteString(v.Value)
				sb.WriteString("\n")
			case *ast.Ident:
				sb.WriteString(v.Name)
				sb.WriteString(" ")
			case *ast.SelectorExpr:
				sb.WriteString(v.Sel.Name)
				sb.WriteString(" ")
			}
			return true
		})
		return sb.String()
	}
	t.Fatalf("function %q not found in %s", name, file)
	return ""
}

// callsIdentInHandler reports whether the named function calls a function whose
// selector/ident name exactly matches target (e.g. authn.VerifyTOTP -> "VerifyTOTP"),
// excluding longer names like VerifyTOTPWithLockout.
func callsIdentInHandler(t *testing.T, file, name, target string) bool {
	t.Helper()
	fset := gotoken.NewFileSet()
	src, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	found := false
	for _, d := range src.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch f := call.Fun.(type) {
			case *ast.SelectorExpr:
				if f.Sel.Name == target {
					found = true
				}
			case *ast.Ident:
				if f.Name == target {
					found = true
				}
			}
			return true
		})
	}
	return found
}
