package handlers

// ER5 s07 named residual (TODOS.md ER6 rollup): forgot-password per-account
// recovery budget decoupled from the per-IP login lockout. enumIPGuard bounds
// grinding per SOURCE IP and the TOTP/push factor lockouts bound failed
// verifications, but a DISTRIBUTED attacker (many IPs, one account) could
// grind recovery attempts — begin challenge minting, and verify traffic that
// carries no code and therefore touches no factor lockout — without any
// per-account bound. These tests pin the budget contract end-to-end:
//
//   - attempts under the budget succeed (begin and verify both);
//   - exhausting the budget produces the EXISTING failure shapes (begin → the
//     uniform decoy; verify → the wrong-code 401) with no oracle, and exactly
//     ONE recovery_budget_exhausted audit row per exhaustion episode;
//   - window expiry restores the budget and attacker traffic can never extend
//     the window;
//   - attempts from N distinct synthetic IPs on ONE account still exhaust the
//     per-account budget while a different account (and a fresh IP) is
//     unaffected;
//   - the occ_4809ab uniform-latency floor survives on the refusal paths.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// seedBudgetTOTPUser seeds a TOTP-enrolled local account (the cheapest MFA the
// budget flow resolves) and registers cleanup for the budget + audit rows the
// test's traffic creates.
func seedBudgetTOTPUser(t *testing.T, pool *pgxpool.Pool, email string) int64 {
	t.Helper()
	ensureEnrollmentLocalDomain(t, pool)
	userID := seedLocalUser(t, pool, email)
	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET totp_enabled = TRUE, push_mfa_enabled = FALSE WHERE id = $1`, userID,
	); err != nil {
		t.Fatalf("enroll totp: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = pool.Exec(ctx, `DELETE FROM auth_lockouts WHERE lockout_key = $1`, recoveryBudgetKey(userID))
		_, _ = pool.Exec(ctx,
			`DELETE FROM admin_audit_log WHERE action = 'recovery_budget_exhausted' AND user_id = $1`, userID)
	})
	return userID
}

// seedBudgetExhausted drives the account's budget row to the exhausted state
// through the accessors themselves (same statements the production seam runs),
// so the refusal-path tests start from a deterministic exhausted episode.
func seedBudgetExhausted(t *testing.T, pool *pgxpool.Pool, userID int64) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `SELECT recovery_budget_acquire($1)`, userID); err != nil {
		t.Fatalf("acquire budget row: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`SELECT recovery_budget_record($1, $2, now() + interval '15 minutes')`,
		userID, recoveryBudgetLimit,
	); err != nil {
		t.Fatalf("record exhausted budget: %v", err)
	}
}

// budgetState reads the account's budget row (count, window horizon) directly.
// The test connection is the cluster superuser, which bypasses the V259
// deny-all FORCE posture exactly as the provisioning/test load assumes.
func budgetState(t *testing.T, pool *pgxpool.Pool, userID int64) (int, time.Time) {
	t.Helper()
	var count int
	var windowUntil time.Time
	if err := pool.QueryRow(context.Background(),
		`SELECT failed_count, locked_until FROM auth_lockouts WHERE lockout_key = $1`,
		recoveryBudgetKey(userID),
	).Scan(&count, &windowUntil); err != nil {
		t.Fatalf("read budget row: %v", err)
	}
	return count, windowUntil
}

// exhaustedAuditRows counts the account's recovery_budget_exhausted emissions.
func exhaustedAuditRows(t *testing.T, pool *pgxpool.Pool, userID int64) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_audit_log
		  WHERE action = 'recovery_budget_exhausted' AND user_id = $1`, userID,
	).Scan(&n); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return n
}

// verifyNoCode is the grind shape the budget exists for: a verify that
// resolves the account but carries no code/nonce — it touches no factor
// lockout, so before the budget it was unbounded for a distributed fleet.
func verifyNoCode(h *AuthHandler, ip, email string) *httptest.ResponseRecorder {
	return postJSON(h.ForgotPasswordVerify, ip, map[string]string{"email": email})
}

// TestRecoveryBudgetKey_SQLParity pins the Go-side key convention to the
// byte-identical 'recovery_user:' || p_user_id the accessor builds SQL-side
// (recovery_budget_accessors.sql): a drifted prefix would silently fork the
// budget into two tables' worth of rows.
func TestRecoveryBudgetKey_SQLParity(t *testing.T) {
	if got := recoveryBudgetKey(910001); got != "recovery_user:910001" {
		t.Fatalf("recoveryBudgetKey = %q, want %q (the accessor's SQL-side convention)", got, "recovery_user:910001")
	}
	if strings.HasPrefix(recoveryBudgetKey(1), "push_user:") || strings.HasPrefix(recoveryBudgetKey(1), "user:") {
		t.Fatal("the recovery budget key must not collide with the push/user lockout dimensions")
	}
}

// ── Fail-closed fault injection ─────────────────────────────────────────────
//
// The push seam's txProbe precedent: scripted pgx.Tx substitutes make every
// transient-failure branch reachable, so the fail-closed contract is PROVEN
// (refusal + uniform shape) rather than asserted unreachable.

// scriptedBudgetRow is a pgx.Row over a scripted budget state or error.
type scriptedBudgetRow struct {
	row recoveryBudgetRow
	err error
}

func (r scriptedBudgetRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if p, ok := dest[0].(*int); ok {
		*p = r.row.attemptCount
	}
	if w, ok := dest[1].(*time.Time); ok {
		*w = r.row.windowUntil
	}
	if u, ok := dest[2].(*time.Time); ok {
		*u = r.row.updatedAt
	}
	return nil
}

// scriptedBudgetTx is a pgx.Tx scripting the budget seam's statement surface.
type scriptedBudgetTx struct {
	pgx.Tx
	state        recoveryBudgetRow
	failQueryRow bool
	failExec     bool
	failCommit   bool
}

func (s *scriptedBudgetTx) QueryRow(context.Context, string, ...any) pgx.Row {
	if s.failQueryRow {
		return scriptedBudgetRow{err: errors.New("injected acquire failure")}
	}
	return scriptedBudgetRow{row: s.state}
}

func (s *scriptedBudgetTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	if s.failExec {
		return pgconn.CommandTag{}, errors.New("injected record failure")
	}
	return pgconn.CommandTag{}, nil
}

func (s *scriptedBudgetTx) Commit(context.Context) error {
	if s.failCommit {
		return errors.New("injected commit failure")
	}
	return nil
}

func (s *scriptedBudgetTx) Rollback(context.Context) error { return nil }

type scriptedBudgetBeginner struct{ tx pgx.Tx }

func (b scriptedBudgetBeginner) Begin(context.Context) (pgx.Tx, error) { return b.tx, nil }

type failingBudgetBeginner struct{}

func (failingBudgetBeginner) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("injected begin failure")
}

// TestConsumeRecoveryBudget_FailClosedBranches drives every transient-failure
// branch of the budget transaction and pins the fail-closed verdict: the
// attempt is refused (exhausted=true) with a non-nil error to log, and — the
// security-critical part — NOTHING is ever reported as a first refusal, so a
// broken database can never mint audit rows or admission decisions.
func TestConsumeRecoveryBudget_FailClosedBranches(t *testing.T) {
	liveWindow := time.Now().Add(recoveryBudgetWindow)
	cases := []struct {
		name string
		tx   *scriptedBudgetTx
	}{
		{"acquire failure", &scriptedBudgetTx{failQueryRow: true}},
		{"open-window record failure", &scriptedBudgetTx{failExec: true}},
		{"refusal record failure", &scriptedBudgetTx{
			state: recoveryBudgetRow{attemptCount: recoveryBudgetLimit, windowUntil: liveWindow}, failExec: true}},
		{"refusal commit failure", &scriptedBudgetTx{
			state: recoveryBudgetRow{attemptCount: recoveryBudgetLimit, windowUntil: liveWindow}, failCommit: true}},
		{"consume record failure", &scriptedBudgetTx{
			state: recoveryBudgetRow{attemptCount: 3, windowUntil: liveWindow}, failExec: true}},
		{"commit failure", &scriptedBudgetTx{
			state: recoveryBudgetRow{attemptCount: 3, windowUntil: liveWindow}, failCommit: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exhausted, firstRefusal, err := consumeRecoveryBudget(context.Background(),
				scriptedBudgetBeginner{tx: tc.tx}, 910001)
			if !exhausted {
				t.Fatalf("%s: exhausted = false — a transient failure must FAIL CLOSED", tc.name)
			}
			if firstRefusal {
				t.Fatalf("%s: a failed bookkeeping transaction must never read as a first refusal", tc.name)
			}
			if err == nil {
				t.Fatalf("%s: exhausted refusal without an error — the caller has nothing to log", tc.name)
			}
		})
	}

	exhausted, firstRefusal, err := consumeRecoveryBudget(context.Background(), failingBudgetBeginner{}, 910001)
	if !exhausted || firstRefusal || err == nil {
		t.Fatalf("begin failure: exhausted=%v firstRefusal=%v err=%v, want true/false/non-nil",
			exhausted, firstRefusal, err)
	}
}

// TestForgotPassword_BudgetFailClosedUniform pins the handler-level fail-closed
// shape: with the budget transaction unavailable (closed worker pool) but the
// request pool live, an exhausted-looking budget answers the UNIFORM failure
// shapes — begin → the decoy, verify → the wrong-code 401 — and emits NO audit
// row (a bookkeeping failure is not an exhaustion episode).
func TestForgotPassword_BudgetFailClosedUniform(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	withEnumGuard(t, 100, time.Minute)
	email := "recovery-budget-fc-" + randSuffix() + "@example.com"
	userID := seedBudgetTOTPUser(t, pool, email)

	closed := createClosedPool(t)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool:           pool,
		DatabaseWorker: pgxutil.WorkerPool{Pool: closed},
		JWT:            newTestJWT(),
		Logger:         discardLogger(),
	})

	if rr := postJSON(h.ForgotPasswordBegin, "203.0.113.108", map[string]string{"email": email}); rr.Code != http.StatusOK {
		t.Fatalf("fail-closed begin: status %d, want the uniform 200 decoy", rr.Code)
	}
	rr := verifyNoCode(h, "203.0.113.108", email)
	if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "invalid verification code") {
		t.Fatalf("fail-closed verify: status %d body %s, want the uniform 401", rr.Code, rr.Body.String())
	}
	if n := exhaustedAuditRows(t, pool, userID); n != 0 {
		t.Fatalf("fail-closed bookkeeping wrote %d audit rows, want 0 (no exhaustion episode occurred)", n)
	}
}

// TestForgotPassword_RecoveryBudgetSeamWired is the structural guard: both
// endpoints must consume the per-account budget. The begin refusal's DECOY
// shape is proven behaviorally by TestForgotPasswordRecoveryBudget_
// BeginExhaustionDecoyShaped.
func TestForgotPassword_RecoveryBudgetSeamWired(t *testing.T) {
	begin := handlerFuncBody(t, "forgot_password.go", "ForgotPasswordBegin")
	if !strings.Contains(begin, "recoveryBudgetRefused") {
		t.Error("ForgotPasswordBegin must consume the per-account recovery budget")
	}
	verify := handlerFuncBody(t, "forgot_password.go", "ForgotPasswordVerify")
	if !strings.Contains(verify, "recoveryBudgetRefused") {
		t.Error("ForgotPasswordVerify must consume the per-account recovery budget")
	}
}

// TestForgotPasswordRecoveryBudget_UnderBudgetSucceeds proves the budget does
// not disturb legitimate recovery: begins and verifies inside the budget keep
// their exact pre-budget shapes, and each attempt is counted.
func TestForgotPasswordRecoveryBudget_UnderBudgetSucceeds(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	withEnumGuard(t, 100, time.Minute)
	email := "recovery-budget-ok-" + randSuffix() + "@example.com"
	userID := seedBudgetTOTPUser(t, pool, email)

	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	for i := 0; i < 3; i++ {
		rr := postJSON(h.ForgotPasswordBegin, "203.0.113.101", map[string]string{"email": email})
		if rr.Code != http.StatusOK {
			t.Fatalf("begin %d under budget: status %d, want 200: %s", i+1, rr.Code, rr.Body.String())
		}
		var resp map[string]string
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode begin body: %v", err)
		}
		if resp["method"] != "totp" || resp["message"] != msgForgotPasswordGeneric {
			t.Fatalf("begin %d under budget changed the uniform shape: %v", i+1, resp)
		}

		rr = verifyNoCode(h, "203.0.113.101", email)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("verify %d under budget: status %d, want the uniform 401", i+1, rr.Code)
		}
	}

	count, windowUntil := budgetState(t, pool, userID)
	if count != 6 {
		t.Fatalf("budget count = %d, want 6 (3 begins + 3 verifies all consumed)", count)
	}
	if !windowUntil.After(time.Now()) {
		t.Fatalf("window_until = %v, want a live fixed window after the first attempt", windowUntil)
	}
	if n := exhaustedAuditRows(t, pool, userID); n != 0 {
		t.Fatalf("under-budget traffic wrote %d audit rows, want 0 (exhaustion-only emission)", n)
	}
}

// TestForgotPasswordRecoveryBudget_ExhaustionUniformAndAudited is the core
// residual proof: driving the account to the budget limit keeps the EXISTING
// failure shapes (no oracle — attempt 31 is byte-identical to attempt 1), the
// refusal never extends the fixed window, the refusal never moves a factor
// lockout, and the exhaustion writes exactly ONE recovery_budget_exhausted
// audit row for the episode (no per-refusal flood for the attacker to amplify).
func TestForgotPasswordRecoveryBudget_ExhaustionUniformAndAudited(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	withEnumGuard(t, 100, time.Minute)
	email := "recovery-budget-x-" + randSuffix() + "@example.com"
	userID := seedBudgetTOTPUser(t, pool, email)

	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	const ip = "203.0.113.102"
	var firstBody string
	for i := 0; i < recoveryBudgetLimit; i++ {
		rr := verifyNoCode(h, ip, email)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d within budget: status %d, want the uniform 401", i+1, rr.Code)
		}
		if i == 0 {
			firstBody = rr.Body.String()
		}
		if rr.Body.String() != firstBody {
			t.Fatalf("attempt %d body drifted from attempt 1 — an exhaustion oracle:\n  a=%s\n  b=%s",
				i+1, firstBody, rr.Body.String())
		}
	}

	count, windowAtLimit := budgetState(t, pool, userID)
	if count != recoveryBudgetLimit || !windowAtLimit.After(time.Now()) {
		t.Fatalf("at the limit: count=%d window=%v, want %d + a live window", count, windowAtLimit, recoveryBudgetLimit)
	}

	// Two refusals past the limit: byte-identical to the in-budget failure.
	for i := 0; i < 2; i++ {
		rr := verifyNoCode(h, ip, email)
		if rr.Code != http.StatusUnauthorized || rr.Body.String() != firstBody {
			t.Fatalf("refused attempt %d: status %d body %s, want the byte-identical uniform 401",
				recoveryBudgetLimit+i+1, rr.Code, rr.Body.String())
		}
	}

	// The refusal is count-only accounting: the window anchor NEVER moved.
	count, windowAfterRefusals := budgetState(t, pool, userID)
	if count != recoveryBudgetLimit+2 {
		t.Fatalf("post-refusal count = %d, want %d (refusals are recorded, window untouched)", count, recoveryBudgetLimit+2)
	}
	if !windowAfterRefusals.Equal(windowAtLimit) {
		t.Fatalf("a refusal moved the window: %v -> %v — attacker traffic must never extend it",
			windowAtLimit, windowAfterRefusals)
	}

	// Exactly ONE audit row for the episode, on the first refusal.
	if n := exhaustedAuditRows(t, pool, userID); n != 1 {
		t.Fatalf("exhaustion wrote %d audit rows, want exactly 1 (first-refusal-only)", n)
	}
	var notes string
	if err := pool.QueryRow(context.Background(),
		`SELECT notes FROM admin_audit_log
		  WHERE action = 'recovery_budget_exhausted' AND user_id = $1`, userID,
	).Scan(&notes); err != nil {
		t.Fatalf("read audit row: %v", err)
	}
	if !strings.Contains(notes, fmt.Sprint(recoveryBudgetLimit)) {
		t.Fatalf("audit notes %q must carry the exhausted count (%d)", notes, recoveryBudgetLimit)
	}

	// A refusal never reaches verification: no factor lockout state moved.
	var totpAttempts int
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE(totp_failed_attempts, 0) FROM users WHERE id = $1`, userID,
	).Scan(&totpAttempts); err != nil {
		t.Fatalf("read totp lockout state: %v", err)
	}
	if totpAttempts != 0 {
		t.Fatalf("budget refusals recorded %d TOTP lockout failures — the budget refuses BEFORE verification", totpAttempts)
	}

	// Per-account isolation: a different account's begin is served normally.
	otherEmail := "recovery-budget-other-" + randSuffix() + "@example.com"
	seedBudgetTOTPUser(t, pool, otherEmail)
	if rr := postJSON(h.ForgotPasswordBegin, "203.0.113.103", map[string]string{"email": otherEmail}); rr.Code != http.StatusOK {
		t.Fatalf("a different account must not inherit the exhausted budget: status %d", rr.Code)
	}
}

// TestForgotPasswordRecoveryBudget_BeginExhaustionDecoyShaped pins the begin
// refusal's external shape: an exhausted PUSH account's begin answers the
// uniform TOTP-shaped decoy (the same shape the existing challenge-failure
// fallback produces) and skips challenge dispatch entirely — no challenge row,
// no push notification mint for a refused request.
func TestForgotPasswordRecoveryBudget_BeginExhaustionDecoyShaped(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	withEnumGuard(t, 100, time.Minute)
	ensureEnrollmentLocalDomain(t, pool)
	ctx := context.Background()
	email := "recovery-budget-push-" + randSuffix() + "@example.com"
	userID := seedLocalUser(t, pool, email)
	if _, err := pool.Exec(ctx,
		`UPDATE users SET push_mfa_enabled = TRUE, totp_enabled = FALSE WHERE id = $1`, userID,
	); err != nil {
		t.Fatalf("enroll push: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM auth_lockouts WHERE lockout_key = $1`, recoveryBudgetKey(userID))
		_, _ = pool.Exec(ctx,
			`DELETE FROM admin_audit_log WHERE action = 'recovery_budget_exhausted' AND user_id = $1`, userID)
	})
	seedBudgetExhausted(t, pool, userID)

	provider := authn.NewNumberMatchPushProvider(ctx, pool, nil, "", "", discardLogger())
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger(), PushMFA: provider})

	rr := postJSON(h.ForgotPasswordBegin, "203.0.113.104", map[string]string{"email": email})
	if rr.Code != http.StatusOK {
		t.Fatalf("exhausted begin: status %d, want the uniform 200 decoy", rr.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode begin body: %v", err)
	}
	if resp["method"] != "totp" || resp["message"] != msgForgotPasswordGeneric {
		t.Fatalf("exhausted begin body %v, want the decoy shape {totp, generic}", resp)
	}
	if _, hasNonce := resp["nonce"]; hasNonce {
		t.Fatal("an exhausted begin must not mint a nonce — dispatch must be skipped")
	}
	var challenges int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM push_mfa_challenges WHERE user_id = $1`, userID,
	).Scan(&challenges); err != nil {
		t.Fatalf("count challenges: %v", err)
	}
	if challenges != 0 {
		t.Fatalf("an exhausted begin minted %d push challenges — dispatch must be skipped", challenges)
	}

	// The refusal was recorded count-only against the unchanged window.
	count, _ := budgetState(t, pool, userID)
	if count != recoveryBudgetLimit+1 {
		t.Fatalf("post-refusal count = %d, want %d", count, recoveryBudgetLimit+1)
	}
	if n := exhaustedAuditRows(t, pool, userID); n != 1 {
		t.Fatalf("begin exhaustion wrote %d audit rows, want 1", n)
	}
}

// TestForgotPasswordRecoveryBudget_WindowExpiryRestores proves the fixed
// window restores on schedule: a refused (exhausted) account's next attempt
// after expiry OPENS a fresh window and is ADMITTED — while the wire shape
// stays the uniform failure either way (a no-code verify is a uniform 401 both
// refused and admitted; the restore is proven by the budget row).
func TestForgotPasswordRecoveryBudget_WindowExpiryRestores(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	withEnumGuard(t, 100, time.Minute)
	email := "recovery-budget-exp-" + randSuffix() + "@example.com"
	userID := seedBudgetTOTPUser(t, pool, email)

	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	const ip = "203.0.113.105"
	seedBudgetExhausted(t, pool, userID)

	if rr := verifyNoCode(h, ip, email); rr.Code != http.StatusUnauthorized {
		t.Fatalf("exhausted verify: status %d, want the uniform 401", rr.Code)
	}
	if count, window := budgetState(t, pool, userID); count != recoveryBudgetLimit+1 || !window.After(time.Now()) {
		t.Fatalf("pre-expiry state count=%d window=%v, want %d + live window", count, window, recoveryBudgetLimit+1)
	}

	// Expire the window out-of-band (the one lever an attacker does NOT have —
	// only time moves the anchor).
	if _, err := pool.Exec(context.Background(),
		`UPDATE auth_lockouts SET locked_until = now() - interval '1 second' WHERE lockout_key = $1`,
		recoveryBudgetKey(userID),
	); err != nil {
		t.Fatalf("expire window: %v", err)
	}

	if rr := verifyNoCode(h, ip, email); rr.Code != http.StatusUnauthorized {
		t.Fatalf("post-expiry verify: status %d, want the uniform 401 (admitted, no-code failure)", rr.Code)
	}
	count, window := budgetState(t, pool, userID)
	if count != 1 {
		t.Fatalf("post-expiry count = %d, want 1 (fresh window, budget restored)", count)
	}
	if !window.After(time.Now()) {
		t.Fatalf("post-expiry window = %v, want a freshly anchored live window", window)
	}
	if n := exhaustedAuditRows(t, pool, userID); n != 1 {
		t.Fatalf("an expired episode must not emit further audit rows: got %d, want 1", n)
	}
}

// TestForgotPasswordRecoveryBudget_DistributedIPsExhaustAccount is the residual's
// headline scenario: attempts from MANY distinct source IPs on ONE account
// exhaust the per-account budget even though every IP stays far inside the
// real per-IP guard (10 per 5 minutes), and the account's budget refusal holds
// for yet another fresh IP while that IP and a different account are both
// still served.
func TestForgotPasswordRecoveryBudget_DistributedIPsExhaustAccount(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	// The PRODUCTION per-IP budget: each synthetic IP gets 3 attempts, well
	// under the 10-per-5-minutes cap, so every refusal below is the ACCOUNT
	// budget's, not the IP guard's.
	withEnumGuard(t, 10, 5*time.Minute)
	email := "recovery-budget-dist-" + randSuffix() + "@example.com"
	userID := seedBudgetTOTPUser(t, pool, email)

	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	const perIP = 3
	ips := make([]string, 12)
	for i := range ips {
		ips[i] = fmt.Sprintf("198.51.100.%d", 10+i) // 12 distinct synthetic sources
	}
	attempt := 0
	for _, ip := range ips {
		for j := 0; j < perIP; j++ {
			attempt++
			rr := verifyNoCode(h, ip, email)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("distributed attempt %d from %s: status %d, want the uniform 401",
					attempt, ip, rr.Code)
			}
		}
	}

	count, window := budgetState(t, pool, userID)
	if count != len(ips)*perIP {
		t.Fatalf("distributed budget count = %d, want %d (every IP's attempts hit ONE account budget)",
			count, len(ips)*perIP)
	}
	if count < recoveryBudgetLimit || !window.After(time.Now()) {
		t.Fatalf("budget never exhausted by the distributed fleet: count=%d window=%v", count, window)
	}
	if n := exhaustedAuditRows(t, pool, userID); n != 1 {
		t.Fatalf("distributed exhaustion wrote %d audit rows, want 1", n)
	}

	// A THIRTEENTH fresh IP is still refused for THIS account (the budget is
	// account-keyed, not IP-keyed)...
	freshIP := "198.51.100.99"
	if rr := verifyNoCode(h, freshIP, email); rr.Code != http.StatusUnauthorized {
		t.Fatalf("fresh IP against exhausted account: status %d, want the uniform 401", rr.Code)
	}
	// ...while the SAME fresh IP is served for a DIFFERENT account (its own
	// per-IP budget is untouched) — the refusal is per-account only.
	otherEmail := "recovery-budget-dist2-" + randSuffix() + "@example.com"
	seedBudgetTOTPUser(t, pool, otherEmail)
	if rr := postJSON(h.ForgotPasswordBegin, freshIP, map[string]string{"email": otherEmail}); rr.Code != http.StatusOK {
		t.Fatalf("fresh IP against a different account: status %d, want 200 (per-account, not per-IP)", rr.Code)
	}
}

// TestForgotPasswordRecoveryBudget_LatencyFloorIntactOnExhaustion pins the
// occ_4809ab uniform-latency floor on the refusal paths: budget exhaustion
// consumes the attempt WITHOUT changing the response latency shape — a refused
// verify meets the same floor as any other failure leg, and a refused begin
// meets the same floor as the decoy (which the er5s08 tests pin against the
// real-account leg).
func TestForgotPasswordRecoveryBudget_LatencyFloorIntactOnExhaustion(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	withEnumGuard(t, 100, time.Minute)
	email := "recovery-budget-lat-" + randSuffix() + "@example.com"
	userID := seedBudgetTOTPUser(t, pool, email)
	seedBudgetExhausted(t, pool, userID)

	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	verifyReq := func() (*httptest.ResponseRecorder, time.Duration) {
		req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password/verify",
			strings.NewReader(`{"email":"`+email+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.106:40000"
		rr := httptest.NewRecorder()
		start := time.Now()
		h.ForgotPasswordVerify(rr, req)
		return rr, time.Since(start)
	}
	beginReq := func() (*httptest.ResponseRecorder, time.Duration) {
		req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password/begin",
			strings.NewReader(`{"email":"`+email+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.106:40001"
		rr := httptest.NewRecorder()
		start := time.Now()
		h.ForgotPasswordBegin(rr, req)
		return rr, time.Since(start)
	}

	// Warm the pool so first-request cost does not skew the sample.
	verifyNoCode(h, "203.0.113.107", "ghost@example.com")

	rr, verifyElapsed := verifyReq()
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("refused verify: status %d, want 401", rr.Code)
	}
	floor := enumConstantDelay - 15*time.Millisecond
	if verifyElapsed < floor {
		t.Fatalf("refused verify answered in %v, below the uniform floor (%v) — budget exhaustion would be a timing oracle",
			verifyElapsed, enumConstantDelay)
	}

	rr, beginElapsed := beginReq()
	if rr.Code != http.StatusOK {
		t.Fatalf("refused begin: status %d, want the uniform 200 decoy", rr.Code)
	}
	if beginElapsed < floor {
		t.Fatalf("refused begin answered in %v, below the uniform floor (%v)", beginElapsed, enumConstantDelay)
	}
}
