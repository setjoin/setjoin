package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pwhash"
)

const (
	msgForgotPasswordGeneric = "If an account with that email exists and has multi-factor authentication enabled, a verification challenge has been sent."

	// msgInvalidVerificationCode is the uniform failure body every
	// verification-refusing branch on ForgotPasswordVerify returns (unknown
	// account, wrong code, no code at all, budget-refused): one byte-shape so
	// none of those states can be told apart on the wire.
	msgInvalidVerificationCode = "invalid verification code"

	// msgAccountLocked is the single 429 body both recovery verification
	// branches return when the per-account lockout trips. It is the only
	// response on this endpoint allowed to differ from the uniform
	// "invalid verification code" failure — by status code 429.
	msgAccountLocked = "account locked due to too many verification attempts"

	// enumConstantDelay is applied to every enumerable-endpoint failure path so
	// the "no such account" branch takes the same wall-clock time as a real one.
	enumConstantDelay = 100 * time.Millisecond
)

// enumUniformFloor holds the response until at least enumConstantDelay has
// elapsed since start, so the decoy leg and the REAL account legs answer in
// indistinguishable time. The previous constant delay was one-sided — only the
// decoy slept, so a real TOTP account's begin response returned immediately and
// the ~100ms latency delta itself was an existence oracle. Work that must run
// before the response (challenge dispatch) naturally exceeds the floor; the
// floor raises the cheap legs to meet it.
func enumUniformFloor(start time.Time) {
	if elapsed := time.Since(start); elapsed < enumConstantDelay {
		time.Sleep(enumConstantDelay - elapsed)
	}
}

// pushRecoveryVerifier is the per-account lockout seam ForgotPasswordVerify
// requires of the push provider before any in-band recovery verification:
// authn.NumberMatchPushProvider implements it
// (authn.NumberMatchPushProvider.VerifyChallengeWithLockout). A provider that
// does not implement the seam is refused the push branch entirely — fail-closed,
// never an unbounded in-band verification path.
type pushRecoveryVerifier interface {
	VerifyChallengeWithLockout(ctx context.Context, userID int64, nonceHex, answer string) (authn.PushVerifyOutcome, error)
}

// ── Shared enumeration-defence seam ─────────────────────────────────────────
//
// Several pre-auth endpoints (forgot-password begin/verify, webauthn login
// begin, push send) accept an email or otherwise reveal whether an account
// exists. The prior hardening wave fixed one such site (webauthn) and left
// siblings leaking. This seam is the single mechanism every enumerable endpoint
// routes through, so the "indistinguishable by existence + per-IP limited"
// property holds by construction rather than per-handler copy-paste:
//
//   - enumIPGuard rate-limits per source IP (like PushMFASend's AllowIP), so an
//     attacker cannot grind many emails from one IP regardless of existence.
//   - enumUniformOK / enumUniformReject emit a byte-identical body+status for the
//     "does not exist / no MFA" outcome, with a constant delay, so timing and
//     content do not betray account existence.

// enumIPGuard is the process-wide per-IP budget for enumerable endpoints. The
// budget is generous enough for legitimate retries but caps automated grinding.
// Shares authn.IPRateLimiter (the same limiter push.go uses) rather than
// duplicating the fixed-window logic here.
var enumIPGuard = authn.NewIPRateLimiter(10, 5*time.Minute)

// enumRateLimited applies the shared per-IP budget and, when exceeded, writes a
// uniform 429 and returns true (the caller must stop). It is the first line of
// every enumerable handler.
func enumRateLimited(w http.ResponseWriter, r *http.Request) bool {
	if !enumIPGuard.Allow(httputil.ClientIP(r)) {
		httputil.WriteJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": "too many requests, please wait and try again",
		})
		return true
	}
	return false
}

// ── Per-account recovery attempt budget (ER5 s07 named residual) ────────────
//
// enumIPGuard bounds grinding PER SOURCE IP; the TOTP/push factor lockouts
// bound failed VERIFICATIONS. Neither bounds a DISTRIBUTED attacker (many IPs,
// one account) grinding forgot-password RECOVERY attempts against a single
// account: begin hammers mint push challenges / notification floods, and a
// verify that carries no code touches no factor lockout at all while still
// resolving the account and running the uniform failure path. This seam is
// that missing per-account bound, deliberately DECOUPLED from the per-IP
// guard: one fixed-window attempt budget per account covering begin+confirm
// regardless of which IP the attempt came from, so an N-IP fleet exhausts the
// same budget one IP would.
//
// Storage is the SHARED auth_lockouts table (the push lockout's guard-table
// genre; V259 deny-all FORCE posture): row key recovery_user:{user_id} — the
// accessor owns the convention SQL-side so no caller can address the ip:/user:/
// ip_user:/push_user: rows. Every statement reaches the table ONLY through the
// worker-owned SECURITY DEFINER accessors in
// authserver/sql/reducers/recovery_budget_accessors.sql (worker-only EXECUTE,
// provision-roles.sql carve-out), called on the WORKER pool (h.workerPool —
// BYPASSRLS credential; INERT alias of h.pool until DB_WORKER_DSN is set, the
// same routing the push seam's lockoutPool uses).
//
// Window mechanics (fixed window, anchored at the first attempt inside it):
//
//	recoveryBudgetLimit attempts (begin + verify combined) per account per
//	recoveryBudgetWindow; the window anchor lives in locked_until and is
//	NEVER recomputed while active, so expiry restores the budget on schedule
//	and attacker traffic cannot extend it.
//
// Exhaustion is externally SILENT — no oracle: begin answers the uniform decoy
// (byte-identical to the non-exhausted TOTP-account leg; for a push account it
// matches the existing challenge-failure fallback shape) and skips challenge
// dispatch; verify returns the standard wrong-code 401 BEFORE any verification
// runs (no factor lockout moves, no challenge burns). Only the FIRST refusal
// of an exhaustion episode writes the audit row (recovery_budget_exhausted) —
// per-refusal rows would hand the attacker a log-flooding lever. Transient DB
// failures FAIL CLOSED (refusal + logged error), matching the push seam's
// doctrine; the refusal shapes are already the endpoints' uniform failure
// bodies, so a fail-closed refusal leaks nothing.

const (
	// recoveryBudgetLimit bounds begin+confirm attempts per ACCOUNT per window.
	// Generous against legitimate recovery (a real user cannot approach it —
	// the 5-failure factor lockouts bind far earlier) while capping a
	// distributed fleet at a fixed number of recovery attempts per window no
	// matter how many IPs it fronts.
	recoveryBudgetLimit = 30
	// recoveryBudgetWindow is both the accumulation window and the time it
	// takes to restore, aligned with the recovery lockout window the TOTP/push
	// factor seams document (15 minutes).
	recoveryBudgetWindow = 15 * time.Minute
)

// recoveryBudgetKey is the auth_lockouts row key for one account's recovery
// budget, under the table's documented dimension:value convention. The prefix
// cannot collide with the threat pipeline's ip:/user:/ip_user: keys or the
// push seam's push_user: keys. SQL-side ownership of the convention is the
// worker-only accessor recovery_budget_acquire/record (authserver/sql/reducers/
// recovery_budget_accessors.sql), whose statements build the identical
// 'recovery_user:' || p_user_id key — this builder remains the test-side
// parity pin and the documented convention source.
func recoveryBudgetKey(userID int64) string {
	return "recovery_user:" + strconv.FormatInt(userID, 10)
}

// recoveryBudgetRow is one account's budget state as read under the
// transaction's row lock. windowUntil doubles as the fixed-window horizon;
// a fresh row carries the now() "no window open" sentinel.
type recoveryBudgetRow struct {
	attemptCount int
	windowUntil  time.Time
	updatedAt    time.Time
}

// windowActive reports whether the budget's fixed window is still open.
func (r recoveryBudgetRow) windowActive(now time.Time) bool {
	return r.windowUntil.After(now)
}

// recoveryBudgetQuerier is the narrow statement surface the budget seam needs.
// Satisfied by pgx.Tx (the seam's own transaction); the same shape as the
// authn package's lockoutQuerier.
type recoveryBudgetQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

// acquireRecoveryBudgetRow atomically acquires the account's budget row and
// reads the verdict through the worker-owned SECURITY DEFINER accessor
// recovery_budget_acquire (V259 deny-all FORCE: auth_lockouts has zero
// permissive policies, so this seam — not the table — is the write surface).
// The INSERT .. ON CONFLICT DO UPDATE inside the accessor takes the row lock
// on BOTH paths, so concurrent attempts for the account (from any number of
// IPs) serialize on this statement and read the freshest committed state; the
// lock is held by the caller's transaction to commit.
func acquireRecoveryBudgetRow(ctx context.Context, q recoveryBudgetQuerier, userID int64) (recoveryBudgetRow, error) {
	var row recoveryBudgetRow
	err := q.QueryRow(ctx,
		`SELECT attempt_count, window_until, updated_at
		   FROM recovery_budget_acquire($1)`,
		userID,
	).Scan(&row.attemptCount, &row.windowUntil, &row.updatedAt)
	return row, err
}

// recordRecoveryBudget writes the post-decision counter state in the caller's
// transaction (which already holds the row lock) through the worker-only
// recovery_budget_record accessor: attempt consumption, refusal accounting, or
// window restore/reset. windowUntil is ALWAYS the definite horizon the policy
// decided (a fresh anchor, the unchanged prior anchor, or a reset sentinel via
// time.Time{} → NULL → the accessor re-arms the now() sentinel), so a refusal
// can never drift the window the way a recomputed one could.
func recordRecoveryBudget(ctx context.Context, q recoveryBudgetQuerier, userID int64, count int, windowUntil time.Time) error {
	var until *time.Time
	if !windowUntil.IsZero() {
		until = &windowUntil
	}
	_, err := q.Exec(ctx,
		`SELECT recovery_budget_record($1, $2, $3)`,
		userID, count, until)
	return err
}

// recoveryBudgetBeginner is the transaction seam consumeRecoveryBudget runs
// on. Satisfied by pgxutil.WorkerPool (the worker credential, production and
// default test wiring); the fail-closed tests substitute scripted beginners so
// every transient-failure branch is reachable without a real faulting DB.
type recoveryBudgetBeginner interface {
	Begin(context.Context) (pgx.Tx, error)
}

// consumeRecoveryBudget charges ONE recovery attempt (a begin or a verify)
// against the account's fixed-window budget and reports whether the attempt is
// refused. The whole decision is ONE transaction on the worker pool: acquire
// (row lock) → fixed-window decision → record → commit, so attempts from any
// number of concurrent IPs serialize on the account row and a request that
// arrives after the budget's last admission committed is refused before doing
// anything else.
//
// exhausted=true (including every transient failure — fail closed, err
// non-nil for the caller to log) means the caller must answer the endpoint's
// UNIFORM failure shape and stop. firstRefusal=true marks the FIRST refusal of
// an exhaustion episode (prior count exactly at the limit) — the audit trigger;
// later refusals within the same window bump the counter only, so the attacker
// never gains a per-request audit write.
func consumeRecoveryBudget(ctx context.Context, wp recoveryBudgetBeginner, userID int64) (exhausted, firstRefusal bool, err error) {
	tx, err := wp.Begin(ctx)
	if err != nil {
		return true, false, fmt.Errorf("recovery budget begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	state, err := acquireRecoveryBudgetRow(ctx, tx, userID)
	if err != nil {
		return true, false, fmt.Errorf("recovery budget acquire: %w", err)
	}
	now := time.Now()

	switch {
	case !state.windowActive(now):
		// Fresh row (now() sentinel) or expired window: this attempt OPENS the
		// next window anchored at now and is admitted as its first attempt —
		// window expiry restores the budget on schedule, untouched by how much
		// grinding filled the previous one.
		if err := recordRecoveryBudget(ctx, tx, userID, 1, now.Add(recoveryBudgetWindow)); err != nil {
			return true, false, fmt.Errorf("recovery budget open window: %w", err)
		}
	case state.attemptCount >= recoveryBudgetLimit:
		// Window still active and the budget is spent: refuse. The refusal is
		// recorded count-only under the UNCHANGED anchor (honest grinding
		// accounting; the window always expires on schedule) — the refused
		// attempt itself consumes nothing further.
		if err := recordRecoveryBudget(ctx, tx, userID, state.attemptCount+1, state.windowUntil); err != nil {
			return true, false, fmt.Errorf("recovery budget record refusal: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return true, false, fmt.Errorf("recovery budget commit refusal: %w", err)
		}
		return true, state.attemptCount == recoveryBudgetLimit, nil
	default:
		// Admitted inside the active window: consume one attempt, horizon
		// unchanged (a fixed window, not a sliding one).
		if err := recordRecoveryBudget(ctx, tx, userID, state.attemptCount+1, state.windowUntil); err != nil {
			return true, false, fmt.Errorf("recovery budget consume: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return true, false, fmt.Errorf("recovery budget commit: %w", err)
	}
	return false, false, nil
}

// auditRecoveryBudgetExhausted writes the established admin_audit_log emission
// for the FIRST refusal of a recovery-budget exhaustion episode (best-effort,
// the established convention on non-transactional paths — totp_removal.go).
// Fields stay within the table's existing shape: the server-resolved account
// id, the client IP, and the exhausted count in notes — no PII beyond what
// every other emission here already records.
func (h *accountRecoveryHandler) auditRecoveryBudgetExhausted(r *http.Request, userID int64) {
	h.pool.Exec(r.Context(),
		`INSERT INTO admin_audit_log (user_id, ip, action, target_type, target_id, notes)
		 VALUES ($1, $2::INET, 'recovery_budget_exhausted', 'user', $1, $3)`,
		userID, httputil.ClientIP(r),
		fmt.Sprintf("forgot-password recovery budget exhausted: %d attempts within the %d-minute window",
			recoveryBudgetLimit, int(recoveryBudgetWindow.Minutes())))
}

// recoveryBudgetRefused folds the seam's verdict into the handlers: log any
// fail-closed bookkeeping error, emit the one-shot audit row on the episode's
// first refusal, and report whether the attempt must be refused.
func (h *accountRecoveryHandler) recoveryBudgetRefused(r *http.Request, userID int64) bool {
	exhausted, firstRefusal, err := consumeRecoveryBudget(r.Context(), h.workerPool, userID)
	if err != nil {
		h.logger.Warn("forgot-password: recovery budget bookkeeping error (fail-closed)", "error", err)
	}
	if exhausted && firstRefusal {
		h.auditRecoveryBudgetExhausted(r, userID)
	}
	return exhausted
}

// ── Forgot Password ────────────────────────────────────────────────────────

// ForgotPasswordBegin checks if the given email has MFA set up and returns the
// verification method. The response is UNIFORM with respect to account existence:
// a missing account, a disabled account, and an existing account with no MFA all
// receive the SAME status + body (method "totp" + the generic message) after the
// SAME constant delay, so neither content nor timing reveals whether the account
// exists. A real push-MFA account additionally receives a nonce (it must, to be
// able to answer the challenge); a TOTP account's begin response is already
// byte-identical to the decoy. Per-IP rate limiting (the shared enumIPGuard,
// matching PushMFASend's AllowIP) caps grinding across emails; the per-account
// recovery budget (consumeRecoveryBudget, ER5 s07) additionally caps grinding
// against ONE account from ANY number of IPs.
//
// POST /auth/forgot-password/begin  { email }
func (h *accountRecoveryHandler) ForgotPasswordBegin(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if enumRateLimited(w, r) {
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Email == "" {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "email is required"})
		return
	}

	user, method := h.resolveForgotPasswordMethod(r.Context(), req.Email)

	// Uniform decoy response for non-existent / no-MFA accounts: identical to a
	// real TOTP account's begin response so existence cannot be inferred. The
	// uniform floor (not a decoy-only sleep) keeps the cheap real legs — decoy
	// AND real TOTP — above the same minimum wall-clock time, so latency cannot
	// separate them either.
	decoy := func() {
		enumUniformFloor(start)
		httputil.WriteJSON(w, http.StatusOK, map[string]string{
			"method":  "totp",
			"message": msgForgotPasswordGeneric,
		})
	}

	if user == nil {
		decoy()
		return
	}

	// Per-account recovery budget (ER5 s07): a real account's begin consumes
	// one attempt regardless of method or outcome. An exhausted (or fail-closed)
	// budget answers the DECOY — byte-identical to the non-exhausted TOTP
	// account leg, so budget state cannot be enumerated either — and skips
	// challenge dispatch entirely (no push notifications minted, no challenge
	// rows written for a request that is refused anyway).
	if h.recoveryBudgetRefused(r, user.ID) {
		decoy()
		return
	}

	resp := map[string]string{"method": method, "message": msgForgotPasswordGeneric}

	if method == "push" && h.pushMFA != nil {
		// Bind this challenge to the recovery purpose via session_id: the
		// verify seam only accepts challenges stamped with
		// authn.ForgotPasswordChallengePurpose, so a login-generated challenge
		// can never be consumed through this path (and vice versa the login
		// flow never consumes these — it refuses in-band answers with 410).
		challenge, err := h.pushMFA.GenerateChallenge(r.Context(), user.ID, authn.ForgotPasswordChallengePurpose)
		if err != nil {
			h.logger.Warn("forgot-password: push challenge generation failed, falling back to TOTP", "error", err)
			var totpEnabled bool
			if err := h.pool.QueryRow(r.Context(),
				`SELECT COALESCE(totp_enabled, FALSE) FROM users WHERE id = $1`, user.ID,
			).Scan(&totpEnabled); err != nil {
				h.logger.Warn("forgot-password: TOTP fallback check failed", "error", err)
			}
			if totpEnabled {
				resp["method"] = "totp"
			} else {
				// Push-only account whose challenge could not be sent: emit the
				// decoy so a transient failure does not become an existence oracle.
				decoy()
				return
			}
		} else {
			resp["nonce"] = challenge.Nonce
		}
	}

	// Real-account response: a TOTP-enrolled account reaches here with NO
	// challenge dispatch work done, so it must meet the same floor as the decoy
	// (the push branch's dispatch already exceeds it, which the floor enforces
	// for free).
	enumUniformFloor(start)
	httputil.WriteJSON(w, http.StatusOK, resp)
}

// resolveForgotPasswordMethod returns the user and best MFA method.
// Returns nil, "" if the user doesn't exist or has no MFA enabled.
//
// The enrollment snapshot comes from the shared CredentialStore (the same source
// Login / WebAuthn read), but the SELECTION here is deliberately NOT
// SelectMFAMethod: forgot-password prefers TOTP when both are enrolled (the
// inverse of the login Push>TOTP order). That asymmetry is pre-existing and
// load-bearing — keeping it local preserves byte-identical behavior.
func (h *accountRecoveryHandler) resolveForgotPasswordMethod(ctx context.Context, email string) (*userRow, string) {
	creds, err := h.credentials.CredentialsByEmail(ctx, email)
	if err != nil {
		return nil, ""
	}

	if !creds.AnyChallengeMFAEnrolled() {
		return nil, ""
	}

	user := &userRow{ID: creds.UserID, Email: email, TOTPEnabled: creds.TOTPEnrolled, PushMFAEnabled: creds.PushMFAEnrolled}
	method := "totp"
	if !creds.TOTPEnrolled && creds.PushMFAEnrolled {
		method = "push"
	}
	return user, method
}

// ForgotPasswordVerify validates the MFA code and returns a short-lived
// password reset JWT.
//
// POST /auth/forgot-password/verify  { email, code | nonce, answer }
//
// Bounds: the shared per-IP enumIPGuard caps grinding from one source, and the
// per-account recovery budget (consumeRecoveryBudget, ER5 s07) caps attempts
// against ONE account across all sources — an exhausted budget answers the
// uniform wrong-code 401 before any verification runs.
func (h *accountRecoveryHandler) ForgotPasswordVerify(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	// Same per-IP grinding cap as ForgotPasswordBegin: this endpoint is also an
	// enumeration / brute-force surface, so it routes through the shared seam too.
	if enumRateLimited(w, r) {
		return
	}
	var req struct {
		Email  string `json:"email"`
		Code   string `json:"code"`
		Nonce  string `json:"nonce"`
		Answer string `json:"answer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Email == "" {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "email is required"})
		return
	}

	user, _ := h.resolveForgotPasswordMethod(r.Context(), req.Email)
	if user == nil {
		time.Sleep(enumConstantDelay)
		httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": msgInvalidVerificationCode})
		return
	}

	// The SAME per-account recovery budget begin consumes (ER5 s07): one verify
	// attempt per request regardless of branch or outcome. An exhausted (or
	// fail-closed) budget returns the standard failure — byte-identical to the
	// wrong-code 401 — BEFORE any verification runs, so no factor lockout
	// moves, no challenge burns, and a distributed fleet (many IPs, one
	// account) cannot grind verification attempts past the budget the per-IP
	// guard cannot see.
	if h.recoveryBudgetRefused(r, user.ID) {
		time.Sleep(enumConstantDelay)
		httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": msgInvalidVerificationCode})
		return
	}

	var verified bool

	if req.Nonce != "" && h.pushMFA != nil {
		// Route the push branch through the SAME per-account lockout seam the
		// TOTP branch uses, so the forgot-password push path cannot be used to
		// grind number-match answers across fresh challenges: 5 failed answers
		// within the window lock the account and return the same 429 the TOTP
		// lockout returns (the only branch that legitimately reveals nothing
		// beyond "too many attempts"). The seam also rejects challenges not
		// minted for this recovery purpose. A provider without the seam is
		// refused (verified stays false → uniform 401).
		if rv, ok := h.pushMFA.(pushRecoveryVerifier); ok {
			outcome, lockErr := rv.VerifyChallengeWithLockout(r.Context(), user.ID, req.Nonce, req.Answer)
			if lockErr != nil {
				h.logger.Error("forgot-password: push lockout bookkeeping error", "error", lockErr)
			}
			if outcome == authn.PushVerifyLocked {
				time.Sleep(enumConstantDelay)
				httputil.WriteJSON(w, http.StatusTooManyRequests, map[string]string{"error": msgAccountLocked})
				return
			}
			verified = outcome == authn.PushVerifyAccepted
		}
	} else if req.Code != "" {
		// Route the TOTP code through the SAME lockout seam TOTPVerify uses, so the
		// forgot-password TOTP path cannot be used to brute-force codes without the
		// 5-failure → 15-minute lock. A locked account returns 429 (the only branch
		// that legitimately reveals nothing beyond "too many attempts").
		//
		// v7 §2.3 caller table: a TOTPBookkeepingError here is 500 with NO
		// enumeration signal (no constant-time delay theater on an
		// infrastructure failure) and NO reset_token — the cycle rolled back
		// and nothing may proceed on unknown bookkeeping state.
		outcome, cycleErr := authn.VerifyTOTPWithLockout(r.Context(), h.pool, user.ID, req.Code)
		if outcome == authn.TOTPBookkeepingError {
			h.logger.Error("forgot-password: TOTP lockout bookkeeping error", "user_id", user.ID, "error", cycleErr)
			httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
		if outcome == authn.TOTPLocked {
			time.Sleep(enumConstantDelay)
			httputil.WriteJSON(w, http.StatusTooManyRequests, map[string]string{"error": msgAccountLocked})
			return
		}
		verified = outcome == authn.TOTPAccepted
	}

	if !verified {
		h.logger.Warn("forgot-password: verification failed", "email", req.Email)
		time.Sleep(enumConstantDelay)
		httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": msgInvalidVerificationCode})
		return
	}

	resetToken, err := h.jwt.IssuePasswordReset(user.ID, user.Email)
	if err != nil {
		h.logger.Error("forgot-password: token issue failed", "error", err)
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{
		"reset_token": resetToken,
	})
}

// ForgotPasswordReset consumes the reset token and sets a new password.
//
// POST /auth/forgot-password/reset  { email, reset_token, new_password }
func (h *accountRecoveryHandler) ForgotPasswordReset(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Email       string `json:"email"`
		ResetToken  string `json:"reset_token"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Email == "" || req.ResetToken == "" || req.NewPassword == "" {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "email, reset_token, and new_password are required"})
		return
	}

	claims, err := h.jwt.Validate(req.ResetToken)
	if err != nil || claims.Type != token.TypePasswordReset {
		httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired reset token"})
		return
	}

	if !strings.EqualFold(claims.Email, req.Email) {
		httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired reset token"})
		return
	}

	tokenHash := token.HashTokenHex(req.ResetToken)
	tag, err := h.pool.Exec(r.Context(),
		`INSERT INTO used_password_reset_tokens (token_hash) VALUES ($1) ON CONFLICT DO NOTHING`,
		tokenHash,
	)
	if err != nil {
		h.logger.Error("forgot-password: token tracking failed", "error", err)
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired reset token"})
		return
	}

	// is_admin is DERIVED from admin_role_assignments (isAdminExprSQL), NOT the
	// vestigial users.is_admin column — the RBAC cut-over left that column
	// DEFAULT false NOT NULL and the grant path never sets it, so reading it raw
	// applied the WEAKER non-admin password policy to every governed admin. Same
	// canonical derivation as impersonation.go / lookupUser / session.Me.
	var isAdmin bool
	if err := h.pool.QueryRow(r.Context(),
		`SELECT `+isAdminExprSQL+` FROM users WHERE id = $1`, claims.UserID,
	).Scan(&isAdmin); err != nil {
		httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
		return
	}

	var pwCheckRaw json.RawMessage
	if err := h.pool.QueryRow(r.Context(),
		`SELECT validate_password($1, $2)`, req.NewPassword, isAdmin,
	).Scan(&pwCheckRaw); err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	var pwCheck struct {
		Valid bool   `json:"valid"`
		Error string `json:"error"`
	}
	json.Unmarshal(pwCheckRaw, &pwCheck)
	if !pwCheck.Valid {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": pwCheck.Error})
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	defer tx.Rollback(r.Context())
	if _, err := tx.Exec(r.Context(),
		`SELECT identity_auth_local_mint_fence($1)`, claims.UserID,
	); err != nil {
		httputil.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "credential update fence unavailable",
		})
		return
	}

	newHash, err := pwhash.HashPasswordWithProfile(req.NewPassword)
	if err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	if _, err := tx.Exec(r.Context(),
		`UPDATE users SET password_hash = $1 WHERE id = $2`,
		string(newHash), claims.UserID,
	); err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	if err := h.svc.RevokeAllForUserTx(r.Context(), tx, claims.UserID); err != nil {
		h.logger.Error("forgot-password: token revocation failed", "error", err)
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	h.logger.Info("password reset via forgot-password flow",
		"user_id", claims.UserID,
		"email", claims.Email,
	)

	httputil.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "Password has been reset. You may now sign in with your new password.",
	})
}
