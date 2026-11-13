package handlers

// possession_totp_budget_test.go — the possession/totp failure budget
// (r1 receipt defect 2; scheme v7 §2.3): evaluated TOTP failures through the
// REAL possession handler must accumulate toward the account lock — the
// handler commits the evaluated failure bookkeeping before answering 403 —
// and a locked account refuses valid and invalid codes alike with the
// counter untouched.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func seedEnabledTOTP(t *testing.T, h *AuthHandler, userID int64) {
	t.Helper()
	if _, err := h.pool.Exec(context.Background(),
		`UPDATE users SET totp_enabled = TRUE,
		                  totp_enabled_at = now(),
		                  totp_secret_enc = pgp_sym_encrypt($2, current_setting('app.encryption_key')),
		                  totp_failed_attempts = 0,
		                  totp_locked_until = NULL
		  WHERE id = $1`, userID, removalTestSecret,
	); err != nil {
		t.Fatalf("seed enabled totp: %v", err)
	}
}

func readTOTPBudget(t *testing.T, h *AuthHandler, userID int64) (attempts int, lockedUntil *time.Time) {
	t.Helper()
	if err := h.pool.QueryRow(context.Background(),
		`SELECT totp_failed_attempts, totp_locked_until FROM users WHERE id = $1`, userID,
	).Scan(&attempts, &lockedUntil); err != nil {
		t.Fatalf("read totp budget: %v", err)
	}
	return attempts, lockedUntil
}

// TestFailedPossessionTOTPCountsTowardBudget is the r1 defect 2
// reproduction: repeated wrong-code guesses against the REAL
// POST /auth/mfa/possession/totp handler accumulate toward the five-attempt
// lock (the evaluated failure bookkeeping COMMITS), and once locked, valid
// and invalid codes are refused 429 without moving the counter.
func TestFailedPossessionTOTPCountsTowardBudget(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUser(t, h, "totpbudget", false)
	seedEnabledTOTP(t, h, userID)

	body := func(code string) map[string]any {
		return map[string]any{"operation": "recovery.regenerate", "code": code}
	}

	// Five evaluated failures: each answers 403 AND commits its increment.
	for i := 1; i <= 5; i++ {
		rr := postPossession(h, "/auth/mfa/possession/totp", body("000000"), nil, claims)
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "invalid TOTP") {
			t.Fatalf("attempt %d: status = %d body %s, want 403 invalid TOTP code", i, rr.Code, rr.Body.String())
		}
		attempts, _ := readTOTPBudget(t, h, userID)
		if attempts != i {
			t.Fatalf("attempt %d: persisted counter = %d, want %d — the evaluated failure did not commit", i, attempts, i)
		}
	}

	// The 5th sets the lock.
	_, lockedUntil := readTOTPBudget(t, h, userID)
	if lockedUntil == nil || !lockedUntil.After(time.Now()) {
		t.Fatalf("lock not set by the 5th evaluated failure: %v", lockedUntil)
	}

	// The 6th — wrong code — is refused LOCKED (429) without increment.
	rr := postPossession(h, "/auth/mfa/possession/totp", body("000000"), nil, claims)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("locked wrong code: status = %d body %s, want 429", rr.Code, rr.Body.String())
	}
	// A VALID code is refused LOCKED too — without being consumed.
	valid, err := totp.GenerateCode(removalTestSecret, time.Now())
	if err != nil {
		t.Fatalf("generate valid code: %v", err)
	}
	rr = postPossession(h, "/auth/mfa/possession/totp", body(valid), nil, claims)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("locked valid code: status = %d body %s, want 429", rr.Code, rr.Body.String())
	}
	attempts, _ := readTOTPBudget(t, h, userID)
	if attempts != 5 {
		t.Fatalf("locked refusals moved the counter: %d, want exactly 5", attempts)
	}
}

// TestTOTPBudgetMixedEntryPointsSerializeThroughRealHandlers is the r2
// defect 5a completion of the §4.1 mixed-entry case, tightened by the r4
// acceptance review: mixed-entry assertions must observe and control ACTUAL
// evaluations per caller — never infer an either-401-or-429 accounting from
// the aggregate counter. Three phases pin the behavior through the REAL
// handlers (login TOTPVerify, removal TOTPRemovalBegin, forgot-password
// ForgotPasswordVerify):
//
//   - Phase 1 (deterministic pinning): one solo wrong-code attempt per caller,
//     the counter observed between attempts. Every caller's 401 coincides with
//     exactly +1 — WHICH request evaluated is observed, not inferred — and no
//     caller is locked yet.
//   - Phase 2 (controlled concurrency): the counter is parked at EXACTLY 4, so
//     one more evaluated failure can exist; one attempt per caller fires
//     concurrently. The headroom CONTROL pins the evaluated count at exactly
//     one of the three (observed as the single 401), the other two must answer
//     their locked 429, and the counter observes 5 with the lock set.
//   - Phase 3 (locked refusals): a further attempt through every caller is
//     exactly 429 with NO counter movement.
//
// A final concurrent load phase keeps the serialization-under-load coverage
// while asserting only REQUIRED per-caller mappings (login/removal answer
// 401-evaluated or 429-locked and nothing else, and their 401s each committed
// exactly one increment so they can never exceed the budget; forgot answers
// the uniform 401/429 refusals only) plus the aggregate authority (EXACTLY 5,
// lock set, no 500s).
func TestTOTPBudgetMixedEntryPointsSerializeThroughRealHandlers(t *testing.T) {
	h := newPossessionHarness(t)
	ctx := context.Background()

	userID, claims := newPossessionUserWithEmail(t, h, "mixed-entry", false)
	seedEnabledTOTP(t, h, userID)
	if _, err := h.pool.Exec(ctx,
		`UPDATE users SET password_hash = $2, totp_failed_attempts = 0,
		                  totp_locked_until = NULL WHERE id = $1`, userID, mustHash(t, "correct-horse-battery"),
	); err != nil {
		t.Fatalf("seed password: %v", err)
	}
	// The forgot-password verify rides the shared per-IP enum guard and the
	// per-account recovery budget: give this test its own generous guard so
	// other tests' global-limiter usage cannot leak a pre-cycle 429 in.
	withEnumGuard(t, 100, time.Minute)

	pending, err := h.jwt.IssueMFAPending(userID, claims.Email)
	if err != nil {
		t.Fatalf("issue mfa pending: %v", err)
	}

	// attempt delivers ONE wrong-code attempt through the named entry point's
	// REAL handler and returns the HTTP status. Required per-caller mappings
	// (the §2.3 caller table through the real arms):
	//   login / removal: 401 ≡ an EVALUATED failure (its increment committed);
	//                    429 ≡ a locked refusal (no evaluation, no increment).
	//                    No third shape exists on these arms.
	//   forgot:          the same cycle drives its TOTP branch (401 evaluated /
	//                    429 locked), but the per-IP enum guard and the
	//                    per-account recovery budget answer PRE-CYCLE refusals
	//                    in the same 401/429 shapes — nothing else (never 500).
	attempt := func(entry string) int {
		var req *http.Request
		switch entry {
		case "login":
			req = httptest.NewRequest(http.MethodPost, "/auth/totp/verify",
				strings.NewReader(`{"mfa_token":"`+pending+`","code":"000000"}`))
			rr := httptest.NewRecorder()
			h.TOTPVerify(rr, req)
			return rr.Code
		case "removal":
			req = httptest.NewRequest(http.MethodPost, "/auth/totp/removal/begin",
				strings.NewReader(`{"password":"correct-horse-battery","code":"000000"}`))
			req = req.WithContext(ContextWithUser(req.Context(), claims))
			rr := httptest.NewRecorder()
			h.TOTPRemovalBegin(rr, req)
			return rr.Code
		case "forgot":
			req = httptest.NewRequest(http.MethodPost, "/auth/forgot-password/verify",
				strings.NewReader(`{"email":"`+claims.Email+`","code":"000000"}`))
			rr := httptest.NewRecorder()
			h.ForgotPasswordVerify(rr, req)
			return rr.Code
		}
		panic("unknown entry " + entry)
	}
	entries := []string{"login", "removal", "forgot"}

	// ── Phase 1: deterministic per-caller evaluation pinning ────────────────
	// Solo sequential wrong-code attempts: each caller's 401 must coincide
	// with exactly +1 on the counter observed between attempts — the request's
	// evaluation is OBSERVED, never inferred from an aggregate.
	for _, entry := range entries {
		before, beforeLock := readTOTPBudget(t, h, userID)
		if beforeLock != nil {
			t.Fatalf("phase 1 (%s): fixture locked early: %v", entry, beforeLock)
		}
		if code := attempt(entry); code != http.StatusUnauthorized {
			t.Fatalf("phase 1 (%s): solo wrong-code attempt answered %d, want exactly 401 (an evaluated failure)", entry, code)
		}
		after, afterLock := readTOTPBudget(t, h, userID)
		if after != before+1 {
			t.Fatalf("phase 1 (%s): the 401 did not commit exactly one increment: counter %d → %d — WHICH request evaluated must be observable, not inferred", entry, before, after)
		}
		if afterLock != nil {
			t.Fatalf("phase 1 (%s): lock set at %d attempts, want unlocked", entry, after)
		}
	}

	// ── Phase 2: controlled-concurrency pinning (headroom = exactly 1) ──────
	// Park at EXACTLY 4: one more evaluated failure CAN exist. One attempt per
	// caller fires concurrently; the headroom control pins the evaluated count
	// at exactly one of the three, whoever wins the fence.
	if _, err := h.pool.Exec(ctx,
		`UPDATE users SET totp_failed_attempts = 4, totp_locked_until = NULL WHERE id = $1`, userID,
	); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		entry string
		code  int
	}
	var mu sync.Mutex
	outcomes := make([]outcome, 0, len(entries))
	var wg sync.WaitGroup
	for _, entry := range entries {
		wg.Add(1)
		go func(entry string) {
			defer wg.Done()
			code := attempt(entry)
			mu.Lock()
			outcomes = append(outcomes, outcome{entry, code})
			mu.Unlock()
		}(entry)
	}
	wg.Wait()

	evaluated := 0
	for _, o := range outcomes {
		switch o.code {
		case http.StatusUnauthorized:
			// The one evaluated request — through ANY caller's arm. The
			// headroom guarantees exactly one; a second would mean an
			// evaluated failure committed beyond the budget or a locked
			// caller evaluated anyway.
			evaluated++
		case http.StatusTooManyRequests:
			// The locked refusals.
		default:
			t.Fatalf("phase 2 (%s): answered %d — the required mapping is 401 evaluated / 429 locked only", o.entry, o.code)
		}
	}
	if evaluated != 1 {
		t.Fatalf("phase 2: evaluated failures = %d across %v, want EXACTLY 1 (the headroom control pins which request evaluated)", evaluated, outcomes)
	}
	attempts, lockedUntil := readTOTPBudget(t, h, userID)
	if attempts != 5 {
		t.Fatalf("phase 2: counter = %d, want EXACTLY 5", attempts)
	}
	if lockedUntil == nil || !lockedUntil.After(time.Now()) {
		t.Fatalf("phase 2: lock not set by the 5th evaluated failure: %v", lockedUntil)
	}

	// ── Phase 3: locked refusals through every caller, no counter movement ──
	for _, entry := range entries {
		if code := attempt(entry); code != http.StatusTooManyRequests {
			t.Fatalf("phase 3 (%s): locked entry answered %d, want exactly 429 (refused without evaluation)", entry, code)
		}
	}
	after, afterLock := readTOTPBudget(t, h, userID)
	if after != 5 || !afterLock.After(time.Now()) {
		t.Fatalf("phase 3: locked refusals moved the budget: %d %v, want 5 and a live lock", after, afterLock)
	}

	// ── Phase 4: concurrent load, REQUIRED mappings + aggregate authority ───
	// Twelve concurrent wrong-code attempts (4 per caller) from a clean
	// budget. No per-request attribution is claimed here; what IS asserted is
	// each caller's required mapping (login/removal: 401 evaluated or 429
	// locked, nothing else — and each of their 401s committed exactly one
	// increment, so their count can never exceed the budget), the aggregate
	// authority (EXACTLY 5, lock set), and zero bookkeeping 500s.
	if _, err := h.pool.Exec(ctx,
		`UPDATE users SET totp_failed_attempts = 0, totp_locked_until = NULL WHERE id = $1`, userID,
	); err != nil {
		t.Fatal(err)
	}
	var wg2 sync.WaitGroup
	var mu2 sync.Mutex
	load := make([]outcome, 0, 12)
	for i := 0; i < 12; i++ {
		entry := entries[i%len(entries)]
		wg2.Add(1)
		go func(entry string) {
			defer wg2.Done()
			code := attempt(entry)
			mu2.Lock()
			load = append(load, outcome{entry, code})
			mu2.Unlock()
		}(entry)
	}
	wg2.Wait()

	direct401s := 0
	for _, o := range load {
		switch o.entry {
		case "login", "removal":
			switch o.code {
			case http.StatusUnauthorized:
				direct401s++ // REQUIRED: each of these committed exactly one increment
			case http.StatusTooManyRequests:
			default:
				t.Fatalf("phase 4 (%s): answered %d — want 401 evaluated / 429 locked only", o.entry, o.code)
			}
		case "forgot":
			if o.code != http.StatusUnauthorized && o.code != http.StatusTooManyRequests {
				t.Fatalf("phase 4 (forgot): answered %d — want the uniform 401/429 refusals only", o.code)
			}
		}
	}
	if direct401s > 5 {
		t.Fatalf("phase 4: %d login/removal 401s exceed the five-attempt budget — an evaluated mapping lied about its increment", direct401s)
	}
	loadAttempts, loadLock := readTOTPBudget(t, h, userID)
	if loadAttempts != 5 {
		t.Fatalf("phase 4: counter = %d after the concurrent race, want EXACTLY 5 (no lost update)", loadAttempts)
	}
	if loadLock == nil || !loadLock.After(time.Now()) {
		t.Fatalf("phase 4: lock not set by the 5th evaluated failure: %v", loadLock)
	}
}
