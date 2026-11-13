package authn

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// closedPool returns a pgxpool.Pool that is immediately closed so any Exec/Query
// returns an error. Mirrors the handler-package helper so authn-package tests can
// exercise fail-open / short-circuit branches without a live database.
func closedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig("postgres://127.0.0.1:5432/test?connect_timeout=1")
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	pool.Close()
	return pool
}

// ── TOTP lockout decision logic (pure) ──────────────────────────────────────

// TestNextTOTPLockout_TripsAtThreshold proves the pure lockout decision: the
// account is NOT locked until the 5th consecutive failure, and IS locked exactly
// at the threshold, for totpLockDuration. This is the single policy both the
// MFA-step path and the forgot-password TOTP path now share via
// VerifyTOTPWithLockout, so the brute-force ceiling is identical everywhere.
func TestNextTOTPLockout_TripsAtThreshold(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	for prior := 0; prior < totpMaxFailures-1; prior++ {
		newCount, lockedUntil := NextTOTPLockout(prior, now)
		if newCount != prior+1 {
			t.Errorf("prior=%d: newCount=%d, want %d", prior, newCount, prior+1)
		}
		if lockedUntil != nil {
			t.Errorf("prior=%d: locked too early (%v); lock must only trip at %d failures",
				prior, *lockedUntil, totpMaxFailures)
		}
	}

	// The failure that reaches the threshold must lock for exactly totpLockDuration.
	newCount, lockedUntil := NextTOTPLockout(totpMaxFailures-1, now)
	if newCount != totpMaxFailures {
		t.Fatalf("threshold failure newCount=%d, want %d", newCount, totpMaxFailures)
	}
	if lockedUntil == nil {
		t.Fatal("account must be locked at the failure threshold")
	}
	if want := now.Add(totpLockDuration); !lockedUntil.Equal(want) {
		t.Errorf("lockedUntil=%v, want %v", *lockedUntil, want)
	}
}

// TestTOTPLockState_Locked verifies the persisted-state predicate used to gate
// verification: a future lockedUntil means locked, a past one (or nil) means not.
func TestTOTPLockState_Locked(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	future := now.Add(time.Minute)
	past := now.Add(-time.Minute)

	if (TOTPLockState{LockedUntil: nil}).Locked(now) {
		t.Error("nil lockedUntil must not be locked")
	}
	if (TOTPLockState{LockedUntil: &past}).Locked(now) {
		t.Error("past lockedUntil must not be locked")
	}
	if !(TOTPLockState{LockedUntil: &future}).Locked(now) {
		t.Error("future lockedUntil must be locked")
	}
}

// TestVerifyTOTPWithLockout_FailsOpenButNeverGrants pins the shared seam's
// DB-failure contract. REVISED DELIBERATELY (possession scheme v7 §2.3): the
// historical fail-open load (a discarded lock-state read error, with the
// verify still attempted) is one of the three named defects the fenced cycle
// repairs — a bookkeeping failure now yields TOTPBookkeepingError, the cycle
// is rolled back, and the caller must refuse. The unchanging invariant this
// test keeps from its pre-gate form: a DB error must NEVER yield
// TOTPAccepted (would grant access on failure).
func TestVerifyTOTPWithLockout_FailsOpenButNeverGrants(t *testing.T) {
	pool := closedPool(t)
	outcome, err := VerifyTOTPWithLockout(context.Background(), pool, 42, "123456")
	if outcome == TOTPAccepted {
		t.Fatal("a DB error must NEVER yield TOTPAccepted (would grant access on failure)")
	}
	if outcome != TOTPBookkeepingError {
		t.Errorf("outcome on DB error = %d, want TOTPBookkeepingError (%d) — the v7 §2.3 fail-closed refusal", outcome, TOTPBookkeepingError)
	}
	if err == nil {
		t.Error("TOTPBookkeepingError must carry the wrapped cause for the caller's log")
	}
}

// ── Source-level guards: the structural fixes cannot silently regress ────────

// TestConfirmTOTP_ValidatesPendingSecret is a source-level guard for the
// ConfirmTOTP regression fix. Enrollment confirm runs while totp_enabled is still
// FALSE; the OLD code called VerifyTOTP (which filters totp_enabled = TRUE) so
// confirm could NEVER succeed. The fix routes ConfirmTOTP through the pending
// path (verifyPendingTOTP). This test fails against the old code (which called
// VerifyTOTP from ConfirmTOTP) and passes against the fix.
func TestConfirmTOTP_ValidatesPendingSecret(t *testing.T) {
	fn := funcBody(t, "ConfirmTOTP")
	if !strings.Contains(fn, "verifyPendingTOTP") {
		t.Error("ConfirmTOTP must validate the first code via verifyPendingTOTP (pending secret path); " +
			"using VerifyTOTP would require totp_enabled=TRUE and confirm could never succeed")
	}
	if callsEnabledOnlyVerify(t, "ConfirmTOTP") {
		t.Error("ConfirmTOTP must NOT call the enabled-only VerifyTOTP during enrollment confirm")
	}
}

// TestConfirmTOTP_LifecycleFenceSerializesRemoval is the source-level guard for
// the removal/confirm race fix (med-webmail-mfa-lifecycle-001 r2, Astra P1):
// enrollment confirmation and factor removal are competing transactions on the
// same users row, and the OLD ConfirmTOTP verified the code and flipped
// totp_enabled in two unsynchronized statements, so "verification → removal
// commit → confirmation update" resurrected an enabled factor over erased
// secrets. The fix must keep the pending-path verification, take the same
// user-row fence the removal holds BEFORE verifying, and flip totp_enabled with
// a guarded write that fails closed on zero rows.
func TestConfirmTOTP_LifecycleFenceSerializesRemoval(t *testing.T) {
	src := funcBody(t, "ConfirmTOTP")
	for _, needle := range []string{
		"Begin",                       // the fence only exists inside one transaction
		"FOR NO KEY UPDATE",           // the fence: conflicts with DisableTOTPWithStepUp's FOR UPDATE
		"verifyPendingTOTP",           // verification must run UNDER the fence, not before it
		"RowsAffected",                // the enable is a guarded write whose zero-row outcome fails closed
		"COALESCE(totp_enabled",       // never enable over an already-active or wiped factor
		"totp_secret_enc IS NOT NULL", // never enable over an erased secret
		"Commit",
	} {
		if !strings.Contains(src, needle) {
			t.Errorf("ConfirmTOTP must contain %q (removal/confirm lifecycle fence)", needle)
		}
	}
}

// TestVerifyPendingTOTP_DoesNotRequireEnabled proves the pending verify path
// fetches the secret regardless of totp_enabled (requireEnabled=false), so the
// first enrollment code can be validated before TOTP is active.
func TestVerifyPendingTOTP_DoesNotRequireEnabled(t *testing.T) {
	src := funcBody(t, "verifyPendingTOTP")
	if !strings.Contains(src, "verifyTOTPCore") || !strings.Contains(src, "false") {
		t.Error("verifyPendingTOTP must delegate to verifyTOTPCore with requireEnabled=false")
	}
}

// TestVerifyTOTPCore_AtomicReplayClaim is the source-level guard for the TOCTOU
// replay-race fix. The OLD code did fetch-secret / SELECT last_totp_used_at /
// UPDATE as three separate non-transactional steps, so two concurrent requests
// with the same code could both pass. The fix collapses the replay defence into a
// single conditional UPDATE whose WHERE clause is the window guard and whose
// RETURNING proves which caller won the claim. This guard fails if anyone
// re-introduces a standalone SELECT of last_totp_used_at (the read half of the
// old TOCTOU) into the verify core.
func TestVerifyTOTPCore_AtomicReplayClaim(t *testing.T) {
	src := funcBody(t, "verifyTOTPCore")

	// The atomic claim: a single UPDATE ... WHERE last_totp_used_at (window guard)
	// ... RETURNING. All three tokens must be present in the same function.
	for _, needle := range []string{"UPDATE users", "last_totp_used_at", "RETURNING"} {
		if !strings.Contains(src, needle) {
			t.Errorf("verifyTOTPCore must contain %q as part of the atomic replay-claim UPDATE", needle)
		}
	}

	// The read half of the OLD TOCTOU — a standalone SELECT of last_totp_used_at —
	// must NOT be present: the window check now lives in the UPDATE's WHERE clause.
	if strings.Contains(src, "SELECT last_totp_used_at") ||
		strings.Contains(src, "SELECT id, last_totp_used_at") {
		t.Error("verifyTOTPCore must not SELECT last_totp_used_at separately; the window guard belongs in the atomic UPDATE WHERE clause (TOCTOU)")
	}
}

func TestGenerateTOTPEnrollmentSecret_GuardsActiveFactorAtWrite(t *testing.T) {
	src := funcBody(t, "generateTOTPEnrollmentSecret")
	for _, needle := range []string{"totp_enabled", "enabled = TRUE", "mfa_status", "RowsAffected"} {
		if !strings.Contains(src, needle) {
			t.Errorf("generateTOTPEnrollmentSecret must enforce %q in the guarded write", needle)
		}
	}
	if !strings.Contains(funcBody(t, "GenerateTOTPEnrollmentSecretTx"),
		"generateTOTPEnrollmentSecret") {
		t.Error("transactional enrollment setup must use the same guarded write")
	}
}

func TestConfirmTOTPEnrollment_OwnsAtomicSecurityBoundary(t *testing.T) {
	wrapper := funcBody(t, "ConfirmTOTPEnrollment")
	for _, needle := range []string{"BeginTx", "ConfirmTOTPEnrollmentTx", "Commit"} {
		if !strings.Contains(wrapper, needle) {
			t.Errorf("ConfirmTOTPEnrollment wrapper must contain %q", needle)
		}
	}
	src := funcBody(t, "ConfirmTOTPEnrollmentTx")
	// "NextTOTPLockout" was replaced (v7 §2.3) by the SINGLE-statement atomic
	// increment — the lost-update repair — so the marker pins the new form.
	for _, needle := range []string{
		"FOR NO KEY UPDATE", "mfa_status", "totp_enabled",
		"totp_failed_attempts + 1",
		"last_totp_used_at", "RowsAffected", "totp_confirmed",
		"factor_generation = factor_generation + 1",
	} {
		if !strings.Contains(src, needle) {
			t.Errorf("ConfirmTOTPEnrollmentTx must contain %q", needle)
		}
	}
	if strings.Contains(src, ".Commit(") {
		t.Error("ConfirmTOTPEnrollmentTx must leave commit to its caller")
	}
}

// ── AST helpers ─────────────────────────────────────────────────────────────

// funcBody returns the source text of the named top-level function in totp.go.
func funcBody(t *testing.T, name string) string {
	t.Helper()
	fset := token.NewFileSet()
	src, err := parser.ParseFile(fset, "totp.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse totp.go: %v", err)
	}
	for _, d := range src.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name {
			continue
		}
		var sb strings.Builder
		ast.Inspect(fn, func(n ast.Node) bool {
			if bl, ok := n.(*ast.BasicLit); ok {
				sb.WriteString(bl.Value)
				sb.WriteString("\n")
			}
			if id, ok := n.(*ast.Ident); ok {
				sb.WriteString(id.Name)
				sb.WriteString(" ")
			}
			return true
		})
		return sb.String()
	}
	t.Fatalf("function %q not found in totp.go", name)
	return ""
}

// callsEnabledOnlyVerify reports whether the named function calls VerifyTOTP
// (the enabled-only verifier) directly.
func callsEnabledOnlyVerify(t *testing.T, name string) bool {
	t.Helper()
	fset := token.NewFileSet()
	src, err := parser.ParseFile(fset, "totp.go", nil, 0)
	if err != nil {
		t.Fatalf("parse totp.go: %v", err)
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
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "VerifyTOTP" {
				found = true
			}
			return true
		})
	}
	return found
}
