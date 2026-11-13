package authn

// totp_verify_split_test.go — the machinery-vs-observation split of the
// shared TOTP cycle (opus r1 finding 4): a REPLAYED code is an evaluated
// rejection and counts toward the lockout; a statement error or a missing
// enabled secret can never evaluate the proof and yields TOTPBookkeepingError
// (fail-closed, NO counter write). Driven against a programmable store stub
// so the statement classification is pinned exactly.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pquerna/otp/totp"
)

// stubRow is a pgx.Row whose Scan is a closure.
type stubRow struct {
	scan func(dest ...any) error
}

func (r stubRow) Scan(dest ...any) error { return r.scan(dest...) }

// splitStub dispatches the cycle's three reads by their SQL shape and counts
// every Exec (the only write the cycle makes is the counter statement).
// claimReads counts the REPLAY-claim reads: the distinguishing marker of the
// split — the claim only runs when a code actually VERIFIED (r8: the pre-r8
// replay test submitted a fixed wrong code and never reached it).
type splitStub struct {
	lockScan   func(dest ...any) error // "FOR NO KEY UPDATE" read
	secretScan func(dest ...any) error // "pgp_sym_decrypt" read
	claimScan  func(dest ...any) error // "last_totp_used_at" claim
	claimReads int
	execCalls  int
	execSQL    string
}

func (s *splitStub) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	switch {
	case contains(sql, "FOR NO KEY UPDATE"):
		return stubRow{s.lockScan}
	case contains(sql, "pgp_sym_decrypt"):
		return stubRow{s.secretScan}
	case contains(sql, "last_totp_used_at"):
		s.claimReads++
		return stubRow{s.claimScan}
	}
	panic("unexpected query: " + sql)
}

func (s *splitStub) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	s.execCalls++
	s.execSQL = sql
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		// strings.Contains, without the import churn in the stub
		indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

func lockedRow(t *testing.T) func(dest ...any) error {
	return func(dest ...any) error {
		lockUntil := dest[0].(**time.Time)
		*lockUntil = nil
		return nil
	}
}

// A replayed code: the code VERIFIES against the secret, and the replay
// claim misses (window already claimed) — an EVALUATED rejection that counts
// (r8: the submitted code must be VALID for its window, and the test asserts
// the replay claim was actually reached — the split's distinguishing
// behavior a fixed wrong code never exercised).
func TestSplitReplayCountsAsInvalidCode(t *testing.T) {
	s := &splitStub{
		lockScan: lockedRow(t),
		secretScan: func(dest ...any) error {
			*(dest[0].(*string)) = "JBSWY3DPEHPK3PXP"
			return nil
		},
		claimScan: func(dest ...any) error { return pgx.ErrNoRows },
	}
	valid, err := totp.GenerateCode("JBSWY3DPEHPK3PXP", time.Now())
	if err != nil {
		t.Fatalf("generate valid code: %v", err)
	}
	outcome, err := VerifyTOTPWithLockoutTx(context.Background(), s, 1, valid)
	if outcome != TOTPInvalid {
		t.Fatalf("replayed code outcome = %v (err: %v), want TOTPInvalid", outcome, err)
	}
	if err != nil {
		t.Fatalf("replayed code must not surface an error, got %v", err)
	}
	if s.claimReads != 1 {
		t.Fatalf("replay-claim reads = %d, want 1 — the code must VERIFY so the cycle reaches the replay claim (the split's distinguishing path)", s.claimReads)
	}
	if s.execCalls != 1 {
		t.Fatalf("exec calls = %d, want 1 (the replay counts toward the lockout)", s.execCalls)
	}
}

// A statement error at the secret read: the proof can never be evaluated —
// bookkeeping, fail-closed, NO counter write.
func TestSplitVerifyStatementErrorIsBookkeeping(t *testing.T) {
	s := &splitStub{
		lockScan: lockedRow(t),
		secretScan: func(dest ...any) error {
			return errors.New("injected secret-read failure")
		},
	}
	outcome, err := VerifyTOTPWithLockoutTx(context.Background(), s, 1, "123456")
	if outcome != TOTPBookkeepingError {
		t.Fatalf("statement-error outcome = %v, want TOTPBookkeepingError", outcome)
	}
	if err == nil {
		t.Fatal("bookkeeping outcome must carry the wrapped error")
	}
	if s.execCalls != 0 {
		t.Fatalf("exec calls = %d, want 0 (no counter for an unevaluated proof)", s.execCalls)
	}
}

// A missing enabled secret (totp_enabled = FALSE or the row gone): nothing
// to verify against — the same fail-closed bookkeeping refusal, no counter.
func TestSplitMissingSecretIsBookkeeping(t *testing.T) {
	s := &splitStub{
		lockScan:   lockedRow(t),
		secretScan: func(dest ...any) error { return pgx.ErrNoRows },
	}
	outcome, err := VerifyTOTPWithLockoutTx(context.Background(), s, 1, "123456")
	if outcome != TOTPBookkeepingError {
		t.Fatalf("missing-secret outcome = %v, want TOTPBookkeepingError", outcome)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("missing-secret err = %v, want the wrapped pgx.ErrNoRows", err)
	}
	if s.execCalls != 0 {
		t.Fatalf("exec calls = %d, want 0", s.execCalls)
	}
}

// Sanity: a plain wrong code still evaluates and counts (the unchanged
// majority path the split must not disturb).
func TestSplitWrongCodeStillCounts(t *testing.T) {
	s := &splitStub{
		lockScan: lockedRow(t),
		secretScan: func(dest ...any) error {
			*(dest[0].(*string)) = "JBSWY3DPEHPK3PXP"
			return nil
		},
	}
	// The claim read only happens for a VALID code; a wrong code stops at
	// the constant-time compare — asserted here (r8) so the control stays
	// the exact negative of the replay case above.
	outcome, err := VerifyTOTPWithLockoutTx(context.Background(), s, 1, "000000")
	if outcome != TOTPInvalid {
		t.Fatalf("wrong-code outcome = %v (err: %v), want TOTPInvalid", outcome, err)
	}
	if err != nil {
		t.Fatalf("wrong code must not surface an error, got %v", err)
	}
	if s.claimReads != 0 {
		t.Fatalf("replay-claim reads = %d, want 0 (a wrong code never reaches the claim)", s.claimReads)
	}
	if s.execCalls != 1 {
		t.Fatalf("exec calls = %d, want 1", s.execCalls)
	}
}
