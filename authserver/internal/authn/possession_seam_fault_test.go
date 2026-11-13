package authn

// possession_seam_fault_test.go — statement-fault injection AT THE SEAM for
// the possession gate's storage and TOTP-cycle arms the DB-driven suites
// cannot reach (TODOS: possession surface coverage seams). The production
// stores are already interfaces (GrantStore, totpCycleStore,
// totpEnrollmentStore, userReadStore, pgx.Tx), so each previously
// unreachable SELECT/Exec failure arm is driven by a scripted stub and
// asserted on the OBSERVABLE production handling: the exact wrapped error,
// the typed refusal, or the typed outcome — never merely line execution.
//
// Classes still NOT covered here (recorded honestly):
//   - crypto/rand entropy arms (mintReauthToken, newTOTPKey, the
//     webauthn_user_handle mint): rand.Reader is not a seam without a
//     production change beyond interface extraction;
//   - the dead provisioning-URI fallback body (ProvisioningURIForSecret's
//     Sprintf arm — NewKeyFromURL cannot fail on the canonical URL shape);
//   - json.Marshal arms over protocol/webauthn library types and the
//     go-webauthn begin/validate internal errors.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pquerna/otp/totp"
)

// --- seam stubs (SQL-dispatched, mirroring the splitStub convention) ---

// scanRow is a pgx.Row whose Scan is a closure.
type seamRow struct{ scan func(dest ...any) error }

func (r seamRow) Scan(dest ...any) error { return r.scan(dest...) }

func seamErrRow() seamRow { return seamRow{scan: func(...any) error { return errInjected }} }

func seamNoRowsRow() seamRow { return seamRow{scan: func(...any) error { return pgx.ErrNoRows }} }

// seamGrantStore is a GrantStore stub for one BindGrantTarget call shape.
type seamGrantStore struct {
	updateRow pgx.Row
	stateRow  pgx.Row
}

func (s *seamGrantStore) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("DELETE 0"), nil
}

func (s *seamGrantStore) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	if strings.Contains(sql, "RETURNING token_hash") {
		return s.updateRow
	}
	return s.stateRow
}

// seamCycleStore drives the TOTP cycle's statements by SQL shape. The nil
// pgx.Tx embed satisfies the interface for the Tx-taking callers while the
// overrides carry every statement the cycle makes.
type seamCycleStore struct {
	pgx.Tx // nil embed

	lockRead   func(dest ...any) error // FOR NO KEY UPDATE read
	secretRead func(dest ...any) error // pgp_sym_decrypt read
	claimRead  func(dest ...any) error // last_totp_used_at claim
	recordScan func(dest ...any) error // failure-increment RETURNING read
	recordErr  error                   // record statement error (pre-Scan)
	enableErr  error                   // enable Exec error
	enableTag  pgconn.CommandTag
	auditErr   error
	execSQLs   []string
}

func (s *seamCycleStore) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	switch {
	case strings.Contains(sql, "FOR NO KEY UPDATE") && strings.Contains(sql, "totp_locked_until"):
		return seamRow{s.lockRead}
	case strings.Contains(sql, "pgp_sym_decrypt"):
		return seamRow{s.secretRead}
	case strings.Contains(sql, "last_totp_used_at"):
		return seamRow{s.claimRead}
	case strings.Contains(sql, "totp_failed_attempts = totp_failed_attempts + 1"):
		if s.recordErr != nil {
			return seamRow{func(...any) error { return s.recordErr }}
		}
		return seamRow{s.recordScan}
	}
	panic("seamCycleStore: unexpected query: " + sql)
}

func (s *seamCycleStore) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	s.execSQLs = append(s.execSQLs, sql)
	if strings.Contains(sql, "totp_enabled = TRUE") {
		if s.enableErr != nil {
			return pgconn.CommandTag{}, s.enableErr
		}
		return s.enableTag, nil
	}
	if strings.Contains(sql, "admin_audit_log") && s.auditErr != nil {
		return pgconn.CommandTag{}, s.auditErr
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

// gateTxStub is a pgx.Tx stub for the registration ceremony loader.
type gateTxStub struct {
	pgx.Tx    // nil embed — unstubbed methods panic (the loader uses three)
	userRow   pgx.Row
	queryRows pgx.Rows
	queryErr  error
}

func (t *gateTxStub) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (t *gateTxStub) QueryRow(context.Context, string, ...any) pgx.Row { return t.userRow }

func (t *gateTxStub) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return t.queryRows, t.queryErr
}

// gateRowsStub is a pgx.Rows stub yielding one credential row (Scan driven).
type gateRowsStub struct {
	pgx.Rows // nil embed
	scanErr  error
	closed   bool
}

func (r *gateRowsStub) Next() bool { return !r.closed }

func (r *gateRowsStub) Scan(...any) error { return r.scanErr }

func (r *gateRowsStub) Close() { r.closed = true }

func (r *gateRowsStub) Err() error { return nil }

// userReadStub drives loadUserReadOnlyFiltered's two reads.
type userReadStub struct {
	userRow  pgx.Row
	credRows pgx.Rows
	queryErr error
}

func (u *userReadStub) QueryRow(context.Context, string, ...any) pgx.Row { return u.userRow }

func (u *userReadStub) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return u.credRows, u.queryErr
}

// validSeamSecret mints a base32 secret and the code valid for it right now.
func validSeamSecret(t *testing.T) (secret, code string) {
	t.Helper()
	secret = "MFRGGZDFMZTWQ2LKNNWG23TPM5XGK3DR" // fixed base32 payload
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	return secret, code
}

// --- possession.go: the §1.6 binding-state read fault (467-468) ---

func TestBindGrantTargetStateReadFault(t *testing.T) {
	ctx := context.Background()
	store := &seamGrantStore{updateRow: seamNoRowsRow(), stateRow: seamErrRow()}
	_, err := BindGrantTarget(ctx, store, "hash-x", 1, "jti-x", "target-x")
	if err == nil || !strings.Contains(err.Error(), "grant binding state") || !errors.Is(err, errInjected) {
		t.Fatalf("BindGrantTarget state-read fault = %v, want the wrapped binding-state error", err)
	}
}

// --- totp.go: statement faults on the shared cycle seam ---

func TestValidateTOTPCodeSkipsUnmintableWindows(t *testing.T) {
	// GenerateCodeCustom fails for a non-base32 secret: every window candidate
	// errors and the compare folds to false without panicking (the continue arm).
	if ValidateTOTPCode("123456", "!!!not-base32!!!") {
		t.Fatal("ValidateTOTPCode accepted a code against an unmintable secret")
	}
}

func TestVerifyTOTPClaimWriteFault(t *testing.T) {
	secret, code := validSeamSecret(t)
	stub := &seamCycleStore{
		lockRead: func(dest ...any) error {
			*(dest[0].(**time.Time)) = nil // unlocked
			*(dest[1].(*int)) = 0
			return nil
		},
		secretRead: func(dest ...any) error {
			*(dest[0].(*string)) = secret
			return nil
		},
		claimRead: func(...any) error { return errInjected },
	}
	ok, err := verifyPendingTOTP(context.Background(), stub, 1, code)
	if ok || err == nil || !strings.Contains(err.Error(), "totp replay claim") {
		t.Fatalf("verify with faulted claim = (%v,%v), want the wrapped replay-claim error", ok, err)
	}
}

func TestGenerateTOTPEnrollmentSecretTxFaults(t *testing.T) {
	ctx := context.Background()
	// Statement fault: the guarded store fails → the wrapped error, no URI.
	tx := &gateTxStub{}
	stub := &faultExecTx{Tx: tx, execErr: errInjected}
	if _, err := GenerateTOTPEnrollmentSecretTx(ctx, stub, 1, "u@example.test", "SetJoin"); err == nil || !strings.Contains(err.Error(), "store enrollment totp secret") {
		t.Fatalf("enrollment secret store fault = %v, want the wrapped store error", err)
	}
	// Happy path through the Tx wrapper: tag UPDATE 1 → the provisioning URI.
	happy := &gateTxStub{}
	stub2 := &faultExecTx{Tx: happy, tag: pgconn.NewCommandTag("UPDATE 1")}
	uri, err := GenerateTOTPEnrollmentSecretTx(ctx, stub2, 1, "u@example.test", "SetJoin")
	if err != nil || !strings.Contains(uri, "otpauth://totp/") {
		t.Fatalf("enrollment secret happy = (%q,%v), want a provisioning URI", uri, err)
	}
}

// faultExecTx layers a controllable Exec over a pgx.Tx.
type faultExecTx struct {
	pgx.Tx
	execErr error
	tag     pgconn.CommandTag
}

func (t *faultExecTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	if t.execErr != nil {
		return pgconn.CommandTag{}, t.execErr
	}
	return t.tag, nil
}

func TestConfirmTOTPEnrollmentTxSeamFaults(t *testing.T) {
	ctx := context.Background()
	secret, code := validSeamSecret(t)

	enqueue := func(lock func(...any) error, record func(dest ...any) error, recordErr error, enableErr error, enableTag pgconn.CommandTag, auditErr error) *seamCycleStore {
		return &seamCycleStore{
			lockRead:   lock,
			secretRead: func(dest ...any) error { *(dest[0].(*string)) = secret; return nil },
			claimRead:  func(...any) error { return pgx.ErrNoRows }, // unreachable here
			recordScan: record,
			recordErr:  recordErr,
			enableErr:  enableErr,
			enableTag:  enableTag,
			auditErr:   auditErr,
		}
	}
	happyLock := func(dest ...any) error {
		*(dest[0].(**string)) = &secret
		*(dest[1].(*bool)) = false
		*(dest[2].(*int)) = 0
		*(dest[3].(**time.Time)) = nil
		*(dest[4].(**time.Time)) = nil // last_used: old enough
		*(dest[5].(*string)) = "enrollment_required"
		return nil
	}

	t.Run("lock read missing user", func(t *testing.T) {
		stub := enqueue(func(...any) error { return pgx.ErrNoRows }, nil, nil, nil, pgconn.CommandTag{}, nil)
		outcome, err := ConfirmTOTPEnrollmentTx(ctx, stub, 1, code, "")
		if outcome != TOTPInvalid || !errors.Is(err, ErrTOTPEnrollmentUnavailable) {
			t.Fatalf("missing-user lock read = (%v,%v), want (TOTPInvalid, ErrTOTPEnrollmentUnavailable)", outcome, err)
		}
	})
	t.Run("lock read statement fault", func(t *testing.T) {
		stub := enqueue(func(...any) error { return errInjected }, nil, nil, nil, pgconn.CommandTag{}, nil)
		outcome, err := ConfirmTOTPEnrollmentTx(ctx, stub, 1, code, "")
		if outcome != TOTPInvalid || !strings.Contains(err.Error(), "lock totp enrollment") {
			t.Fatalf("faulted lock read = (%v,%v), want the wrapped lock error", outcome, err)
		}
	})
	t.Run("replay window invalidates a verified code", func(t *testing.T) {
		freshLock := func(dest ...any) error {
			happyLock(dest...)
			now := time.Now()
			*(dest[4].(**time.Time)) = &now // claimed moments ago
			return nil
		}
		stub := enqueue(freshLock, func(dest ...any) error { *(dest[0].(**time.Time)) = nil; return nil }, nil, nil, pgconn.CommandTag{}, nil)
		outcome, err := ConfirmTOTPEnrollmentTx(ctx, stub, 1, code, "")
		if outcome != TOTPInvalid || err != nil {
			t.Fatalf("replayed code = (%v,%v), want (TOTPInvalid, nil)", outcome, err)
		}
	})
	t.Run("record failure zero rows → locked", func(t *testing.T) {
		stub := enqueue(happyLock, func(...any) error { return pgx.ErrNoRows }, nil, nil, pgconn.CommandTag{}, nil)
		stub.secretRead = func(...any) error { return pgx.ErrNoRows } // invalid code path
		outcome, err := ConfirmTOTPEnrollmentTx(ctx, stub, 1, "0000000", "")
		if outcome != TOTPLocked || err != nil {
			t.Fatalf("locked refusal = (%v,%v), want (TOTPLocked, nil)", outcome, err)
		}
	})
	t.Run("record failure statement fault", func(t *testing.T) {
		stub := enqueue(happyLock, nil, errInjected, nil, pgconn.CommandTag{}, nil)
		stub.secretRead = func(...any) error { return pgx.ErrNoRows }
		outcome, err := ConfirmTOTPEnrollmentTx(ctx, stub, 1, "0000000", "")
		if outcome != TOTPInvalid || !strings.Contains(err.Error(), "record enrollment totp failure") {
			t.Fatalf("faulted record = (%v,%v), want the wrapped record error", outcome, err)
		}
	})
	t.Run("enable statement fault", func(t *testing.T) {
		stub := enqueue(happyLock, nil, nil, errInjected, pgconn.CommandTag{}, nil)
		outcome, err := ConfirmTOTPEnrollmentTx(ctx, stub, 1, code, "")
		if outcome != TOTPInvalid || !strings.Contains(err.Error(), "enable enrollment totp") {
			t.Fatalf("faulted enable = (%v,%v), want the wrapped enable error", outcome, err)
		}
	})
	t.Run("enable matched zero rows", func(t *testing.T) {
		stub := enqueue(happyLock, nil, nil, nil, pgconn.NewCommandTag("UPDATE 0"), nil)
		outcome, err := ConfirmTOTPEnrollmentTx(ctx, stub, 1, code, "")
		if outcome != TOTPInvalid || !errors.Is(err, ErrTOTPEnrollmentUnavailable) {
			t.Fatalf("zero-row enable = (%v,%v), want (TOTPInvalid, ErrTOTPEnrollmentUnavailable)", outcome, err)
		}
	})
	t.Run("audit statement fault", func(t *testing.T) {
		stub := enqueue(happyLock, nil, nil, nil, pgconn.NewCommandTag("UPDATE 1"), errInjected)
		outcome, err := ConfirmTOTPEnrollmentTx(ctx, stub, 1, code, "")
		if outcome != TOTPInvalid || !strings.Contains(err.Error(), "audit enrollment totp") {
			t.Fatalf("faulted audit = (%v,%v), want the wrapped audit error", outcome, err)
		}
	})
}

// NOTE: recordTOTPFailureTx's errors.Is(err, pgx.ErrNoRows) arm is a
// same-transaction DEFENSIVE arm, deliberately left uncovered: its statement
// is an Exec, and pgx Exec returns a zero-row CommandTag, never
// pgx.ErrNoRows — no store, real or scripted, can produce that branch.

// --- pool-seam statement faults (the closed-pool and trigger precedent) ---

func TestGenerateTOTPSecretStoreFault(t *testing.T) {
	// The pool is the seam: a closed pool fails the guarded store statement.
	pool := armsClosedPool(t)
	if _, err := GenerateTOTPSecret(context.Background(), pool, 1, "u@example.test", "SetJoin"); err == nil || !strings.Contains(err.Error(), "store totp secret") {
		t.Fatalf("GenerateTOTPSecret(closed pool) = %v, want the wrapped store error", err)
	}
}

func TestConfirmTOTPEnrollmentBeginFault(t *testing.T) {
	// Begin is the seam for the wrapper: a closed pool fails it before any
	// statement, and the wrapper answers the bookkeeping-grade failure.
	pool := armsClosedPool(t)
	outcome, err := ConfirmTOTPEnrollment(context.Background(), pool, 1, "0000000", "")
	if outcome != TOTPInvalid || err == nil || !strings.Contains(err.Error(), "begin totp enrollment confirm") {
		t.Fatalf("ConfirmTOTPEnrollment(closed pool) = (%v,%v), want the wrapped begin error", outcome, err)
	}
}

func TestResetTOTPLockoutStoreFault(t *testing.T) {
	// The pool is the seam: the reset's error propagates unwrapped so callers
	// observe the bookkeeping failure (never a silent pass).
	pool := armsClosedPool(t)
	if err := ResetTOTPLockout(context.Background(), pool, 1); err == nil {
		t.Fatal("ResetTOTPLockout(closed pool) returned no error")
	}
}

func TestConfirmTOTPEnableStatementFault(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	userID, secret := makeTOTPUser(t, pool, false)
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	// Fault ONLY the guarded enable (totp_enabled flips TRUE): the replay
	// claim inside verification leaves it FALSE, so verification succeeds and
	// the enable statement alone fails — the wrap-and-rollback arm.
	fn := "seam_confirm_enable_fault"
	trig := fn + "_trig"
	armsFaultTrigger(t, pool, fn, trig, "users", "BEFORE UPDATE",
		"NEW.id = "+armsUID(userID)+" AND NEW.totp_enabled IS TRUE")

	if err := ConfirmTOTP(ctx, pool, userID, code); err == nil || !strings.Contains(err.Error(), "enable totp confirm") {
		t.Fatalf("ConfirmTOTP with a faulted enable = %v, want the wrapped enable error", err)
	}
	// The factor is still NOT enabled (the failed enable rolled back).
	var enabled bool
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(totp_enabled, FALSE) FROM users WHERE id = $1`, userID).Scan(&enabled); err != nil || enabled {
		t.Fatalf("factor state after faulted confirm = %v (%v), want disabled", enabled, err)
	}
}

func TestDisableTOTPDisableStatementFault(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	userID, secret := makeTOTPUser(t, pool, true)
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	// Fault ONLY the removal statement (totp_enabled flips FALSE with the
	// secret wiped): verification succeeds, the disable fails — the raw-error
	// arm (no wrap) with the factor left intact.
	fn := "seam_disable_fault"
	trig := fn + "_trig"
	armsFaultTrigger(t, pool, fn, trig, "users", "BEFORE UPDATE",
		"NEW.id = "+armsUID(userID)+" AND OLD.totp_enabled IS TRUE AND NEW.totp_enabled IS NOT TRUE")

	if err := DisableTOTP(ctx, pool, userID, code); err == nil {
		t.Fatal("DisableTOTP with a faulted disable returned no error")
	}
	var enabled bool
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(totp_enabled, FALSE) FROM users WHERE id = $1`, userID).Scan(&enabled); err != nil || !enabled {
		t.Fatalf("factor state after faulted disable = %v (%v), want still enabled", enabled, err)
	}
}

// --- webauthn_possession.go: ceremony loader faults ---

func TestLoadUserReadOnlyFilteredFaults(t *testing.T) {
	p := &PasskeyProvider{}
	ctx := context.Background()

	if _, err := p.loadUVUserReadOnly(ctx, &userReadStub{userRow: seamErrRow()}, 1); err == nil {
		t.Fatal("loadUVUserReadOnly with a faulted user read returned no error")
	}
	if _, err := p.loadUserReadOnly(ctx, &userReadStub{userRow: seamNoRowsRow()}, 1); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("loadUserReadOnly with a missing user = %v, want pgx.ErrNoRows", err)
	}
	if _, err := p.loadUserReadOnly(ctx, &userReadStub{
		userRow: seamRow{scan: func(dest ...any) error {
			*(dest[0].(*int64)) = 1
			*(dest[1].(*string)) = "u@example.test"
			*(dest[2].(*string)) = "u"
			*(dest[3].(*[]byte)) = []byte("handle")
			return nil
		}},
		credRows: &gateRowsStub{scanErr: errInjected},
	}, 1); !errors.Is(err, errInjected) {
		t.Fatalf("credential scan fault = %v, want errInjected", err)
	}
}

func TestLoadUserForRegistrationTxFaults(t *testing.T) {
	ctx := context.Background()
	userRow := func(handle []byte) pgx.Row {
		return seamRow{scan: func(dest ...any) error {
			*(dest[0].(*int64)) = 1
			*(dest[1].(*string)) = "u@example.test"
			*(dest[2].(*string)) = "u"
			*(dest[3].(*[]byte)) = handle
			return nil
		}}
	}

	// User read fault (fresh handle: the mint/persist never runs).
	if _, err := loadUserForRegistrationTx(ctx, &gateTxStub{userRow: seamErrRow()}, 1); err == nil {
		t.Fatal("registration load with a faulted user read returned no error")
	}
	// Credential query fault (durable handle present: no mint UPDATE).
	if _, err := loadUserForRegistrationTx(ctx, &gateTxStub{
		userRow:  userRow([]byte("durable-handle")),
		queryErr: errInjected,
	}, 1); !errors.Is(err, errInjected) {
		t.Fatalf("credential query fault = %v, want errInjected", err)
	}
	// Credential scan fault.
	if _, err := loadUserForRegistrationTx(ctx, &gateTxStub{
		userRow:   userRow([]byte("durable-handle")),
		queryRows: &gateRowsStub{scanErr: errInjected},
	}, 1); !errors.Is(err, errInjected) {
		t.Fatalf("credential scan fault = %v, want errInjected", err)
	}
}

// --- residual cheap arms found by the after-measurement ---

func TestDisableTOTPInvalidCodeRefusal(t *testing.T) {
	// A wrong code refuses the removal before any statement: the typed
	// invalid-code error (no wrap). The fixture secret is RANDOMLY generated,
	// so wrongness must not depend on the code draw: 7 digits always
	// length-mismatches the 6-digit validator output (ConstantTimeCompare),
	// and an unlucky "valid" collision can neither disable the fixture
	// factor nor pollute any sibling subtest.
	pool := integrationPool(t)
	userID, _ := makeTOTPUser(t, pool, true)
	if err := DisableTOTP(context.Background(), pool, userID, "0000000"); err == nil || err.Error() != "invalid TOTP code" {
		t.Fatalf("DisableTOTP(wrong code) = %v, want the typed invalid-code error", err)
	}
}

func TestLoadUserReadOnlyFilteredQueryFault(t *testing.T) {
	// The credential-list Query itself fails (not the row scan).
	p := &PasskeyProvider{}
	stub := &userReadStub{
		userRow: seamRow{scan: func(dest ...any) error {
			*(dest[0].(*int64)) = 1
			*(dest[1].(*string)) = "u@example.test"
			*(dest[2].(*string)) = "u"
			*(dest[3].(*[]byte)) = []byte("handle")
			return nil
		}},
		queryErr: errInjected,
	}
	if _, err := p.loadUVUserReadOnly(context.Background(), stub, 1); !errors.Is(err, errInjected) {
		t.Fatalf("credential query fault = %v, want errInjected", err)
	}
}

func TestBeginRegistrationCeremonyPropagatesLoadFault(t *testing.T) {
	// The ceremony begin is its caller's transaction: a faulted user load
	// propagates verbatim (options/session are never minted).
	p := &PasskeyProvider{}
	_, _, _, err := p.BeginRegistrationCeremony(context.Background(), &gateTxStub{userRow: seamErrRow()}, 1)
	if err == nil {
		t.Fatal("BeginRegistrationCeremony with a faulted load returned no error")
	}
}
