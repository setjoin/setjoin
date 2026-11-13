package authn

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// totpValidateOpts mirrors the defaults used by totp.Validate (RFC 6238):
// 30 s period, ±1 skew, 6 digits, SHA-1.
var totpValidateOpts = totp.ValidateOpts{
	Period:    30,
	Skew:      1,
	Digits:    otp.DigitsSix,
	Algorithm: otp.AlgorithmSHA1,
}

// ErrTOTPEnrollmentUnavailable is returned when a short-lived enrollment proof
// no longer maps to an enabled user who is still required to enroll. Callers
// deliberately expose this as a constant-shaped re-login response: policy may
// have changed, the account may have been disabled, or enrollment may already
// have completed.
var ErrTOTPEnrollmentUnavailable = errors.New("TOTP enrollment unavailable")

// validateTOTPConstantTime reports whether code is a valid TOTP for secret at
// time t. The submitted code is compared against every expected code in the
// validation window (current period ± skew) using crypto/subtle.ConstantTimeCompare,
// so the matching path leaks neither whether a code matched nor which window it
// matched: every candidate is always compared and the boolean result is folded
// in constant time. Behaviour is identical to totp.Validate; only the app-level
// compare is made explicitly timing-safe.
func validateTOTPConstantTime(code, secret string, t time.Time) bool {
	match := 0
	period := int64(totpValidateOpts.Period)
	counter := t.Unix() / period
	skew := int64(totpValidateOpts.Skew)
	for offset := -skew; offset <= skew; offset++ {
		candidateTime := time.Unix((counter+offset)*period, 0)
		expected, err := totp.GenerateCodeCustom(secret, candidateTime, totpValidateOpts)
		if err != nil {
			continue
		}
		// ConstantTimeCompare returns 1 only when lengths and bytes match; it is
		// length-safe, so a wrong-length code is handled without branching on code.
		match |= subtle.ConstantTimeCompare([]byte(code), []byte(expected))
	}
	return match == 1
}

// totpReplayWindow is the RFC 6238 §5.2 replay window: a code accepted within
// this window of a previous acceptance is rejected as a replay.
const totpReplayWindow = 30 * time.Second

// VerifyTOTP validates a 6-digit TOTP code for an account whose TOTP is already
// enabled. The secret is stored AES-encrypted via pgcrypto; the encryption key
// is set as the session variable app.encryption_key at pool connect time.
//
// Replay protection (RFC 6238 §5.2) is enforced atomically: the success path
// commits the acceptance with a single conditional UPDATE that doubles as a
// claim, so two concurrent requests presenting the same valid code cannot both
// succeed — exactly one wins the UPDATE; the loser is treated as a replay.
func VerifyTOTP(ctx context.Context, pool *pgxpool.Pool, userID int64, code string) (bool, error) {
	return verifyTOTPCore(ctx, pool, userID, code, true)
}

// totpVerifyStore is the pool/tx seam for the TOTP verify core: the lifecycle
// fence (ConfirmTOTP) must run the secret read and the replay claim on the SAME
// transaction that holds the user-row lock, so verification can never race a
// concurrent factor removal across two separate connections.
type totpVerifyStore interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// verifyPendingTOTP validates a code against a PENDING secret (totp_enabled may
// still be FALSE). Used during enrollment confirmation, before TOTP is active.
// The store may be a transaction — ConfirmTOTP always passes its fence tx so
// verification happens under the lifecycle lock. Replay-claim semantics are
// identical to VerifyTOTP.
func verifyPendingTOTP(ctx context.Context, store totpVerifyStore, userID int64, code string) (bool, error) {
	return verifyTOTPCore(ctx, store, userID, code, false)
}

// verifyTOTPCore is the shared verify+replay-claim implementation.
//
// When requireEnabled is true the secret is only fetched if totp_enabled = TRUE
// (the normal MFA-step path). When false the secret is fetched regardless, so
// enrollment confirmation can validate the first code against the pending secret
// that GenerateTOTPSecret stored while totp_enabled was still FALSE.
//
// The replay defence is a single conditional UPDATE that atomically claims the
// 30 s window: it only affects a row when last_totp_used_at is outside the
// window, and RETURNING tells us whether THIS call won the claim. This collapses
// the old fetch / SELECT last_used / UPDATE TOCTOU into one atomic statement, so
// concurrent duplicate submissions of the same code yield exactly one success.
func verifyTOTPCore(ctx context.Context, store totpVerifyStore, userID int64, code string, requireEnabled bool) (bool, error) {
	enabledFilter := ""
	if requireEnabled {
		enabledFilter = " AND totp_enabled = TRUE"
	}
	var secret string
	err := store.QueryRow(ctx,
		`SELECT pgp_sym_decrypt(totp_secret_enc::bytea,
		                        current_setting('app.encryption_key'))
		 FROM users WHERE id = $1`+enabledFilter,
		userID,
	).Scan(&secret)
	if err != nil {
		return false, fmt.Errorf("totp lookup: %w", err)
	}
	if !validateTOTPConstantTime(code, secret, time.Now()) {
		return false, nil
	}

	// Atomic replay claim: succeed only if no code was accepted within the
	// replay window. The WHERE clause is the guard and RETURNING is the proof of
	// which concurrent caller won. A row is returned to exactly one caller.
	var claimed int64
	err = store.QueryRow(ctx,
		`UPDATE users
			    SET last_totp_used_at = now()
			  WHERE id = $1
			    AND (last_totp_used_at IS NULL
			         OR last_totp_used_at < now() - make_interval(secs => $2))
			  RETURNING id`,
		userID, totpReplayWindow.Seconds(),
	).Scan(&claimed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The window guard rejected the claim: the code was already accepted
			// within the replay window (a replay or a lost concurrent race).
			// Typed sentinel so the shared cycle can distinguish this EVALUATED
			// rejection from bookkeeping-grade failures (r7: the machinery-vs-
			// observation split).
			return false, ErrTOTPReplayed
		}
		return false, fmt.Errorf("totp replay claim: %w", err)
	}
	return true, nil
}

// GenerateTOTPSecret creates a new TOTP secret, stores it encrypted in the DB
// (totp_enabled stays false), and returns the provisioning URI for QR rendering.
// Call ConfirmTOTP with a valid code to activate.
func newTOTPKey(email, issuer string) (*otp.Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: email,
		SecretSize:  32,
		Rand:        rand.Reader,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, err
	}
	return key, nil
}

func GenerateTOTPSecret(ctx context.Context, pool *pgxpool.Pool, userID int64, email, issuer string) (string, error) {
	key, err := newTOTPKey(email, issuer)
	if err != nil {
		return "", err
	}

	_, err = pool.Exec(ctx,
		`UPDATE users
		 SET totp_secret_enc = pgp_sym_encrypt($1, current_setting('app.encryption_key'))
		 WHERE id = $2`,
		key.Secret(), userID,
	)
	if err != nil {
		return "", fmt.Errorf("store totp secret: %w", err)
	}
	return key.URL(), nil
}

// NewTOTPProvisioningSecret generates a fresh TOTP key and returns its
// provisioning URI + raw secret WITHOUT writing any durable state. The
// gated setup arms (possession scheme v7 §1.6) stage the secret into
// totp_pending_enrollments instead of overwriting the ACTIVE factor — the
// replacement-setup-overwrites-live-secret defect this scheme repairs.
func NewTOTPProvisioningSecret(email, issuer string) (uri, secret string, err error) {
	key, err := newTOTPKey(email, issuer)
	if err != nil {
		return "", "", err
	}
	return key.URL(), key.Secret(), nil
}

// GenerateTOTPEnrollmentSecret rotates the pending secret for a user who has
// proved their password but cannot receive an access token until mandatory MFA
// enrollment completes. The write itself carries every state guard so a stale
// mfa_pending token can never overwrite an already-active authenticator.
// Replaying setup is intentionally "latest secret wins" while enrollment is
// pending; the threat interceptor rate-limits the public endpoint.
func GenerateTOTPEnrollmentSecret(ctx context.Context, pool *pgxpool.Pool, userID int64, email, issuer string) (string, error) {
	return generateTOTPEnrollmentSecret(ctx, pool, userID, email, issuer)
}

// GenerateTOTPEnrollmentSecretTx is the caller-owned transaction variant used
// when a federated identity fence must cover the pending-secret write.
func GenerateTOTPEnrollmentSecretTx(ctx context.Context, tx pgx.Tx, userID int64, email, issuer string) (string, error) {
	return generateTOTPEnrollmentSecret(ctx, tx, userID, email, issuer)
}

type totpEnrollmentStore interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func generateTOTPEnrollmentSecret(ctx context.Context, store totpEnrollmentStore, userID int64, email, issuer string) (string, error) {
	key, err := newTOTPKey(email, issuer)
	if err != nil {
		return "", err
	}

	tag, err := store.Exec(ctx,
		`UPDATE users
		    SET totp_secret_enc = pgp_sym_encrypt($1, current_setting('app.encryption_key')),
		        last_totp_used_at = NULL
		  WHERE id = $2
		    AND enabled = TRUE
		    AND COALESCE(totp_enabled, FALSE) = FALSE
		    AND (mfa_status($2)->>'status') = 'enrollment_required'`,
		key.Secret(), userID,
	)
	if err != nil {
		return "", fmt.Errorf("store enrollment totp secret: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return "", ErrTOTPEnrollmentUnavailable
	}
	return key.URL(), nil
}

// ConfirmTOTP enables TOTP for userID after verifying the first code against the
// PENDING secret stored by GenerateTOTPSecret. During enrollment totp_enabled is
// still FALSE, so confirmation must validate via the pending path — using the
// enabled-only VerifyTOTP here would never find the secret and confirm could
// never succeed.
//
// Lifecycle fence (med-webmail-mfa-lifecycle-001): enrollment confirmation and
// factor removal (DisableTOTPWithStepUp) are competing transactions on the same
// users row. Confirm takes the same row fence the removal holds BEFORE reading
// the pending secret — unfiltered by any TOTP lifecycle column, or the lock
// would be skipped exactly in the interleaving it exists for — so the two
// transitions serialize and either interleaving converges consistent:
//
//   - confirm wins the fence: the removal blocks, then re-reads the committed
//     enabled row and wipes factor, secret and recovery codes together;
//   - removal wins the fence: confirm re-reads the wiped row under the lock,
//     verification finds no pending secret and the guarded enable matches zero
//     rows, so the confirm FAILS CLOSED — it can never resurrect an enabled
//     factor over erased secrets.
func ConfirmTOTP(ctx context.Context, pool *pgxpool.Pool, userID int64, code string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin totp confirm: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The fence: FOR NO KEY UPDATE (same mode as ConfirmTOTPEnrollmentTx — it
	// conflicts with the removal's FOR UPDATE while still permitting
	// foreign-key KEY SHARE). A missing row (user deleted) fails closed.
	var locked int64
	err = tx.QueryRow(ctx,
		`SELECT id FROM users WHERE id = $1 FOR NO KEY UPDATE`,
		userID,
	).Scan(&locked)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("invalid TOTP code")
		}
		return fmt.Errorf("lock totp confirm: %w", err)
	}

	ok, err := verifyPendingTOTP(ctx, tx, userID, code)
	if err != nil || !ok {
		return fmt.Errorf("invalid TOTP code")
	}

	// Guarded enable: flips only a not-yet-enabled row that still holds a
	// secret, under the fence. Zero rows means the factor state changed under
	// us (removed, or already active) — fail closed instead of resurrecting or
	// double-enabling.
	tag, err := tx.Exec(ctx,
		`UPDATE users
		    SET totp_enabled = TRUE,
		        totp_enabled_at = now()
		  WHERE id = $1
		    AND COALESCE(totp_enabled, FALSE) = FALSE
		    AND totp_secret_enc IS NOT NULL`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("enable totp confirm: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("invalid TOTP code")
	}
	return tx.Commit(ctx)
}

// ConfirmTOTPEnrollment atomically converts the current pending secret into an
// active TOTP factor for a password-verified mfa_pending flow. It serializes
// non-key changes on the user row, re-checks live policy under that lock,
// applies the same five-failure lockout as normal TOTP verification, claims the
// replay window, writes the audit record, and enables TOTP exactly once before
// committing. The row lock deliberately permits foreign-key KEY SHARE so a
// caller-owned transaction can record login/session evidence through the
// normal pool before committing without waiting on itself.
func ConfirmTOTPEnrollment(ctx context.Context, pool *pgxpool.Pool, userID int64, code, clientIP string) (TOTPVerifyOutcome, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return TOTPInvalid, fmt.Errorf("begin totp enrollment confirm: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	outcome, err := ConfirmTOTPEnrollmentTx(ctx, tx, userID, code, clientIP)
	if err != nil {
		return outcome, err
	}
	if err := tx.Commit(ctx); err != nil {
		return TOTPInvalid, fmt.Errorf("commit totp enrollment confirm: %w", err)
	}
	return outcome, nil
}

// ConfirmTOTPEnrollmentTx performs enrollment confirmation inside a
// caller-owned transaction. It never commits: normalized SSO completion uses
// the same transaction for identity_auth_mint_fence, TOTP activation, and the
// refresh-family anchor.
func ConfirmTOTPEnrollmentTx(ctx context.Context, tx pgx.Tx, userID int64, code, clientIP string) (TOTPVerifyOutcome, error) {
	var (
		secret         *string
		totpEnabled    bool
		failedAttempts int
		lockedUntil    *time.Time
		lastUsedAt     *time.Time
		mfaStatus      string
	)
	err := tx.QueryRow(ctx,
		`SELECT CASE WHEN totp_secret_enc IS NULL THEN NULL
		             ELSE pgp_sym_decrypt(totp_secret_enc::bytea,
		                                  current_setting('app.encryption_key'))
		        END,
		        COALESCE(totp_enabled, FALSE),
		        COALESCE(totp_failed_attempts, 0),
		        totp_locked_until,
		        last_totp_used_at,
		        mfa_status(id)->>'status'
		   FROM users
		  WHERE id = $1 AND enabled = TRUE
		  FOR NO KEY UPDATE`,
		userID,
	).Scan(&secret, &totpEnabled, &failedAttempts, &lockedUntil, &lastUsedAt, &mfaStatus)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TOTPInvalid, ErrTOTPEnrollmentUnavailable
		}
		return TOTPInvalid, fmt.Errorf("lock totp enrollment: %w", err)
	}
	if totpEnabled || mfaStatus != "enrollment_required" {
		return TOTPInvalid, ErrTOTPEnrollmentUnavailable
	}

	now := time.Now()
	if lockedUntil != nil && lockedUntil.After(now) {
		return TOTPLocked, nil
	}

	valid := secret != nil && validateTOTPConstantTime(code, *secret, now)
	if valid && lastUsedAt != nil && !lastUsedAt.Before(now.Add(-totpReplayWindow)) {
		valid = false
	}
	if !valid {
		// Single-statement atomic increment (v7 §2.3): the counter moves by
		// the DB's own arithmetic, never by a previously-read absolute count —
		// the lost-update repair. The WHERE guard keeps locked refusals from
		// incrementing.
		var lockedAfter *time.Time
		err := tx.QueryRow(ctx,
			`UPDATE users
			    SET totp_failed_attempts = totp_failed_attempts + 1,
			        totp_locked_until =
			          CASE WHEN totp_failed_attempts + 1 >= $2
			               THEN now() + make_interval(secs => $3)
			               ELSE totp_locked_until END
			  WHERE id = $1
			    AND (totp_locked_until IS NULL OR totp_locked_until <= now())
			  RETURNING totp_locked_until`,
			userID, totpMaxFailures, totpLockDuration.Seconds(),
		).Scan(&lockedAfter)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return TOTPLocked, nil
			}
			return TOTPInvalid, fmt.Errorf("record enrollment totp failure: %w", err)
		}
		if lockedAfter != nil && lockedAfter.After(now) {
			return TOTPLocked, nil
		}
		return TOTPInvalid, nil
	}

	tag, err := tx.Exec(ctx,
		`UPDATE users
		    SET totp_enabled = TRUE,
		        totp_enabled_at = $2,
		        last_totp_used_at = $2,
		        totp_failed_attempts = 0,
		        totp_locked_until = NULL,
		        factor_generation = factor_generation + 1
		  WHERE id = $1
		    AND enabled = TRUE
		    AND COALESCE(totp_enabled, FALSE) = FALSE
		    AND (mfa_status($1)->>'status') = 'enrollment_required'`,
		userID, now,
	)
	if err != nil {
		return TOTPInvalid, fmt.Errorf("enable enrollment totp: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return TOTPInvalid, ErrTOTPEnrollmentUnavailable
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO admin_audit_log (user_id, ip, action, target_type, target_id)
		 VALUES ($1, NULLIF($2, '')::INET, 'totp_confirmed', 'user', $1)`,
		userID, clientIP,
	); err != nil {
		return TOTPInvalid, fmt.Errorf("audit enrollment totp: %w", err)
	}
	return TOTPAccepted, nil
}

// --- Per-account TOTP lockout (RFC 4226 §7.2-7.3) ---
//
// These helpers are the single source of truth for the "5 consecutive failures
// → 15-minute lock" policy, shared by every TOTP-verifying entry point
// (TOTPVerify and the forgot-password TOTP path) so no caller can bypass it.

const (
	// totpMaxFailures is the number of consecutive failed TOTP attempts that
	// trips the per-account lock.
	totpMaxFailures = 5
	// totpLockDuration is how long the account stays locked once tripped.
	totpLockDuration = 15 * time.Minute
)

// Exported policy values for callers outside the package (the budget cycle
// writers in the handlers package embed the same numbers in their SQL).
const (
	// TOTPMaxFailures is the exported lockout threshold.
	TOTPMaxFailures = totpMaxFailures
	// TOTPLockDurationSecs is the exported lock duration in seconds.
	TOTPLockDurationSecs = int64(totpLockDuration / time.Second)
)

// ValidateTOTPCode is the exported constant-time validator: the submitted
// code is compared against every candidate in the validation window
// (current period ± skew) with crypto/subtle, never leaking which window
// matched. Used by the promotion arms that verify a code against a STAGED
// secret under their own fences.
func ValidateTOTPCode(code, secret string) bool {
	return validateTOTPConstantTime(code, secret, time.Now())
}

// ProvisioningURIForSecret re-derives the provisioning URI from an existing
// secret (the §1.6 resume rule: retry-after-network-loss re-derives the URI
// from the SAME pending secret; no second secret is minted).
func ProvisioningURIForSecret(secret, email, issuer string) (string, error) {
	key, err := otp.NewKeyFromURL(totpGenerateURL(secret, email, issuer))
	if err != nil {
		// Fall back to building the URL directly for canonical output.
		return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
			url.PathEscape(issuer), url.PathEscape(email), secret, url.QueryEscape(issuer)), nil
	}
	return key.URL(), nil
}

func totpGenerateURL(secret, email, issuer string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		url.PathEscape(issuer), url.PathEscape(email), secret, url.QueryEscape(issuer))
}

// NextTOTPLockout is the pure lockout decision: given the number of consecutive
// failures recorded SO FAR and the time of the new failure, it returns the new
// failure count and, when the threshold is reached, the time the account stays
// locked until (nil when not yet locked). Keeping this pure makes the policy
// testable without a database and identical for every caller.
func NextTOTPLockout(priorFailures int, now time.Time) (newFailures int, lockedUntil *time.Time) {
	newFailures = priorFailures + 1
	if newFailures >= totpMaxFailures {
		t := now.Add(totpLockDuration)
		return newFailures, &t
	}
	return newFailures, nil
}

// TOTPLockState is the persisted lockout state for an account.
type TOTPLockState struct {
	FailedAttempts int
	LockedUntil    *time.Time
}

// Locked reports whether the account is currently locked at time now.
func (s TOTPLockState) Locked(now time.Time) bool {
	return s.LockedUntil != nil && s.LockedUntil.After(now)
}

// LoadTOTPLockState reads the current lockout counters for userID. A missing row
// or read error yields a zero (unlocked) state with the error, so callers may
// fail open on read errors exactly as the inline path did.
func LoadTOTPLockState(ctx context.Context, pool *pgxpool.Pool, userID int64) (TOTPLockState, error) {
	var s TOTPLockState
	err := pool.QueryRow(ctx,
		`SELECT totp_locked_until, COALESCE(totp_failed_attempts, 0) FROM users WHERE id = $1`,
		userID,
	).Scan(&s.LockedUntil, &s.FailedAttempts)
	return s, err
}

// TOTPLockedUnderFence reports whether the account's TOTP budget is currently
// locked, reading the lock state on the caller's transaction. This is §2.3
// step 2 for callers that evaluate the code OUTSIDE the shared
// VerifyTOTPWithLockoutTx cycle (the bootstrap promotion): the caller must
// hold — or have taken as an earlier statement — the users row fence, so the
// read observes every lock committed before the fence was acquired and
// excludes every cycle still queued behind it. The caller refuses LOCKED
// without evaluating the presented code: a valid code must never reach
// promotion, whose write clears the active lock (r3 defect 6).
func TOTPLockedUnderFence(ctx context.Context, q totpCycleStore, userID int64) (bool, error) {
	var lockedUntil *time.Time
	err := q.QueryRow(ctx,
		`SELECT totp_locked_until FROM users WHERE id = $1 FOR NO KEY UPDATE`,
		userID,
	).Scan(&lockedUntil)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// No row: nothing to lock. The caller's earlier fence read has
			// already handled a deleted user.
			return false, nil
		}
		return false, fmt.Errorf("totp lock-state read: %w", err)
	}
	return lockedUntil != nil && lockedUntil.After(time.Now()), nil
}

// RecordTOTPFailure increments the consecutive-failure counter for userID and
// applies the lock when the threshold is reached. It returns whether the
// account is now locked. The write is the §2.3 SINGLE-statement atomic form —
// the counter moves by the database's own arithmetic, never by a
// previously-read absolute count (the lost-update repair of the historical
// read-then-write shape). Locked refusals do not increment: when the budget
// is already locked the WHERE guard matches zero rows and (true, nil) is
// returned — a refusal, not a failure increment. This is the ONLY place the
// failure policy is written, so every verify path that calls it gets
// identical lockout behaviour.
func RecordTOTPFailure(ctx context.Context, q totpCycleStore, userID int64, _priorFailures int) (locked bool, err error) {
	var lockedUntil *time.Time
	err = q.QueryRow(ctx,
		`UPDATE users
		    SET totp_failed_attempts = totp_failed_attempts + 1,
		        totp_locked_until =
		          CASE WHEN totp_failed_attempts + 1 >= $2
		               THEN now() + make_interval(secs => $3)
		               ELSE totp_locked_until END
		  WHERE id = $1
		    AND (totp_locked_until IS NULL OR totp_locked_until <= now())
		  RETURNING totp_locked_until`,
		userID, totpMaxFailures, totpLockDuration.Seconds(),
	).Scan(&lockedUntil)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Locked budget: refused bookkeeping, never an increment.
			return true, nil
		}
		return false, err
	}
	return lockedUntil != nil, nil
}

// ResetTOTPLockout clears the failure counter and lock after a successful verify.
func ResetTOTPLockout(ctx context.Context, pool *pgxpool.Pool, userID int64) error {
	_, err := pool.Exec(ctx,
		`UPDATE users SET totp_failed_attempts = 0, totp_locked_until = NULL WHERE id = $1`,
		userID)
	return err
}

// TOTPVerifyOutcome is the result of the shared TOTP verification cycle:
// either the code was accepted, the account is locked, the code was
// rejected, or the lockout BOOKKEEPING itself failed.
type TOTPVerifyOutcome int

const (
	// TOTPInvalid means the code did not validate (and the failure was recorded
	// toward the lockout counter).
	TOTPInvalid TOTPVerifyOutcome = iota
	// TOTPLocked means the account is currently locked out; no verification was
	// attempted.
	TOTPLocked
	// TOTPAccepted means the code validated and the lockout counter was reset.
	TOTPAccepted
	// TOTPBookkeepingError means a statement of the cycle errored: the cycle
	// was rolled back and the counters are exactly as before. No caller may
	// proceed — and no caller may report acceptance — on this outcome
	// (possession scheme v7 §2.3: explicit caller handling of bookkeeping
	// failures; the failure is a distinct refusal, never a silent pass).
	TOTPBookkeepingError
)

// ErrTOTPReplayed is the evaluated replay rejection: the presented code
// VERIFIED against the secret but its 30 s window was already claimed
// (verifyTOTPCore). The shared cycle treats it as an invalid code (counter
// recorded), never as bookkeeping — the proof was observed and rejected.
var ErrTOTPReplayed = errors.New("totp code already used")

// totpCycleStore is the tx seam for the WHOLE load→check-locked→verify→
// record/reset cycle: the lock read, the verify's secret read + replay
// claim, and the counter write all run on the SAME transaction (v7 §2.3 —
// one transaction-aware verification cycle for every shared TOTP caller).
type totpCycleStore interface {
	totpVerifyStore
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// recordTOTPFailureTx is the §2.3 single-statement atomic increment (the
// evaluated-failure write shared by the wrong-code and replay paths).
func recordTOTPFailureTx(ctx context.Context, q totpCycleStore, userID int64) (TOTPVerifyOutcome, error) {
	if _, err := q.Exec(ctx,
		`UPDATE users
		    SET totp_failed_attempts = totp_failed_attempts + 1,
		        totp_locked_until =
		          CASE WHEN totp_failed_attempts + 1 >= $2
		               THEN now() + make_interval(secs => $3)
		               ELSE totp_locked_until END
		  WHERE id = $1
		    AND (totp_locked_until IS NULL OR totp_locked_until <= now())
		  RETURNING totp_failed_attempts`,
		userID, totpMaxFailures, totpLockDuration.Seconds(),
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The WHERE guard matched zero rows: the budget locked between
			// the lock read and this write. Only possible for a caller that
			// did NOT hold the users fence across the cycle — fail closed as
			// a locked refusal (the counter did not move).
			return TOTPLocked, nil
		}
		return TOTPBookkeepingError, fmt.Errorf("record totp failure: %w", err)
	}
	return TOTPInvalid, nil
}

// VerifyTOTPWithLockoutTx runs the ENTIRE lockout cycle inside the caller's
// transaction, which must hold (or take as its first statement) the users
// row fence FOR NO KEY UPDATE:
//
//  1. Lock + read: SELECT ... FOR NO KEY UPDATE — replaces the fail-open
//     pool-level LoadTOTPLockState read. A missing row (deleted user) →
//     invalid, no writes.
//  2. Locked → TOTPLocked, no writes (locked refusals do not increment).
//  3. Verify on the SAME store: secret read + constant-time compare + atomic
//     replay claim (verifyTOTPCore). The verify outcome follows the
//     machinery-vs-observation split (r7): a REPLAYED code is an EVALUATED
//     rejection — it verified against the secret but its window was already
//     claimed — and counts like any invalid code; every OTHER verify error
//     is a statement failure or a missing enabled secret (nothing to
//     evaluate) and yields TOTPBookkeepingError: fail-closed, NO counter,
//     the caller refuses without reporting an invalid code.
//  4. Record/reset: failure → the §2.3 single-statement atomic increment;
//     success → reset in the same transaction.
//
// Any statement error yields TOTPBookkeepingError (with the wrapped error)
// and the cycle is rolled back by the caller's transaction — counters are
// exactly as before. The whole-cycle-in-one-transaction property closes the
// pause-and-clear hole BY CONSTRUCTION: the lock check and the reset share
// the fence, so a lock committed by a concurrent cycle is either visible to
// step 1 or blocked behind this cycle's fence — no interleaving exists in
// which a stale "unlocked" observation clears a lock that exists at write
// time.
func VerifyTOTPWithLockoutTx(ctx context.Context, q totpCycleStore, userID int64, code string) (TOTPVerifyOutcome, error) {
	// Step 1: lock + read (fail CLOSED — a read error is bookkeeping failure,
	// never an open door).
	var lockedUntil *time.Time
	err := q.QueryRow(ctx,
		`SELECT totp_locked_until, COALESCE(totp_failed_attempts, 0)
		   FROM users WHERE id = $1 FOR NO KEY UPDATE`,
		userID,
	).Scan(&lockedUntil, new(int))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TOTPInvalid, nil
		}
		return TOTPBookkeepingError, fmt.Errorf("totp lock-state read: %w", err)
	}

	// Step 2: locked → refuse without verify, without writes.
	if lockedUntil != nil && lockedUntil.After(time.Now()) {
		return TOTPLocked, nil
	}

	// Step 3: verify on the SAME store — with the machinery-vs-observation
	// split (see the doc comment): replay = evaluated (counter), everything
	// else = bookkeeping (fail-closed, no counter).
	ok, err := verifyTOTPCore(ctx, q, userID, code, true)
	if err != nil {
		if errors.Is(err, ErrTOTPReplayed) {
			return recordTOTPFailureTx(ctx, q, userID)
		}
		return TOTPBookkeepingError, fmt.Errorf("totp verify: %w", err)
	}

	// Step 4: record/reset as single-statement atomic writes.
	if !ok {
		return recordTOTPFailureTx(ctx, q, userID)
	}

	if _, err := q.Exec(ctx,
		`UPDATE users SET totp_failed_attempts = 0, totp_locked_until = NULL WHERE id = $1`,
		userID,
	); err != nil {
		return TOTPBookkeepingError, fmt.Errorf("reset totp lockout: %w", err)
	}
	return TOTPAccepted, nil
}

// VerifyTOTPWithLockout is the SINGLE entry point every unauthenticated TOTP
// verification path must use. It is now a thin BEGIN/COMMIT wrapper around
// VerifyTOTPWithLockoutTx, so every caller — login second factor,
// forgot-password, removal begin — runs the WHOLE load→check-locked→verify→
// record/reset cycle inside one transaction holding the users row fence
// (v7 §2.3). The returned error (if any) is a TOTPBookkeepingError-grade
// failure: the cycle rolled back and the caller must refuse, never report
// acceptance.
func VerifyTOTPWithLockout(ctx context.Context, pool *pgxpool.Pool, userID int64, code string) (outcome TOTPVerifyOutcome, err error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return TOTPBookkeepingError, fmt.Errorf("begin totp lockout cycle: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	outcome, err = VerifyTOTPWithLockoutTx(ctx, tx, userID, code)
	if err != nil {
		return outcome, err
	}
	if err := tx.Commit(ctx); err != nil {
		return TOTPBookkeepingError, fmt.Errorf("commit totp lockout cycle: %w", err)
	}
	return outcome, nil
}

// DisableTOTP removes TOTP from the account. Requires a valid code as confirmation.
func DisableTOTP(ctx context.Context, pool *pgxpool.Pool, userID int64, code string) error {
	ok, err := VerifyTOTP(ctx, pool, userID, code)
	if err != nil || !ok {
		return fmt.Errorf("invalid TOTP code")
	}
	_, err = pool.Exec(ctx,
		`UPDATE users SET totp_enabled = FALSE, totp_enabled_at = NULL, totp_secret_enc = NULL WHERE id = $1`,
		userID,
	)
	return err
}
