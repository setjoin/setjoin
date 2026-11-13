package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"setjoin.com/shared/pwhash"
)

// TOTPRemovalStepUpTTL bounds the single-use de-enrollment step-up token. It
// mirrors the mfa_pending second-step lifetime: long enough for one settings
// round trip, short enough that an intercepted token expires before it is
// useful.
const TOTPRemovalStepUpTTL = 5 * time.Minute

// De-enrollment failure taxonomy. The handler maps each sentinel to one HTTP
// outcome and one audit action; callers must classify with errors.Is.
var (
	// ErrInvalidRemovalPassword: the session holder's password did not verify.
	ErrInvalidRemovalPassword = errors.New("invalid password")
	// ErrInvalidRemovalCode: neither the TOTP code nor (when recovery codes
	// exist) the submitted recovery code verified. This is the self-service
	// refusal a locked-out user (lost authenticator, no recovery codes) hits.
	ErrInvalidRemovalCode = errors.New("invalid removal code")
	// ErrTOTPLocked: the account is locked by the TOTP failure policy; the
	// lockout/backoff policy is the existing authn one, not a new one.
	ErrTOTPLocked = errors.New("totp locked")
	// ErrTOTPNotEnabled: there is no active TOTP factor to remove (or it was
	// removed concurrently between step-up and confirmation).
	ErrTOTPNotEnabled = errors.New("totp not enabled")
	// ErrTOTPRemovalStepUpInvalid: the step-up token is missing, malformed,
	// expired, bound to a different session, or already consumed (replay).
	ErrTOTPRemovalStepUpInvalid = errors.New("totp removal step-up token invalid")
)

// BeginTOTPRemoval validates the de-enrollment decision table for an
// authenticated user and, on success, issues a single-use step-up token for
// the follow-up removal POST. The decision table:
//
//  1. TOTP present: password + current TOTP code.
//  2. Authenticator lost, recovery codes remain: password + valid recovery
//     code. The recovery code is verified WITHOUT consuming it — the removal
//     transaction deletes all recovery codes together with the factor, so
//     consuming at step-up would burn a code whenever the user abandons the
//     flow before the removal POST.
//  3. Authenticator lost, no recovery codes: every code submission fails
//     verification and the flow is refused on the self-service path; such
//     users are routed to the admin/support recovery flow (policy owned
//     elsewhere — the refusal here is deliberate fail-closed).
//
// The issued token is bound to sessionJTI (the authenticated access token's
// jti); the removal POST must present it on the same session.
//
// Code verification routes through VerifyTOTPWithLockout so failed attempts
// feed the same 5-failure lockout as every other TOTP path (existing authn
// policy), and a locked account refuses both code paths.
func BeginTOTPRemoval(ctx context.Context, pool *pgxpool.Pool, userID int64, password, code, sessionJTI string) (string, error) {
	var totpEnabled bool
	var backupCodes []string
	err := pool.QueryRow(ctx,
		`SELECT COALESCE(totp_enabled, FALSE), COALESCE(totp_backup_codes_enc, '{}')
		   FROM users WHERE id = $1`,
		userID,
	).Scan(&totpEnabled, &backupCodes)
	if err != nil {
		return "", fmt.Errorf("totp removal state lookup: %w", err)
	}
	if !totpEnabled {
		return "", ErrTOTPNotEnabled
	}

	if err := VerifyTOTPRemovalPassword(ctx, pool, userID, password); err != nil {
		return "", err
	}

	// v7 §2.3 shared-cycle caller (inventory item 4): the removal begin's TOTP
	// verification rides the ONE fenced cycle. A TOTPBookkeepingError outcome
	// is a distinct refusal — the wrapped error propagates (handler → 500) and
	// the recovery-code fallback MUST NOT run on bookkeeping failure.
	outcome, cycleErr := VerifyTOTPWithLockout(ctx, pool, userID, code)
	switch outcome {
	case TOTPAccepted:
		// Decision-table case 1: password + current TOTP code.
	case TOTPLocked:
		return "", ErrTOTPLocked
	case TOTPBookkeepingError:
		return "", fmt.Errorf("totp removal lockout bookkeeping: %w", cycleErr)
	default:
		if cycleErr != nil {
			return "", fmt.Errorf("totp removal lockout bookkeeping: %w", cycleErr)
		}
		// Decision-table case 2: authenticator lost, recovery codes remain.
		// Only reached while the account is not locked (Locked returned above),
		// so the recovery attempt cannot ride past the lockout policy.
		if len(backupCodes) > 0 {
			ok, hasErr := hasBackupCode(ctx, pool, userID, code)
			if hasErr != nil {
				return "", fmt.Errorf("totp removal recovery code check: %w", hasErr)
			}
			if ok {
				break
			}
		}
		return "", ErrInvalidRemovalCode
	}

	return IssueTOTPRemovalStepUp(ctx, pool, userID, sessionJTI)
}

// VerifyTOTPRemovalPassword verifies the session holder's current password
// against the stored hash (dispatching on hash format via the one pwhash
// seam, so SM3-era hashes verify identically to the login path).
func VerifyTOTPRemovalPassword(ctx context.Context, pool *pgxpool.Pool, userID int64, password string) error {
	var hash string
	if err := pool.QueryRow(ctx,
		`SELECT password_hash FROM users WHERE id = $1`, userID,
	).Scan(&hash); err != nil {
		return fmt.Errorf("totp removal password lookup: %w", err)
	}
	if hash == "" || pwhash.VerifyPasswordHash(hash, password) != nil {
		return ErrInvalidRemovalPassword
	}
	return nil
}

// hasBackupCode reports whether code matches one of the stored recovery-code
// hashes WITHOUT consuming it. The consuming single-use check for login is
// VerifyBackupCode; de-enrollment deliberately re-verifies nothing here — the
// issued step-up token carries the proof, and the removal transaction deletes
// every recovery code.
func hasBackupCode(ctx context.Context, pool *pgxpool.Pool, userID int64, code string) (bool, error) {
	var hashes []string
	err := pool.QueryRow(ctx,
		`SELECT totp_backup_codes_enc FROM users WHERE id = $1`, userID,
	).Scan(&hashes)
	if err != nil {
		return false, err
	}
	for _, h := range hashes {
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(code)) == nil {
			return true, nil
		}
	}
	return false, nil
}

// IssueTOTPRemovalStepUp mints a fresh opaque step-up token and stores only
// its SHA-256 hash, bound to the user and the authenticated session
// (sessionJTI is the access token's jti). Consumption requires the same jti,
// so a token stolen from one session is inert in another; an empty jti fails
// closed at consumption time (the guard never matches). Any prior step-up
// rows for the user are deleted first, so at most one live token exists per
// user and abandoned flows never accumulate rows.
func IssueTOTPRemovalStepUp(ctx context.Context, pool *pgxpool.Pool, userID int64, sessionJTI string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("totp removal step-up entropy: %w", err)
	}
	token := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))

	_, err := pool.Exec(ctx,
		`DELETE FROM totp_removal_step_ups WHERE user_id = $1`, userID)
	if err != nil {
		return "", fmt.Errorf("totp removal step-up cleanup: %w", err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO totp_removal_step_ups (token_hash, user_id, session_jti, expires_at)
		 VALUES ($1, $2, $3, now() + make_interval(secs => $4))`,
		hex.EncodeToString(sum[:]), userID, sessionJTI, TOTPRemovalStepUpTTL.Seconds(),
	)
	if err != nil {
		return "", fmt.Errorf("totp removal step-up store: %w", err)
	}
	return token, nil
}

// DisableTOTPWithStepUp consumes a single-use step-up token and removes the
// TOTP factor and every recovery code in ONE serialized transaction, so a
// replayed token, an expired token, a foreign-session token, or a concurrent
// double-submission is refused with the factor intact, and no partial removal
// can ever commit. Atomicity and serialization:
//
//   - the §2.2 canonical fences run first: identity_auth_person_fence (the
//     shared revocation boundary) then the users row (FOR UPDATE — the
//     historical mode, which conflicts with ConfirmTOTP's FOR NO KEY UPDATE,
//     so both serialize);
//   - consumption is the DELETE ... RETURNING below: exactly one concurrent
//     caller can consume a token; every other caller gets zero rows;
//   - the factor wipe bumps factor_generation (§1.8: removal mutates the
//     factor set even though it is not re-gated) and the success audit row
//     commit together.
func DisableTOTPWithStepUp(ctx context.Context, pool *pgxpool.Pool, userID int64, sessionJTI, stepUpToken, clientIP string) error {
	if stepUpToken == "" {
		return ErrTOTPRemovalStepUpInvalid
	}
	sum := sha256.Sum256([]byte(stepUpToken))
	tokenHash := hex.EncodeToString(sum[:])

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("totp removal tx begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := PersonFence(ctx, tx, userID); err != nil {
		return fmt.Errorf("totp removal person fence: %w", err)
	}

	var consumed string
	err = tx.QueryRow(ctx,
		`DELETE FROM totp_removal_step_ups
		  WHERE token_hash = $1 AND user_id = $2 AND session_jti = $3 AND expires_at > now()
		  RETURNING token_hash`,
		tokenHash, userID, sessionJTI,
	).Scan(&consumed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTOTPRemovalStepUpInvalid
		}
		return fmt.Errorf("totp removal step-up consume: %w", err)
	}

	var enabled bool
	err = tx.QueryRow(ctx,
		`SELECT totp_enabled FROM users WHERE id = $1 AND totp_enabled = TRUE FOR UPDATE`,
		userID,
	).Scan(&enabled)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTOTPNotEnabled
		}
		return fmt.Errorf("totp removal factor lock: %w", err)
	}

	tag, err := tx.Exec(ctx,
		`UPDATE users
		    SET totp_enabled = FALSE,
		        totp_enabled_at = NULL,
		        totp_secret_enc = NULL,
		        totp_backup_codes_enc = NULL,
		        totp_failed_attempts = 0,
		        totp_locked_until = NULL,
		        last_totp_used_at = NULL,
		        factor_generation = factor_generation + 1
		  WHERE id = $1`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("totp removal wipe: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("totp removal wipe: %d rows affected", tag.RowsAffected())
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO admin_audit_log (user_id, ip, action, target_type, target_id)
		 VALUES ($1, $2::INET, 'totp_removed', 'user', $1)`,
		userID, clientIP,
	); err != nil {
		return fmt.Errorf("totp removal audit: %w", err)
	}

	return tx.Commit(ctx)
}
