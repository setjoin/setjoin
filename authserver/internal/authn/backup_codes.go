package authn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"setjoin.com/shared/pwhash"
)

// GenerateBackupCodes creates 10 single-use backup codes for a user.
// Each code is 8 hex characters (crypto/rand), bcrypt-hashed before storage.
// The raw codes are returned to the caller once and never stored in plaintext.
func GenerateBackupCodes(ctx context.Context, pool *pgxpool.Pool, userID int64) ([]string, error) {
	rawCodes, hashedCodes, err := newBackupCodes()
	if err != nil {
		return nil, err
	}
	if _, err := pool.Exec(ctx,
		`UPDATE users SET totp_backup_codes_enc = $1 WHERE id = $2`,
		hashedCodes, userID,
	); err != nil {
		return nil, fmt.Errorf("store backup codes: %w", err)
	}
	return rawCodes, nil
}

// GenerateBackupCodesTx is the caller-owned-transaction variant the gated
// regeneration arm uses (possession scheme v7 §2.2): the codes write rides
// the SAME transaction that consumed the proof grant and bumps the factor
// generation, so grant consumption + mutation + audit commit or roll back
// together.
func GenerateBackupCodesTx(ctx context.Context, tx pgx.Tx, userID int64) ([]string, error) {
	rawCodes, hashedCodes, err := newBackupCodes()
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE users SET totp_backup_codes_enc = $1 WHERE id = $2`,
		hashedCodes, userID,
	); err != nil {
		return nil, fmt.Errorf("store backup codes: %w", err)
	}
	return rawCodes, nil
}

func newBackupCodes() (rawCodes, hashedCodes []string, err error) {
	for i := 0; i < 10; i++ {
		b := make([]byte, 4)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		code := hex.EncodeToString(b)
		rawCodes = append(rawCodes, code)

		hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if err != nil {
			return nil, nil, err
		}
		hashedCodes = append(hashedCodes, string(hash))
	}
	return rawCodes, hashedCodes, nil
}

// VerifyBackupCode checks a submitted code against the stored hashes.
// On match, the matching hash is removed (single-use).
// Returns true if the code was valid and consumed.
func VerifyBackupCode(ctx context.Context, pool *pgxpool.Pool, userID int64, code string) (bool, error) {
	var hashes []string
	err := pool.QueryRow(ctx,
		`SELECT totp_backup_codes_enc FROM users WHERE id = $1`, userID,
	).Scan(&hashes)
	if err != nil {
		return false, err
	}
	if len(hashes) == 0 {
		return false, nil
	}

	// Find matching hash. VerifyCredentialHash is the shared seam's
	// bcrypt-only credential arm: backup codes have always been written
	// bcrypt (newBackupCodes below) and must never silently widen to the
	// password seam's SM3 dispatch (see pwhash.VerifyCredentialHash).
	matchIdx := -1
	for i, h := range hashes {
		if pwhash.VerifyCredentialHash(h, code) == nil {
			matchIdx = i
			break
		}
	}
	if matchIdx < 0 {
		return false, nil
	}

	// Consume the matched code ATOMICALLY (mirrors the TOTP replay claim in totp.go):
	// array_remove + the `= ANY(...)` guard only mutate the row while THIS exact hash
	// is still present, and RETURNING proves which concurrent caller won. The old
	// read-modify-write (SELECT array → write shrunken array) had two TOCTOU bugs:
	// (1) two requests with the SAME code both matched and both wrote, consuming a
	// single-use code twice (MFA second-factor replay); (2) two requests with
	// DIFFERENT codes each wrote back the original-minus-their-index array
	// last-write-wins, RESURRECTING the other's just-consumed code. The row-level
	// lock serializes the claim so exactly one wins and nothing is resurrected.
	matched := hashes[matchIdx]
	var consumed int64
	err = pool.QueryRow(ctx,
		`UPDATE users
		    SET totp_backup_codes_enc = array_remove(totp_backup_codes_enc, $1)
		  WHERE id = $2
		    AND $1 = ANY(totp_backup_codes_enc)
		  RETURNING id`,
		matched, userID,
	).Scan(&consumed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The code was already consumed by a concurrent request (lost the race) —
			// single-use, so this caller must NOT also succeed.
			return false, nil
		}
		return false, fmt.Errorf("remove consumed backup code: %w", err)
	}

	return true, nil
}

// HasBackupCodes returns true if the user has active backup codes.
func HasBackupCodes(ctx context.Context, pool *pgxpool.Pool, userID int64) bool {
	var hashes []string
	err := pool.QueryRow(ctx,
		`SELECT totp_backup_codes_enc FROM users WHERE id = $1`, userID,
	).Scan(&hashes)
	if err != nil {
		return false
	}
	return len(hashes) > 0
}
