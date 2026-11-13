package handlers

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// UserCredentials is the MFA-enrollment snapshot for one account: which
// second-factor methods the user has enrolled, read once and then used to pick
// the challenge to offer. It is the single source the pre-auth flows consult
// instead of each re-deriving "which MFA does this user have?" from its own ad
// hoc SELECT — the prior pattern that let the three accept cascades (password
// Login, WebAuthn login-finish, forgot-password) drift apart.
//
//   - TOTPEnrolled / PushMFAEnrolled are challengeable second factors offered at
//     login (users.totp_enabled / users.push_mfa_enabled).
//   - WebAuthnEnrolled is true when the user has at least one un-revoked passkey;
//     passkeys are their OWN login entry point (WebAuthnLogin*), never offered as
//     a step-up here, so this flag never drives SelectMFAMethod — it is reported
//     for completeness / future surfaces only.
//   - BackupCodesAvailable is true when one-time backup codes are stored; backup
//     codes are a fallback the user types, not a challenge the server initiates,
//     so they too never win SelectMFAMethod.
type UserCredentials struct {
	UserID               int64
	Email                string
	TOTPEnrolled         bool
	PushMFAEnrolled      bool
	WebAuthnEnrolled     bool
	BackupCodesAvailable bool
}

// AnyChallengeMFAEnrolled reports whether the user is enrolled in a second
// factor the server can CHALLENGE at login (TOTP or push). It is the exact
// predicate the legacy Login / WebAuthn cascades used as their gate
// (`TOTPEnabled || PushMFAEnabled`) — backup codes and passkeys are not
// server-initiated challenges, so they do not flip this on.
func (c UserCredentials) AnyChallengeMFAEnrolled() bool {
	return c.TOTPEnrolled || c.PushMFAEnrolled
}

// SelectMFAMethod encodes the EXISTING accept order Push > TOTP > Backup used by
// the password Login and the WebAuthn login-finish step: offer push when it is
// available (the user enrolled it AND a push provider is wired — the caller folds
// both into pushAvailable), otherwise fall back to TOTP, otherwise no challenge.
// Backup codes are never returned (they ride as a fallback list entry, not a
// primary challenge). Returns "push", "totp", or "" (no challengeable factor).
//
// The forgot-password flow deliberately does NOT use this helper: it prefers
// TOTP when both are enrolled (resolveForgotPasswordMethod), the inverse order.
// That asymmetry is pre-existing and load-bearing for byte-identical behavior, so
// it keeps its own selection over the same UserCredentials data source.
func (c UserCredentials) SelectMFAMethod(pushAvailable bool) string {
	if c.PushMFAEnrolled && pushAvailable {
		return "push"
	}
	if c.TOTPEnrolled {
		return "totp"
	}
	return ""
}

// CredentialStore resolves a user's MFA-enrollment snapshot. Injected into the
// auth handlers like the connector store: production wires dbCredentialStore over
// the pool; a nil store defaults to it, and a test may substitute a fake without
// a live DB.
type CredentialStore interface {
	// CredentialsFor reads the enrollment snapshot for an enabled user by id.
	CredentialsFor(ctx context.Context, userID int64) (UserCredentials, error)
	// CredentialsByEmail reads the snapshot for an enabled user by email
	// (case-insensitive, matching the login/forgot-password lookups).
	CredentialsByEmail(ctx context.Context, email string) (UserCredentials, error)
}

// dbCredentialStore is the production CredentialStore over the PgBouncer pool.
type dbCredentialStore struct{ pool *pgxpool.Pool }

func (s dbCredentialStore) CredentialsFor(ctx context.Context, userID int64) (UserCredentials, error) {
	return s.scan(ctx, "u.id = $1", userID)
}

func (s dbCredentialStore) CredentialsByEmail(ctx context.Context, email string) (UserCredentials, error) {
	// lower(u.email) = lower($1) on the RAW input — byte-identical to the legacy
	// verifyPassword / resolveForgotPasswordMethod / lookupUser("email") lookups.
	// Deliberately NOT canonicalized here: canonicalization would also trim/strip
	// the input, which would change which inputs match (e.g. a leading-space email)
	// versus those bare-lower sites. The SQL case-fold is the whole match key.
	return s.scan(ctx, "lower(u.email) = lower($1)", email)
}

func (s dbCredentialStore) scan(ctx context.Context, pred string, arg any) (UserCredentials, error) {
	var c UserCredentials
	// pred is a fixed in-package literal (never user input); arg is parameterized.
	query := "SELECT u.id, u.email," +
		" COALESCE(u.totp_enabled, FALSE)," +
		" COALESCE(u.push_mfa_enabled, FALSE)," +
		" EXISTS (SELECT 1 FROM passkey_credentials pc WHERE pc.user_id = u.id AND pc.revoked_at IS NULL)," +
		" COALESCE(array_length(u.totp_backup_codes_enc, 1), 0) > 0" +
		" FROM users u WHERE " + pred + " AND u.enabled = TRUE"
	err := s.pool.QueryRow(ctx, query, arg).Scan(
		&c.UserID, &c.Email, &c.TOTPEnrolled, &c.PushMFAEnrolled, &c.WebAuthnEnrolled, &c.BackupCodesAvailable,
	)
	if err != nil {
		return UserCredentials{}, err
	}
	return c, nil
}
