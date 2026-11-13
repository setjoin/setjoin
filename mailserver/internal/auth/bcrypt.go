package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/pwhash"
)

// User is an alias for the shared pwhash.User type.
type User = pwhash.User

// ErrInvalidCredentials is an alias for the shared sentinel.
var ErrInvalidCredentials = pwhash.ErrInvalidCredentials

// CheckPassword delegates to the shared pwhash package, then refuses guest
// accounts (guest-accounts spec §2.2): IMAP (imap.go:463/:2167), SMTP
// submission (submission.go:398), DAV basic-auth (basic.go:60) and the LDAP
// bind (ldap/server.go:188) ALL funnel through this one wrapper — guests have
// no protocol surface, and "probably fails downstream for lack of a mailbox"
// is not a deny-at-the-door. Same error as a bad password (no oracle). The
// lookup is the SECURITY DEFINER is_guest_account() (FORCE-RLS-safe from any
// pool); a lookup error fails CLOSED. Web login is authserver-side (its own
// bcrypt path) and unaffected — guests log in there.
func CheckPassword(ctx context.Context, pool *pgxpool.Pool, email, password string) (*User, error) {
	u, err := pwhash.CheckPassword(ctx, pool, email, password)
	if err != nil {
		return nil, err
	}
	var isGuest bool
	if err := pool.QueryRow(ctx, `SELECT is_guest_account($1)`, u.ID).Scan(&isGuest); err != nil {
		return nil, ErrInvalidCredentials // fail closed on lookup error
	}
	if isGuest {
		return nil, ErrInvalidCredentials
	}
	return u, nil
}

// HashPassword delegates to the shared pwhash package.
func HashPassword(password string) (string, error) {
	return pwhash.HashPassword(password)
}

// LookupByEmail delegates to the shared pwhash package.
func LookupByEmail(ctx context.Context, pool *pgxpool.Pool, email string) (*User, error) {
	return pwhash.LookupByEmail(ctx, pool, email)
}

// LookupByID returns a user record by primary key. Used when refreshing tokens.
// Not in shared/pwhash — specific to gateway.
func LookupByID(ctx context.Context, pool *pgxpool.Pool, id int64) (*User, error) {
	var u User
	err := pool.QueryRow(ctx,
		`SELECT u.id, u.email, u.display_name, u.is_admin, u.totp_enabled
		 FROM users u WHERE u.id = $1 AND u.enabled = TRUE`,
		id,
	).Scan(&u.ID, &u.Email, &u.DisplayName, &u.IsAdmin, &u.TOTPEnabled)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	return &u, nil
}
