package pwhash

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CheckAppPassword verifies a raw app password token against the stored SHA-256 hash.
// Returns the owning user if the token is valid, active, and not expired.
// Updates last_used_at on the app password, last_login_at on the user,
// and writes an auth_event_log entry on success.
func CheckAppPassword(ctx context.Context, pool *pgxpool.Pool, email, token string) (*User, error) {
	hash := sha256.Sum256([]byte(token))
	hashHex := hex.EncodeToString(hash[:])

	var userID int64
	err := pool.QueryRow(ctx,
		`SELECT u.id FROM users u
		 JOIN app_passwords ap ON ap.user_id = u.id
		 WHERE lower(u.email) = lower($1)
		   AND u.enabled = TRUE
		   AND ap.token_hash = $2
		   AND ap.revoked_at IS NULL
		   AND (ap.expires_at IS NULL OR ap.expires_at > now())`,
		email, hashHex,
	).Scan(&userID)
	if err != nil {
		LogAuthEvent(ctx, pool, AuthEvent{
			Event: "login_failed", Provider: "app_password", Email: email,
		}, nil)
		return nil, err
	}

	// Update last_used_at + last_login_at
	_, _ = pool.Exec(ctx,
		`UPDATE app_passwords SET last_used_at = now()
		 WHERE user_id = $1 AND token_hash = $2 AND revoked_at IS NULL`,
		userID, hashHex)
	_, _ = pool.Exec(ctx,
		`UPDATE users SET last_login_at = now() WHERE id = $1`, userID)

	// Log the auth event
	LogAuthEvent(ctx, pool, AuthEvent{
		UserID: &userID, Event: "login", Provider: "app_password", Email: email,
	}, nil)

	// Fetch full user record
	var u User
	err = pool.QueryRow(ctx,
		`SELECT id, email, display_name, is_admin
		 FROM users WHERE id = $1 AND enabled = TRUE`,
		userID,
	).Scan(&u.ID, &u.Email, &u.DisplayName, &u.IsAdmin)
	if err != nil {
		return nil, err
	}
	return &u, nil
}
