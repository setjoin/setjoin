package pwhash

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CheckCommonPassword returns true if the password matches a known common password.
// The password is lowercased and hashed with SHA-256 before lookup against
// the common_passwords table.
func CheckCommonPassword(ctx context.Context, pool *pgxpool.Pool, password string) (bool, error) {
	hash := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(password))))
	var exists bool
	err := pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM common_passwords WHERE password_hash = $1)`,
		hash[:],
	).Scan(&exists)
	if err != nil {
		slog.Error("common password check query failed", "error", err)
	}
	return exists, err
}
