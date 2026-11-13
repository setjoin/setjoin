package handlers

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// topCommonPasswords is a small, curated list of the most common passwords.
// These are the passwords most likely to appear in credential-stuffing attacks.
// For a full 10k-word list, seed from an external file via SeedCommonPasswords.
var topCommonPasswords = []string{
	"password", "123456", "12345678", "qwerty", "abc123",
	"monkey", "1234567", "letmein", "trustno1", "dragon",
	"baseball", "iloveyou", "master", "sunshine", "ashley",
	"bailey", "shadow", "123123", "654321", "superman",
	"qazwsx", "michael", "football", "password1", "welcome",
	"login", "admin", "princess", "starwars", "access",
	"flower", "hottie", "loveme", "missyou", "whatever",
	"nicole", "jessica", "charlie", "donald", "george",
	"maggie", "pepper", "cheese", "ginger", "cookie",
	"summer", "winter", "spring", "autumn", "thomas",
	"andrew", "joshua", "matthew", "daniel", "william",
	"robert", "joseph", "jennifer", "amanda", "melissa",
	"111111", "000000", "696969", "121212", "qwerty123",
}

// SeedCommonPasswords inserts the top common passwords into the database.
// Uses ON CONFLICT DO NOTHING so it is safe to call multiple times.
func SeedCommonPasswords(ctx context.Context, pool *pgxpool.Pool) error {
	for _, pw := range topCommonPasswords {
		hash := sha256.Sum256([]byte(strings.ToLower(pw)))
		if _, err := pool.Exec(ctx,
			`INSERT INTO common_passwords (password_hash) VALUES ($1) ON CONFLICT DO NOTHING`,
			hash[:],
		); err != nil {
			return err
		}
	}
	slog.Info("common passwords seeded", "count", len(topCommonPasswords))
	return nil
}
