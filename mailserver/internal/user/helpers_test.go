package user

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
)

// testPool returns a pool connected to the local dev database.
// Skips the test if DB_DSN is not set.
func testPool(t *testing.T) *pgxpool.Pool {
	return testsupport.OpenTestPool(t)
}

func testLogger() *slog.Logger {
	return testsupport.TestLogger()
}

// ensureTestDomain creates a test domain and returns its ID.
// Returns 0 if the domains table or users.domain_id column doesn't exist (pre-schema DB).
// Idempotent: returns existing domain if already present.
func ensureTestDomain(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	ctx := context.Background()

	// Check if domains table exists (must check table_schema to avoid
	// matching information_schema.domains, a built-in system view).
	var exists bool
	err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables
		 WHERE table_schema = 'public' AND table_name = 'domains')`,
	).Scan(&exists)
	if err != nil || !exists {
		return 0
	}

	// Also check that users.domain_id column exists — the test DB may have
	// an incomplete schema where domains table exists but users lacks domain_id.
	var colExists bool
	err = pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.columns
		 WHERE table_schema = 'public' AND table_name = 'users' AND column_name = 'domain_id')`,
	).Scan(&colExists)
	if err != nil || !colExists {
		return 0
	}

	var domainID int64
	err = pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ('setjoin.test')
		 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`,
	).Scan(&domainID)
	if err != nil {
		t.Fatalf("ensureTestDomain: %v", err)
	}
	return domainID
}

// createTestUser inserts a test user and returns the new user ID.
func createTestUser(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	ctx := context.Background()

	domainID := ensureTestDomain(t, pool)

	suffix := randomSuffix(t)
	username := "test-" + suffix
	email := username + "@setjoin.test"

	var userID int64
	var err error
	if domainID != 0 {
		err = pool.QueryRow(ctx,
			`INSERT INTO users (username, email, display_name, password_hash, domain_id)
			 VALUES ($1, $2, $3, $4, $5)
			 RETURNING id`,
			username, email, "Test User", "$2a$10$placeholder", domainID,
		).Scan(&userID)
	} else {
		err = pool.QueryRow(ctx,
			`INSERT INTO users (username, email, display_name, password_hash)
			 VALUES ($1, $2, $3, $4)
			 RETURNING id`,
			username, email, "Test User", "$2a$10$placeholder",
		).Scan(&userID)
	}
	if err != nil {
		t.Fatalf("createTestUser: %v", err)
	}

	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM user_sender_list WHERE user_id = $1`, userID)
		pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
	})
	return userID
}

func randomSuffix(_ *testing.T) string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic("rand.Read failed: " + err.Error())
	}
	return fmt.Sprintf("%x", b)
}
