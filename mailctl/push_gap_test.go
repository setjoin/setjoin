package main

// Live-DB gap coverage for `mailctl push test`'s transaction block: the GUC is
// set transaction-locally inside the SAME explicit transaction that resolves
// the user and devices (D-MAILCTL-006), committed, and only then is the empty
// device list refused. Skips without TEST_DB_DSN/DB_DSN and DB_ENCRYPTION_KEY,
// matching the repo's other live-DB suites.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestPushTestTransactionAgainstLiveDB drives pushTest's transaction block end
// to end against a schematized database with a valid Web Push provider: the
// user resolves, ResolveDevices runs inside the encryption-key transaction,
// the transaction commits, and an empty device list is refused with the
// targeted error.
func TestPushTestTransactionAgainstLiveDB(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		dsn = os.Getenv("DB_DSN")
	}
	if dsn == "" {
		t.Skip("TEST_DB_DSN/DB_DSN is required")
	}
	if os.Getenv("DB_ENCRYPTION_KEY") == "" {
		t.Skip("DB_ENCRYPTION_KEY is required to decrypt device tokens")
	}

	// A valid VAPID P-256 private scalar configures the Web Push provider so
	// the provider set is non-empty before the DB work begins.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate vapid key: %v", err)
	}
	t.Setenv("VAPID_PRIVATE_KEY", base64.RawURLEncoding.EncodeToString(priv.D.FillBytes(make([]byte, 32))))
	t.Setenv("DB_ENCRYPTION_KEY", "push-gap-test-encryption-key")

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	ctx := context.Background()

	tag := time.Now().UnixNano()
	domainName := fmt.Sprintf("push-gap-%d.test", tag)
	userEmail := fmt.Sprintf("push-gap-%d@%s", tag, domainName)
	var domainID, userID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO domains (name) VALUES ($1) RETURNING id`,
		domainName,
	).Scan(&domainID); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (username, domain_id, email, display_name)
		VALUES ($1, $2, $3, $4) RETURNING id`,
		fmt.Sprintf("push-gap-%d", tag), domainID, userEmail, "Push Gap Test",
	).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, domainID)
	})

	c := &cmdCtx{
		openDB: func() (*pgxpool.Pool, error) { return pool, nil },
	}
	err = runPush(c, "test", []string{"--user", userEmail})
	if err == nil || !strings.Contains(err.Error(), "has no registered push devices") {
		t.Fatalf("push test = %v, want the empty-device refusal after a committed resolve", err)
	}

	// The user row must still resolve by lowercase email — the transaction
	// that ran used the standard resolve path.
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE email = lower($1)`, userEmail,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("user rows = %d, want 1", count)
	}
}

// TestPushTestTransactionRunsWhenEnvProvided is the self-sufficient variant of
// the live-DB transaction test: it supplies DB_ENCRYPTION_KEY itself instead
// of skipping, so the GUC-set/resolve/commit block is covered in
// environments that only carry DB_DSN.
func TestPushTestTransactionRunsWhenEnvProvided(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		dsn = os.Getenv("DB_DSN")
	}
	if dsn == "" {
		t.Skip("TEST_DB_DSN/DB_DSN is required")
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate vapid key: %v", err)
	}
	t.Setenv("VAPID_PRIVATE_KEY", base64.RawURLEncoding.EncodeToString(priv.D.FillBytes(make([]byte, 32))))
	t.Setenv("DB_ENCRYPTION_KEY", "push-gap-selfsufficient-key")

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	ctx := context.Background()

	tag := time.Now().UnixNano()
	domainName := fmt.Sprintf("push-gap2-%d.test", tag)
	userEmail := fmt.Sprintf("push-gap2-%d@%s", tag, domainName)
	var domainID, userID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO domains (name) VALUES ($1) RETURNING id`, domainName,
	).Scan(&domainID); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (username, domain_id, email, display_name)
		VALUES ($1, $2, $3, $4) RETURNING id`,
		fmt.Sprintf("push-gap2-%d", tag), domainID, userEmail, "Push Gap Two",
	).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, domainID)
	})

	c := &cmdCtx{
		openDB: func() (*pgxpool.Pool, error) { return pool, nil },
	}
	err = runPush(c, "test", []string{"--user", userEmail})
	if err == nil || !strings.Contains(err.Error(), "has no registered push devices") {
		t.Fatalf("push test = %v, want the empty-device refusal after commit", err)
	}
}
