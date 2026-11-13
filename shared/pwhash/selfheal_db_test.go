package pwhash

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"setjoin.com/shared/testsupport"
)

// TestCheckPassword_RehashSelfHeal proves the NeedsRehash wiring into the
// CheckPassword success path (D-SHARED-PWHASH-V-004): a stored hash written
// below the shared strength floor (seeded at bcrypt.MinCost) is transparently
// re-minted after a successful login — the stored hash changes, meets the
// floor cost, still verifies the same password, and the self-heal is
// idempotent (an at-floor hash is never rewritten).
func TestCheckPassword_RehashSelfHeal(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	password := "Sup3r-Secret-pw"
	stored := seedCheckPasswordUser(t, pool, password)

	var before string
	if err := pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE email = $1`, stored).Scan(&before); err != nil {
		t.Fatalf("read hash before: %v", err)
	}
	if cost, err := bcrypt.Cost([]byte(before)); err != nil || cost >= bcrypt.DefaultCost {
		t.Fatalf("seed must be below the floor for this test (cost=%d, err=%v)", cost, err)
	}

	if _, err := CheckPassword(ctx, pool, stored, password); err != nil {
		t.Fatalf("CheckPassword before self-heal: %v", err)
	}

	var after string
	if err := pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE email = $1`, stored).Scan(&after); err != nil {
		t.Fatalf("read hash after: %v", err)
	}
	if after == before {
		t.Fatal("below-floor hash was not upgraded — NeedsRehash self-heal missing from CheckPassword")
	}
	if cost, err := bcrypt.Cost([]byte(after)); err != nil || cost < bcrypt.DefaultCost {
		t.Fatalf("upgraded hash must meet the shared floor (cost=%d, err=%v)", cost, err)
	}
	if err := VerifyPasswordHash(after, password); err != nil {
		t.Fatalf("upgraded hash must still verify the same password: %v", err)
	}

	// At-floor hashes are stable: a second CheckPassword must NOT rewrite.
	// (This pass also exercises the cache path: the entry keyed on the
	// pre-upgrade hash is superseded by a fresh read of the new hash.)
	if _, err := CheckPassword(ctx, pool, stored, password); err != nil {
		t.Fatalf("CheckPassword after self-heal: %v", err)
	}
	var stable string
	if err := pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE email = $1`, stored).Scan(&stable); err != nil {
		t.Fatalf("read hash after second CheckPassword: %v", err)
	}
	if stable != after {
		t.Fatal("at-floor hash was rewritten — self-heal must be idempotent")
	}
}

// seedCheckPasswordUser inserts a throwaway domain + user with a lower-case
// stored email and the given password hashed BELOW the strength floor
// (bcrypt.MinCost). Returns the stored email and registers cleanup.
func seedCheckPasswordUser(t *testing.T, pool *pgxpool.Pool, password string) string {
	t.Helper()
	ctx := context.Background()
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatalf("rand: %v", err)
	}
	uniq := hex.EncodeToString(suffix)
	dom := "pwhash-" + uniq + ".local"
	stored := "alice@" + dom

	var domID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, dom,
	).Scan(&domID); err != nil {
		t.Skipf("could not seed domain (schema not loaded?): %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt hash: %v", err)
	}
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash, enabled)
		 VALUES ($1, $2, 'Alice', $3, $4, TRUE) RETURNING id`,
		"alice-"+uniq, stored, domID, string(hash),
	).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, domID)
	})
	return stored
}
