package local

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
	"setjoin.com/shared/pwhash"
)

// testPool opens a pool against TEST_DB_DSN (or DB_DSN) or skips. The local
// connector's queries don't need the pgcrypto encryption-key session var, so a
// plain pool is sufficient. Mirrors authn/totp_db_integration_test.go's skip.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		dsn = os.Getenv("DB_DSN")
	}
	if dsn == "" {
		t.Skip("TEST_DB_DSN / DB_DSN not set; skipping local connector DB test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Skipf("DSN set but pool open failed (%v); skipping", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func randSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)
}

// seedUser inserts a throwaway domain + user with a lower-case stored email (as
// provisioning guarantees) and the given bcrypt-hashed password. Returns the
// stored (lower) email and registers cleanup.
func seedUser(t *testing.T, pool *pgxpool.Pool, password string) string {
	t.Helper()
	ctx := context.Background()
	uniq := randSuffix(t)
	dom := "localconn-" + uniq + ".local"
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
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, domID)
	})
	return stored
}

// TestVerifyPassword_MixedCase_Regression proves the connector VerifyPassword
// resolves the owner row for a mixed-case lookup key (defense-in-depth: the
// connector path's lone case-sensitive sibling now folds through the seam).
// Against the PRE-FIX code (raw `email = $1`) the mixed-case case FAILS.
func TestVerifyPassword_MixedCase_Regression(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	password := "Sup3r-Secret-pw"
	stored := seedUser(t, pool, password)
	c := &Connector{id: 1, pool: pool}

	// stored is "alice@localconn-<uniq>.local"; flip case on both parts.
	mixedCase := "Alice@" + strings.ToUpper(stored[strings.IndexByte(stored, '@')+1:])

	if err := c.VerifyPassword(ctx, mixedCase, password); err != nil {
		t.Fatalf("mixed-case VerifyPassword FAILED for an existing user (regression): %v", err)
	}
	// Exact-case still works; wrong password still rejected.
	if err := c.VerifyPassword(ctx, stored, password); err != nil {
		t.Fatalf("exact-case VerifyPassword regressed: %v", err)
	}
	if err := c.VerifyPassword(ctx, mixedCase, "wrong-"+password); err == nil {
		t.Fatal("wrong password accepted — the fix must only relax CASE, not the password check")
	}
}

// TestChangePassword_MixedCase_Regression proves ChangePassword (a) verifies the
// old password against the owner row for a mixed-case key, (b) actually WRITES
// the new hash to that row (asserts password_hash changed — catches the D3
// UPDATE-predicate / zero-rows-no-op bug), and (c) the new password then
// verifies. Against PRE-FIX code the mixed-case SELECT fails ("user not found");
// even with only the SELECT folded, the un-folded UPDATE would write zero rows
// and the new password would NOT verify.
func TestChangePassword_MixedCase_Regression(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	oldPassword := "Old-Secret-pw-123"
	newPassword := "New-Secret-pw-456"
	stored := seedUser(t, pool, oldPassword)
	c := &Connector{id: 1, pool: pool}

	mixedCase := "Alice@" + strings.ToUpper(stored[strings.IndexByte(stored, '@')+1:])

	// Capture the stored hash before the change so we can assert it really moved.
	var before string
	if err := pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE email = $1`, stored).Scan(&before); err != nil {
		t.Fatalf("read hash before: %v", err)
	}

	if err := c.ChangePassword(ctx, mixedCase, oldPassword, newPassword); err != nil {
		t.Fatalf("mixed-case ChangePassword FAILED for an existing user (regression): %v", err)
	}

	// The new hash must actually be written to the owner row (D3: the UPDATE
	// predicate must fold too, or this is a silent no-op).
	var after string
	if err := pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE email = $1`, stored).Scan(&after); err != nil {
		t.Fatalf("read hash after: %v", err)
	}
	if after == before {
		t.Fatal("password_hash unchanged — the UPDATE wrote zero rows (D3 predicate-drift bug)")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(after), []byte(newPassword)); err != nil {
		t.Fatalf("stored hash does not match the NEW password: %v", err)
	}

	// And the connector now verifies the NEW password (mixed-case key again).
	if err := c.VerifyPassword(ctx, mixedCase, newPassword); err != nil {
		t.Fatalf("new password does not verify after change: %v", err)
	}
	// Wrong old password is still rejected (case-relaxation only).
	if err := c.ChangePassword(ctx, mixedCase, "wrong-old", "another-pw-789"); err == nil {
		t.Fatal("wrong current password accepted — fix must only relax CASE")
	}
}

// TestChangePassword_DisabledUserRefused proves predicate parity
// (D-AUTHSERVER-INTERNAL-CONNECTOR-003): the UPDATE carries the same
// `enabled = TRUE` qualifier as the verification SELECT, so a user disabled
// before the call is refused and its stored credential is NOT rotated.
func TestChangePassword_DisabledUserRefused(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	oldPassword := "Old-Secret-pw-123"
	stored := seedUser(t, pool, oldPassword)
	c := &Connector{id: 1, pool: pool}

	if _, err := pool.Exec(ctx, `UPDATE users SET enabled = FALSE WHERE email = $1`, stored); err != nil {
		t.Fatalf("disable user: %v", err)
	}

	var before string
	if err := pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE email = $1`, stored).Scan(&before); err != nil {
		t.Fatalf("read hash before: %v", err)
	}

	if err := c.ChangePassword(ctx, stored, oldPassword, "New-Secret-pw-456"); err == nil {
		t.Fatal("ChangePassword succeeded for a DISABLED user — enabled=TRUE predicate parity broken")
	}

	var after string
	if err := pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE email = $1`, stored).Scan(&after); err != nil {
		t.Fatalf("read hash after: %v", err)
	}
	if after != before {
		t.Fatal("password_hash of a disabled user was rotated — the UPDATE must refuse disabled rows")
	}
}

// TestCredentialPaths_UniformErrorSurface proves the enumeration doctrine
// (D-AUTHSERVER-INTERNAL-CONNECTOR-005): on both credential paths the
// missing-user outcome and the wrong-password outcome return the SAME uniform
// error (pwhash.ErrInvalidCredentials), and the miss branch performs equal
// hash work via the dummy verify (structurally pinned by the identical error
// contract; the dummy-hash call sites are the only paths returning early).
func TestCredentialPaths_UniformErrorSurface(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	password := "Sup3r-Secret-pw"
	stored := seedUser(t, pool, password)
	c := &Connector{id: 1, pool: pool}
	missing := "nobody-" + randSuffix(t) + "@example.invalid"

	// VerifyPassword: found-user/wrong-password vs missing-user must not be
	// distinguishable by error text.
	wrongPwErr := c.VerifyPassword(ctx, stored, "wrong-"+password)
	missingErr := c.VerifyPassword(ctx, missing, password)
	if wrongPwErr == nil || missingErr == nil {
		t.Fatalf("credential misses must error (wrong=%v missing=%v)", wrongPwErr, missingErr)
	}
	if wrongPwErr.Error() != missingErr.Error() {
		t.Fatalf("VerifyPassword discloses account existence: wrong-password %q vs missing-user %q", wrongPwErr, missingErr)
	}
	if !errors.Is(missingErr, pwhash.ErrInvalidCredentials) {
		t.Fatalf("miss branch must return the uniform pwhash.ErrInvalidCredentials, got %q", missingErr)
	}

	// ChangePassword: same uniformity contract.
	cpWrongErr := c.ChangePassword(ctx, stored, "wrong-old", "irrelevant-new")
	cpMissingErr := c.ChangePassword(ctx, missing, password, "irrelevant-new")
	if cpWrongErr == nil || cpMissingErr == nil {
		t.Fatalf("ChangePassword misses must error (wrong=%v missing=%v)", cpWrongErr, cpMissingErr)
	}
	if cpWrongErr.Error() != cpMissingErr.Error() {
		t.Fatalf("ChangePassword discloses account existence: wrong-password %q vs missing-user %q", cpWrongErr, cpMissingErr)
	}
	if !errors.Is(cpMissingErr, pwhash.ErrInvalidCredentials) {
		t.Fatalf("miss branch must return the uniform pwhash.ErrInvalidCredentials, got %q", missingErr)
	}
}

// TestVerifyPassword_RehashSelfHeal proves the NeedsRehash self-heal
// (D-AUTHSERVER-INTERNAL-CONNECTOR-006): a stored hash written below the
// shared strength floor (seeded at bcrypt.MinCost) is transparently upgraded
// through the pwhash seam after a successful verification — the stored hash
// changes, meets the floor cost, and still verifies the same password. A
// hash already at the floor is left untouched.
func TestVerifyPassword_RehashSelfHeal(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	password := "Sup3r-Secret-pw"
	stored := seedUser(t, pool, password) // seedUser hashes at bcrypt.MinCost
	c := &Connector{id: 1, pool: pool}

	var before string
	if err := pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE email = $1`, stored).Scan(&before); err != nil {
		t.Fatalf("read hash before: %v", err)
	}
	if cost, err := bcrypt.Cost([]byte(before)); err != nil || cost >= bcrypt.DefaultCost {
		t.Fatalf("seed must be below the floor for this test (cost=%d, err=%v)", cost, err)
	}

	if err := c.VerifyPassword(ctx, stored, password); err != nil {
		t.Fatalf("verify before self-heal: %v", err)
	}

	var after string
	if err := pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE email = $1`, stored).Scan(&after); err != nil {
		t.Fatalf("read hash after: %v", err)
	}
	if after == before {
		t.Fatal("below-floor hash was not upgraded — NeedsRehash self-heal missing")
	}
	if cost, err := bcrypt.Cost([]byte(after)); err != nil || cost < bcrypt.DefaultCost {
		t.Fatalf("upgraded hash must meet the shared floor (cost=%d, err=%v)", cost, err)
	}
	if err := pwhash.VerifyPasswordHash(after, password); err != nil {
		t.Fatalf("upgraded hash must still verify the same password: %v", err)
	}

	// At-floor hashes are stable: a second verify must NOT rewrite.
	if err := c.VerifyPassword(ctx, stored, password); err != nil {
		t.Fatalf("verify after self-heal: %v", err)
	}
	var stable string
	if err := pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE email = $1`, stored).Scan(&stable); err != nil {
		t.Fatalf("read hash after second verify: %v", err)
	}
	if stable != after {
		t.Fatal("at-floor hash was rewritten — self-heal must be idempotent")
	}
}

// TestChangePassword_WritesThroughSharedSeam pins the single hash-policy seam
// (D-AUTHSERVER-INTERNAL-CONNECTOR-006): the new hash written by
// ChangePassword meets the shared pwhash strength floor — the former
// direct-bcrypt branch with its env-downgradable BCRYPT_COST knob is gone.
func TestChangePassword_WritesThroughSharedSeam(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	oldPassword := "Old-Secret-pw-123"
	newPassword := "New-Secret-pw-456"
	stored := seedUser(t, pool, oldPassword)
	c := &Connector{id: 1, pool: pool}

	if err := c.ChangePassword(ctx, stored, oldPassword, newPassword); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	var hash string
	if err := pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE email = $1`, stored).Scan(&hash); err != nil {
		t.Fatalf("read rotated hash: %v", err)
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("rotated hash is not bcrypt: %v", err)
	}
	if cost < bcrypt.DefaultCost {
		t.Fatalf("rotated hash cost %d is below the shared floor — direct-bcrypt bypass resurrected?", cost)
	}
	if pwhash.NeedsRehash(hash) {
		t.Fatal("rotated hash still flagged NeedsRehash — must be written at the seam floor")
	}
}

// TestNoEnvCostKnobRemains is a source-scan pin (ad_tls_test.go T2 pattern):
// the connector must contain no environment reads — the BCRYPT_COST
// env-downgradable cost bypass was removed with the direct-bcrypt branch, and
// no replacement env knob may reappear on this credential path.
func TestNoEnvCostKnobRemains(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "local.go", nil, 0)
	if err != nil {
		t.Fatalf("parse local.go: %v", err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "os" && sel.Sel.Name == "Getenv" {
				t.Error("os.Getenv call found in local.go — the env cost bypass must stay removed")
			}
		}
		return true
	})
	for _, imp := range file.Imports {
		if strings.Contains(imp.Path.Value, "crypto/bcrypt") {
			t.Error("direct crypto/bcrypt import found in local.go — hashing must go through the shared pwhash seam")
		}
	}
}
