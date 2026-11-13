package token

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests cover the root-cause fix: RefreshTokens must refuse rotation for
// a disabled (users.enabled = FALSE) user on BOTH branches — the normal path
// and the 30s grace-window retry path — with an error indistinguishable from
// an invalid/expired refresh token (no oracle). Before this fix neither
// branch's user lookup selected `enabled` at all, so a disabled/suspended
// user with a live refresh chain could keep refreshing indefinitely. Requires
// a live DB; skipped otherwise (mirrors the other refresh_*_test.go files in
// this package).

// TestRefreshTokens_DisabledUser_NormalPath: a disabled user's not-yet-rotated
// refresh token must be refused, and the error must read exactly like an
// invalid/expired token — never a distinguishable "disabled" message.
func TestRefreshTokens_DisabledUser_NormalPath(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping refresh-enabled integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	var domainID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM domains LIMIT 1`).Scan(&domainID); err != nil {
		t.Skipf("no domain in test DB: %v", err)
	}

	const testUserID = 999990
	const testEmail = "dbtest-refresh-disabled@example.com"
	pool.Exec(ctx, `INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		VALUES ($1, 'dbtest-refresh-disabled', $2, $3, 'DB Test Refresh Disabled', TRUE)
		ON CONFLICT (id) DO UPDATE SET enabled = TRUE`, testUserID, domainID, testEmail)
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM oauth_tokens WHERE user_id = $1`, testUserID)
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, testUserID)
	})

	p := newTestProvider(t)

	// Sanity: while enabled, refresh succeeds (rules out a bug that always
	// refuses).
	initialFamily := uuid.New().String()
	sanityTok, err := p.IssueRefreshWithFamily(testUserID, testEmail, initialFamily)
	if err != nil {
		t.Fatalf("IssueRefreshWithFamily (sanity): %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO oauth_tokens (user_id, token_hash, token_type, expires_at, family_id)
		 VALUES ($1, $2, 'refresh', now() + interval '30 days', $3::uuid)
		 ON CONFLICT DO NOTHING`,
		testUserID, tokenHash(sanityTok), initialFamily,
	); err != nil {
		t.Fatalf("seed oauth_tokens (sanity): %v", err)
	}
	if _, err := RefreshTokens(ctx, pool, p, nil, sanityTok); err != nil {
		t.Fatalf("RefreshTokens while enabled must succeed: %v", err)
	}

	// A second, not-yet-rotated token — this is the one under test.
	family := uuid.New().String()
	refreshTok, err := p.IssueRefreshWithFamily(testUserID, testEmail, family)
	if err != nil {
		t.Fatalf("IssueRefreshWithFamily: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO oauth_tokens (user_id, token_hash, token_type, expires_at, family_id)
		 VALUES ($1, $2, 'refresh', now() + interval '30 days', $3::uuid)
		 ON CONFLICT DO NOTHING`,
		testUserID, tokenHash(refreshTok), family,
	); err != nil {
		t.Fatalf("seed oauth_tokens: %v", err)
	}

	if _, err := pool.Exec(ctx, `UPDATE users SET enabled = FALSE WHERE id = $1`, testUserID); err != nil {
		t.Fatalf("disable user: %v", err)
	}

	_, err = RefreshTokens(ctx, pool, p, nil, refreshTok)
	if err == nil {
		t.Fatal("RefreshTokens for a disabled user must fail")
	}
	if !strings.Contains(err.Error(), "refresh token revoked or expired") {
		t.Fatalf("disabled-user refresh error = %q, want the same shape as an invalid/expired token", err.Error())
	}

	var live int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM oauth_tokens WHERE user_id = $1 AND revoked_at IS NULL`,
		testUserID,
	).Scan(&live); err != nil {
		t.Fatalf("count live rows: %v", err)
	}
	if live != 0 {
		t.Fatalf("%d oauth_tokens row(s) still live for the disabled user, want 0 (refresh must revoke the family, not just refuse once)", live)
	}
}

// TestRefreshTokens_DisabledUser_GraceWindow: the SECOND call site — a client
// retry within the 30s post-rotation grace window — must independently refuse
// a disabled user too (it is a separate SQL lookup from the normal path, so
// fixing one and not the other is a real, easy-to-make mistake).
func TestRefreshTokens_DisabledUser_GraceWindow(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping refresh-enabled integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	var domainID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM domains LIMIT 1`).Scan(&domainID); err != nil {
		t.Skipf("no domain in test DB: %v", err)
	}

	const testUserID = 999991
	const testEmail = "dbtest-refresh-disabled-grace@example.com"
	pool.Exec(ctx, `INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		VALUES ($1, 'dbtest-refresh-disabled-grace', $2, $3, 'DB Test Refresh Disabled Grace', TRUE)
		ON CONFLICT (id) DO UPDATE SET enabled = TRUE`, testUserID, domainID, testEmail)
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM oauth_tokens WHERE user_id = $1`, testUserID)
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, testUserID)
	})

	p := newTestProvider(t)
	family := uuid.New().String()
	refreshTok, err := p.IssueRefreshWithFamily(testUserID, testEmail, family)
	if err != nil {
		t.Fatalf("IssueRefreshWithFamily: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO oauth_tokens (user_id, token_hash, token_type, expires_at, family_id)
		 VALUES ($1, $2, 'refresh', now() + interval '30 days', $3::uuid)
		 ON CONFLICT DO NOTHING`,
		testUserID, tokenHash(refreshTok), family,
	); err != nil {
		t.Fatalf("seed oauth_tokens: %v", err)
	}

	// Rotate once while enabled — this is what lands the original row inside
	// the 30s grace window (rotated_at = now(), successor row inserted).
	if _, err := RefreshTokens(ctx, pool, p, nil, refreshTok); err != nil {
		t.Fatalf("RefreshTokens (hop 1, priming the grace window): %v", err)
	}

	// Disable the user, then replay the ORIGINAL token — within the grace
	// window this hits the grace-window branch, NOT the normal path.
	if _, err := pool.Exec(ctx, `UPDATE users SET enabled = FALSE WHERE id = $1`, testUserID); err != nil {
		t.Fatalf("disable user: %v", err)
	}

	_, err = RefreshTokens(ctx, pool, p, nil, refreshTok)
	if err == nil {
		t.Fatal("grace-window retry for a disabled user must fail")
	}
	if !strings.Contains(err.Error(), "refresh token revoked or expired") {
		t.Fatalf("disabled-user grace-window error = %q, want the same shape as an invalid/expired token", err.Error())
	}

	var live int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM oauth_tokens WHERE user_id = $1 AND revoked_at IS NULL`,
		testUserID,
	).Scan(&live); err != nil {
		t.Fatalf("count live rows: %v", err)
	}
	if live != 0 {
		t.Fatalf("%d oauth_tokens row(s) still live for the disabled user, want 0", live)
	}
}
