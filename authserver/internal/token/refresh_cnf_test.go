package token

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/jwtutil"
)

// TestRefreshTokensCarriesCnf is the red-first evidence for the refresh-path
// gap flagged in the DPoP MFA-binding task: before this fix, issueAndStore
// minted the post-rotation access token via IssueAccessWithDevice (no cnf
// param at all) and the successor refresh token via IssueRefreshWithFamily
// (same), so a session bound at login/MFA-completion silently became UNBOUND
// the moment the client's first /auth/refresh landed — even with
// feature.token_binding on and feature.cae_runtime eventually enforcing it.
//
// Requires a live DB (oauth_tokens row + rotation); skipped otherwise.
func TestRefreshTokensCarriesCnf(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping refresh-cnf integration test")
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

	const testUserID = 999996 // distinct from the risk/family test fixtures
	const testEmail = "dbtest-refresh-cnf@example.com"
	pool.Exec(ctx, `INSERT INTO users (id, username, domain_id, email, display_name)
		VALUES ($1, 'dbtest-refresh-cnf', $2, $3, 'DB Test Refresh Cnf')
		ON CONFLICT DO NOTHING`, testUserID, domainID, testEmail)
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM oauth_tokens WHERE user_id = $1`, testUserID)
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, testUserID)
	})

	p := newTestProvider(t)
	cnf := &jwtutil.ConfirmationClaim{JKT: "test-jkt-thumbprint-abc123"}

	// The anchor refresh token (as TokenService.Issue mints it at login/MFA
	// completion) carries cnf directly on the refresh JWT — this is the seam
	// that lets rotation read it back without a new DB column.
	initialFamily := uuid.New().String()
	refreshTok, err := p.IssueRefreshWithFamilyAndCnf(testUserID, testEmail, initialFamily, cnf)
	if err != nil {
		t.Fatalf("IssueRefreshWithFamilyAndCnf: %v", err)
	}
	h := tokenHash(refreshTok)
	if _, err := pool.Exec(ctx,
		`INSERT INTO oauth_tokens (user_id, token_hash, token_type, expires_at, family_id)
		 VALUES ($1, $2, 'refresh', now() + interval '30 days', $3::uuid)
		 ON CONFLICT DO NOTHING`,
		testUserID, h, initialFamily,
	); err != nil {
		t.Fatalf("seed oauth_tokens: %v", err)
	}

	// ── Hop 1 ──
	result, err := RefreshTokens(ctx, pool, p, nil, refreshTok)
	if err != nil {
		t.Fatalf("RefreshTokens (hop 1): %v", err)
	}
	accessClaims, err := p.Validate(result.AccessToken)
	if err != nil {
		t.Fatalf("validate access token (hop 1): %v", err)
	}
	if accessClaims.Cnf == nil || accessClaims.Cnf.JKT != cnf.JKT {
		t.Fatalf("hop 1: access token cnf = %+v, want jkt %q — refresh dropped the DPoP binding", accessClaims.Cnf, cnf.JKT)
	}
	refreshClaims, err := p.Validate(result.RefreshToken)
	if err != nil {
		t.Fatalf("validate successor refresh token (hop 1): %v", err)
	}
	if refreshClaims.Cnf == nil || refreshClaims.Cnf.JKT != cnf.JKT {
		t.Fatalf("hop 1: successor refresh token cnf = %+v, want jkt %q — binding would be lost on the NEXT refresh too", refreshClaims.Cnf, cnf.JKT)
	}

	// ── Hop 2: binding must survive a SECOND rotation, not just the first. ──
	result2, err := RefreshTokens(ctx, pool, p, nil, result.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshTokens (hop 2): %v", err)
	}
	accessClaims2, err := p.Validate(result2.AccessToken)
	if err != nil {
		t.Fatalf("validate access token (hop 2): %v", err)
	}
	if accessClaims2.Cnf == nil || accessClaims2.Cnf.JKT != cnf.JKT {
		t.Fatalf("hop 2: access token cnf = %+v, want jkt %q — binding did not survive a second rotation", accessClaims2.Cnf, cnf.JKT)
	}
}

// TestRefreshTokensNoCnfStaysUnbound verifies the graceful-degrade side: a
// refresh token that was never bound (no cnf, the pre-CA-3a / toggle-off
// case) stays unbound after rotation — no accidental binding is invented.
func TestRefreshTokensNoCnfStaysUnbound(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping refresh-cnf integration test")
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

	const testUserID = 999995
	const testEmail = "dbtest-refresh-nocnf@example.com"
	pool.Exec(ctx, `INSERT INTO users (id, username, domain_id, email, display_name)
		VALUES ($1, 'dbtest-refresh-nocnf', $2, $3, 'DB Test Refresh No Cnf')
		ON CONFLICT DO NOTHING`, testUserID, domainID, testEmail)
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM oauth_tokens WHERE user_id = $1`, testUserID)
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, testUserID)
	})

	p := newTestProvider(t)
	initialFamily := uuid.New().String()
	refreshTok, err := p.IssueRefreshWithFamily(testUserID, testEmail, initialFamily)
	if err != nil {
		t.Fatalf("IssueRefreshWithFamily: %v", err)
	}
	h := tokenHash(refreshTok)
	if _, err := pool.Exec(ctx,
		`INSERT INTO oauth_tokens (user_id, token_hash, token_type, expires_at, family_id)
		 VALUES ($1, $2, 'refresh', now() + interval '30 days', $3::uuid)
		 ON CONFLICT DO NOTHING`,
		testUserID, h, initialFamily,
	); err != nil {
		t.Fatalf("seed oauth_tokens: %v", err)
	}

	result, err := RefreshTokens(ctx, pool, p, nil, refreshTok)
	if err != nil {
		t.Fatalf("RefreshTokens: %v", err)
	}
	accessClaims, err := p.Validate(result.AccessToken)
	if err != nil {
		t.Fatalf("validate access token: %v", err)
	}
	if accessClaims.Cnf != nil {
		t.Fatalf("unbound session: access token must stay unbound after refresh, got cnf %+v", accessClaims.Cnf)
	}
}
