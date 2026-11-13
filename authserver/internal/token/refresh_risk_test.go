package token

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/toggle"
)

// TestReadRiskGate verifies the toggle gate: nil or disabled toggles return nil
// without touching the pool (fail-open contract). No DB required.
func TestReadRiskGate(t *testing.T) {
	ctx := context.Background()
	// nil toggles → nil (feature absent)
	if readRisk(ctx, nil, nil, 1) != nil {
		t.Fatal("nil toggles must return nil risk claim")
	}
	// toggle explicitly off → nil
	off := toggle.NewTestFlags(map[string]bool{toggle.FeatureUserRisk: false})
	if readRisk(ctx, nil, off, 1) != nil {
		t.Fatal("disabled feature.user_risk must return nil risk claim")
	}
}

// TestRefreshTokensCarriesRisk verifies the end-to-end fix: the access token
// minted by RefreshTokens carries the Risk claim when feature.user_risk is on
// and the user has an elevated risk row. Requires a live DB; skipped otherwise.
func TestRefreshTokensCarriesRisk(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping refresh-risk integration test")
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

	const testUserID = 999998 // distinct from TestRefreshRotationInheritsFamily (999999)
	const testEmail = "dbtest-refresh-risk@example.com"

	pool.Exec(ctx, `INSERT INTO users (id, username, domain_id, email, display_name)
		VALUES ($1, 'dbtest-refresh-risk', $2, $3, 'DB Test Refresh Risk')
		ON CONFLICT DO NOTHING`, testUserID, domainID, testEmail)
	// Seed an elevated risk row (score 60 = medium → RequiresMFA true).
	pool.Exec(ctx, `INSERT INTO user_risk (user_id, score, level, signals)
		VALUES ($1, 60, 'medium', '["travel"]'::jsonb)
		ON CONFLICT (user_id) DO UPDATE SET score=60, level='medium', signals='["travel"]'::jsonb`,
		testUserID)
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM oauth_tokens WHERE user_id = $1`, testUserID)
		pool.Exec(ctx, `DELETE FROM user_risk WHERE user_id = $1`, testUserID)
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

	on := toggle.NewTestFlags(map[string]bool{toggle.FeatureUserRisk: true})
	result, err := RefreshTokens(ctx, pool, p, on, refreshTok)
	if err != nil {
		t.Fatalf("RefreshTokens: %v", err)
	}

	claims, err := p.Validate(result.AccessToken)
	if err != nil {
		t.Fatalf("Validate access token: %v", err)
	}
	if claims.Risk == nil {
		t.Fatal("access token after refresh must carry Risk claim when feature.user_risk is on and user has elevated risk row")
	}
	if !claims.Risk.RequiresMFA {
		t.Fatalf("Risk.RequiresMFA must be true for medium risk; got %+v", claims.Risk)
	}
}

// TestRefreshTokensRiskOffByDefault verifies that without toggles (nil) the
// access token carries no Risk claim — the default before CA-3b is deployed.
// Requires a live DB (same user_risk seed as above); skipped otherwise.
func TestRefreshTokensRiskOffByDefault(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping refresh-risk integration test")
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

	const testUserID = 999997
	const testEmail = "dbtest-refresh-risk-off@example.com"
	pool.Exec(ctx, `INSERT INTO users (id, username, domain_id, email, display_name)
		VALUES ($1, 'dbtest-refresh-risk-off', $2, $3, 'DB Test Refresh Risk Off')
		ON CONFLICT DO NOTHING`, testUserID, domainID, testEmail)
	pool.Exec(ctx, `INSERT INTO user_risk (user_id, score, level, signals)
		VALUES ($1, 75, 'high', '["spray"]'::jsonb)
		ON CONFLICT (user_id) DO UPDATE SET score=75, level='high', signals='["spray"]'::jsonb`,
		testUserID)
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM oauth_tokens WHERE user_id = $1`, testUserID)
		pool.Exec(ctx, `DELETE FROM user_risk WHERE user_id = $1`, testUserID)
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

	// nil toggles = feature off
	result, err := RefreshTokens(ctx, pool, p, nil, refreshTok)
	if err != nil {
		t.Fatalf("RefreshTokens: %v", err)
	}
	claims, err := p.Validate(result.AccessToken)
	if err != nil {
		t.Fatalf("Validate access token: %v", err)
	}
	if claims.Risk != nil {
		t.Fatal("access token must NOT carry Risk claim when feature.user_risk is off (nil toggles)")
	}
}
