package token

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/cryptokey"
)

// newTestProvider returns a JWTProvider for unit tests (no DB required).
func newTestProvider(t *testing.T) *JWTProvider {
	t.Helper()
	return NewJWTProvider(
		"test-secret-32-bytes-long-ok-now!!",
		nil,
		cryptokey.ProfileStandard,
		time.Hour,
		720*time.Hour,
		"test-issuer",
	)
}

// TestAccessTokenHasJTI asserts that every access token carries a non-empty jti.
func TestAccessTokenHasJTI(t *testing.T) {
	p := newTestProvider(t)
	tok, err := p.IssueAccess(1, "a@b", false)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := p.Validate(tok)
	if err != nil {
		t.Fatal(err)
	}
	if claims.JTI == "" {
		t.Fatal("access token must carry a jti (CA-3 per-session denylist substrate)")
	}
}

// TestAccessTokenJTIUnique asserts two access tokens issued by the same provider
// carry different jti values (each token gets a fresh random id).
func TestAccessTokenJTIUnique(t *testing.T) {
	p := newTestProvider(t)

	tok1, err := p.IssueAccess(1, "a@b", false)
	if err != nil {
		t.Fatal(err)
	}
	tok2, err := p.IssueAccess(1, "a@b", false)
	if err != nil {
		t.Fatal(err)
	}

	c1, err := p.Validate(tok1)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := p.Validate(tok2)
	if err != nil {
		t.Fatal(err)
	}

	if c1.JTI == c2.JTI {
		t.Fatalf("two access tokens must have different jti values, both got %q", c1.JTI)
	}
}

// TestFamilyIDRoundTrip asserts FamilyID survives sign → Validate.
func TestFamilyIDRoundTrip(t *testing.T) {
	p := newTestProvider(t)
	wantFamily := uuid.New().String()

	tok, err := p.IssueRefreshWithFamily(1, "a@b", wantFamily)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := p.Validate(tok)
	if err != nil {
		t.Fatal(err)
	}
	if claims.FamilyID != wantFamily {
		t.Fatalf("FamilyID = %q, want %q", claims.FamilyID, wantFamily)
	}
}

func TestFamilyAccessMintDefaultsAuthenticationTimeForSIF(t *testing.T) {
	provider := newTestProvider(t)
	sif := int64(300)
	raw, err := provider.IssueAccessCAFamilySession(
		42, "sif-family@example.com", false,
		nil, nil, nil, nil, AuthContext{}, nil, &sif, nil,
		"family-sif", "member",
	)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := provider.Validate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if claims.SessionAuthTime == nil || *claims.SessionAuthTime <= 0 {
		t.Fatalf("session auth time=%v, want current timestamp", claims.SessionAuthTime)
	}
	if claims.FamilyID != "family-sif" {
		t.Fatalf("family=%q, want family-sif", claims.FamilyID)
	}
}

// TestIssueRefreshNewFamily asserts IssueRefresh (the login path) mints a
// fresh non-empty family_id on every call (no two calls share a family).
func TestIssueRefreshNewFamily(t *testing.T) {
	p := newTestProvider(t)

	tok1, err := p.IssueRefresh(1, "a@b")
	if err != nil {
		t.Fatal(err)
	}
	tok2, err := p.IssueRefresh(1, "a@b")
	if err != nil {
		t.Fatal(err)
	}

	c1, err := p.Validate(tok1)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := p.Validate(tok2)
	if err != nil {
		t.Fatal(err)
	}

	if c1.FamilyID == "" {
		t.Fatal("IssueRefresh must mint a non-empty FamilyID")
	}
	if c1.FamilyID == c2.FamilyID {
		t.Fatalf("two independent logins must produce different family IDs, both got %q", c1.FamilyID)
	}
}

// TestRefreshRotationInheritsFamily asserts that refresh rotation carries the
// parent token's family_id into the successor. This test requires a live DB;
// it is skipped when TEST_DB_DSN is unset.
func TestRefreshRotationInheritsFamily(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping DB-backed family inheritance test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	// Seed a test user if not present. We need a valid domain_id; pick the
	// first available domain from the DB (a fresh test DB always has at least one).
	var domainID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM domains LIMIT 1`).Scan(&domainID); err != nil {
		t.Skipf("no domain in test DB, cannot seed test user: %v", err)
	}

	const testUserID = 999999
	const testEmail = "dbtest-family@example.com"

	// Insert a throwaway user for the duration of the test; delete it on cleanup.
	// ON CONFLICT DO NOTHING handles a leftover row from a previous interrupted run.
	_, err = pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name)
		 VALUES ($1, 'dbtest-family', $2, $3, 'DB Test Family')
		 ON CONFLICT DO NOTHING`,
		testUserID, domainID, testEmail,
	)
	if err != nil {
		t.Fatalf("seed user INSERT: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM oauth_tokens WHERE user_id = $1`, testUserID)
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, testUserID)
	})

	p := newTestProvider(t)

	// Simulate initial login: mint + store a refresh token with a fresh family.
	initialFamily := uuid.New().String()
	refreshTok, err := p.IssueRefreshWithFamily(testUserID, testEmail, initialFamily)
	if err != nil {
		t.Fatalf("IssueRefreshWithFamily: %v", err)
	}

	// Insert the initial refresh token into oauth_tokens (simulating the login path).
	h := tokenHash(refreshTok)
	_, err = pool.Exec(ctx,
		`INSERT INTO oauth_tokens (user_id, token_hash, token_type, expires_at, family_id)
		 VALUES ($1, $2, 'refresh', now() + interval '30 days', $3::uuid)
		 ON CONFLICT DO NOTHING`,
		testUserID, h, initialFamily,
	)
	if err != nil {
		t.Fatalf("seed oauth_tokens INSERT: %v", err)
	}

	// Rotate: this should inherit initialFamily. nil toggles = feature.user_risk off (no risk query).
	result, err := RefreshTokens(ctx, pool, p, nil, refreshTok)
	if err != nil {
		t.Fatalf("RefreshTokens: %v", err)
	}

	// Validate the new refresh token's family_id.
	newClaims, err := p.Validate(result.RefreshToken)
	if err != nil {
		t.Fatalf("Validate successor: %v", err)
	}
	if newClaims.FamilyID != initialFamily {
		t.Fatalf("successor refresh token family_id = %q, want inherited %q", newClaims.FamilyID, initialFamily)
	}

	// Also check the DB row.
	var dbFamily string
	err = pool.QueryRow(ctx,
		`SELECT family_id::text FROM oauth_tokens WHERE token_hash = $1`,
		tokenHash(result.RefreshToken),
	).Scan(&dbFamily)
	if err != nil {
		t.Fatalf("query successor family_id from DB: %v", err)
	}
	if dbFamily != initialFamily {
		t.Fatalf("DB family_id = %q, want %q", dbFamily, initialFamily)
	}
}
