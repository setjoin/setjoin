package token

// ER5 er5-s08 occurrence test (refresh-token-grace-successor-fork): presenting
// a parent refresh token again within the 30s grace window must extend the
// CURRENT chain tip — never insert a SECOND active child of the same parent.
// The old grace branch minted each retry's successor with the PARENT as
// previous_token_hash, forking the family: two live refresh chains from one
// credential, and the reuse-detection signal never fired for the fork.

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestRefreshTokens_GraceRetryExtendsChainTipWithoutForking drives the real
// rotation twice inside the grace window: presentation #1 (normal rotation)
// mints S1 from the parent; presentation #2 (grace retry) must mint S2 whose
// predecessor is S1 (the tip), leaving exactly ONE active child of the parent.
func TestRefreshTokens_GraceRetryExtendsChainTipWithoutForking(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping grace-fork integration test")
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
	const testEmail = "dbtest-grace-fork@example.com"
	pool.Exec(ctx, `INSERT INTO users (id, username, domain_id, email, display_name, enabled)
		VALUES ($1, 'dbtest-grace-fork', $2, $3, 'DB Test Grace Fork', TRUE)
		ON CONFLICT (id) DO UPDATE SET enabled = TRUE`, testUserID, domainID, testEmail)
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM oauth_tokens WHERE user_id = $1`, testUserID)
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, testUserID)
	})

	p := newTestProvider(t)
	family := uuid.New().String()
	parent, err := p.IssueRefreshWithFamily(testUserID, testEmail, family)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO oauth_tokens (user_id, token_hash, token_type, expires_at, family_id)
		 VALUES ($1, $2, 'refresh', now() + interval '30 days', $3::uuid)`,
		testUserID, tokenHash(parent), family,
	); err != nil {
		t.Fatalf("seed parent anchor: %v", err)
	}

	// Presentation #1: normal rotation — parent → S1.
	res1, err := RefreshTokens(ctx, pool, p, nil, parent)
	if err != nil {
		t.Fatalf("first rotation: %v", err)
	}
	if res1.RefreshToken == "" || res1.RefreshToken == parent {
		t.Fatal("first rotation did not mint a fresh refresh token")
	}

	// Presentation #2: the SAME parent again, inside the grace window.
	res2, err := RefreshTokens(ctx, pool, p, nil, parent)
	if err != nil {
		t.Fatalf("grace-window retry: %v (a client retry within the grace window must be honored)", err)
	}

	// The retry's successor must NOT be a second child of the parent.
	var parentChildren int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM oauth_tokens WHERE previous_token_hash = $1`, tokenHash(parent),
	).Scan(&parentChildren); err != nil {
		t.Fatal(err)
	}
	if parentChildren != 1 {
		t.Fatalf("parent has %d active-or-superseded children after a grace retry, want exactly 1 — the family forked", parentChildren)
	}

	// The retry's successor chains from the CURRENT tip (S1), same family.
	var predecessorIsTip bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM oauth_tokens child
			JOIN oauth_tokens tip ON tip.token_hash = child.previous_token_hash
			WHERE child.previous_token_hash = tip.token_hash
			  AND child.family_id::text = $1
			  AND tip.rotated_at IS NOT NULL
			  AND tip.rotated_at > now() - interval '5 seconds'
		)`, family,
	).Scan(&predecessorIsTip); err != nil {
		t.Fatal(err)
	}
	if !predecessorIsTip {
		t.Fatal("the grace retry's successor does not chain from a rotated same-family tip — the chain did not extend linearly")
	}

	// Family integrity: exactly one UNROTATED (live) refresh anchor remains.
	var liveAnchors int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM oauth_tokens
		 WHERE user_id = $1 AND family_id::text = $2
		 AND rotated_at IS NULL AND revoked_at IS NULL AND expires_at > now()`,
		testUserID, family,
	).Scan(&liveAnchors); err != nil {
		t.Fatal(err)
	}
	if liveAnchors != 1 {
		t.Fatalf("%d live (unrotated) family anchors after the grace retry, want exactly 1", liveAnchors)
	}

	// Rotation still mints: presenting the retry's fresh token rotates normally.
	res3, err := RefreshTokens(ctx, pool, p, nil, res2.RefreshToken)
	if err != nil {
		t.Fatalf("presenting the grace-retry successor: %v", err)
	}
	_ = res3
}
