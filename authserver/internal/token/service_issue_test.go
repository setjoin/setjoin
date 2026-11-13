package token

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/jwtutil"
)

func cleanupIssueTestUser(pool *pgxpool.Pool, ctx context.Context, userID int64, email string) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// These fixed-ID test actors must survive repeated package runs. Disable
	// protection triggers only on this connection-local cleanup transaction;
	// production paths never use this bypass.
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role=replica`); err != nil {
		return
	}
	_, _ = tx.Exec(ctx, `DELETE FROM oauth_tokens WHERE user_id=$1`, userID)
	_, _ = tx.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1`, userID)
	_, _ = tx.Exec(ctx,
		`DELETE FROM mailboxes WHERE user_id=$1 OR lower(email)=lower($2)`,
		userID, email,
	)
	_, _ = tx.Exec(ctx,
		`DELETE FROM users WHERE id=$1 OR lower(email)=lower($2)`,
		userID, email,
	)
	_ = tx.Commit(ctx)
}

func closedIssueTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(
		context.Background(),
		"postgres://setjoin-test:unused@127.0.0.1:1/setjoin?connect_timeout=1",
	)
	if err != nil {
		t.Fatalf("create closed test pool: %v", err)
	}
	pool.Close()
	return pool
}

func TestIssueTxRejectsNilTransaction(t *testing.T) {
	svc := NewTokenService(newTestProvider(t), nil, nil)
	_, err := svc.IssueTx(context.Background(), nil, IssueInput{})
	if !errors.Is(err, ErrIssueStore) {
		t.Fatalf("IssueTx(nil) error = %v, want ErrIssueStore", err)
	}
}

func TestRevokeAllForUserPropagatesStoreFailure(t *testing.T) {
	svc := NewTokenService(
		newTestProvider(t),
		closedIssueTestPool(t),
		nil,
	)
	if err := svc.RevokeAllForUser(context.Background(), 42); err == nil {
		t.Fatal("RevokeAllForUser on a closed pool unexpectedly succeeded")
	}
}

// seedIssueTestUser inserts a throwaway user (deleted on cleanup, along with
// its oauth_tokens rows) and returns its id + email. Skips when TEST_DB_DSN is
// unset, mirroring TestRefreshRotationInheritsFamily.
func seedIssueTestUser(t *testing.T, userID int64, username, email string) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping DB-backed issuance test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	cleanupIssueTestUser(pool, ctx, userID, email)

	// Use any existing domain; on a schema-only (unfixtured) test DB seed a
	// throwaway one so the regression runs instead of skipping.
	var domainID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM domains LIMIT 1`).Scan(&domainID); err != nil {
		if err := pool.QueryRow(ctx,
			`INSERT INTO domains (name) VALUES ($1) RETURNING id`, username+".example",
		).Scan(&domainID); err != nil {
			t.Skipf("cannot seed test domain: %v", err)
		}
		t.Cleanup(func() {
			pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, domainID)
		})
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name)
		 VALUES ($1, $2, $3, $4, 'DB Test Issue')
		 ON CONFLICT DO NOTHING`,
		userID, username, domainID, email,
	)
	if err != nil {
		t.Fatalf("seed user INSERT: %v", err)
	}
	t.Cleanup(func() {
		cleanupIssueTestUser(pool, ctx, userID, email)
	})
	return pool, ctx
}

// TestIssuePersistsFamilyAnchor asserts TokenService.Issue persists the
// oauth_tokens anchor row WITH a non-NULL family_id equal to the refresh JWT's
// fam claim, and with previous_token_hash NULL (this row IS the family anchor).
// This is the login-path half of the hop-one closure: before Issue existed, the
// login insert dropped family_id (4 cols) so the anchor row had NULL family and
// the JWT's login-minted fam claim was never persisted.
func TestIssuePersistsFamilyAnchor(t *testing.T) {
	const userID = 999998
	const email = "dbtest-issue@example.com"
	pool, ctx := seedIssueTestUser(t, userID, "dbtest-issue", email)

	p := newTestProvider(t)
	svc := NewTokenService(p, pool, nil)

	res, err := svc.Issue(ctx, IssueInput{UserID: userID, Email: email, Factors: []string{AMRPassword}})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	claims, err := p.Validate(res.RefreshToken)
	if err != nil {
		t.Fatalf("Validate refresh: %v", err)
	}
	if claims.FamilyID == "" {
		t.Fatal("login refresh token must carry a non-empty fam claim")
	}

	var dbFamily *string
	var prevHash []byte
	if err := pool.QueryRow(ctx,
		`SELECT family_id::text, previous_token_hash FROM oauth_tokens WHERE token_hash = $1`,
		tokenHash(res.RefreshToken),
	).Scan(&dbFamily, &prevHash); err != nil {
		t.Fatalf("query anchor row: %v", err)
	}
	if dbFamily == nil {
		t.Fatal("anchor row family_id is NULL — the JWT fam claim was not persisted (hop-one hole)")
	}
	if *dbFamily != claims.FamilyID {
		t.Fatalf("anchor row family_id = %q, want the JWT fam claim %q", *dbFamily, claims.FamilyID)
	}
	if prevHash != nil {
		t.Fatalf("anchor row previous_token_hash must be NULL (login IS the anchor), got %x", prevHash)
	}
}

func TestIssueBindsRefreshFamilyToDeviceAndSignInFrequency(t *testing.T) {
	const userID = 999_990
	const email = "dbtest-issue-controls@example.com"
	pool, ctx := seedIssueTestUser(
		t, userID, "dbtest-issue-controls", email,
	)

	provider := newTestProvider(t)
	svc := NewTokenService(provider, pool, nil)
	sif := int64(7200)
	device := &jwtutil.DeviceClaim{
		ID:               "device-at-login",
		Platform:         "windows",
		TrustTier:        "compliant",
		ComplianceStatus: "ok",
	}
	result, err := svc.Issue(ctx, IssueInput{
		UserID: userID, Email: email, Factors: []string{AMRPassword},
		Device: device, SIF: &sif,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	accessClaims, err := provider.Validate(result.AccessToken)
	if err != nil {
		t.Fatalf("validate access: %v", err)
	}
	refreshClaims, err := provider.Validate(result.RefreshToken)
	if err != nil {
		t.Fatalf("validate refresh: %v", err)
	}
	if accessClaims.FamilyID == "" || accessClaims.FamilyID != refreshClaims.FamilyID {
		t.Fatalf("access/refresh family mismatch: %q / %q",
			accessClaims.FamilyID, refreshClaims.FamilyID)
	}
	if accessClaims.SessionAuthTime == nil ||
		refreshClaims.SessionAuthTime == nil ||
		*accessClaims.SessionAuthTime != *refreshClaims.SessionAuthTime {
		t.Fatalf("access/refresh family auth_time mismatch: %v / %v",
			accessClaims.SessionAuthTime, refreshClaims.SessionAuthTime)
	}
	if refreshClaims.Device == nil || refreshClaims.Device.ID != device.ID {
		t.Fatalf("refresh family omitted login device: %+v", refreshClaims.Device)
	}
	if refreshClaims.SignInFreq == nil || *refreshClaims.SignInFreq != sif {
		t.Fatalf("refresh family omitted SIF: %v", refreshClaims.SignInFreq)
	}
}

func TestIssueTxDefersFamilyAnchorUntilCallerCommit(t *testing.T) {
	const userID = 999996
	const email = "dbtest-issue-tx@example.com"
	pool, ctx := seedIssueTestUser(t, userID, "dbtest-issue-tx", email)

	p := newTestProvider(t)
	svc := NewTokenService(p, pool, nil)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck -- commit makes this a no-op.

	res, err := svc.IssueTx(ctx, tx, IssueInput{
		UserID:  userID,
		Email:   email,
		Factors: []string{AMRPassword},
	})
	if err != nil {
		t.Fatalf("IssueTx: %v", err)
	}
	var visibleBeforeCommit int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM oauth_tokens WHERE token_hash=$1`,
		tokenHash(res.RefreshToken),
	).Scan(&visibleBeforeCommit); err != nil {
		t.Fatalf("query before commit: %v", err)
	}
	if visibleBeforeCommit != 0 {
		t.Fatalf("family anchor visible before caller commit = %d, want 0", visibleBeforeCommit)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	var visibleAfterCommit int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM oauth_tokens WHERE token_hash=$1`,
		tokenHash(res.RefreshToken),
	).Scan(&visibleAfterCommit); err != nil {
		t.Fatalf("query after commit: %v", err)
	}
	if visibleAfterCommit != 1 {
		t.Fatalf("family anchor visible after caller commit = %d, want 1", visibleAfterCommit)
	}
}

func TestNormalizedMintFenceRejectsAfterConcurrentDisable(t *testing.T) {
	const userID = 998991
	const email = "dbtest-normalized-disable@example.com"
	pool, ctx := seedIssueTestUser(
		t, userID, "dbtest-normalized-disable", email,
	)

	var mailboxID, sourceID, sourceGeneration, linkID, linkGeneration int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO mailboxes(
			user_id,domain_id,email,display_name,type,is_primary
		)
		SELECT id,domain_id,email,display_name,'personal',true
		  FROM users WHERE id=$1
		RETURNING id
	`, userID).Scan(&mailboxID); err != nil {
		t.Fatalf("seed normalized primary mailbox: %v", err)
	}
	sourceKey := "oidc:disable-race-" + time.Now().UTC().Format("20060102150405.000000000")
	if err := pool.QueryRow(ctx, `
		INSERT INTO identity_sources(
			source_key,display_name,kind,capabilities,state
		) VALUES(
			$1,'Normalized disable race','oidc',
			'{"authenticate":true,"provision_lifecycle":false,"stable_immutable_subject":true}'::jsonb,
			'active'
		) RETURNING id,generation
	`, sourceKey).Scan(&sourceID, &sourceGeneration); err != nil {
		t.Fatalf("seed normalized source: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO user_identity_links(
			user_id,source_id,external_subject,purposes,state,link_method
		) VALUES($1,$2,$3,ARRAY['authenticate'],'active','jit')
		RETURNING id,generation
	`, userID, sourceID, "subject-"+sourceKey).
		Scan(&linkID, &linkGeneration); err != nil {
		t.Fatalf("seed normalized link: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM user_identity_links WHERE id=$1`, linkID)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM identity_sources WHERE id=$1`, sourceID)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM mailboxes WHERE id=$1`, mailboxID)
	})

	disableTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer disableTx.Rollback(ctx) //nolint:errcheck
	if _, err := disableTx.Exec(ctx,
		`UPDATE users SET enabled=false WHERE id=$1`, userID,
	); err != nil {
		t.Fatalf("stage concurrent disable: %v", err)
	}

	fenceTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer fenceTx.Rollback(ctx) //nolint:errcheck
	fenceResult := make(chan error, 1)
	go func() {
		_, err := fenceTx.Exec(ctx,
			`SELECT identity_auth_mint_fence($1,$2,$3,$4,$5)`,
			userID, sourceID, sourceGeneration, linkID, linkGeneration,
		)
		fenceResult <- err
	}()

	select {
	case err := <-fenceResult:
		t.Fatalf("mint fence did not serialize behind the uncommitted disable: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := disableTx.Commit(ctx); err != nil {
		t.Fatalf("commit concurrent disable: %v", err)
	}
	err = <-fenceResult
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "BZ235" {
		t.Fatalf("mint fence after disable error = %v, want BZ235", err)
	}

	var anchors int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM oauth_tokens WHERE user_id=$1`, userID,
	).Scan(&anchors); err != nil {
		t.Fatal(err)
	}
	if anchors != 0 {
		t.Fatalf("post-disable refresh-family anchors = %d, want 0", anchors)
	}
}

// TestIssueThenRotate_ReuseRevokesLoginFamily is the hop-one regression:
// login (Issue) → rotate once → replay the ORIGINAL refresh token → the whole
// family anchored at LOGIN is revoked, including the rotated (successor) token.
// The successor must inherit the login anchor's family (previously it started a
// FRESH family because the login row had NULL family_id — "parent family_id
// scan failed; starting fresh family").
func TestIssueThenRotate_ReuseRevokesLoginFamily(t *testing.T) {
	const userID = 999997
	const email = "dbtest-issue-rotate@example.com"
	pool, ctx := seedIssueTestUser(t, userID, "dbtest-issue-rotate", email)

	p := newTestProvider(t)
	svc := NewTokenService(p, pool, nil)

	// Login.
	res, err := svc.Issue(ctx, IssueInput{UserID: userID, Email: email, Factors: []string{AMRPassword}})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	loginClaims, err := p.Validate(res.RefreshToken)
	if err != nil {
		t.Fatalf("Validate login refresh: %v", err)
	}
	loginFamily := loginClaims.FamilyID

	// Rotate once. The successor must inherit the LOGIN family (hop one).
	rot, err := svc.Refresh(ctx, res.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh (hop one): %v", err)
	}
	rotClaims, err := p.Validate(rot.RefreshToken)
	if err != nil {
		t.Fatalf("Validate rotated refresh: %v", err)
	}
	rotAccessClaims, err := p.Validate(rot.AccessToken)
	if err != nil {
		t.Fatalf("Validate rotated access: %v", err)
	}
	if rotAccessClaims.FamilyID != rotClaims.FamilyID {
		t.Fatalf("rotated access family = %q, want refresh family %q", rotAccessClaims.FamilyID, rotClaims.FamilyID)
	}
	if rotClaims.FamilyID != loginFamily {
		t.Fatalf("hop-one successor family = %q, want the login anchor family %q (fresh family = the hop-one hole)", rotClaims.FamilyID, loginFamily)
	}
	var rotDBFamily *string
	if err := pool.QueryRow(ctx,
		`SELECT family_id::text FROM oauth_tokens WHERE token_hash = $1`,
		tokenHash(rot.RefreshToken),
	).Scan(&rotDBFamily); err != nil {
		t.Fatalf("query successor row: %v", err)
	}
	if rotDBFamily == nil || *rotDBFamily != loginFamily {
		t.Fatalf("successor DB family = %v, want login anchor family %q", rotDBFamily, loginFamily)
	}

	// Push the original token's rotation outside the 30s retry grace window,
	// then replay it: reuse detection must trip and revoke everything.
	if _, err := pool.Exec(ctx,
		`UPDATE oauth_tokens SET rotated_at = now() - interval '61 seconds' WHERE token_hash = $1`,
		tokenHash(res.RefreshToken),
	); err != nil {
		t.Fatalf("backdate rotated_at: %v", err)
	}
	if _, err := svc.Refresh(ctx, res.RefreshToken); err == nil {
		t.Fatal("replaying the original refresh token must fail (reuse detection)")
	} else if !strings.Contains(err.Error(), "reuse") {
		t.Fatalf("replay error = %v, want suspicious-reuse detection", err)
	}

	// The whole login-anchored family is revoked — including the rotated token.
	var live int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM oauth_tokens WHERE family_id = $1::uuid AND revoked_at IS NULL`,
		loginFamily,
	).Scan(&live); err != nil {
		t.Fatalf("count live family rows: %v", err)
	}
	if live != 0 {
		t.Fatalf("%d token(s) in the login family still live after reuse detection, want 0", live)
	}
	var rotRevoked bool
	if err := pool.QueryRow(ctx,
		`SELECT revoked_at IS NOT NULL FROM oauth_tokens WHERE token_hash = $1`,
		tokenHash(rot.RefreshToken),
	).Scan(&rotRevoked); err != nil {
		t.Fatalf("query rotated token revocation: %v", err)
	}
	if !rotRevoked {
		t.Fatal("rotated (successor) token must be revoked after replay of the login-family original")
	}
}
