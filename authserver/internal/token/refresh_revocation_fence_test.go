package token

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func seedRefreshAnchor(
	t *testing.T,
	userID int64,
	email string,
) (*JWTProvider, string) {
	t.Helper()
	provider := newTestProvider(t)
	family := uuid.NewString()
	refresh, err := provider.IssueRefreshWithFamily(userID, email, family)
	if err != nil {
		t.Fatalf("IssueRefreshWithFamily: %v", err)
	}
	return provider, refresh
}

func waitForPersonFence(
	t *testing.T,
	ctx context.Context,
	userID int64,
	pool queryRower,
) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var acquired bool
		if err := pool.QueryRow(ctx,
			`SELECT pg_try_advisory_lock(
			    hashtextextended('identity-person:'||($1::bigint)::text,0)
			 )`,
			userID,
		).Scan(&acquired); err != nil {
			t.Fatalf("probe person fence: %v", err)
		}
		if !acquired {
			return
		}
		if err := pool.QueryRow(ctx,
			`SELECT pg_advisory_unlock(
			    hashtextextended('identity-person:'||($1::bigint)::text,0)
			 )`,
			userID,
		).Scan(new(bool)); err != nil {
			t.Fatalf("release person-fence probe: %v", err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("refresh did not acquire the person fence before its token row lock")
		case <-ticker.C:
		}
	}
}

func TestRefreshPersonFenceOrdersSuccessorBeforeConcurrentRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	pool := testPool(t)
	userID := seedUser(t, pool)
	const email = "dbtest-revoke-notify@example.com"
	provider, refresh := seedRefreshAnchor(t, userID, email)
	if _, err := pool.Exec(ctx,
		`INSERT INTO oauth_tokens(
		    user_id,token_hash,token_type,expires_at,family_id
		 ) VALUES($1,$2,'refresh',now()+interval '1 hour',$3::uuid)`,
		userID, tokenHash(refresh), uuid.NewString(),
	); err != nil {
		t.Fatalf("seed refresh anchor: %v", err)
	}

	blocker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin parent blocker: %v", err)
	}
	defer blocker.Rollback(ctx) //nolint:errcheck
	if _, err := blocker.Exec(ctx,
		`SELECT 1 FROM oauth_tokens WHERE token_hash=$1 FOR UPDATE`,
		tokenHash(refresh),
	); err != nil {
		t.Fatalf("lock parent refresh row: %v", err)
	}

	refreshDone := make(chan error, 1)
	go func() {
		_, refreshErr := RefreshTokens(ctx, pool, provider, nil, refresh)
		refreshDone <- refreshErr
	}()
	waitForPersonFence(t, ctx, userID, pool)

	revokeDone := make(chan error, 1)
	go func() {
		_, revokeErr := RevokeAndNotifyTx(
			ctx, pool, userID, 0, "refresh_race_regression",
		)
		revokeDone <- revokeErr
	}()

	if err := blocker.Commit(ctx); err != nil {
		t.Fatalf("release parent refresh row: %v", err)
	}
	select {
	case err := <-refreshDone:
		if err != nil {
			t.Fatalf("refresh ordered before revocation: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("refresh did not finish")
	}
	select {
	case err := <-revokeDone:
		if err != nil {
			t.Fatalf("concurrent revocation: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("revocation did not finish")
	}

	var active int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM oauth_tokens
		  WHERE user_id=$1 AND revoked_at IS NULL`,
		userID,
	).Scan(&active); err != nil {
		t.Fatalf("read post-race token state: %v", err)
	}
	if active != 0 {
		t.Fatalf("revocation missed %d successor token(s)", active)
	}
}

func TestRefreshPersonFenceRejectsParentRevokedBeforeRotation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	pool := testPool(t)
	userID := seedUser(t, pool)
	const email = "dbtest-revoke-notify@example.com"
	provider, refresh := seedRefreshAnchor(t, userID, email)
	if _, err := pool.Exec(ctx,
		`INSERT INTO oauth_tokens(
		    user_id,token_hash,token_type,expires_at,family_id
		 ) VALUES($1,$2,'refresh',now()+interval '1 hour',$3::uuid)`,
		userID, tokenHash(refresh), uuid.NewString(),
	); err != nil {
		t.Fatalf("seed refresh anchor: %v", err)
	}

	revokeTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin revocation: %v", err)
	}
	defer revokeTx.Rollback(ctx) //nolint:errcheck
	if _, err := revokeAndNotifyExistingTx(
		ctx, revokeTx, userID, 0, "refresh_race_regression",
	); err != nil {
		t.Fatalf("revoke before refresh: %v", err)
	}

	refreshDone := make(chan error, 1)
	go func() {
		_, refreshErr := RefreshTokens(ctx, pool, provider, nil, refresh)
		refreshDone <- refreshErr
	}()
	if err := revokeTx.Commit(ctx); err != nil {
		t.Fatalf("commit revocation: %v", err)
	}
	select {
	case err := <-refreshDone:
		if err == nil || !strings.Contains(err.Error(), "revoked or expired") {
			t.Fatalf("refresh after committed revocation error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("refresh did not finish")
	}

	var active, successors int
	if err := pool.QueryRow(ctx,
		`SELECT
		   count(*) FILTER (WHERE revoked_at IS NULL),
		   count(*) FILTER (WHERE previous_token_hash=$2)
		 FROM oauth_tokens WHERE user_id=$1`,
		userID, tokenHash(refresh),
	).Scan(&active, &successors); err != nil {
		t.Fatalf("read post-revocation token state: %v", err)
	}
	if active != 0 || successors != 0 {
		t.Fatalf("revoked parent produced state: active=%d successors=%d", active, successors)
	}
}

func TestRefreshRejectsSignedAndStoredPrincipalMismatch(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	claimUserID := seedUser(t, pool)
	const storedUserID int64 = 999_996
	var domainID int64
	if err := pool.QueryRow(ctx, `SELECT domain_id FROM users WHERE id=$1`, claimUserID).
		Scan(&domainID); err != nil {
		t.Fatalf("read fixture domain: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users(id,username,domain_id,email,display_name,enabled)
		 VALUES($1,'dbtest-refresh-mismatch',$2,
		        'dbtest-refresh-mismatch@example.com',
		        'DB Test Refresh Mismatch',TRUE)
		 ON CONFLICT(id) DO UPDATE SET enabled=TRUE`,
		storedUserID, domainID,
	); err != nil {
		t.Fatalf("seed stored principal: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(),
			`DELETE FROM oauth_tokens WHERE user_id=$1`, storedUserID) //nolint:errcheck
		pool.Exec(context.Background(),
			`DELETE FROM users WHERE id=$1`, storedUserID) //nolint:errcheck
	})

	provider, refresh := seedRefreshAnchor(
		t, claimUserID, "dbtest-revoke-notify@example.com",
	)
	if _, err := pool.Exec(ctx,
		`INSERT INTO oauth_tokens(
		    user_id,token_hash,token_type,expires_at,family_id
		 ) VALUES($1,$2,'refresh',now()+interval '1 hour',$3::uuid)`,
		storedUserID, tokenHash(refresh), uuid.NewString(),
	); err != nil {
		t.Fatalf("seed mismatched refresh anchor: %v", err)
	}

	if _, err := RefreshTokens(ctx, pool, provider, nil, refresh); err == nil ||
		!strings.Contains(err.Error(), "revoked or expired") {
		t.Fatalf("principal mismatch error = %v", err)
	}
	var revoked bool
	if err := pool.QueryRow(ctx,
		`SELECT revoked_at IS NOT NULL
		   FROM oauth_tokens WHERE token_hash=$1`,
		tokenHash(refresh),
	).Scan(&revoked); err != nil {
		t.Fatalf("read mismatched anchor: %v", err)
	}
	if !revoked {
		t.Fatal("mismatched durable anchor remained active")
	}
}
