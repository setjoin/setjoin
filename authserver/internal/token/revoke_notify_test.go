package token

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/testsupport"
)

func testPool(t *testing.T) *pgxpool.Pool {
	return testsupport.OpenTestPool(t)
}

// seedUser inserts a throwaway user and returns their ID. Cleaned up on t.Cleanup.
func seedUser(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	ctx := context.Background()
	var domainID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM domains LIMIT 1`).Scan(&domainID); err != nil {
		t.Skipf("no domain in test DB: %v", err)
	}
	const uid int64 = 999997
	_, err := pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name)
		 VALUES ($1, 'dbtest-revoke-notify', $2, 'dbtest-revoke-notify@example.com', 'DB Test Revoke Notify')
		 ON CONFLICT DO NOTHING`,
		uid, domainID,
	)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM ws_subscriptions WHERE user_id = $1`, uid)              //nolint:errcheck
		pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, uid)                      //nolint:errcheck
		pool.Exec(ctx, `DELETE FROM identity_auth_link_elevations WHERE user_id = $1`, uid) //nolint:errcheck
		pool.Exec(ctx, `DELETE FROM session_revocations WHERE user_id = $1`, uid)           //nolint:errcheck
		pool.Exec(ctx, `DELETE FROM oauth_tokens WHERE user_id = $1`, uid)                  //nolint:errcheck
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, uid)                              //nolint:errcheck
	})
	return uid
}

func TestRevokeAndNotifyTxInsertsDenylistRow(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	uid := seedUser(t, pool)

	const sessionID = "dbtest-revoke-notify-session"
	if _, err := pool.Exec(ctx,
		`INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method)
		 VALUES ($1,$2,decode(repeat('ab',32),'hex'),now()+interval '1 hour','oidc')`,
		sessionID, uid,
	); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO ws_subscriptions(connection_id,session_id,user_id)
		 VALUES ('dbtest-revoke-notify-ws',$1,$2)`,
		sessionID, uid,
	); err != nil {
		t.Fatalf("seed websocket subscription: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO oauth_tokens(user_id,token_hash,token_type,expires_at)
		 VALUES ($1,decode(repeat('cd',32),'hex'),'refresh',now()+interval '1 hour')`,
		uid,
	); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT identity_auth_link_elevation_begin(
		    $1,gen_random_uuid(),$2,decode(repeat('ab',32),'hex'),
		    'oidc','test-provider',now()+interval '5 minutes'
		 )`,
		uid, sessionID,
	).Scan(new([]byte)); err != nil {
		t.Fatalf("seed link elevation: %v", err)
	}

	id, err := RevokeAndNotifyTx(ctx, pool, uid, 0, "admin_revoke_all")
	if err != nil {
		t.Fatalf("RevokeAndNotifyTx: %v", err)
	}
	var scope string
	if err := pool.QueryRow(ctx,
		`SELECT scope FROM session_revocations WHERE id=$1`, id).Scan(&scope); err != nil {
		t.Fatalf("denylist row not found: %v", err)
	}
	if scope != "all" {
		t.Fatalf("want scope=all, got %q", scope)
	}

	var activeTokens, sessions, subscriptions, elevations int
	if err := pool.QueryRow(ctx,
		`SELECT
		   count(*) FILTER (WHERE revoked_at IS NULL),
		   (SELECT count(*) FROM sessions WHERE user_id=$1),
		   (SELECT count(*) FROM ws_subscriptions WHERE user_id=$1),
		   (SELECT count(*) FROM identity_auth_link_elevations WHERE user_id=$1)
		 FROM oauth_tokens WHERE user_id=$1`,
		uid,
	).Scan(&activeTokens, &sessions, &subscriptions, &elevations); err != nil {
		t.Fatalf("read post-revocation state: %v", err)
	}
	if activeTokens != 0 || sessions != 0 || subscriptions != 0 || elevations != 0 {
		t.Fatalf(
			"revocation left active state: tokens=%d sessions=%d subscriptions=%d elevations=%d",
			activeTokens, sessions, subscriptions, elevations,
		)
	}
}

func TestRevokeAllForUserTxRevokesCompleteSessionStateAtomically(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	uid := seedUser(t, pool)

	const sessionID = "dbtest-revoke-existing-tx-session"
	if _, err := pool.Exec(ctx,
		`INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method)
		 VALUES ($1,$2,decode(repeat('de',32),'hex'),now()+interval '1 hour','password')`,
		sessionID, uid,
	); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO ws_subscriptions(connection_id,session_id,user_id)
		 VALUES ('dbtest-revoke-existing-tx-ws',$1,$2)`,
		sessionID, uid,
	); err != nil {
		t.Fatalf("seed websocket subscription: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO oauth_tokens(user_id,token_hash,token_type,expires_at)
		 VALUES ($1,decode(repeat('ef',32),'hex'),'refresh',now()+interval '1 hour')`,
		uid,
	); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT identity_auth_link_elevation_begin(
		    $1,gen_random_uuid(),$2,decode(repeat('de',32),'hex'),
		    'oidc','test-provider',now()+interval '5 minutes'
		 )`,
		uid, sessionID,
	).Scan(new([]byte)); err != nil {
		t.Fatalf("seed link elevation: %v", err)
	}

	svc := NewTokenService(nil, pool, nil)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin rollback proof transaction: %v", err)
	}
	if err := svc.RevokeAllForUserTx(ctx, tx, uid); err != nil {
		t.Fatalf("RevokeAllForUserTx: %v", err)
	}
	assertRevocationState(t, ctx, tx, uid, 0, 0, 0, 0, 1)
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback proof transaction: %v", err)
	}
	assertRevocationState(t, ctx, pool, uid, 1, 1, 1, 1, 0)

	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin commit proof transaction: %v", err)
	}
	if err := svc.RevokeAllForUserTx(ctx, tx, uid); err != nil {
		t.Fatalf("RevokeAllForUserTx after rollback: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit proof transaction: %v", err)
	}
	assertRevocationState(t, ctx, pool, uid, 0, 0, 0, 0, 1)
}

func TestRevocationPersonFenceCannotMissConcurrentTokenMint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool := testPool(t)
	uid := seedUser(t, pool)

	mintTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin mint tx: %v", err)
	}
	defer mintTx.Rollback(ctx) //nolint:errcheck
	if _, err := mintTx.Exec(ctx,
		`SELECT identity_auth_local_mint_fence($1)`, uid,
	); err != nil {
		t.Fatalf("acquire mint fence: %v", err)
	}

	revokeDone := make(chan error, 1)
	go func() {
		_, revokeErr := RevokeAndNotifyTx(
			ctx, pool, uid, 0, "concurrent_credential_change",
		)
		revokeDone <- revokeErr
	}()

	// Let revocation reach the per-person fence. Before the ordering fix its
	// oauth_tokens UPDATE ran before blocking here and therefore missed the row
	// this still-authorized mint commits below.
	time.Sleep(150 * time.Millisecond)
	if _, err := mintTx.Exec(ctx,
		`INSERT INTO oauth_tokens(user_id,token_hash,token_type,expires_at)
		 VALUES ($1,decode(repeat('9a',32),'hex'),'refresh',now()+interval '1 hour')`,
		uid,
	); err != nil {
		t.Fatalf("insert concurrent token anchor: %v", err)
	}
	if err := mintTx.Commit(ctx); err != nil {
		t.Fatalf("commit concurrent token anchor: %v", err)
	}

	select {
	case err := <-revokeDone:
		if err != nil {
			t.Fatalf("concurrent revocation: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("concurrent revocation did not finish")
	}

	var active int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM oauth_tokens
		  WHERE user_id=$1 AND revoked_at IS NULL`,
		uid,
	).Scan(&active); err != nil {
		t.Fatalf("read concurrent token state: %v", err)
	}
	if active != 0 {
		t.Fatalf("revocation missed %d token(s) minted before its person fence completed", active)
	}
}

type queryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func assertRevocationState(
	t *testing.T,
	ctx context.Context,
	q queryRower,
	uid int64,
	wantActiveTokens, wantSessions, wantSubscriptions, wantElevations, wantRevocations int,
) {
	t.Helper()
	var activeTokens, sessions, subscriptions, elevations, revocations int
	if err := q.QueryRow(ctx,
		`SELECT
		   (SELECT count(*) FROM oauth_tokens WHERE user_id=$1 AND revoked_at IS NULL),
		   (SELECT count(*) FROM sessions WHERE user_id=$1),
		   (SELECT count(*) FROM ws_subscriptions WHERE user_id=$1),
		   (SELECT count(*) FROM identity_auth_link_elevations WHERE user_id=$1),
		   (SELECT count(*) FROM session_revocations
		     WHERE user_id=$1 AND reason='credential_change')`,
		uid,
	).Scan(&activeTokens, &sessions, &subscriptions, &elevations, &revocations); err != nil {
		t.Fatalf("read revocation state: %v", err)
	}
	if activeTokens != wantActiveTokens ||
		sessions != wantSessions ||
		subscriptions != wantSubscriptions ||
		elevations != wantElevations ||
		revocations != wantRevocations {
		t.Fatalf(
			"revocation state = tokens:%d sessions:%d subscriptions:%d elevations:%d revocations:%d; want %d/%d/%d/%d/%d",
			activeTokens, sessions, subscriptions, elevations, revocations,
			wantActiveTokens, wantSessions, wantSubscriptions, wantElevations, wantRevocations,
		)
	}
}
