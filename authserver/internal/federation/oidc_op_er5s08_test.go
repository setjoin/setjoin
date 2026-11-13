package federation

// ER5 er5-s08 occurrence tests:
//   - session-revocation.oidc-userinfo-ignores-revocation: /userinfo must run
//     the same durable revocation check as /introspect (the DB row is the only
//     revocation record; the library's cryptographic verification cannot see
//     it), so a revoked access token stops serving identity claims immediately.
//   - race-condition.oidc-refresh-rotation: the OIDC refresh rotation is atomic
//     under a row lock — concurrent refreshes with one refresh token produce
//     exactly ONE successor, and the loser is refused (concurrent replay
//     detection), instead of both requests minting live successors.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// TestOPStorage_SetUserinfoFromToken_RevokedIsRejected mirrors the
// introspection revocation test: SetUserinfoFromToken on a revoked access
// token must return an error (the zitadel handler then rejects the userinfo
// request) instead of serving claims forever.
func TestOPStorage_SetUserinfoFromToken_RevokedIsRejected(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("setup exec failed: %v\nSQL: %s", err, sql)
		}
	}
	exec(`INSERT INTO domains (id, name, is_local) VALUES (88013, 'optok13.test', TRUE) ON CONFLICT (id) DO NOTHING`)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name)
	      VALUES (88013, 'optok13', 88013, 'optok13@optok13.test', 'OP Tok13') ON CONFLICT (id) DO NOTHING`)
	exec(`INSERT INTO oidc_clients (id, name, secret, redirect_uris, grant_types, scopes, enabled, client_type)
	      VALUES ('optok-client13', 'optok-client13', '', '{https://x/cb}', '{authorization_code}', '{openid}', TRUE, 'public')
	      ON CONFLICT (id) DO NOTHING`)
	exec(`INSERT INTO oidc_tokens (id, client_id, user_id, subject, scopes, expires_at, revoked_at)
	      VALUES ('optok-userinfo-revoked', 'optok-client13', 88013, '88013', '{openid,profile}', now() + interval '5 minutes', now())
	      ON CONFLICT (id) DO UPDATE SET revoked_at = now()`)
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM oidc_tokens WHERE client_id = 'optok-client13'`)
		pool.Exec(ctx, `DELETE FROM oidc_clients WHERE id = 'optok-client13'`)
		pool.Exec(ctx, `DELETE FROM users WHERE id = 88013`)
		pool.Exec(ctx, `DELETE FROM domains WHERE id = 88013`)
	})

	storage := NewOPStorage(pool, nil)
	userinfo := new(oidc.UserInfo)
	if err := storage.SetUserinfoFromToken(ctx, userinfo, "optok-userinfo-revoked", "88013", ""); err == nil {
		t.Fatal("SetUserinfoFromToken(revoked token) = nil error — a revoked OIDC access token must stop serving identity claims at /userinfo (the introspection path already refuses; userinfo had no revocation check at all)")
	}
	if userinfo.Subject != "" && userinfo.Email != "" {
		t.Fatal("revoked token produced identity claims")
	}

	// An ACTIVE token still serves claims (positive leg of the fence).
	exec(`INSERT INTO oidc_tokens (id, client_id, user_id, subject, scopes, expires_at)
	      VALUES ('optok-userinfo-active', 'optok-client13', 88013, '88013', '{openid,profile}', now() + interval '5 minutes')
	      ON CONFLICT (id) DO UPDATE SET revoked_at = NULL, expires_at = now() + interval '5 minutes'`)
	userinfo = new(oidc.UserInfo)
	if err := storage.SetUserinfoFromToken(ctx, userinfo, "optok-userinfo-active", "88013", ""); err != nil {
		t.Fatalf("SetUserinfoFromToken(active token) = %v, want nil", err)
	}
}

// TestOIDCTokenStore_Rotation_ConcurrentReplaySingleWinner proves the atomic
// rotation: N concurrent refreshes presenting the SAME refresh token yield
// exactly one winner; every loser is refused, and the predecessor is revoked —
// no parallel successor chains.
func TestOIDCTokenStore_Rotation_ConcurrentReplaySingleWinner(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("setup exec failed: %v\nSQL: %s", err, sql)
		}
	}
	exec(`INSERT INTO domains (id, name, is_local) VALUES (88014, 'optok14.test', TRUE) ON CONFLICT (id) DO NOTHING`)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name)
	      VALUES (88014, 'optok14', 88014, 'optok14@optok14.test', 'OP Tok14') ON CONFLICT (id) DO NOTHING`)
	exec(`INSERT INTO oidc_clients (id, name, secret, redirect_uris, grant_types, scopes, enabled, client_type)
	      VALUES ('optok-client14', 'optok-client14', '', '{https://x/cb}', '{authorization_code,refresh_token}', '{openid}', TRUE, 'public')
	      ON CONFLICT (id) DO NOTHING`)
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM oidc_tokens WHERE client_id = 'optok-client14'`)
		pool.Exec(ctx, `DELETE FROM oidc_clients WHERE id = 'optok-client14'`)
		pool.Exec(ctx, `DELETE FROM users WHERE id = 88014`)
		pool.Exec(ctx, `DELETE FROM domains WHERE id = 88014`)
	})

	s := newOIDCTokenStore(pool)
	req := &storedAuthRequest{userID: "88014", clientID: "optok-client14", scopes: []string{"openid"}}

	// Fresh grant with a refresh token attached.
	_, refreshToken1, _, err := s.createAccessAndRefreshTokens(ctx, req, "")
	if err != nil {
		t.Fatalf("initial grant: %v", err)
	}

	// 8 concurrent rotations presenting the same refresh token.
	const racers = 8
	var wg sync.WaitGroup
	winners := make(chan string, racers)
	failures := make(chan error, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			accessID, refreshToken2, _, err := s.createAccessAndRefreshTokens(ctx, req, refreshToken1)
			if err != nil {
				failures <- err
				return
			}
			winners <- accessID + "|" + refreshToken2
		}()
	}
	wg.Wait()
	close(winners)
	close(failures)

	wins := 0
	for range winners {
		wins++
	}
	if wins != 1 {
		t.Fatalf("concurrent refreshes with one token produced %d winners, want exactly 1 — concurrent replay must not mint parallel successors", wins)
	}
	if lost := len(failures); lost != racers-1 {
		t.Fatalf("%d racers failed, want %d", lost, racers-1)
	}

	// Reusing the ORIGINAL refresh token after rotation is refused (revoked).
	if _, _, _, err := s.createAccessAndRefreshTokens(ctx, req, refreshToken1); err == nil {
		t.Fatal("rotated-away refresh token minted a successor — predecessor revocation did not commit with the rotation")
	}
}

// TestOIDCTokenStore_Rotation_PredecessorRevokedAtomically pins the sequential
// invariant the transaction guarantees: after one rotation the predecessor's
// row is revoked, and tokenRequestByRefreshToken refuses it.
func TestOIDCTokenStore_Rotation_PredecessorRevokedAtomically(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("setup exec failed: %v\nSQL: %s", err, sql)
		}
	}
	exec(`INSERT INTO domains (id, name, is_local) VALUES (88015, 'optok15.test', TRUE) ON CONFLICT (id) DO NOTHING`)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name)
	      VALUES (88015, 'optok15', 88015, 'optok15@optok15.test', 'OP Tok15') ON CONFLICT (id) DO NOTHING`)
	exec(`INSERT INTO oidc_clients (id, name, secret, redirect_uris, grant_types, scopes, enabled, client_type)
	      VALUES ('optok-client15', 'optok-client15', '', '{https://x/cb}', '{authorization_code,refresh_token}', '{openid}', TRUE, 'public')
	      ON CONFLICT (id) DO NOTHING`)
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM oidc_tokens WHERE client_id = 'optok-client15'`)
		pool.Exec(ctx, `DELETE FROM oidc_clients WHERE id = 'optok-client15'`)
		pool.Exec(ctx, `DELETE FROM users WHERE id = 88015`)
		pool.Exec(ctx, `DELETE FROM domains WHERE id = 88015`)
	})

	s := newOIDCTokenStore(pool)
	req := &storedAuthRequest{userID: "88015", clientID: "optok-client15", scopes: []string{"openid"}}

	_, refreshToken1, _, err := s.createAccessAndRefreshTokens(ctx, req, "")
	if err != nil {
		t.Fatalf("initial grant: %v", err)
	}
	if _, err := s.tokenRequestByRefreshToken(ctx, refreshToken1); err != nil {
		t.Fatalf("fresh refresh token rejected before any rotation: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	_, _, _, _ = s.createAccessAndRefreshTokens(ctx, req, refreshToken1)
	if time.Now().After(deadline) {
		t.Fatal("rotation took unreasonably long")
	}
	if _, err := s.tokenRequestByRefreshToken(ctx, refreshToken1); err == nil {
		t.Fatal("predecessor refresh token still resolves after rotation — revocation was best-effort, not atomic")
	}
}

// TestOIDCTokenStore_Rotation_PropagatesClosedPoolFailures pins the
// error-propagation legs of the atomic rotation: with an unusable pool both the
// fresh grant and the rotation fail loudly — a failed mint or revocation must
// never look like a successful grant (the pre-fix code ignored the revocation
// UPDATE's error entirely).
func TestOIDCTokenStore_Rotation_PropagatesClosedPoolFailures(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()
	s := newOIDCTokenStore(pool)
	req := &storedAuthRequest{userID: "1", clientID: "c", scopes: []string{"openid"}}

	pool.Close()
	if _, _, _, err := s.createAccessAndRefreshTokens(ctx, req, ""); err == nil {
		t.Fatal("fresh grant swallowed a closed-pool failure")
	}
	if _, _, _, err := s.createAccessAndRefreshTokens(ctx, req, "some-refresh-token"); err == nil {
		t.Fatal("rotation swallowed a closed-pool failure")
	}
	if _, _, err := s.createAccessToken(ctx, req); err == nil {
		t.Fatal("CreateAccessToken delegation swallowed a closed-pool failure")
	}
}
