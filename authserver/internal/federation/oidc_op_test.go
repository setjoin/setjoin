package federation

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"setjoin.com/shared/jwtutil"
)

// testDB returns a pgxpool connected to TEST_DB_DSN, or skips the test.
func testDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to test db: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

func TestOPStorage_GetClientByClientID_PublicClient(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()

	storage := NewOPStorage(pool, nil)
	// We use a nil keyMgr because GetClientByClientID doesn't use it.

	// Insert a public client into oidc_clients
	_, err := pool.Exec(ctx,
		`INSERT INTO oidc_clients (id, name, secret, redirect_uris, grant_types, scopes, enabled, client_type)
		 VALUES ('test-public-spa', 'Test Public SPA', '', '{https://spa.example.com/cb}',
		         '{authorization_code}', '{openid,profile}', TRUE, 'public')
		 ON CONFLICT (id) DO UPDATE SET client_type = 'public'`)
	if err != nil {
		t.Fatalf("insert test client: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM oidc_clients WHERE id = 'test-public-spa'`)
	})

	client, err := storage.GetClientByClientID(ctx, "test-public-spa")
	if err != nil {
		t.Fatalf("GetClientByClientID: %v", err)
	}

	if got := client.AuthMethod(); got != oidc.AuthMethodNone {
		t.Errorf("public client AuthMethod() = %q, want %q", got, oidc.AuthMethodNone)
	}
	if got := client.ApplicationType(); got != op.ApplicationTypeNative {
		t.Errorf("public client ApplicationType() = %v, want %v", got, op.ApplicationTypeNative)
	}
	if got := client.GetID(); got != "test-public-spa" {
		t.Errorf("GetID() = %q, want %q", got, "test-public-spa")
	}
}

func TestOPStorage_GetClientByClientID_ConfidentialClient(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()

	storage := NewOPStorage(pool, nil)

	// Insert a confidential client with bcrypt-hashed secret
	_, err := pool.Exec(ctx,
		`INSERT INTO oidc_clients (id, name, secret, redirect_uris, grant_types, scopes, enabled, client_type)
		 VALUES ('test-confidential-api', 'Test Confidential API',
		         '$2a$10$placeholderhashedsecret1234567890abcdef',
		         '{https://api.example.com/cb}',
		         '{authorization_code,refresh_token}', '{openid,profile,email}', TRUE, 'confidential')
		 ON CONFLICT (id) DO UPDATE SET client_type = 'confidential'`)
	if err != nil {
		t.Fatalf("insert test client: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM oidc_clients WHERE id = 'test-confidential-api'`)
	})

	client, err := storage.GetClientByClientID(ctx, "test-confidential-api")
	if err != nil {
		t.Fatalf("GetClientByClientID: %v", err)
	}

	if got := client.AuthMethod(); got != oidc.AuthMethodBasic {
		t.Errorf("confidential client AuthMethod() = %q, want %q", got, oidc.AuthMethodBasic)
	}
	if got := client.ApplicationType(); got != op.ApplicationTypeWeb {
		t.Errorf("confidential client ApplicationType() = %v, want %v", got, op.ApplicationTypeWeb)
	}
	if got := client.GetID(); got != "test-confidential-api" {
		t.Errorf("GetID() = %q, want %q", got, "test-confidential-api")
	}
}

func TestOPStorage_GetClientByClientID_MissingClientTypeDefaultsConfidential(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()

	storage := NewOPStorage(pool, nil)

	// Insert a client without explicit client_type (simulates pre-migration row)
	// The COALESCE in the query should default to 'confidential'.
	_, err := pool.Exec(ctx,
		`INSERT INTO oidc_clients (id, name, secret, redirect_uris, grant_types, scopes, enabled)
		 VALUES ('test-legacy-no-type', 'Test Legacy', '$2a$10$placeholderhash',
		         '{https://legacy.example.com/cb}',
		         '{authorization_code}', '{openid}', TRUE)
		 ON CONFLICT (id) DO UPDATE SET client_type = NULL`)
	if err != nil {
		t.Fatalf("insert legacy client: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM oidc_clients WHERE id = 'test-legacy-no-type'`)
	})

	client, err := storage.GetClientByClientID(ctx, "test-legacy-no-type")
	if err != nil {
		t.Fatalf("GetClientByClientID: %v", err)
	}

	// Legacy (missing client_type) should behave as confidential.
	if got := client.AuthMethod(); got != oidc.AuthMethodBasic {
		t.Errorf("legacy client AuthMethod() = %q, want %q (confidential fallback)", got, oidc.AuthMethodBasic)
	}
	if got := client.ApplicationType(); got != op.ApplicationTypeWeb {
		t.Errorf("legacy client ApplicationType() = %v, want %v (confidential fallback)", got, op.ApplicationTypeWeb)
	}
}

func TestOPStorage_GetClientByClientID_UnknownClientID(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()

	storage := NewOPStorage(pool, nil)

	_, err := storage.GetClientByClientID(ctx, "nonexistent-client-id")
	if err == nil {
		t.Error("expected error for unknown client ID, got nil")
	}
}

// TestOIDCTokenStore_RevokeIsIdempotentAndClientScoped pins the RFC 7009 §2.2
// contract on the unified OIDC-token revoke seam (Wave 3): revocation is
// idempotent (unknown / already-revoked / another client's token → success, not
// an error), and a client may only revoke its OWN tokens. Regression guard for
// the 500-on-no-match bug the client_id scoping introduced.
func TestOIDCTokenStore_RevokeIsIdempotentAndClientScoped(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("setup exec failed: %v\nSQL: %s", err, sql)
		}
	}
	revoked := func() bool {
		t.Helper()
		var r bool
		if err := pool.QueryRow(ctx,
			`SELECT revoked_at IS NOT NULL FROM oidc_tokens WHERE id = 'optok-tok'`).Scan(&r); err != nil {
			t.Fatalf("query revoked state: %v", err)
		}
		return r
	}

	// FK chain: domain → user → two clients → an active token owned by clientA.
	// Divergent high ids (ADR-003 discipline) so nothing collides with seed data.
	exec(`INSERT INTO domains (id, name, is_local) VALUES (88001, 'optok.test', TRUE) ON CONFLICT (id) DO NOTHING`)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name)
	      VALUES (88001, 'optok', 88001, 'optok@optok.test', 'OP Tok') ON CONFLICT (id) DO NOTHING`)
	for _, c := range []string{"optok-clientA", "optok-clientB"} {
		exec(`INSERT INTO oidc_clients (id, name, secret, redirect_uris, grant_types, scopes, enabled, client_type)
		      VALUES ($1, $1, '', '{https://x/cb}', '{authorization_code}', '{openid}', TRUE, 'public')
		      ON CONFLICT (id) DO NOTHING`, c)
	}
	exec(`INSERT INTO oidc_tokens (id, client_id, user_id, subject, refresh_token_hash, scopes, expires_at)
	      VALUES ('optok-tok', 'optok-clientA', 88001, '88001', $1, '{openid}', now() + interval '1 hour')
	      ON CONFLICT (id) DO UPDATE SET revoked_at = NULL`, sha256Hex("tokA"))
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM oidc_tokens WHERE id = 'optok-tok'`)
		pool.Exec(ctx, `DELETE FROM oidc_clients WHERE id IN ('optok-clientA','optok-clientB')`)
		pool.Exec(ctx, `DELETE FROM users WHERE id = 88001`)
		pool.Exec(ctx, `DELETE FROM domains WHERE id = 88001`)
	})

	s := newOIDCTokenStore(pool)

	// Unknown token → idempotent success (NOT a 500/oracle).
	if err := s.revoke(ctx, "no-such-token", "optok-clientA"); err != nil {
		t.Fatalf("revoke(unknown) = %v, want nil (RFC 7009 idempotent)", err)
	}
	// Cross-client: clientB cannot revoke clientA's token; still success, row stays active.
	if err := s.revoke(ctx, "tokA", "optok-clientB"); err != nil {
		t.Fatalf("revoke(tokA, clientB) = %v, want nil", err)
	}
	if revoked() {
		t.Fatal("cross-client revoke wrongly revoked clientA's token")
	}
	// Owner revoke: succeeds and the row is now revoked.
	if err := s.revoke(ctx, "tokA", "optok-clientA"); err != nil {
		t.Fatalf("revoke(tokA, clientA) = %v, want nil", err)
	}
	if !revoked() {
		t.Fatal("owner revoke did not revoke the token")
	}
	// Already-revoked → still idempotent success.
	if err := s.revoke(ctx, "tokA", "optok-clientA"); err != nil {
		t.Fatalf("revoke(already-revoked) = %v, want nil (idempotent)", err)
	}
}

// TestOIDCTokenStore_RefreshToken_ExpiredRejected pins codebase-review 2026-07-11
// A5: a refresh token whose OWN expiry (refresh_expires_at) has passed must be
// rejected by both refresh-grant lookup paths, even though revoked_at is NULL
// (no one explicitly revoked it — it just outlived its lifetime). Before the
// fix neither query filtered on refresh_expires_at at all, so an expired
// refresh token worked forever.
func TestOIDCTokenStore_RefreshToken_ExpiredRejected(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("setup exec failed: %v\nSQL: %s", err, sql)
		}
	}

	exec(`INSERT INTO domains (id, name, is_local) VALUES (88002, 'optok2.test', TRUE) ON CONFLICT (id) DO NOTHING`)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name)
	      VALUES (88002, 'optok2', 88002, 'optok2@optok2.test', 'OP Tok2') ON CONFLICT (id) DO NOTHING`)
	exec(`INSERT INTO oidc_clients (id, name, secret, redirect_uris, grant_types, scopes, enabled, client_type)
	      VALUES ('optok-client2', 'optok-client2', '', '{https://x/cb}', '{authorization_code,refresh_token}', '{openid}', TRUE, 'public')
	      ON CONFLICT (id) DO NOTHING`)
	// An access token row long past its own 5-min expiry, carrying a refresh
	// token whose OWN expiry has ALSO passed, never revoked.
	exec(`INSERT INTO oidc_tokens (id, client_id, user_id, subject, refresh_token_hash, scopes, expires_at, refresh_expires_at)
	      VALUES ('optok-tok2', 'optok-client2', 88002, '88002', $1, '{openid}', now() - interval '1 hour', now() - interval '1 minute')
	      ON CONFLICT (id) DO UPDATE SET refresh_expires_at = now() - interval '1 minute', revoked_at = NULL`,
		sha256Hex("expired-refresh-tok2"))
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM oidc_tokens WHERE id = 'optok-tok2'`)
		pool.Exec(ctx, `DELETE FROM oidc_clients WHERE id = 'optok-client2'`)
		pool.Exec(ctx, `DELETE FROM users WHERE id = 88002`)
		pool.Exec(ctx, `DELETE FROM domains WHERE id = 88002`)
	})

	s := newOIDCTokenStore(pool)

	if _, err := s.tokenRequestByRefreshToken(ctx, "expired-refresh-tok2"); err != op.ErrInvalidRefreshToken {
		t.Fatalf("tokenRequestByRefreshToken(expired) = %v, want op.ErrInvalidRefreshToken (not-yet-fixed code accepts it forever)", err)
	}
	if _, _, err := s.refreshTokenInfo(ctx, "optok-client2", "expired-refresh-tok2"); err != op.ErrInvalidRefreshToken {
		t.Fatalf("refreshTokenInfo(expired) = %v, want op.ErrInvalidRefreshToken", err)
	}
}

// TestOIDCTokenStore_CreateAccessAndRefreshTokens_SetsOwnRefreshExpiry asserts
// the mint path stamps refresh_expires_at independently of the access token's
// own (much shorter) expires_at — the fix for A5's "never expire" half.
func TestOIDCTokenStore_CreateAccessAndRefreshTokens_SetsOwnRefreshExpiry(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("setup exec failed: %v\nSQL: %s", err, sql)
		}
	}
	exec(`INSERT INTO domains (id, name, is_local) VALUES (88003, 'optok3.test', TRUE) ON CONFLICT (id) DO NOTHING`)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name)
	      VALUES (88003, 'optok3', 88003, 'optok3@optok3.test', 'OP Tok3') ON CONFLICT (id) DO NOTHING`)
	exec(`INSERT INTO oidc_clients (id, name, secret, redirect_uris, grant_types, scopes, enabled, client_type)
	      VALUES ('optok-client3', 'optok-client3', '', '{https://x/cb}', '{authorization_code,refresh_token}', '{openid}', TRUE, 'public')
	      ON CONFLICT (id) DO NOTHING`)
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM oidc_tokens WHERE client_id = 'optok-client3'`)
		pool.Exec(ctx, `DELETE FROM oidc_clients WHERE id = 'optok-client3'`)
		pool.Exec(ctx, `DELETE FROM users WHERE id = 88003`)
		pool.Exec(ctx, `DELETE FROM domains WHERE id = 88003`)
	})

	s := newOIDCTokenStore(pool)
	req := &storedAuthRequest{userID: "88003", clientID: "optok-client3", scopes: []string{"openid"}}

	accessID, _, _, err := s.createAccessAndRefreshTokens(ctx, req, "")
	if err != nil {
		t.Fatalf("createAccessAndRefreshTokens: %v", err)
	}

	var accessExp, refreshExp time.Time
	if err := pool.QueryRow(ctx,
		`SELECT expires_at, refresh_expires_at FROM oidc_tokens WHERE id = $1`, accessID,
	).Scan(&accessExp, &refreshExp); err != nil {
		t.Fatalf("query minted row: %v", err)
	}
	if !refreshExp.After(accessExp) {
		t.Fatalf("refresh_expires_at (%v) not after access expires_at (%v); refresh token must outlive the access token", refreshExp, accessExp)
	}
	if refreshExp.Before(time.Now().Add(24 * time.Hour)) {
		t.Fatalf("refresh_expires_at = %v, want at least 24h out (a bare 5-min-TTL refresh window is the bug)", refreshExp)
	}
}

// TestOPStorage_SetIntrospectionFromToken_RevokedIsInactive pins the other
// half of A5: RFC 7662 introspection must not report Active=true for a
// revoked token. The zitadel library already rejects an EXPIRED JWT before
// ever calling SetIntrospectionFromToken (VerifyAccessToken/CheckExpiration),
// so the gap this closes is specifically the revoked_at check.
func TestOPStorage_SetIntrospectionFromToken_RevokedIsInactive(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("setup exec failed: %v\nSQL: %s", err, sql)
		}
	}
	exec(`INSERT INTO domains (id, name, is_local) VALUES (88004, 'optok4.test', TRUE) ON CONFLICT (id) DO NOTHING`)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name)
	      VALUES (88004, 'optok4', 88004, 'optok4@optok4.test', 'OP Tok4') ON CONFLICT (id) DO NOTHING`)
	exec(`INSERT INTO oidc_clients (id, name, secret, redirect_uris, grant_types, scopes, enabled, client_type)
	      VALUES ('optok-client4', 'optok-client4', '', '{https://x/cb}', '{authorization_code}', '{openid}', TRUE, 'public')
	      ON CONFLICT (id) DO NOTHING`)
	exec(`INSERT INTO oidc_tokens (id, client_id, user_id, subject, scopes, expires_at, revoked_at)
	      VALUES ('optok-introspect-revoked', 'optok-client4', 88004, '88004', '{openid}', now() + interval '5 minutes', now())
	      ON CONFLICT (id) DO UPDATE SET revoked_at = now()`)
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM oidc_tokens WHERE client_id = 'optok-client4'`)
		pool.Exec(ctx, `DELETE FROM oidc_clients WHERE id = 'optok-client4'`)
		pool.Exec(ctx, `DELETE FROM users WHERE id = 88004`)
		pool.Exec(ctx, `DELETE FROM domains WHERE id = 88004`)
	})

	storage := NewOPStorage(pool, nil)
	resp := new(oidc.IntrospectionResponse)
	err := storage.SetIntrospectionFromToken(ctx, resp, "optok-introspect-revoked", "88004", "optok-client4")
	if err == nil {
		t.Fatal("SetIntrospectionFromToken(revoked token) = nil error, want an error so the library reports {\"active\":false} (RFC 7662 revocation must be honored)")
	}
	if resp.Active {
		t.Fatal("SetIntrospectionFromToken(revoked token) set Active=true on a revoked token")
	}
}

func TestOPStorage_AuthorizationRequestCompletionAndConsume(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("setup exec failed: %v\nSQL: %s", err, sql)
		}
	}
	exec(`INSERT INTO domains (id, name, is_local)
	      VALUES (88005, 'opauth5.test', TRUE) ON CONFLICT (id) DO NOTHING`)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name)
	      VALUES (88005, 'opauth5', 88005, 'opauth5@opauth5.test', 'OP Auth5')
	      ON CONFLICT (id) DO NOTHING`)
	exec(`INSERT INTO oidc_clients
	        (id, name, secret, redirect_uris, grant_types, scopes, enabled, client_type)
	      VALUES
	        ('opauth-client5', 'opauth-client5', '', '{https://rp.test/cb}',
	         '{authorization_code,refresh_token}', '{openid,profile,email}', TRUE, 'public')
	      ON CONFLICT (id) DO NOTHING`)
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM oidc_tokens WHERE client_id = 'opauth-client5'`)
		pool.Exec(ctx, `DELETE FROM oidc_auth_requests WHERE client_id = 'opauth-client5'`)
		pool.Exec(ctx, `DELETE FROM oidc_clients WHERE id = 'opauth-client5'`)
		pool.Exec(ctx, `DELETE FROM users WHERE id = 88005`)
		pool.Exec(ctx, `DELETE FROM domains WHERE id = 88005`)
	})

	keyDir := t.TempDir()
	keyMgr, err := LoadOrGenerateKey(keyDir+"/oidc-private.pem", keyDir+"/oidc-public.pem")
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	storage := NewOPStorage(pool, keyMgr)
	if err := storage.CompleteAuthRequest(ctx, "", 88005, time.Time{}, "", nil); err == nil {
		t.Fatal("empty authorization request id was accepted")
	}
	created, err := storage.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID:     "opauth-client5",
		RedirectURI:  "https://rp.test/cb",
		ResponseType: oidc.ResponseTypeCode,
		Scopes:       []string{"openid", "profile", "email"},
		State:        "state-5",
	}, "")
	if err != nil {
		t.Fatalf("CreateAuthRequest: %v", err)
	}
	if created.Done() {
		t.Fatal("new authorization request is already done")
	}
	defaulted, err := storage.CreateAuthRequest(ctx, &oidc.AuthRequest{
		ClientID: "opauth-client5", RedirectURI: "https://rp.test/cb",
		ResponseType: oidc.ResponseTypeCode, Scopes: []string{"openid"},
		State: "state-defaulted",
	}, "")
	if err != nil {
		t.Fatalf("CreateAuthRequest(defaulted): %v", err)
	}
	if err := storage.CompleteAuthRequest(ctx, defaulted.GetID(), 88005, time.Time{}, "", nil); err != nil {
		t.Fatalf("CompleteAuthRequest(defaulted): %v", err)
	}
	var defaultedAuthTime time.Time
	var defaultedACR string
	if err := pool.QueryRow(ctx,
		`SELECT auth_time,acr FROM oidc_auth_requests WHERE id=$1`, defaulted.GetID(),
	).Scan(&defaultedAuthTime, &defaultedACR); err != nil {
		t.Fatal(err)
	}
	if defaultedAuthTime.IsZero() || defaultedACR != jwtutil.ACRAAL1 {
		t.Fatalf("default auth context = %v/%q", defaultedAuthTime, defaultedACR)
	}

	authAt := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	if err := storage.CompleteAuthRequest(
		ctx, created.GetID(), 88005, authAt, "aal2", []string{"pwd", "otp", "mfa"},
	); err != nil {
		t.Fatalf("CompleteAuthRequest: %v", err)
	}
	if err := storage.CompleteAuthRequest(
		ctx, created.GetID(), 88004, authAt, "aal1", []string{"pwd"},
	); err == nil {
		t.Fatal("different user took over completed authorization request")
	}
	if err := storage.CompleteAuthRequest(
		ctx, created.GetID(), 88005, authAt.Add(time.Minute), "aal1", []string{"pwd"},
	); err == nil {
		t.Fatal("same user replay overwrote completed authorization request")
	}

	completed, err := storage.AuthRequestByID(ctx, created.GetID())
	if err != nil {
		t.Fatalf("AuthRequestByID: %v", err)
	}
	if !completed.Done() || completed.GetSubject() != "88005" {
		t.Fatalf("completed request = done:%v subject:%q", completed.Done(), completed.GetSubject())
	}
	if completed.GetACR() != "aal2" || len(completed.GetAMR()) != 3 {
		t.Fatalf("completed auth context = %q %v", completed.GetACR(), completed.GetAMR())
	}

	userinfo := new(oidc.UserInfo)
	if err := storage.SetUserinfoFromScopes(
		ctx, userinfo, "88005", "opauth-client5", []string{"openid", "email", "profile"},
	); err != nil {
		t.Fatalf("SetUserinfoFromScopes: %v", err)
	}
	if userinfo.Subject != "88005" ||
		userinfo.Email != "opauth5@opauth5.test" ||
		!bool(userinfo.EmailVerified) ||
		userinfo.Name != "OP Auth5" {
		t.Fatalf("OIDC subject claims = subject:%q email:%q verified:%v name:%q",
			userinfo.Subject, userinfo.Email, userinfo.EmailVerified, userinfo.Name)
	}
	if err := storage.SetUserinfoFromScopes(
		ctx, new(oidc.UserInfo), "not-a-user-id", "opauth-client5", []string{"email"},
	); err == nil {
		t.Fatal("userinfo scope expansion accepted an invalid subject")
	}
	if err := storage.SetUserinfoFromScopes(
		ctx, new(oidc.UserInfo), "999999999", "opauth-client5", []string{"profile"},
	); err == nil {
		t.Fatal("userinfo scope expansion accepted a missing subject")
	}
	exec(`INSERT INTO oidc_tokens
	        (id,client_id,user_id,subject,scopes,expires_at)
	      VALUES ('opauth-userinfo-token5','opauth-client5',88005,'88005',
	              '{email,profile}',now()+interval '5 minutes')`)
	if err := storage.SetUserinfoFromToken(
		ctx, new(oidc.UserInfo), "opauth-userinfo-token5", "not-a-user-id", "",
	); err == nil {
		t.Fatal("token userinfo expansion accepted an invalid subject")
	}

	client, err := storage.GetClientByClientID(ctx, "opauth-client5")
	if err != nil {
		t.Fatalf("GetClientByClientID: %v", err)
	}
	idToken, err := op.CreateIDToken(
		ctx,
		"https://opauth5.test",
		completed,
		5*time.Minute,
		"non-empty-access-token",
		"",
		storage,
		client,
	)
	if err != nil {
		t.Fatalf("CreateIDToken: %v", err)
	}
	decrypted, err := oidc.DecryptToken(idToken)
	if err != nil {
		t.Fatalf("DecryptToken: %v", err)
	}
	var tokenClaims *oidc.IDTokenClaims
	if _, err := oidc.ParseToken(decrypted, &tokenClaims); err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if tokenClaims.Email != "opauth5@opauth5.test" || !bool(tokenClaims.EmailVerified) {
		t.Fatalf("ID token email claims = email:%q verified:%v",
			tokenClaims.Email, tokenClaims.EmailVerified)
	}

	const authCode = "library-generated-authorization-code-5"
	if err := storage.SaveAuthCode(ctx, created.GetID(), authCode); err != nil {
		t.Fatalf("SaveAuthCode: %v", err)
	}
	if err := storage.SaveAuthCode(ctx, created.GetID(), "replacement-code"); err == nil {
		t.Fatal("authorization request accepted a replacement code")
	}
	if _, err := storage.AuthRequestByCode(ctx, created.GetID()); err == nil {
		t.Fatal("request id was accepted as the authorization code")
	}

	var storedDigest []byte
	if err := pool.QueryRow(ctx,
		`SELECT code_hash FROM oidc_auth_requests WHERE id = $1`, created.GetID(),
	).Scan(&storedDigest); err != nil {
		t.Fatalf("read stored code digest: %v", err)
	}
	wantDigest := authorizationCodeDigest(authCode)
	if string(storedDigest) != string(wantDigest) {
		t.Fatal("stored authorization code digest does not match the generated code")
	}
	if string(storedDigest) == authCode {
		t.Fatal("authorization code was stored recoverably")
	}

	if _, err := storage.AuthRequestByCode(ctx, authCode); err != nil {
		t.Fatalf("AuthRequestByCode first consume: %v", err)
	}
	if _, err := storage.AuthRequestByCode(ctx, authCode); err == nil {
		t.Fatal("authorization request code was consumable twice")
	}
}

func TestStoredClientScopeRestrictionsAreCallable(t *testing.T) {
	client := &storedClient{id: "scope-callback-client"}
	scopes := []string{"openid", "profile"}
	callbacks := map[string]func([]string) []string{
		"id_token":     client.RestrictAdditionalIdTokenScopes(),
		"access_token": client.RestrictAdditionalAccessTokenScopes(),
	}
	for name, callback := range callbacks {
		if callback == nil {
			t.Fatalf("%s scope restriction callback is nil", name)
		}
		got := callback(scopes)
		if len(got) != len(scopes) || got[0] != scopes[0] || got[1] != scopes[1] {
			t.Fatalf("%s scope restriction changed registered scopes: got %v, want %v", name, got, scopes)
		}
	}

	dir := t.TempDir()
	keyMgr, err := LoadOrGenerateKey(dir+"/oidc-private.pem", dir+"/oidc-public.pem")
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	storage := NewOPStorage(nil, keyMgr)
	request := (&storedAuthRequest{
		clientID: "scope-callback-client",
		userID:   "88005",
		scopes:   scopes,
	}).withAuthContext("aal2", []string{"pwd", "otp", "mfa"})
	signed, err := op.CreateJWT(
		context.Background(),
		"https://op.example.test",
		request,
		time.Now().Add(5*time.Minute),
		"access-token-id",
		client,
		storage,
	)
	if err != nil {
		t.Fatalf("CreateJWT: %v", err)
	}
	if signed == "" {
		t.Fatal("CreateJWT returned an empty token")
	}
}

func TestOPStorageRejectsInvalidBindingsAndPropagatesClosedPoolFailures(t *testing.T) {
	pool := testDB(t)
	storage := NewOPStorage(pool, nil)
	ctx := context.Background()

	if _, err := storage.AuthRequestByCode(ctx, ""); err == nil {
		t.Fatal("empty authorization code was accepted")
	}
	if err := storage.SaveAuthCode(ctx, "", "code"); err == nil {
		t.Fatal("empty authorization request id was accepted")
	}

	pool.Close()
	if err := storage.CompleteAuthRequest(ctx, "request", 1, time.Now(), "aal1", []string{"pwd"}); err == nil {
		t.Fatal("completion swallowed a closed-pool failure")
	}
	if err := storage.SaveAuthCode(ctx, "request", "code"); err == nil {
		t.Fatal("authorization-code binding swallowed a closed-pool failure")
	}
}

func TestApplyUserinfoClaimsHonorsRequestedScopes(t *testing.T) {
	userinfo := new(oidc.UserInfo)
	applyUserinfoClaims(userinfo, true, false, "user@example.test", "Ignored Name")
	if userinfo.Email != "user@example.test" || !bool(userinfo.EmailVerified) || userinfo.Name != "" {
		t.Fatalf("email-only claims = %+v", userinfo)
	}
	applyUserinfoClaims(userinfo, false, true, "ignored@example.test", "Display Name")
	if userinfo.Email != "user@example.test" || userinfo.Name != "Display Name" {
		t.Fatalf("profile claims = %+v", userinfo)
	}
}

func TestSetUserinfoFromScopesLoadsRequestedClaims(t *testing.T) {
	pool := testDB(t)
	ctx := context.Background()
	username := fmt.Sprintf("opclaims%d", time.Now().UnixNano())
	clientID := username + "-client"
	tokenID := username + "-token"
	var mailboxID, userID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account($1)`, username).Scan(&mailboxID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, mailboxID).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM oidc_tokens WHERE id=$1`, tokenID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oidc_clients WHERE id=$1`, clientID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})
	if _, err := pool.Exec(ctx, `
		INSERT INTO oidc_clients(
			id,name,secret,redirect_uris,grant_types,scopes,enabled,client_type
		) VALUES($1,$1,'','{https://rp.example.test/callback}',
			'{authorization_code}','{openid,email,profile}',TRUE,'public')`, clientID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO oidc_tokens(id,client_id,user_id,subject,scopes,expires_at)
		VALUES($1,$2,$3,$4,'{email,profile}',now()+interval '5 minutes')`,
		tokenID, clientID, userID, fmt.Sprint(userID)); err != nil {
		t.Fatal(err)
	}

	userinfo := new(oidc.UserInfo)
	if err := NewOPStorage(pool, nil).SetUserinfoFromScopes(
		ctx, userinfo, fmt.Sprint(userID), "unused-client", []string{"openid", "email", "profile"},
	); err != nil {
		t.Fatal(err)
	}
	if userinfo.Subject != fmt.Sprint(userID) || userinfo.Email == "" || userinfo.Name == "" {
		t.Fatalf("userinfo = %+v", userinfo)
	}
	fromToken := new(oidc.UserInfo)
	if err := NewOPStorage(pool, nil).SetUserinfoFromToken(
		ctx, fromToken, tokenID, fmt.Sprint(userID), "",
	); err != nil {
		t.Fatal(err)
	}
	if fromToken.Subject != fmt.Sprint(userID) || fromToken.Email == "" || fromToken.Name == "" {
		t.Fatalf("token userinfo = %+v", fromToken)
	}
}

// TestStoredAuthRequest_GetCodeChallenge_NilWhenAbsent pins the setjoin half of
// the "PKCE required for public clients" contract. The zitadel op library only
// rejects a public-client (AuthMethodNone) token exchange with "PKCE required"
// when GetCodeChallenge() returns nil (op/token_code.go). That nil is produced
// here, not by the library: an auth request with no stored challenge MUST report
// nil, never a zero-value *oidc.CodeChallenge (which the library would treat as a
// present challenge and let the exchange through without PKCE). This is a unit
// test, no DB — it guards the exact value that feeds the library gate.
func TestStoredAuthRequest_GetCodeChallenge_NilWhenAbsent(t *testing.T) {
	r := &storedAuthRequest{codeChallenge: ""}
	if got := r.GetCodeChallenge(); got != nil {
		t.Fatalf("GetCodeChallenge() with empty challenge = %+v, want nil (a non-nil challenge lets a public client skip PKCE at the library gate)", got)
	}
}

// TestStoredAuthRequest_GetCodeChallenge_PinsS256 pins the downgrade guard: no
// matter what code_challenge_method the client stored (including "plain"),
// GetCodeChallenge() reports Method=S256. The proof is behavioral, not just a
// field check — a plain-computed challenge (challenge == verifier) must FAIL the
// library's verifier once it is treated as S256, while a correctly SHA256-hashed
// challenge must pass. This is what makes a plain-downgrade attack impossible even
// if a client crafts a plain challenge.
func TestStoredAuthRequest_GetCodeChallenge_PinsS256(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	// A client that stored a *plain* challenge (challenge == verifier) and method "plain".
	rPlain := &storedAuthRequest{codeChallenge: verifier, codeChallengeMethod: string(oidc.CodeChallengeMethodPlain)}
	ch := rPlain.GetCodeChallenge()
	if ch == nil {
		t.Fatal("GetCodeChallenge() with a stored challenge = nil, want non-nil")
	}
	if ch.Method != oidc.CodeChallengeMethodS256 {
		t.Fatalf("GetCodeChallenge().Method = %q, want %q (method must be pinned, never taken from the client)", ch.Method, oidc.CodeChallengeMethodS256)
	}
	// Because the method is pinned to S256, the plain challenge (== verifier) no
	// longer verifies: the library SHA256-hashes the verifier before comparing.
	if oidc.VerifyCodeChallenge(ch, verifier) {
		t.Fatal("a plain-style challenge verified under the pinned S256 method — plain downgrade is NOT blocked")
	}

	// A client that correctly sent an S256 challenge verifies as normal.
	rS256 := &storedAuthRequest{codeChallenge: oidc.NewSHACodeChallenge(verifier), codeChallengeMethod: string(oidc.CodeChallengeMethodS256)}
	if !oidc.VerifyCodeChallenge(rS256.GetCodeChallenge(), verifier) {
		t.Fatal("a correct S256 challenge failed to verify")
	}
}

// TestPublicClient_PKCERequiredGate asserts the two setjoin-controlled inputs that
// drive the library's "PKCE required" rejection are both in place together for a
// public client: AuthMethod()==AuthMethodNone AND a no-challenge auth request
// yields GetCodeChallenge()==nil. op/token_code.go rejects exactly this pair with
// "PKCE required". If a refactor ever made a public client report a different auth
// method, or made GetCodeChallenge() return a non-nil zero value, the library gate
// would silently open — this test fails first.
func TestPublicClient_PKCERequiredGate(t *testing.T) {
	client := &storedClient{clientType: "public"}
	if got := client.AuthMethod(); got != oidc.AuthMethodNone {
		t.Fatalf("public client AuthMethod() = %q, want %q (the library only enforces PKCE for AuthMethodNone clients)", got, oidc.AuthMethodNone)
	}

	// A token exchange whose auth request carries no challenge: the library reads
	// GetCodeChallenge()==nil and, for an AuthMethodNone client, returns "PKCE
	// required". AuthorizeCodeChallenge confirms a nil challenge + empty verifier
	// is the no-PKCE state the gate then rejects.
	noChallenge := &storedAuthRequest{codeChallenge: ""}
	if noChallenge.GetCodeChallenge() != nil {
		t.Fatal("no-challenge auth request produced a non-nil challenge; the public-client PKCE gate would not fire")
	}
	if err := op.AuthorizeCodeChallenge("", noChallenge.GetCodeChallenge()); err != nil {
		t.Fatalf("AuthorizeCodeChallenge(nil challenge, no verifier) = %v; expected the no-PKCE state that token_code.go rejects for public clients", err)
	}
}
