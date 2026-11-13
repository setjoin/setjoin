package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/testsupport"
)

// -- auth gate --

func TestRevoke_RejectsUnauthenticated(t *testing.T) {
	h := &RevokeHandler{Pool: createClosedPool(t), APIKey: testAPIKey}
	form := url.Values{"token": {"some-token"}}
	req := httptest.NewRequest("POST", "/auth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (no client auth, no API key)", rr.Code)
	}
}

func TestRevoke_RejectsUnknownBasicClient(t *testing.T) {
	h := &RevokeHandler{Pool: createClosedPool(t), APIKey: testAPIKey}
	form := url.Values{"token": {"some-token"}}
	req := httptest.NewRequest("POST", "/auth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	basic := base64.StdEncoding.EncodeToString([]byte("client:secret"))
	req.Header.Set("Authorization", "Basic "+basic)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for unresolvable client", rr.Code)
	}
}

func TestRevoke_MissingTokenIsBadRequest(t *testing.T) {
	h := &RevokeHandler{Pool: createClosedPool(t), APIKey: testAPIKey}
	req := httptest.NewRequest("POST", "/auth/revoke", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for missing token", rr.Code)
	}
}

// -- structural idempotency: RevokeByToken filters on revoked_at IS NULL and
// ignores token_type_hint, so re-revoking or hinting cannot change the outcome.
func TestRevokeByToken_IsIdempotentBySource(t *testing.T) {
	src := funcSrc(t, "../token/refresh.go", "RevokeByToken")
	if !strings.Contains(src, "revoked_at IS NULL") {
		t.Error("RevokeByToken must filter on revoked_at IS NULL so re-revocation is a no-op")
	}
	if !strings.Contains(src, "token_hash = $1") {
		t.Error("RevokeByToken must look up by token_hash (type-agnostic)")
	}
	if strings.Contains(src, "token_type_hint") {
		t.Error("RevokeByToken must NOT branch on token_type_hint (RFC 7009: hint is advisory)")
	}
}

// -- client-credential extraction (pure) --

func TestExtractClientCredentials_Basic(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader(""))
	basic := base64.StdEncoding.EncodeToString([]byte("cid:csecret"))
	req.Header.Set("Authorization", "Basic "+basic)
	_ = req.ParseForm()
	creds := extractClientCredentials(req)
	if !creds.present || creds.id != "cid" || creds.secret != "csecret" {
		t.Errorf("Basic creds = %+v, want id=cid secret=csecret present", creds)
	}
}

func TestExtractClientCredentials_PostBody(t *testing.T) {
	form := url.Values{"client_id": {"cid2"}, "client_secret": {"csecret2"}}
	req := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = req.ParseForm()
	creds := extractClientCredentials(req)
	if !creds.present || creds.id != "cid2" || creds.secret != "csecret2" {
		t.Errorf("POST creds = %+v, want id=cid2 secret=csecret2 present", creds)
	}
}

func TestExtractClientCredentials_AbsentIsNotPresent(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = req.ParseForm()
	creds := extractClientCredentials(req)
	if creds.present {
		t.Errorf("creds.present = true with no credentials supplied")
	}
}

func TestExtractClientCredentials_BasicPreferredOverBody(t *testing.T) {
	form := url.Values{"client_id": {"bodyid"}, "client_secret": {"bodysecret"}}
	req := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	basic := base64.StdEncoding.EncodeToString([]byte("basicid:basicsecret"))
	req.Header.Set("Authorization", "Basic "+basic)
	_ = req.ParseForm()
	creds := extractClientCredentials(req)
	if creds.id != "basicid" {
		t.Errorf("expected Basic to win over body, got id=%q", creds.id)
	}
}

// -- DB-gated idempotency proof (runs only when DB_DSN points at a loaded DB) --

func TestRevoke_IdempotentAgainstLiveDB(t *testing.T) {
	pool := testsupport.OpenTestPool(t)

	ctx := context.Background()
	// Revoking a token that does not exist must be a no-op (no error).
	if err := token.RevokeByToken(ctx, pool, "definitely-not-a-real-token-value", ""); err != nil {
		t.Errorf("RevokeByToken on unknown token returned error: %v", err)
	}
	// Revoking it again is still a no-op.
	if err := token.RevokeByToken(ctx, pool, "definitely-not-a-real-token-value", ""); err != nil {
		t.Errorf("second RevokeByToken returned error: %v", err)
	}
}

// liveDSN returns a DSN for a loaded test DB (DB_DSN preferred, TEST_DB_DSN
// fallback), or skips the test when neither is set.
func liveDSN(t *testing.T) string {
	t.Helper()
	if dsn := os.Getenv("DB_DSN"); dsn != "" {
		return dsn
	}
	if dsn := os.Getenv("TEST_DB_DSN"); dsn != "" {
		return dsn
	}
	t.Skip("neither DB_DSN nor TEST_DB_DSN set — skipping live cross-client revocation test")
	return ""
}

// seedRevToken inserts an active oauth_tokens row for userID with the given raw
// token string and client_id (nil clientID => NULL client_id), and registers
// cleanup. It returns the raw token to present to RevokeByToken.
func seedRevToken(t *testing.T, pool *pgxpool.Pool, userID int64, rawToken string, clientID any) string {
	t.Helper()
	ctx := context.Background()
	h := sha256.Sum256([]byte(rawToken))
	_, err := pool.Exec(ctx,
		`INSERT INTO oauth_tokens (user_id, client_id, token_hash, token_type, expires_at)
		 VALUES ($1, $2, $3, 'access', now() + interval '1 hour')`,
		userID, clientID, h[:])
	if err != nil {
		t.Fatalf("seed token: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM oauth_tokens WHERE token_hash = $1`, h[:]) })
	return rawToken
}

// tokenRevoked reports whether the row for rawToken has revoked_at set.
func tokenRevoked(t *testing.T, pool *pgxpool.Pool, rawToken string) bool {
	t.Helper()
	h := sha256.Sum256([]byte(rawToken))
	var revoked bool
	err := pool.QueryRow(context.Background(),
		`SELECT revoked_at IS NOT NULL FROM oauth_tokens WHERE token_hash = $1`, h[:],
	).Scan(&revoked)
	if err != nil {
		t.Fatalf("read revoked_at: %v", err)
	}
	return revoked
}

// TestRevokeByToken_ClientScoped is the RFC 7009 §2.1 proof: the requesting
// client may only revoke tokens issued to it (or to no client). A cross-client
// revoke is a silent no-op; a client can revoke its own token and a no-client
// token.
func TestRevokeByToken_ClientScoped(t *testing.T) {
	dsn := liveDSN(t)
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	ctx := context.Background()

	// Throwaway user under any existing domain.
	suffix := time.Now().Format("150405.000000000")
	var userID int64
	err = pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name)
		 VALUES ($1, (SELECT MIN(id) FROM domains), $2, 'Revoke Test')
		 RETURNING id`,
		"revtest-"+suffix, "revtest-"+suffix+"@example.com",
	).Scan(&userID)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID) })

	const clientA, clientB = "client-a-rev", "client-b-rev"
	tokA := seedRevToken(t, pool, userID, "tok-a-"+suffix, clientA)
	tokB := seedRevToken(t, pool, userID, "tok-b-"+suffix, clientB)
	tokNil := seedRevToken(t, pool, userID, "tok-nil-"+suffix, nil)

	// 1. Client A tries to revoke Client B's token — MUST be a no-op (idempotent
	//    success, but the token stays active). This is the RFC 7009 §2.1 guard.
	if err := token.RevokeByToken(ctx, pool, tokB, clientA); err != nil {
		t.Fatalf("cross-client revoke errored: %v", err)
	}
	if tokenRevoked(t, pool, tokB) {
		t.Error("SECURITY: client A revoked client B's token (cross-client revoke must be a no-op)")
	}

	// 2. Client A revokes its OWN token — succeeds.
	if err := token.RevokeByToken(ctx, pool, tokA, clientA); err != nil {
		t.Fatalf("self revoke errored: %v", err)
	}
	if !tokenRevoked(t, pool, tokA) {
		t.Error("client A failed to revoke its own token")
	}

	// 3. Client A revokes a no-client (NULL client_id) token — succeeds, because
	//    no owning client exists to scope it to (e.g. internal/first-party tokens).
	if err := token.RevokeByToken(ctx, pool, tokNil, clientA); err != nil {
		t.Fatalf("no-client revoke errored: %v", err)
	}
	if !tokenRevoked(t, pool, tokNil) {
		t.Error("a no-client token must be revocable by an authenticated client")
	}

	// 4. The internal API-key caller (empty clientID) can ALSO revoke the
	//    no-client token but must NOT touch client B's token.
	tokNil2 := seedRevToken(t, pool, userID, "tok-nil2-"+suffix, nil)
	if err := token.RevokeByToken(ctx, pool, tokNil2, ""); err != nil {
		t.Fatalf("internal-caller no-client revoke errored: %v", err)
	}
	if !tokenRevoked(t, pool, tokNil2) {
		t.Error("internal caller (empty clientID) must revoke no-client tokens")
	}
	if err := token.RevokeByToken(ctx, pool, tokB, ""); err != nil {
		t.Fatalf("internal-caller cross-client revoke errored: %v", err)
	}
	if tokenRevoked(t, pool, tokB) {
		t.Error("SECURITY: internal caller (empty clientID) revoked a client-owned token")
	}
}
