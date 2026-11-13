package handlers

// ER5 er5-s08 occurrence tests (credential-lifecycle.passkey-id-roundtrip):
// passkey revoke and rename must decode the wire's base64url credential id back
// to the RAW bytes passkey_credentials.id stores. The old handlers compared the
// ENCODED text's bytes against raw IDs — revocation (the lifecycle control for
// a stolen authenticator) matched no row and silently did nothing.

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/authserver/internal/token"
)

func newPasskeyTestHandler(t *testing.T) (*AuthHandler, *pgxpool.Pool) {
	t.Helper()
	dsn := liveDSN(t)
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	passkey, err := authn.NewPasskeyProvider(pool, "localhost", "SetJoin", "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	h := NewAuthHandler(AuthHandlerConfig{
		Pool:    pool,
		JWT:     newTestJWT(),
		Logger:  discardLogger(),
		Passkey: passkey,
	})
	return h, pool
}

// seedRevokeGrant inserts the webauthn.revoke proof grant the possession
// issuance endpoints mint (possession scheme v7 §3) — the revoke fixture the
// gated DELETE consumes. Returns the raw token to present.
func seedRevokeGrant(t *testing.T, pool *pgxpool.Pool, h *AuthHandler, userID int64, wireID string) string {
	t.Helper()
	rawID, err := base64.RawURLEncoding.DecodeString(wireID)
	if err != nil {
		t.Fatalf("decode fixture credential id: %v", err)
	}
	target := base64.RawURLEncoding.EncodeToString(rawID)
	// authedRequest attaches claims with an EMPTY jti — bind the fixture
	// grant to that same jti so the consumption predicate matches.
	return seedSessionGrant(t, h, userID, "", "webauthn.revoke", &target, "password", nil)
}

func authedRequest(userID int64, method, target, body string) *http.Request {
	var reader *bytes.Reader
	if body == "" {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader([]byte(body))
	}
	req := httptest.NewRequest(method, target, reader)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ContextWithUser(req.Context(), &token.Claims{UserID: userID}))
	return req
}

func TestWebAuthnCredentialIDRoundtrip_RevokeAndRename(t *testing.T) {
	h, pool := newPasskeyTestHandler(t)
	ctx := context.Background()

	userID := seedPushUser(t, pool, "passkey-roundtrip@example.com")

	// The raw credential ID exactly as an authenticator produces it, stored raw
	// in passkey_credentials.id.
	rawID := []byte("\x01\xde\xad\xbe\xef\xd0\x00" + "roundtrip-raw-bytes")
	if _, err := pool.Exec(ctx,
		`INSERT INTO passkey_credentials (id, user_id, public_key, device_name)
		 VALUES ($1, $2, decode('00','hex'), 'test-key')`,
		rawID, userID,
	); err != nil {
		t.Fatalf("seed passkey credential: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM passkey_credentials WHERE user_id = $1`, userID)
	})

	// The wire carries the base64url encoding List emits — NOT the raw bytes.
	wireID := base64.RawURLEncoding.EncodeToString(rawID)

	// Rename via the encoded id must UPDATE the raw-id row.
	rr := httptest.NewRecorder()
	renameReq := authedRequest(userID, http.MethodPut,
		"/auth/webauthn/credential/"+wireID+"/name", `{"device_name":"renamed-key"}`)
	renameReq.SetPathValue("id", wireID)
	h.WebAuthnNameCredential(rr, renameReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("rename with base64url id: got %d, want 200 (the id roundtrip must decode back to raw bytes): %s", rr.Code, rr.Body.String())
	}
	var deviceName string
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(device_name,'') FROM passkey_credentials WHERE id = $1 AND user_id = $2`, rawID, userID,
	).Scan(&deviceName); err != nil {
		t.Fatalf("renamed row missing under the RAW credential id: %v", err)
	}
	if deviceName != "renamed-key" {
		t.Fatalf("device_name = %q, want renamed-key", deviceName)
	}

	// Revoke via the encoded id must set revoked_at on the raw-id row — the
	// credential-lifecycle control a user exercises when a laptop is stolen.
	// REVISED (possession scheme v7 §3): revocation is gated — the fixture
	// seeds the webauthn.revoke grant the issuance endpoints mint, bound to
	// the presented credential id at the current generation.
	grantToken := seedRevokeGrant(t, pool, h, userID, wireID)
	rr = httptest.NewRecorder()
	req := authedRequest(userID, http.MethodDelete, "/auth/webauthn/credential/"+wireID, "")
	req.Header.Set(ReauthTokenHeader, grantToken)
	req.SetPathValue("id", wireID)
	h.WebAuthnRevokeCredential(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("revoke with base64url id: got %d, want 204: %s", rr.Code, rr.Body.String())
	}
	var revoked bool
	if err := pool.QueryRow(ctx,
		`SELECT revoked_at IS NOT NULL FROM passkey_credentials WHERE id = $1 AND user_id = $2`, rawID, userID,
	).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("revoke with the encoded credential id did NOT revoke the raw-id row — lifecycle control is dead")
	}
}

// TestWebAuthnCredentialID_MalformedEncodingRefused pins the fail-closed input
// side: an id that is not valid base64url is a 400 on BOTH management
// endpoints, never a silent no-op.
func TestWebAuthnCredentialID_MalformedEncodingRefused(t *testing.T) {
	h, _ := newPasskeyTestHandler(t)
	claims := &token.Claims{UserID: 123}
	for _, bad := range []string{"!!not-base64!!", "a b", "abc$"} {
		req := httptest.NewRequest(http.MethodDelete, "/auth/webauthn/credential/x", nil)
		req.SetPathValue("id", bad)
		req = req.WithContext(ContextWithUser(req.Context(), claims))
		rr := httptest.NewRecorder()
		h.WebAuthnRevokeCredential(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("revoke credential id %q: got %d, want 400", bad, rr.Code)
		}

		renameReq := httptest.NewRequest(http.MethodPut, "/auth/webauthn/credential/x/name", bytes.NewReader([]byte(`{"device_name":"x"}`)))
		renameReq.SetPathValue("id", bad)
		renameReq = renameReq.WithContext(ContextWithUser(renameReq.Context(), claims))
		renameRR := httptest.NewRecorder()
		h.WebAuthnNameCredential(renameRR, renameReq)
		if renameRR.Code != http.StatusBadRequest {
			t.Errorf("rename credential id %q: got %d, want 400", bad, renameRR.Code)
		}
	}
}
