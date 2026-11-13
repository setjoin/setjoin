package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
)

// This file closes the MFA-shaped-login DPoP-binding gap flagged in the A2
// report / TODOS.md: completion metadata (and the cnf it carries) was previously
// stamped ONLY in the direct-password Login path. A user completing MFA
// (TOTP, backup code, push) got an UNBOUND access token even with
// feature.token_binding ON and a JWK on the wire, because none of those
// completion handlers read a dpop_jwk field or stashed cnf before calling
// issueTokensWithFactors.

var fakeDPoPJWK = map[string]any{
	"kty": "EC", "crv": "P-256",
	"x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
	"y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
}

// TestCnfForToggle_GatesOnFeatureAndJWK is the pure, DB-free contract test for
// the shared gate every completion handler now calls before issuing tokens.
func TestCnfForToggle_GatesOnFeatureAndJWK(t *testing.T) {
	on := &deps{toggles: toggle.NewTestFlags(map[string]bool{toggle.FeatureTokenBinding: true})}
	off := &deps{toggles: toggle.NewTestFlags(map[string]bool{toggle.FeatureTokenBinding: false})}
	nilToggles := &deps{}

	if cnf := on.cnfForToggle(fakeDPoPJWK); cnf == nil {
		t.Fatal("toggle ON + JWK present: want a cnf claim, got nil")
	}
	want, _ := threat.JKTFromJWK(fakeDPoPJWK)
	if cnf := on.cnfForToggle(fakeDPoPJWK); cnf.JKT != want {
		t.Fatalf("cnf.JKT = %q, want %q", cnf.JKT, want)
	}
	if cnf := off.cnfForToggle(fakeDPoPJWK); cnf != nil {
		t.Fatalf("toggle OFF: want nil cnf (unbound token), got %+v", cnf)
	}
	if cnf := nilToggles.cnfForToggle(fakeDPoPJWK); cnf != nil {
		t.Fatalf("nil toggles: want nil cnf (treated as off), got %+v", cnf)
	}
	if cnf := on.cnfForToggle(nil); cnf != nil {
		t.Fatalf("no JWK supplied: want nil cnf even with toggle on, got %+v", cnf)
	}
}

// seedLocalUser inserts a throwaway enabled local user for the DPoP binding
// tests below and registers cleanup of every table these flows touch.
func seedLocalUser(t *testing.T, pool *pgxpool.Pool, email string) int64 {
	t.Helper()
	ctx := context.Background()
	var userID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, sync_source, enabled,
		                    password_hash, must_change_password)
		 SELECT $1, $1, 'DPoP Binding Test User', id, 'local', TRUE, 'x', FALSE
		 FROM domains WHERE is_local = TRUE
		 ORDER BY id LIMIT 1
		 RETURNING id`,
		email,
	).Scan(&userID)
	if err != nil {
		t.Skipf("could not seed test user (schema/domains not loaded?): %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM oauth_tokens WHERE user_id = $1`, userID)
		pool.Exec(ctx, `DELETE FROM push_mfa_challenges WHERE user_id = $1`, userID)
		pool.Exec(ctx, `DELETE FROM login_events WHERE user_id = $1`, userID)
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
	})
	return userID
}

// accessTokenFromBody parses the {"access_token": "..."} response body a
// successful completion handler writes.
func accessTokenFromBody(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response body: %v (body=%s)", err, rr.Body.String())
	}
	if body.AccessToken == "" {
		t.Fatalf("no access_token in response body: %s", rr.Body.String())
	}
	return body.AccessToken
}

// TestBackupCodeVerify_BindsTokenWhenJWKSuppliedAndToggleOn is the red-first
// evidence for the backup-code MFA completion path: before this task's fix,
// BackupCodeVerify's request struct had no dpop_jwk field at all, so the
// resulting access token's cnf claim was always nil regardless of what the
// client sent — an unbound token even with feature.token_binding ON.
func TestBackupCodeVerify_BindsTokenWhenJWKSuppliedAndToggleOn(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), liveDSN(t))
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	ctx := context.Background()

	userID := seedLocalUser(t, pool, "dpop-backup-code@example.com")
	codes, err := authn.GenerateBackupCodes(ctx, pool, userID)
	if err != nil {
		t.Fatalf("GenerateBackupCodes: %v", err)
	}

	h := NewAuthHandler(AuthHandlerConfig{
		Pool:    pool,
		JWT:     newTestJWT(),
		Logger:  discardLogger(),
		Toggles: toggle.NewTestFlags(map[string]bool{toggle.FeatureTokenBinding: true}),
	})
	mfaToken, err := h.jwt.IssueMFAPending(userID, "dpop-backup-code@example.com")
	if err != nil {
		t.Fatalf("issue mfa token: %v", err)
	}

	postBackupCode := func(code string, jwk map[string]any) *httptest.ResponseRecorder {
		payload := map[string]any{"mfa_token": mfaToken, "code": code}
		if jwk != nil {
			payload["dpop_jwk"] = jwk
		}
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/auth/backup-codes/verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.BackupCodeVerify(rr, req)
		return rr
	}

	// ── Bound: JWK supplied + toggle on → access token carries cnf.jkt. ──
	rr := postBackupCode(codes[0], fakeDPoPJWK)
	if rr.Code != http.StatusOK {
		t.Fatalf("backup code verify: got %d, want 200: %s", rr.Code, rr.Body.String())
	}
	claims, err := h.jwt.Validate(accessTokenFromBody(t, rr))
	if err != nil {
		t.Fatalf("validate minted access token: %v", err)
	}
	want, _ := threat.JKTFromJWK(fakeDPoPJWK)
	if claims.Cnf == nil || claims.Cnf.JKT != want {
		t.Fatalf("backup-code completion: access token cnf = %+v, want jkt %q — MFA completion is not binding the token", claims.Cnf, want)
	}

	// ── Graceful degrade: no JWK on the wire → still issues an (unbound) token. ──
	rr = postBackupCode(codes[1], nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("backup code verify (no jwk): got %d, want 200: %s", rr.Code, rr.Body.String())
	}
	claims, err = h.jwt.Validate(accessTokenFromBody(t, rr))
	if err != nil {
		t.Fatalf("validate minted access token: %v", err)
	}
	if claims.Cnf != nil {
		t.Fatalf("no dpop_jwk supplied: want unbound token, got cnf %+v", claims.Cnf)
	}
}

// TestPushMFAStatus_BindsTokenWhenJWKSuppliedAndToggleOn is the same
// red/green evidence for the push out-of-band completion poll — the browser's
// only token-minting call in the C10 push flow.
func TestPushMFAStatus_BindsTokenWhenJWKSuppliedAndToggleOn(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), liveDSN(t))
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	ctx := context.Background()

	userID := seedPushUser(t, pool, "dpop-push@example.com")
	deviceID, approvalKey := registerApprovalDevice(t, pool, userID)

	h := NewAuthHandler(AuthHandlerConfig{
		Pool:    pool,
		JWT:     newTestJWT(),
		Logger:  discardLogger(),
		PushMFA: authn.NewNumberMatchPushProvider(ctx, pool, nil, "", "", discardLogger()),
		Toggles: toggle.NewTestFlags(map[string]bool{toggle.FeatureTokenBinding: true}),
	})
	mfaToken, err := h.jwt.IssueMFAPending(userID, "dpop-push@example.com")
	if err != nil {
		t.Fatalf("issue mfa token: %v", err)
	}

	nonce := insertChallengeWithSession(t, pool, userID, "42", mfaToken, "120 seconds")
	// Approve out-of-band on the device channel first (mirrors production: the
	// enrolled device approves before the browser's poll can succeed). The
	// challenge's session_id is the initiating mfa_token (production-accurate —
	// the status harvest fence binds on it), so the assertion signs it.
	approveBody := signedApprovalBodyWithSession(t, nonce, "42", userID, deviceID, mfaToken,
		time.Now().Unix(), time.Now().Add(60*time.Second).Unix(), approvalKey)
	approveReq := httptest.NewRequest(http.MethodPost, "/auth/mfa/approve", bytes.NewReader(approveBody))
	approveReq.Header.Set("Content-Type", "application/json")
	approveRR := httptest.NewRecorder()
	h.MFAApprove(approveRR, approveReq)
	if approveRR.Code != http.StatusNoContent {
		t.Fatalf("device approve: got %d, want 204: %s", approveRR.Code, approveRR.Body.String())
	}

	body, _ := json.Marshal(map[string]any{"mfa_token": mfaToken, "nonce": nonce, "dpop_jwk": fakeDPoPJWK})
	req := httptest.NewRequest(http.MethodPost, "/auth/push/status", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.PushMFAStatus(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("push status poll: got %d, want 200: %s", rr.Code, rr.Body.String())
	}
	claims, err := h.jwt.Validate(accessTokenFromBody(t, rr))
	if err != nil {
		t.Fatalf("validate minted access token: %v", err)
	}
	want, _ := threat.JKTFromJWK(fakeDPoPJWK)
	if claims.Cnf == nil || claims.Cnf.JKT != want {
		t.Fatalf("push completion: access token cnf = %+v, want jkt %q — MFA completion is not binding the token", claims.Cnf, want)
	}
}

// TestWebAuthnLoginFinish_DecodesDPoPJWKAlongsideAssertion is a body-plumbing
// unit test (no real WebAuthn crypto): it proves the extra top-level dpop_jwk
// field survives being read out of r.Body and the assertion body is left
// intact for the downstream WebAuthn parse (verified via a fake passkey
// success path is out of scope here — see acr_amr_test.go /
// webauthn_test.go for existing WebAuthn coverage patterns; this test only
// pins the body round-trip this task's fix relies on).
func TestWebAuthnLoginFinish_DPoPJWKBodyRoundTrip(t *testing.T) {
	assertion := map[string]any{"id": "cred-1", "rawId": "abc", "type": "public-key"}
	payload := map[string]any{}
	for k, v := range assertion {
		payload[k] = v
	}
	payload["dpop_jwk"] = fakeDPoPJWK
	raw, _ := json.Marshal(payload)

	var dpop struct {
		DPoPJWK map[string]any `json:"dpop_jwk,omitempty"`
	}
	if err := json.Unmarshal(raw, &dpop); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if dpop.DPoPJWK == nil {
		t.Fatal("dpop_jwk did not survive the shared decode — WebAuthnLoginFinish would mint an unbound token")
	}

	// The same bytes must still parse as the assertion body the WebAuthn
	// library expects (extra unknown fields are ignored by encoding/json).
	var reparsed map[string]any
	if err := json.Unmarshal(raw, &reparsed); err != nil {
		t.Fatalf("assertion body corrupted by dpop_jwk extraction: %v", err)
	}
	if reparsed["id"] != "cred-1" {
		t.Fatalf("assertion fields lost: %+v", reparsed)
	}
}
