package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/authserver/internal/authn"
)

// TestPushMFAStatus_InvalidToken is the cheap, DB-free guard: a status poll with
// a bad MFA-pending token is rejected (401) before any challenge lookup.
func TestPushMFAStatus_InvalidToken(t *testing.T) {
	h := newTestAuthHandler() // mock push provider; never reaches the DB on this path
	body, _ := json.Marshal(map[string]string{"mfa_token": "not-a-jwt", "nonce": "abcd"})
	req := httptest.NewRequest(http.MethodPost, "/auth/push/status", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.PushMFAStatus(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("invalid mfa_token: got %d, want 401", rr.Code)
	}
}

// seedPushUser inserts a throwaway enabled local user and registers cleanup.
func seedPushUser(t *testing.T, pool *pgxpool.Pool, email string) int64 {
	t.Helper()
	ctx := context.Background()
	var userID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, sync_source, enabled,
		                    password_hash, must_change_password)
		 SELECT $1, $1, 'Push Status User', id, 'local', TRUE, 'x', FALSE
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

// insertChallenge stores a push_mfa_challenge with a fresh random nonce and the
// given code (verified_at/approved_at NULL), returning the hex nonce the handlers
// take on the wire. The session_id carries "sess", matching the session string
// the native-approval assertions below sign.
func insertChallenge(t *testing.T, pool *pgxpool.Pool, userID int64, code string) string {
	t.Helper()
	return insertChallengeWithSession(t, pool, userID, code, "sess", "120 seconds")
}

// insertChallengeWithSession is insertChallenge with the challenge's session_id
// and TTL under the test's control. Production stamps the initiating
// MFA-pending token here (PushMFASend / the Login push branch), and the
// /auth/push/status harvest fence binds on this exact value.
func insertChallengeWithSession(t *testing.T, pool *pgxpool.Pool, userID int64, code, sessionID, ttl string) string {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := cryptorand.Read(nonce); err != nil {
		t.Fatalf("rand nonce: %v", err)
	}
	nonceHex := hex.EncodeToString(nonce)
	_, err := pool.Exec(context.Background(),
		`INSERT INTO push_mfa_challenges (user_id, challenge_code, nonce, session_id, expires_at)
		 VALUES ($1, $2, decode($3,'hex'), $4, now() + $5::interval)`,
		userID, code, nonceHex, sessionID, ttl,
	)
	if err != nil {
		t.Fatalf("insert challenge: %v", err)
	}
	return nonceHex
}

func registerApprovalDevice(t *testing.T, pool *pgxpool.Pool, userID int64) (int64, *ecdsa.PrivateKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := elliptic.Marshal(elliptic.P256(), privateKey.X, privateKey.Y)
	var deviceID int64
	err = pool.QueryRow(context.Background(),
		`INSERT INTO push_devices(user_id, push_provider, push_token_enc, device_public_key, device_name)
		 VALUES ($1, 'fcm', decode('00','hex'), $2, 'approval-test') RETURNING id`, userID, publicKey,
	).Scan(&deviceID)
	if err != nil {
		t.Fatalf("insert push device: %v", err)
	}
	return deviceID, privateKey
}

func signedApprovalBody(t *testing.T, nonce, code string, userID, deviceID int64, privateKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	now := time.Now().Unix()
	return signedApprovalBodyWithSession(t, nonce, code, userID, deviceID, "sess", now, now+60, privateKey)
}

// signedApprovalBodyWithSession signs the approval assertion for the given
// challenge session string (the challenge row's session_id — in production the
// initiating MFA-pending token), which the approve path verifies canonically.
func signedApprovalBodyWithSession(t *testing.T, nonce, code string, userID, deviceID int64, sessionID string, issuedAt, expiresAt int64, privateKey *ecdsa.PrivateKey) []byte {
	t.Helper()
	assertion := authn.PushApprovalAssertion{
		Protocol: authn.PushApprovalProtocol, Nonce: nonce, Code: code,
		DeviceID: deviceID, UserID: userID, SessionID: sessionID, Decision: "approve",
		IssuedAt: issuedAt, ExpiresAt: expiresAt,
	}
	canonical, err := authn.CanonicalPushApproval(assertion)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	r, s, err := ecdsa.Sign(cryptorand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	body, _ := json.Marshal(map[string]any{
		"nonce": nonce, "code": code, "device_id": deviceID, "decision": "approve",
		"issued_at": issuedAt, "expires_at": expiresAt,
		"signature": base64.RawURLEncoding.EncodeToString(raw),
	})
	return body
}

func TestMFAApproveRejectsLockedExpiredAndBadSignatureAssertions(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), liveDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	userID := seedPushUser(t, pool, "push-negative-assertions@example.com")
	deviceID, approvalKey := registerApprovalDevice(t, pool, userID)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
		PushMFA: authn.NewNumberMatchPushProvider(context.Background(), pool, nil, "", "", discardLogger()),
	})
	post := func(body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/auth/mfa/approve", bytes.NewReader(body))
		rr := httptest.NewRecorder()
		h.MFAApprove(rr, req)
		return rr
	}

	lockedNonce := insertChallenge(t, pool, userID, "42")
	if _, err := pool.Exec(context.Background(), `UPDATE push_mfa_challenges SET failed_attempts=3 WHERE nonce=decode($1,'hex')`, lockedNonce); err != nil {
		t.Fatal(err)
	}
	if rr := post(signedApprovalBody(t, lockedNonce, "42", userID, deviceID, approvalKey)); rr.Code != http.StatusBadRequest {
		t.Fatalf("locked challenge = %d", rr.Code)
	}

	expiredNonce := insertChallenge(t, pool, userID, "42")
	now := time.Now().Unix()
	if rr := post(signedApprovalBodyWithSession(t, expiredNonce, "42", userID, deviceID, "sess", now-121, now+30, approvalKey)); rr.Code != http.StatusBadRequest {
		t.Fatalf("expired assertion = %d", rr.Code)
	}

	badSignatureNonce := insertChallenge(t, pool, userID, "42")
	body := signedApprovalBody(t, badSignatureNonce, "42", userID, deviceID, approvalKey)
	var request map[string]any
	_ = json.Unmarshal(body, &request)
	request["signature"] = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	body, _ = json.Marshal(request)
	if rr := post(body); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad signature = %d", rr.Code)
	}
}

func TestMFAApproveLocksDeviceAgainstConcurrentRevocation(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), liveDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	userID := seedPushUser(t, pool, "push-approval-revocation-race@example.com")
	deviceID, _ := registerApprovalDevice(t, pool, userID)
	nonceHex := insertChallenge(t, pool, userID, "42")
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		t.Fatal(err)
	}

	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	var challengeID, selectedUserID int64
	var code, sessionID string
	var expires int64
	var attempts int
	var publicKey []byte
	if err := tx.QueryRow(context.Background(), mfaApproveChallengeQuery, nonce, deviceID).Scan(
		&challengeID, &selectedUserID, &code, &sessionID, &expires, &attempts, &publicKey,
	); err != nil {
		t.Fatalf("lock approval rows: %v", err)
	}

	revokeCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := pool.Exec(revokeCtx,
		`UPDATE push_devices SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, deviceID,
	); err == nil {
		t.Fatal("concurrent revocation crossed the approval transaction's device-row lock")
	}

	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE push_devices SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, deviceID,
	); err != nil {
		t.Fatalf("revocation remained blocked after approval transaction ended: %v", err)
	}
}

func TestMFAApproveFailsClosedWhenDatabasePoolIsClosed(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), liveDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
		PushMFA: authn.NewNumberMatchPushProvider(context.Background(), pool, nil, "", "", discardLogger()),
	})
	body, _ := json.Marshal(map[string]any{
		"nonce": strings.Repeat("00", 32), "code": "42", "device_id": 1,
		"decision": "approve", "issued_at": time.Now().Unix(), "expires_at": time.Now().Add(time.Minute).Unix(),
		"signature": base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
	})
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/approve", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.MFAApprove(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("closed pool status = %d, want 500", rr.Code)
	}
}

func hasCookie(rr *httptest.ResponseRecorder, name string) bool {
	for _, c := range rr.Result().Cookies() {
		if c.Name == name {
			return true
		}
	}
	return false
}

// TestPushMFAStatus_ApprovedOnlyAfterDeviceApproval is the C10 out-of-band proof:
// the status poll issues a session ONLY after a genuine device approval, and NEVER
// when a 3-strike lockout has merely stamped verified_at. It drives the REAL
// VerifyChallenge lockout and the REAL MFAApprove stamping path against a loaded
// DB so the verified_at-vs-approved_at distinction is exercised end to end.
func TestPushMFAStatus_ApprovedOnlyAfterDeviceApproval(t *testing.T) {
	dsn := liveDSN(t)
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	ctx := context.Background()

	userID := seedPushUser(t, pool, "push-status@example.com")
	deviceID, approvalKey := registerApprovalDevice(t, pool, userID)

	h := NewAuthHandler(AuthHandlerConfig{
		Pool:    pool,
		JWT:     newTestJWT(),
		Logger:  discardLogger(),
		PushMFA: authn.NewNumberMatchPushProvider(ctx, pool, nil, "", "", discardLogger()),
	})
	mfaToken, err := h.jwt.IssueMFAPending(userID, "push-status@example.com")
	if err != nil {
		t.Fatalf("issue mfa token: %v", err)
	}

	pollStatus := func(nonceHex, tok string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"mfa_token": tok, "nonce": nonceHex})
		req := httptest.NewRequest(http.MethodPost, "/auth/push/status", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.PushMFAStatus(rr, req)
		return rr
	}
	approveWithSession := func(nonceHex, code, sessionID string, issuedAt, expiresAt int64) *httptest.ResponseRecorder {
		body := signedApprovalBodyWithSession(t, nonceHex, code, userID, deviceID, sessionID, issuedAt, expiresAt, approvalKey)
		req := httptest.NewRequest(http.MethodPost, "/auth/mfa/approve", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.MFAApprove(rr, req)
		return rr
	}
	approve := func(nonceHex, code string) *httptest.ResponseRecorder {
		return approveWithSession(nonceHex, code, "sess", time.Now().Unix(), time.Now().Add(60*time.Second).Unix())
	}
	decodeBody := func(rr *httptest.ResponseRecorder) map[string]any {
		var m map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &m)
		return m
	}

	// ── 1. Fresh challenge, no approval yet → not approved, no session. ──
	nonceA := insertChallenge(t, pool, userID, "42")
	rr := pollStatus(nonceA, mfaToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("poll (pending): got %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if got := decodeBody(rr)["approved"]; got != false {
		t.Errorf("poll (pending): approved=%v, want false", got)
	}
	if hasCookie(rr, "access_token") {
		t.Error("poll (pending): set an access_token cookie before approval")
	}

	// ── 2. Lockout: 4 wrong device approvals burn the challenge (VerifyChallenge
	//      stamps verified_at). The poll must NOT read that as an approval. ──
	for i := 0; i < 4; i++ {
		if code := approve(nonceA, "99").Code; code != http.StatusBadRequest {
			t.Fatalf("wrong-code approve %d: got %d, want 400", i+1, code)
		}
	}
	var verifiedSet, approvedSet bool
	if err := pool.QueryRow(ctx,
		`SELECT verified_at IS NOT NULL, approved_at IS NOT NULL
		 FROM push_mfa_challenges WHERE nonce = decode($1,'hex') AND user_id = $2`,
		nonceA, userID,
	).Scan(&verifiedSet, &approvedSet); err != nil {
		t.Fatalf("read challenge state after lockout: %v", err)
	}
	if !verifiedSet {
		t.Error("lockout should have stamped verified_at")
	}
	if approvedSet {
		t.Fatal("lockout stamped approved_at — a lockout must never count as an approval")
	}
	rr = pollStatus(nonceA, mfaToken)
	if got := decodeBody(rr)["approved"]; got != false {
		t.Errorf("poll (after lockout): approved=%v, want false — verified_at must not be read as approval", got)
	}
	if hasCookie(rr, "access_token") {
		t.Error("poll (after lockout): issued a session for a locked-out challenge — 2FA bypass")
	}

	// ── 3. Genuine device approval on a fresh challenge → approved_at set; the
	//      poll then issues the login session to the holder of the mfa_token.
	//      The challenge is stamped with the initiating mfa_token as its
	//      session_id (production-accurate: PushMFASend / the Login push branch
	//      both correlate this way), and the approval assertion signs it. ──
	nonceB := insertChallengeWithSession(t, pool, userID, "42", mfaToken, "120 seconds")
	now := time.Now().Unix()
	if rr := approveWithSession(nonceB, "42", mfaToken, now, now+60); rr.Code != http.StatusNoContent {
		t.Fatalf("correct device approve: got %d, want 204: %s", rr.Code, rr.Body.String())
	}
	if err := pool.QueryRow(ctx,
		`SELECT approved_at IS NOT NULL FROM push_mfa_challenges WHERE nonce = decode($1,'hex') AND user_id = $2`,
		nonceB, userID,
	).Scan(&approvedSet); err != nil {
		t.Fatalf("read approved_at after approve: %v", err)
	}
	if !approvedSet {
		t.Fatal("device approval did not stamp approved_at")
	}
	rr = pollStatus(nonceB, mfaToken)
	if rr.Code != http.StatusOK {
		t.Fatalf("poll (approved): got %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if _, ok := decodeBody(rr)["access_token"]; !ok {
		t.Errorf("poll (approved): no access_token in body: %s", rr.Body.String())
	}
	if !hasCookie(rr, "access_token") {
		t.Error("poll (approved): did not set the access_token session cookie")
	}

	// Regression (auth_method fix): the successful sign-in is RECORDED, not silently
	// dropped by a login_events_auth_method_chk violation (factors[0] was the raw AMR
	// code, which the constraint rejects). At least one of the device-approve +
	// status-poll issuances above must have landed a login_events row.
	var signins int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM login_events WHERE user_id = $1 AND success`, userID,
	).Scan(&signins); err != nil {
		t.Fatalf("count login_events: %v", err)
	}
	if signins == 0 {
		t.Error("approved sign-in was not recorded to login_events — auth_method constraint drop regressed")
	}

	// ── 4. Scoping: another user's poll for nonceB never sees the approval. ──
	otherTok, err := h.jwt.IssueMFAPending(userID+9_000_000, "intruder@example.com")
	if err != nil {
		t.Fatalf("issue other mfa token: %v", err)
	}
	rr = pollStatus(nonceB, otherTok)
	if got := decodeBody(rr)["approved"]; got != false {
		t.Errorf("poll (foreign user): approved=%v, want false — challenge lookup must be user-scoped", got)
	}
	if hasCookie(rr, "access_token") {
		t.Error("poll (foreign user): issued a session for another user's approved challenge")
	}
}
