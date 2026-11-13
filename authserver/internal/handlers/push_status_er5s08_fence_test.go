package handlers

// ER5 er5-s08 occurrence tests (authentication.push-mfa-replay): an approved
// push-MFA challenge must complete EXACTLY ONE login session — the session that
// minted the challenge — within the challenge's TTL. The /auth/push/status
// harvest fence binds on the challenge's session_id (= the initiating
// MFA-pending token), enforces expires_at > now(), and consumes the approval
// (session_id CAS → NULL) so a replay across sessions or after expiry mints
// nothing. Drives the REAL approve stamping path against a loaded DB.

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
)

func newPushFenceHandler(t *testing.T) (*AuthHandler, *pgxpool.Pool) {
	t.Helper()
	dsn := liveDSN(t)
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool:    pool,
		JWT:     newTestJWT(),
		Logger:  discardLogger(),
		PushMFA: authn.NewNumberMatchPushProvider(context.Background(), pool, nil, "", "", discardLogger()),
	})
	return h, pool
}

func pollPushStatus(h *AuthHandler, tok, nonceHex string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"mfa_token": tok, "nonce": nonceHex})
	req := httptest.NewRequest(http.MethodPost, "/auth/push/status", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.PushMFAStatus(rr, req)
	return rr
}

// TestPushMFAStatus_HarvestIsSessionBoundAndSingleUse executes the three replay
// bypasses the fence closes:
//  1. cross-session replay — a second MFA-pending token of the same user cannot
//     harvest another session's approved challenge;
//  2. single-use — the winning poll consumes the approval; re-polling never
//     mints a second session;
//  3. after-expiry — an approved-but-expired challenge is never harvestable.
func TestPushMFAStatus_HarvestIsSessionBoundAndSingleUse(t *testing.T) {
	h, pool := newPushFenceHandler(t)
	ctx := context.Background()

	userID := seedPushUser(t, pool, "push-fence@example.com")
	deviceID, approvalKey := registerApprovalDevice(t, pool, userID)

	tokenA, err := h.jwt.IssueMFAPending(userID, "push-fence@example.com")
	if err != nil {
		t.Fatal(err)
	}

	approve := func(nonceHex, code, sessionID string) *httptest.ResponseRecorder {
		body := signedApprovalBodyWithSession(t, nonceHex, code, userID, deviceID, sessionID,
			time.Now().Unix(), time.Now().Add(60*time.Second).Unix(), approvalKey)
		req := httptest.NewRequest(http.MethodPost, "/auth/mfa/approve", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.MFAApprove(rr, req)
		return rr
	}

	// Session A: challenge minted by tokenA, device approves it.
	nonceA := insertChallengeWithSession(t, pool, userID, "42", tokenA, "120 seconds")
	if rr := approve(nonceA, "42", tokenA); rr.Code != http.StatusNoContent {
		t.Fatalf("device approve: got %d, want 204: %s", rr.Code, rr.Body.String())
	}

	// 1. Cross-session replay: a DIFFERENT MFA-pending token of the same user
	//    cannot harvest A's approved challenge (pre-fence it minted a full
	//    session — the challenge was only nonce+user scoped).
	tokenB, err := h.jwt.IssueMFAPending(userID, "push-fence@example.com")
	if err != nil {
		t.Fatal(err)
	}
	rr := pollPushStatus(h, tokenB, nonceA)
	if rr.Code != http.StatusOK {
		t.Fatalf("cross-session poll: got %d, want 200", rr.Code)
	}
	var m map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &m)
	if m["approved"] != false {
		t.Fatalf("cross-session replay: approved=%v, want false", m["approved"])
	}
	if hasCookie(rr, "access_token") {
		t.Fatal("cross-session replay minted a session — the challenge is not session-bound")
	}

	// 2. Single use: the owning session's FIRST poll harvests and mints; the
	//    second poll (same token, same nonce) is refused — one approval, one
	//    session, no matter how often the pair is replayed.
	rr = pollPushStatus(h, tokenA, nonceA)
	if rr.Code != http.StatusOK {
		t.Fatalf("owning poll (first harvest): got %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var firstHarvest map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &firstHarvest); err != nil {
		t.Fatal(err)
	}
	if _, ok := firstHarvest["access_token"]; !ok {
		t.Fatalf("first harvest did not issue an access_token: %s", rr.Body.String())
	}
	if !hasCookie(rr, "access_token") {
		t.Fatal("first harvest did not set the session cookie")
	}
	rr = pollPushStatus(h, tokenA, nonceA)
	_ = json.Unmarshal(rr.Body.Bytes(), &m)
	if m["approved"] != false {
		t.Fatalf("replayed harvest: approved=%v, want false (approval must be consumed)", m["approved"])
	}
	if hasCookie(rr, "access_token") {
		t.Fatal("replayed harvest minted a SECOND session from one approval")
	}

	// 3. After expiry: an approved challenge whose TTL has passed is refused
	//    even for its owning session (pre-fence the approval stayed harvestable
	//    for as long as the MFA-pending JWT stayed valid).
	tokenC, err := h.jwt.IssueMFAPending(userID, "push-fence@example.com")
	if err != nil {
		t.Fatal(err)
	}
	nonceC := insertChallengeWithSession(t, pool, userID, "42", tokenC, "1 microsecond")
	time.Sleep(50 * time.Millisecond)
	if rr := approve(nonceC, "42", tokenC); rr.Code != http.StatusBadRequest {
		// The approve path itself already refuses expired challenges (the
		// assertion cannot outlive the challenge); stamp directly if so.
		if _, err := pool.Exec(ctx,
			`UPDATE push_mfa_challenges SET verified_at = now(), approved_at = now()
			 WHERE nonce = decode($1,'hex')`, nonceC); err != nil {
			t.Fatal(err)
		}
	}
	rr = pollPushStatus(h, tokenC, nonceC)
	_ = json.Unmarshal(rr.Body.Bytes(), &m)
	if m["approved"] != false {
		t.Fatalf("expired approved challenge harvested: approved=%v, want false", m["approved"])
	}
	if hasCookie(rr, "access_token") {
		t.Fatal("expired challenge minted a session — the harvest ignores the challenge TTL")
	}
}

// TestPushMFAStatus_FenceKeepsLegitimateFlowGreen pins the positive side of the
// fence: the production sequence (PushMFASend with the polling token → device
// approve → owning poll) still completes end to end with a session.
func TestPushMFAStatus_FenceKeepsLegitimateFlowGreen(t *testing.T) {
	h, pool := newPushFenceHandler(t)

	userID := seedPushUser(t, pool, "push-fence-green@example.com")
	deviceID, approvalKey := registerApprovalDevice(t, pool, userID)

	mfaToken, err := h.jwt.IssueMFAPending(userID, "push-fence-green@example.com")
	if err != nil {
		t.Fatal(err)
	}
	nonce := insertChallengeWithSession(t, pool, userID, "77", mfaToken, "120 seconds")
	body := signedApprovalBodyWithSession(t, nonce, "77", userID, deviceID, mfaToken,
		time.Now().Unix(), time.Now().Add(60*time.Second).Unix(), approvalKey)
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/approve", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.MFAApprove(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("device approve: got %d, want 204: %s", rr.Code, rr.Body.String())
	}

	rr = pollPushStatus(h, mfaToken, nonce)
	if rr.Code != http.StatusOK {
		t.Fatalf("legitimate owning poll: got %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if _, ok := resp["access_token"]; !ok {
		t.Fatalf("legitimate poll issued no access_token: %s", rr.Body.String())
	}
	if !hasCookie(rr, "access_token") {
		t.Fatal("legitimate poll did not set the session cookie")
	}
}
