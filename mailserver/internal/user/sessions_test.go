package user

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/threat"
)

// seedWebSession inserts a sessions row and returns its id.
func seedWebSession(t *testing.T, h *SessionsHandler, userID int64) string {
	t.Helper()
	ctx := context.Background()
	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO sessions (user_id, expires_at, auth_method)
		 VALUES ($1, now() + interval '1 hour', 'password')
		 RETURNING id`,
		userID,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seedWebSession: %v", err)
	}
	return id
}

// seedOAuthFamily inserts a root refresh oauth_token and returns its id as a string.
func seedOAuthFamily(t *testing.T, h *SessionsHandler, userID int64, clientID string) string {
	t.Helper()
	ctx := context.Background()
	// unique token hash to satisfy the UNIQUE constraint
	hash := sha256.Sum256([]byte("seed-token-" + clientID + "-" + randomSuffix(t)))
	var id int64
	err := h.pool.QueryRow(ctx,
		`INSERT INTO oauth_tokens (user_id, client_id, token_hash, token_type, expires_at)
		 VALUES ($1, $2, $3, 'refresh', now() + interval '30 days')
		 RETURNING id`,
		userID, clientID, hash[:],
	).Scan(&id)
	if err != nil {
		t.Fatalf("seedOAuthFamily: %v", err)
	}
	return fmt.Sprintf("%d", id)
}

// seedOAuthFamilyWithChild inserts a root token (family_id set via gen_random_uuid()) +
// one rotated child token (previous_token_hash = root's hash, same family_id) and
// returns the root token id, child token id, and family_id as strings.
// The child simulates a post-rotation leaf that should also be revoked when the root is.
func seedOAuthFamilyWithChild(t *testing.T, h *SessionsHandler, userID int64, clientID string) (rootID string, childID string, familyID string) {
	t.Helper()
	ctx := context.Background()
	rootHash := sha256.Sum256([]byte("root-" + clientID + "-" + randomSuffix(t)))
	var rid int64
	err := h.pool.QueryRow(ctx,
		`INSERT INTO oauth_tokens (user_id, client_id, token_hash, token_type, expires_at, family_id)
		 VALUES ($1, $2, $3, 'refresh', now() + interval '30 days', gen_random_uuid())
		 RETURNING id, family_id::text`,
		userID, clientID, rootHash[:],
	).Scan(&rid, &familyID)
	if err != nil {
		t.Fatalf("seedOAuthFamilyWithChild root: %v", err)
	}
	childHash := sha256.Sum256([]byte("child-" + clientID + "-" + randomSuffix(t)))
	var cid int64
	err = h.pool.QueryRow(ctx,
		`INSERT INTO oauth_tokens (user_id, client_id, token_hash, token_type, expires_at, family_id, previous_token_hash)
		 VALUES ($1, $2, $3, 'refresh', now() + interval '30 days', $4::uuid, $5)
		 RETURNING id`,
		userID, clientID, childHash[:], familyID, rootHash[:],
	).Scan(&cid)
	if err != nil {
		t.Fatalf("seedOAuthFamilyWithChild child: %v", err)
	}
	return fmt.Sprintf("%d", rid), fmt.Sprintf("%d", cid), familyID
}

// doSessionsRequest issues a GET /user/sessions request with the given auth context.
func doSessionsRequest(h *SessionsHandler, userID int64, jti string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/user/sessions", nil)
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID, JTI: jti})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.List(w, req)
	return w
}

// ── R1 + revoke-other-user-404 ────────────────────────────────────────────────

// GET /user/sessions returns only the caller's sessions and flags the current one;
// DELETE /user/sessions/{id} cannot revoke another user's session (R3 → 404).
func TestSessions_ListR1AndRevokeOwnership(t *testing.T) {
	pool := testPool(t)
	h := NewSessionsHandler(pool)

	userA := createTestUser(t, pool)
	userB := createTestUser(t, pool)

	sessA := seedWebSession(t, h, userA)
	_ = seedOAuthFamily(t, h, userA, "client-a")
	sessB := seedWebSession(t, h, userB)

	// As A: list → 2 rows (1 web + 1 oauth), B's session absent.
	w := doSessionsRequest(h, userA, sessA)
	if w.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Sessions []struct {
			ID      string `json:"id"`
			Kind    string `json:"kind"`
			Current bool   `json:"current"`
		} `json:"sessions"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Sessions) != 2 {
		t.Fatalf("R1: expected 2 sessions for userA, got %d", len(resp.Sessions))
	}
	for _, s := range resp.Sessions {
		if s.ID == sessB {
			t.Error("R1 violated: B's session leaked into A's list")
		}
	}

	// current flag on the presenting web session
	currentCount := 0
	for _, s := range resp.Sessions {
		if s.Current {
			currentCount++
		}
	}
	if currentCount != 1 {
		t.Errorf("expected 1 current row, got %d", currentCount)
	}

	// As A: DELETE B's web session → 404 (R3 ownership)
	req := httptest.NewRequest("DELETE", "/user/sessions/"+sessB, nil)
	req.SetPathValue("id", sessB)
	rctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userA, JTI: sessA})
	req = req.WithContext(rctx)
	w2 := httptest.NewRecorder()
	h.Revoke(w2, req)
	if w2.Code != http.StatusNotFound {
		t.Errorf("R3: expected 404 on cross-user revoke, got %d", w2.Code)
	}
}

// ── EMPTY / only current ──────────────────────────────────────────────────────

// A user with only the current web session returns exactly one row, current=true.
func TestSessions_OnlyCurrent(t *testing.T) {
	pool := testPool(t)
	h := NewSessionsHandler(pool)
	u := createTestUser(t, pool)

	sessID := seedWebSession(t, h, u)

	w := doSessionsRequest(h, u, sessID)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Sessions []struct {
			Current bool `json:"current"`
		} `json:"sessions"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(resp.Sessions))
	}
	if !resp.Sessions[0].Current {
		t.Error("only session should be current=true")
	}
}

// ── current flag across kinds ─────────────────────────────────────────────────

// The row whose id == presenting JTI is current=true; oauth families are current=false.
func TestSessions_CurrentFlagAcrossKinds(t *testing.T) {
	pool := testPool(t)
	h := NewSessionsHandler(pool)
	u := createTestUser(t, pool)

	sessID := seedWebSession(t, h, u)
	_ = seedOAuthFamily(t, h, u, "mobile-client")

	w := doSessionsRequest(h, u, sessID)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Sessions []struct {
			Kind    string `json:"kind"`
			Current bool   `json:"current"`
		} `json:"sessions"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(resp.Sessions))
	}
	webCurrent := 0
	for _, s := range resp.Sessions {
		if s.Kind == "web" && s.Current {
			webCurrent++
		}
		if s.Kind == "oauth" && s.Current {
			t.Error("oauth session should not be current")
		}
	}
	if webCurrent != 1 {
		t.Errorf("expected 1 current web session, got %d", webCurrent)
	}
}

// ── REVOKE-CURRENT ────────────────────────────────────────────────────────────

// Deleting the presenting session succeeds; the row is gone.
func TestSessions_RevokeCurrentSucceeds(t *testing.T) {
	pool := testPool(t)
	h := NewSessionsHandler(pool)
	u := createTestUser(t, pool)

	sessID := seedWebSession(t, h, u)

	req := httptest.NewRequest("DELETE", "/user/sessions/"+sessID, nil)
	req.SetPathValue("id", sessID)
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: u, JTI: sessID})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.Revoke(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Row must be gone
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM sessions WHERE id = $1`, sessID,
	).Scan(&count); err != nil {
		t.Fatalf("check row: %v", err)
	}
	if count != 0 {
		t.Errorf("session row still present after revoke")
	}
}

// ── REVOKE oauth family (findings 2+3) ───────────────────────────────────────

// Revoking a root token must also revoke rotated children in the same family.
// Before the fix: only the root row was marked revoked; the child (held by the
// client after rotation) kept revoked_at IS NULL and could refresh indefinitely.
func TestSessions_RevokeOAuthKillsFamily(t *testing.T) {
	pool := testPool(t)
	h := NewSessionsHandler(pool)
	u := createTestUser(t, pool)
	sessID := seedWebSession(t, h, u)

	rootID, childID, _ := seedOAuthFamilyWithChild(t, h, u, "mobile")

	// Revoke via root id (what the UI sends — the list exposes the root).
	req := httptest.NewRequest("DELETE", "/user/sessions/"+rootID, nil)
	req.SetPathValue("id", rootID)
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: u, JTI: sessID})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.Revoke(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Both root AND child must now have revoked_at set.
	var active int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM oauth_tokens WHERE id = ANY($1::bigint[]) AND revoked_at IS NULL`,
		[]string{rootID, childID},
	).Scan(&active); err != nil {
		t.Fatalf("check revoked: %v", err)
	}
	if active != 0 {
		t.Errorf("expected both root+child revoked, but %d still active", active)
	}
}

// ── REVOKE-ALL ────────────────────────────────────────────────────────────────

// revoke-all marks every oauth family revoked and deletes every web session
// for the caller; other users are untouched.
func TestSessions_RevokeAllScopedToCaller(t *testing.T) {
	pool := testPool(t)
	h := NewSessionsHandler(pool)

	userA := createTestUser(t, pool)
	userB := createTestUser(t, pool)

	// Seed A: 2 oauth families + 1 web session
	seedOAuthFamily(t, h, userA, "app1")
	seedOAuthFamily(t, h, userA, "app2")
	sessA := seedWebSession(t, h, userA)

	// Seed B: 1 oauth family
	_ = seedOAuthFamily(t, h, userB, "b-app")

	req := httptest.NewRequest("POST", "/user/sessions/revoke-all", strings.NewReader(""))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userA, JTI: sessA})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.RevokeAll(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// A's web sessions gone
	var webCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM sessions WHERE user_id = $1`, userA,
	).Scan(&webCount); err != nil {
		t.Fatalf("check web sessions: %v", err)
	}
	if webCount != 0 {
		t.Errorf("expected A's web sessions gone, got %d", webCount)
	}

	// A's oauth tokens revoked
	var activeOAuth int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM oauth_tokens WHERE user_id = $1 AND revoked_at IS NULL`, userA,
	).Scan(&activeOAuth); err != nil {
		t.Fatalf("check oauth: %v", err)
	}
	if activeOAuth != 0 {
		t.Errorf("expected A's oauth tokens revoked, got %d active", activeOAuth)
	}

	// B's oauth token still active
	var bActive int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM oauth_tokens WHERE user_id = $1 AND revoked_at IS NULL`, userB,
	).Scan(&bActive); err != nil {
		t.Fatalf("check B oauth: %v", err)
	}
	if bActive != 1 {
		t.Errorf("expected B's oauth token still active, got %d", bActive)
	}
}

// ── REVOKE-ALL writes the CA-3a denylist (web-session-revoke Tier 1) ─────────

// RevokeAll must also insert a session_revocations scope='all' row for the
// caller, so a still-valid stateless web JWT is actually denied once
// feature.cae_runtime is ON (verified here directly against a real
// threat.SessionDenylist fed from the DB — the same reconcile shape
// cmd/mailserverd/main.go wires in production). A sibling user's session must
// be entirely unaffected.
func TestSessions_RevokeAllWritesDenylistRowAndDeniesFutureAccess(t *testing.T) {
	pool := testPool(t)
	h := NewSessionsHandler(pool)
	ctx := context.Background()

	userA := createTestUser(t, pool)
	userB := createTestUser(t, pool)
	sessA := seedWebSession(t, h, userA)

	// A's (hypothetical) access token was issued before the revoke-all call.
	loginAt := time.Now().Add(-time.Minute)

	req := httptest.NewRequest("POST", "/user/sessions/revoke-all", strings.NewReader(""))
	rctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userA, JTI: sessA})
	req = req.WithContext(rctx)
	w := httptest.NewRecorder()
	h.RevokeAll(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM session_revocations WHERE user_id = $1 AND scope = 'all'`, userA,
	).Scan(&count); err != nil {
		t.Fatalf("check session_revocations: %v", err)
	}
	if count == 0 {
		t.Fatal("expected a session_revocations scope='all' row for the caller after RevokeAll")
	}
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM session_revocations WHERE user_id = $1`, userB,
	).Scan(&count); err != nil {
		t.Fatalf("check B's session_revocations: %v", err)
	}
	if count != 0 {
		t.Error("B must have no session_revocations row from A's RevokeAll")
	}

	// Build a real SessionDenylist from the DB — mirrors main.go's reconcile query.
	dl := threat.NewSessionDenylist(func(rctx context.Context) ([]threat.RevocationRow, error) {
		rows, err := pool.Query(rctx,
			`SELECT user_id, scope, COALESCE(jti,''), COALESCE(family_id,''), not_before
			   FROM session_revocations
			  WHERE expires_at IS NULL OR expires_at > now()`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []threat.RevocationRow
		for rows.Next() {
			var rr threat.RevocationRow
			if err := rows.Scan(&rr.UserID, &rr.Scope, &rr.JTI, &rr.FamilyID, &rr.NotBefore); err != nil {
				return nil, err
			}
			out = append(out, rr)
		}
		return out, rows.Err()
	}, slog.Default())
	if err := dl.Refresh(ctx); err != nil {
		t.Fatalf("denylist refresh: %v", err)
	}

	if !dl.IsRevoked(userA, "any-jti-issued-before-revoke", "", loginAt) {
		t.Error("A's token issued before RevokeAll must be denied once cae_runtime evaluates IsRevoked")
	}
	if dl.IsRevoked(userB, "b-jti", "", loginAt) {
		t.Error("B's session must be unaffected by A's RevokeAll")
	}
}
