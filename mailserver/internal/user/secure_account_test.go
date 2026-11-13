package user

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
)

// doSecureAccount issues POST /user/sign-ins/secure-account as the given user.
func doSecureAccount(h *SecureAccountHandler, userID int64, jti string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/user/sign-ins/secure-account", strings.NewReader(""))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID, JTI: jti})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.Secure(w, req)
	return w
}

// POST /user/sign-ins/secure-account revokes all the caller's sessions AND sets
// must_change_password — atomically (one tx). A user cannot secure another account.
func TestSecureAccount_RevokesAndFlagsSelf(t *testing.T) {
	pool := testPool(t)
	// We need a sessions handler to use its seeders (same pool, same package).
	sessH := NewSessionsHandler(pool)
	h := NewSecureAccountHandler(pool)

	userA := createTestUser(t, pool)
	userB := createTestUser(t, pool)

	// Seed A: oauth family + web session; must_change_password defaults false.
	_ = seedOAuthFamily(t, sessH, userA, "app-a")
	sessA := seedWebSession(t, sessH, userA)
	// Seed B: untouched oauth family.
	_ = seedOAuthFamily(t, sessH, userB, "app-b")

	// POST as A — body user_id is intentionally absent (self-only; endpoint ignores any body id).
	w := doSecureAccount(h, userA, sessA)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "secured" {
		t.Errorf("expected status=secured, got %q", resp["status"])
	}

	ctx := context.Background()

	// A's oauth tokens must be revoked.
	var activeOAuth int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM oauth_tokens WHERE user_id = $1 AND revoked_at IS NULL`, userA,
	).Scan(&activeOAuth); err != nil {
		t.Fatalf("check oauth: %v", err)
	}
	if activeOAuth != 0 {
		t.Errorf("A's oauth tokens still active: %d", activeOAuth)
	}

	// A's web sessions must be gone.
	var webCount int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM sessions WHERE user_id = $1`, userA,
	).Scan(&webCount); err != nil {
		t.Fatalf("check sessions: %v", err)
	}
	if webCount != 0 {
		t.Errorf("A's sessions still present: %d", webCount)
	}

	// must_change_password must be set for A.
	var mustChange bool
	if err := pool.QueryRow(ctx,
		`SELECT must_change_password FROM users WHERE id = $1`, userA,
	).Scan(&mustChange); err != nil {
		t.Fatalf("check must_change_password: %v", err)
	}
	if !mustChange {
		t.Error("must_change_password not set for A")
	}

	// B's oauth token must still be active (R1: self-only).
	var bActive int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM oauth_tokens WHERE user_id = $1 AND revoked_at IS NULL`, userB,
	).Scan(&bActive); err != nil {
		t.Fatalf("check B oauth: %v", err)
	}
	if bActive != 1 {
		t.Errorf("B's oauth should be untouched, got %d active", bActive)
	}
}

// NO OTHER SESSIONS: a user with no oauth families and only the current session can
// still secure (force-reset alone) — must_change_password=true, 200 (drives the UI's
// security.secure_account.no_sessions soften, not an error).
func TestSecureAccount_NoOtherSessionsStillSecures(t *testing.T) {
	pool := testPool(t)
	sessH := NewSessionsHandler(pool)
	h := NewSecureAccountHandler(pool)

	userA := createTestUser(t, pool)
	sessA := seedWebSession(t, sessH, userA)

	w := doSecureAccount(h, userA, sessA)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var mustChange bool
	if err := pool.QueryRow(context.Background(),
		`SELECT must_change_password FROM users WHERE id = $1`, userA,
	).Scan(&mustChange); err != nil {
		t.Fatalf("check must_change_password: %v", err)
	}
	if !mustChange {
		t.Error("must_change_password not set for single-session user")
	}
}

// ATOMICITY (real same-user rollback): authenticate AS userA — whose oauth token
// + session the tx revokes/deletes in steps 1-2 — then force step 3 to fail by an
// uncastable source ip (RemoteAddr has no host:port → ClientIP returns it verbatim
// → '...'::inet raises inside `SELECT secure_account(...,$2::inet,...)`). The
// already-applied same-user oauth-revoke + session-delete MUST roll back. (The old
// version authenticated as a non-existent user with no rows, so "rows survived"
// proved nothing about rollback — review finding.)
func TestSecureAccount_AtomicRollbackOnFailure(t *testing.T) {
	pool := testPool(t)
	sessH := NewSessionsHandler(pool)
	h := NewSecureAccountHandler(pool)

	userA := createTestUser(t, pool)
	sessA := seedWebSession(t, sessH, userA)
	_ = seedOAuthFamily(t, sessH, userA, "app-roll") // 1 active oauth token

	req := httptest.NewRequest("POST", "/user/sign-ins/secure-account", strings.NewReader(""))
	req.RemoteAddr = "bogus-not-an-ip" // no host:port → ClientIP returns verbatim → $2::inet raises in step 3
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userA, JTI: sessA})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.Secure(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on inet-cast failure, got %d: %s", w.Code, w.Body.String())
	}

	bg := context.Background()
	// Proof 1: step-1 oauth revoke (for userA) rolled back → token active again.
	var activeOAuth int
	if err := pool.QueryRow(bg,
		`SELECT COUNT(*) FROM oauth_tokens WHERE user_id = $1 AND revoked_at IS NULL`, userA,
	).Scan(&activeOAuth); err != nil {
		t.Fatalf("check oauth: %v", err)
	}
	if activeOAuth != 1 {
		t.Errorf("rollback failed: A's oauth revoke not rolled back, active=%d (want 1)", activeOAuth)
	}
	// Proof 2: step-2 session delete (for userA) rolled back → session still present.
	var webCount int
	if err := pool.QueryRow(bg, `SELECT COUNT(*) FROM sessions WHERE id = $1`, sessA).Scan(&webCount); err != nil {
		t.Fatalf("check sessions: %v", err)
	}
	if webCount != 1 {
		t.Errorf("rollback failed: A's session delete not rolled back, count=%d (want 1)", webCount)
	}
	// Proof 3: must_change_password never committed.
	var mustChange bool
	if err := pool.QueryRow(bg, `SELECT must_change_password FROM users WHERE id = $1`, userA).Scan(&mustChange); err != nil {
		t.Fatalf("check flag: %v", err)
	}
	if mustChange {
		t.Error("rollback failed: must_change_password set despite tx failure")
	}
}
