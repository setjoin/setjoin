package user

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/threat"
)

// newDenylistFromDB rebuilds the threat.SessionDenylist from the
// session_revocations table (the same reconcile shape main.go wires in
// production and TestSessions_RevokeAllWritesDenylistRowAndDeniesFutureAccess
// uses) so the tests below assert real gateway-side denial, not just row
// presence.
func newDenylistFromDB(t *testing.T, pool *pgxpool.Pool) *threat.SessionDenylist {
	t.Helper()
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
	}, testLogger())
	if err := dl.Refresh(context.Background()); err != nil {
		t.Fatalf("denylist refresh: %v", err)
	}
	return dl
}

// TestSessions_RevokeIndividualWritesDenylistRowAndDeniesFutureAccess pins the
// individual-revoke closure (occ_cea9ecad3167712dff3b74ab): revoking ONE web
// session through DELETE /user/sessions/{id} must write the CA-3a denylist row
// (scope='jti') in the same transaction that deletes the row, so an access JWT
// already issued for that session is denied once cae_runtime evaluates the
// denylist — not only the row deletion.
func TestSessions_RevokeIndividualWritesDenylistRowAndDeniesFutureAccess(t *testing.T) {
	pool := testPool(t)
	h := NewSessionsHandler(pool)
	ctx := context.Background()

	userA := createTestUser(t, pool)
	userB := createTestUser(t, pool)
	sessA := seedWebSession(t, h, userA)
	sessA2 := seedWebSession(t, h, userA)

	// A's (hypothetical) access token was issued before the revocation.
	issuedBefore := time.Now().Add(-time.Minute)

	req := httptest.NewRequest(http.MethodDelete, "/user/sessions/"+sessA, nil)
	req.SetPathValue("id", sessA)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userA, JTI: sessA2}))
	w := httptest.NewRecorder()
	h.Revoke(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// The session row is gone.
	var rows int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM sessions WHERE id = $1`, sessA,
	).Scan(&rows); err != nil {
		t.Fatalf("check session row: %v", err)
	}
	if rows != 0 {
		t.Fatal("session row still present after individual revoke")
	}

	// The denylist entry exists, scoped to exactly this session's jti.
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM session_revocations WHERE user_id = $1 AND scope = 'jti' AND jti = $2`,
		userA, sessA,
	).Scan(&count); err != nil {
		t.Fatalf("check session_revocations: %v", err)
	}
	if count == 0 {
		t.Fatal("individual revoke wrote no session_revocations scope='jti' row — already-issued access JWTs stay usable (the flagged gap)")
	}

	// Sibling user and sibling session are untouched by the denylist write.
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM session_revocations WHERE user_id = $1`, userB,
	).Scan(&count); err != nil {
		t.Fatalf("check B's revocations: %v", err)
	}
	if count != 0 {
		t.Error("B must have no revocation row from A's individual revoke")
	}

	dl := newDenylistFromDB(t, pool)
	if !dl.IsRevoked(userA, sessA, "", issuedBefore) {
		t.Error("A's token for the revoked session issued before the revoke must be denied once cae_runtime evaluates IsRevoked")
	}
	if dl.IsRevoked(userA, sessA2, "", issuedBefore) {
		t.Error("A's OTHER (still-live) session must not be denied by this individual revocation")
	}
	if dl.IsRevoked(userB, "any-jti", "", issuedBefore) {
		t.Error("B must be unaffected by A's individual revoke")
	}
}

// TestSessions_RevokeOAuthFamilyWritesDenylistRow pins the family arm: going
// through the revoke_user_sessions contract, the family revocation also writes
// the scope='family' denylist entry, so access JWTs bound to that family are
// denied even though the refresh rows are gone.
func TestSessions_RevokeOAuthFamilyWritesDenylistRow(t *testing.T) {
	pool := testPool(t)
	h := NewSessionsHandler(pool)
	ctx := context.Background()

	u := createTestUser(t, pool)
	sessID := seedWebSession(t, h, u)
	rootID, childID, familyID := seedOAuthFamilyWithChild(t, h, u, "mobile")

	issuedBefore := time.Now().Add(-time.Minute)

	req := httptest.NewRequest(http.MethodDelete, "/user/sessions/"+rootID, nil)
	req.SetPathValue("id", rootID)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: u, JTI: sessID}))
	w := httptest.NewRecorder()
	h.Revoke(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var active int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM oauth_tokens WHERE id::text = ANY($1) AND revoked_at IS NULL`,
		[]string{rootID, childID},
	).Scan(&active); err != nil {
		t.Fatalf("check revoked tokens: %v", err)
	}
	if active != 0 {
		t.Fatalf("expected root+child revoked, but %d still active", active)
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM session_revocations WHERE user_id = $1 AND scope = 'family' AND family_id = $2`,
		u, familyID,
	).Scan(&count); err != nil {
		t.Fatalf("check family revocation row: %v", err)
	}
	if count == 0 {
		t.Fatal("family revoke wrote no session_revocations scope='family' row")
	}

	dl := newDenylistFromDB(t, pool)
	if !dl.IsRevoked(u, fmt.Sprintf("access-jti-of-%s", childID), familyID, issuedBefore) {
		t.Error("an access token bound to the revoked family and issued before the revoke must be denied")
	}
	if dl.IsRevoked(u, "unrelated-jti", "some-other-family", issuedBefore) {
		t.Error("an unrelated family must not be denied by this family revocation")
	}
}

// TestSessions_RevokeLegacyFamilylessToken pins the legacy arm: a token with
// no family anchor (pre-V025/seed row) is revoked by the exact-token UPDATE,
// and an ALREADY-revoked family-less token reads as 404 (the RowsAffected==0
// arm — same predicate, no double-write).
func TestSessions_RevokeLegacyFamilylessToken(t *testing.T) {
	pool := testPool(t)
	h := NewSessionsHandler(pool)
	ctx := context.Background()

	u := createTestUser(t, pool)
	sessID := seedWebSession(t, h, u)
	tokenID := seedOAuthFamily(t, h, u, "legacy-client") // family_id NULL

	req := httptest.NewRequest(http.MethodDelete, "/user/sessions/"+tokenID, nil)
	req.SetPathValue("id", tokenID)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: u, JTI: sessID}))
	w := httptest.NewRecorder()
	h.Revoke(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("legacy token revoke returned %d, want 200: %s", w.Code, w.Body.String())
	}
	var revoked bool
	if err := pool.QueryRow(ctx,
		`SELECT revoked_at IS NOT NULL FROM oauth_tokens WHERE id::text = $1 AND user_id = $2`,
		tokenID, u,
	).Scan(&revoked); err != nil {
		t.Fatalf("check token: %v", err)
	}
	if !revoked {
		t.Fatal("legacy token not revoked after individual revoke")
	}

	// Revoking it again: the token no longer matches revoked_at IS NULL → 404.
	req = httptest.NewRequest(http.MethodDelete, "/user/sessions/"+tokenID, nil)
	req.SetPathValue("id", tokenID)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: u, JTI: sessID}))
	w = httptest.NewRecorder()
	h.Revoke(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("re-revoke of a revoked legacy token returned %d, want 404", w.Code)
	}
}

// TestSessions_RevokeFailsClosedWhenPoolUnavailable: an infrastructure failure
// before the contract mutation (pool unusable) surfaces as 500 and mutates
// nothing.
func TestSessions_RevokeFailsClosedWhenPoolUnavailable(t *testing.T) {
	pool := testPool(t)
	h := NewSessionsHandler(pool)
	u := createTestUser(t, pool)
	sessID := seedWebSession(t, h, u)

	pool.Close()

	req := httptest.NewRequest(http.MethodDelete, "/user/sessions/"+sessID, nil)
	req.SetPathValue("id", sessID)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: u, JTI: sessID}))
	w := httptest.NewRecorder()
	h.Revoke(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("revoke with unusable pool returned %d, want 500", w.Code)
	}
}

// TestSessions_RevokeCrossUserStill404: the contract path keeps R3 — a foreign
// session id (web or oauth) is 404 and writes nothing.
func TestSessions_RevokeCrossUserStill404(t *testing.T) {
	pool := testPool(t)
	h := NewSessionsHandler(pool)
	ctx := context.Background()

	userA := createTestUser(t, pool)
	userB := createTestUser(t, pool)
	sessB := seedWebSession(t, h, userB)
	oauthB := seedOAuthFamily(t, h, userB, "b-client")
	sessA := seedWebSession(t, h, userA)

	for _, target := range []string{sessB, oauthB} {
		req := httptest.NewRequest(http.MethodDelete, "/user/sessions/"+target, nil)
		req.SetPathValue("id", target)
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userA, JTI: sessA}))
		w := httptest.NewRecorder()
		h.Revoke(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("cross-user revoke of %s returned %d, want 404", target, w.Code)
		}
	}

	// Nothing was written for A, and B's rows survive.
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM session_revocations WHERE user_id = $1`, userA,
	).Scan(&count); err != nil {
		t.Fatalf("check A's revocations: %v", err)
	}
	if count != 0 {
		t.Errorf("A gained %d revocation rows from refused cross-user revokes, want 0", count)
	}
	var liveB int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM sessions WHERE id = $1`, sessB,
	).Scan(&liveB); err != nil {
		t.Fatalf("check B session: %v", err)
	}
	if liveB != 1 {
		t.Error("B's web session was deleted by A's refused revoke")
	}
}
