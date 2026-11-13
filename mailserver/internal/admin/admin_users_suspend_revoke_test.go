package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/webhook"
	"setjoin.com/shared/pgxutil"
)

// This test covers the admin-console suspend path's IMMEDIACY leg: Update
// with {"enabled":false} must, after the DB commit, fire a best-effort POST
// to the authserver's /auth/scim/disable endpoint (via scim.RevokeAuthSessions
// — the SAME seam SCIM disable/delete use) so a live session is cut close to
// immediately rather than waiting for the refresh-time enabled check (the
// root-cause fix in authserver/internal/token/refresh.go) to be hit on the
// user's next token refresh. Before this fix, suspend flipped users.enabled
// and revoked NOTHING — the caller's session stayed usable until its access
// token naturally expired and every refresh silently renewed it forever.

// fakeAuthServerForSuspend captures POSTs to /auth/scim/disable and reports
// the user_id seen on each.
func fakeAuthServerForSuspend(t *testing.T) (*httptest.Server, <-chan int64) {
	t.Helper()
	revoked := make(chan int64, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/scim/disable" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			UserID int64 `json:"user_id"`
		}
		_ = json.Unmarshal(body, &payload)
		revoked <- payload.UserID
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv, revoked
}

// TestUpdate_Suspend_RevokesAuthSessions verifies that disabling a user via
// the admin console (PATCH {"enabled":false}) triggers a session-revocation
// POST keyed on the target's user id.
func TestUpdate_Suspend_RevokesAuthSessions(t *testing.T) {
	pool := mailboxTestPool(t)
	logger := mailboxTestLogger()
	srv, revoked := fakeAuthServerForSuspend(t)
	h := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: pool}, logger, webhook.NewDispatcher(pool, logger), srv.URL, "test-internal-key")

	domA := ensureScopeTestDomain(t, pool, "suspendtest.example")
	userID := createScopeTestUser(t, pool, domA, "suspendtest.example")

	body := `{"enabled":false}`
	rec := httptest.NewRecorder()
	// Unscoped actor (domain scope 0): scopedReq still wires an authenticated,
	// distinct actor id that admin_protection_check/admin_can_manage accept
	// (see scopedReq's doc comment in admin_users_scope_test.go).
	h.Update(rec, scopedReq(http.MethodPatch, userID, 0, body))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("Update (suspend): want 204, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	select {
	case got := <-revoked:
		if got != userID {
			t.Fatalf("RevokeAuthSessions user_id = %d, want %d", got, userID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("admin suspend did not trigger a session-revocation call to the authserver")
	}
}

// TestUpdate_NonSuspend_DoesNotRevoke verifies a non-disabling update (e.g.
// display name) does NOT fire the revocation call.
func TestUpdate_NonSuspend_DoesNotRevoke(t *testing.T) {
	pool := mailboxTestPool(t)
	logger := mailboxTestLogger()
	srv, revoked := fakeAuthServerForSuspend(t)
	h := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: pool}, logger, webhook.NewDispatcher(pool, logger), srv.URL, "test-internal-key")

	domA := ensureScopeTestDomain(t, pool, "suspendtest.example")
	userID := createScopeTestUser(t, pool, domA, "suspendtest.example")

	body := `{"displayName":"Not A Suspend"}`
	rec := httptest.NewRecorder()
	h.Update(rec, scopedReq(http.MethodPatch, userID, 0, body))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("Update (display name): want 204, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	select {
	case got := <-revoked:
		t.Fatalf("non-disabling update must NOT revoke, but revoked user_id %d", got)
	case <-time.After(500 * time.Millisecond):
		// expected: no revoke
	}
}
