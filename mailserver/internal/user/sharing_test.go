package user

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

// createTestUserWithMailbox seeds a user + their primary mailbox and returns
// (userID, mailboxID, email). Cleanup cascades through the mailbox FK.
func createTestUserWithMailbox(t *testing.T, pool *pgxpool.Pool) (int64, int64, string) {
	t.Helper()
	ctx := context.Background()
	domainID := ensureTestDomain(t, pool)
	if domainID == 0 {
		t.Skip("test DB has no domains table")
	}
	userID := createTestUser(t, pool)
	var email string
	if err := pool.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, userID).Scan(&email); err != nil {
		t.Fatalf("read user email: %v", err)
	}
	var mbID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		 VALUES ($1, $2, $3, 'Sharing Test', 'personal', TRUE) RETURNING id`,
		userID, domainID, email).Scan(&mbID)
	if err != nil {
		t.Fatalf("create mailbox: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM mailbox_delegates WHERE mailbox_id = $1`, mbID)
		pool.Exec(context.Background(), `DELETE FROM sharing_defaults WHERE owner_scope = 'user' AND owner_ref = $1`, userID)
		pool.Exec(context.Background(), `DELETE FROM mailboxes WHERE id = $1`, mbID)
	})
	return userID, mbID, email
}

func sharingTestHandler(t *testing.T, pool *pgxpool.Pool) *SharingHandler {
	t.Helper()
	return NewSharingHandler(pgxutil.WorkerPool{Pool: pool}, toggle.NewTestFlags(map[string]bool{}), testLogger())
}

func authedReq(method, path, body string, userID int64) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	claims := &auth.Claims{UserID: userID}
	return req.WithContext(auth.ContextWithUser(req.Context(), claims))
}

func TestSharing_Unauthenticated(t *testing.T) {
	pool := testPool(t)
	h := sharingTestHandler(t, pool)
	for _, tc := range []struct {
		name string
		fn   http.HandlerFunc
	}{
		{"overview", h.Overview},
		{"grant", h.GrantDelegate},
		{"revoke", h.RevokeDelegate},
		{"setDefault", h.SetDefault},
		{"clearDefault", h.ClearDefault},
	} {
		rec := httptest.NewRecorder()
		tc.fn(rec, httptest.NewRequest("GET", "/me/sharing", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: want 401, got %d", tc.name, rec.Code)
		}
	}
}

func TestSharingDelegates_GrantListRevoke(t *testing.T) {
	pool := testPool(t)
	h := sharingTestHandler(t, pool)
	ownerID, mbID, _ := createTestUserWithMailbox(t, pool)
	granteeID, _, granteeEmail := createTestUserWithMailbox(t, pool)

	// grant
	rec := httptest.NewRecorder()
	h.GrantDelegate(rec, authedReq("POST", "/me/sharing/delegates",
		fmt.Sprintf(`{"granteeEmail":%q,"permission":"send_as"}`, granteeEmail), ownerID))
	if rec.Code != http.StatusCreated {
		t.Fatalf("grant: want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM mailbox_delegates WHERE mailbox_id = $1 AND user_id = $2 AND permission = 'send_as'`,
		mbID, granteeID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("delegate row missing: n=%d err=%v", n, err)
	}

	// overview lists the delegate
	rec = httptest.NewRecorder()
	h.Overview(rec, authedReq("GET", "/me/sharing", "", ownerID))
	if rec.Code != http.StatusOK {
		t.Fatalf("overview: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var ov struct {
		Delegates []struct {
			UserID     int64  `json:"userId"`
			Email      string `json:"email"`
			Permission string `json:"permission"`
		} `json:"delegates"`
		DefaultsEnabled bool `json:"defaultsEnabled"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ov); err != nil {
		t.Fatalf("overview decode: %v", err)
	}
	if len(ov.Delegates) != 1 || ov.Delegates[0].Email != granteeEmail || ov.Delegates[0].Permission != "send_as" {
		t.Fatalf("overview delegates wrong: %+v", ov.Delegates)
	}
	if ov.DefaultsEnabled {
		t.Fatal("defaultsEnabled must be false with the toggle off")
	}

	// revoke
	req := authedReq("DELETE", "/me/sharing/delegates/x", "", ownerID)
	req.SetPathValue("userId", fmt.Sprint(granteeID))
	rec = httptest.NewRecorder()
	h.RevokeDelegate(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: want 204, got %d (%s)", rec.Code, rec.Body.String())
	}
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM mailbox_delegates WHERE mailbox_id = $1 AND user_id = $2`,
		mbID, granteeID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("delegate row not removed: n=%d err=%v", n, err)
	}
}

func TestSharingGrant_BadInput(t *testing.T) {
	pool := testPool(t)
	h := sharingTestHandler(t, pool)
	ownerID, _, _ := createTestUserWithMailbox(t, pool)

	// unknown grantee → 404 (BZ114, indistinguishable)
	rec := httptest.NewRecorder()
	h.GrantDelegate(rec, authedReq("POST", "/me/sharing/delegates",
		`{"granteeEmail":"nobody-here@setjoin.test","permission":"send_as"}`, ownerID))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown grantee: want 404, got %d (%s)", rec.Code, rec.Body.String())
	}

	// invalid permission → 400 (BZ115)
	rec = httptest.NewRecorder()
	h.GrantDelegate(rec, authedReq("POST", "/me/sharing/delegates",
		`{"granteeEmail":"nobody-here@setjoin.test","permission":"root"}`, ownerID))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid permission: want 400, got %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestSharingDefault_SetClearRoundtrip(t *testing.T) {
	pool := testPool(t)
	h := sharingTestHandler(t, pool)
	ownerID, _, _ := createTestUserWithMailbox(t, pool)

	// invalid level → 400 (BZ117)
	rec := httptest.NewRecorder()
	h.SetDefault(rec, authedReq("PUT", "/me/sharing/default", `{"audience":"everyone","level":"admin"}`, ownerID))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid level: want 400, got %d (%s)", rec.Code, rec.Body.String())
	}

	// set (audienceRef omitted for everyone → own domain)
	rec = httptest.NewRecorder()
	h.SetDefault(rec, authedReq("PUT", "/me/sharing/default", `{"audience":"everyone","level":"freebusy"}`, ownerID))
	if rec.Code != http.StatusOK {
		t.Fatalf("set default: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.ID == 0 {
		t.Fatalf("set default response: %v (%s)", err, rec.Body.String())
	}

	// overview surfaces it
	rec = httptest.NewRecorder()
	h.Overview(rec, authedReq("GET", "/me/sharing", "", ownerID))
	var ov struct {
		MyDefaults []struct {
			ID    int64  `json:"id"`
			Level string `json:"level"`
		} `json:"myDefaults"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ov); err != nil {
		t.Fatalf("overview decode: %v", err)
	}
	if len(ov.MyDefaults) != 1 || ov.MyDefaults[0].ID != resp.ID || ov.MyDefaults[0].Level != "freebusy" {
		t.Fatalf("overview myDefaults wrong: %+v", ov.MyDefaults)
	}

	// clear
	req := authedReq("DELETE", "/me/sharing/default/x", "", ownerID)
	req.SetPathValue("id", fmt.Sprint(resp.ID))
	rec = httptest.NewRecorder()
	h.ClearDefault(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("clear: want 204, got %d (%s)", rec.Code, rec.Body.String())
	}

	// clearing someone else's row is 404/403 — a second user cannot clear mine
	otherID, _, _ := createTestUserWithMailbox(t, pool)
	rec = httptest.NewRecorder()
	h.SetDefault(rec, authedReq("PUT", "/me/sharing/default", `{"audience":"everyone","level":"none"}`, ownerID))
	if rec.Code != http.StatusOK {
		t.Fatalf("re-set default: want 200, got %d", rec.Code)
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	req = authedReq("DELETE", "/me/sharing/default/x", "", otherID)
	req.SetPathValue("id", fmt.Sprint(resp.ID))
	rec = httptest.NewRecorder()
	h.ClearDefault(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("foreign clear: want 403, got %d (%s)", rec.Code, rec.Body.String())
	}
}
