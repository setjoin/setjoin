package user

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
)

func TestAutoReply_GetRequiresAuth(t *testing.T) {
	h := NewAutoReplyHandler(nil)
	req := httptest.NewRequest("GET", "/user/automatic-replies", nil) // no auth context
	rr := httptest.NewRecorder()
	h.Get(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestAutoReply_SetRequiresAuth(t *testing.T) {
	h := NewAutoReplyHandler(nil)
	req := httptest.NewRequest("PUT", "/user/automatic-replies", nil) // no auth context
	rr := httptest.NewRecorder()
	h.Set(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestAutoReply_SetRejectsBadJSON(t *testing.T) {
	h := NewAutoReplyHandler(nil)
	req := httptest.NewRequest("PUT", "/user/automatic-replies", bytes.NewReader([]byte("not json")))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 999999})
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	h.Set(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rr.Code)
	}
}

func TestAutoReply_SetRejectsBadAudience(t *testing.T) {
	h := NewAutoReplyHandler(nil)
	body := map[string]interface{}{"enabled": true, "external_audience": "bogus"}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("PUT", "/user/automatic-replies", bytes.NewReader(b))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 999999})
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	h.Set(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad external_audience, got %d — body: %s", rr.Code, rr.Body.String())
	}
}

func TestAutoReply_StructInitialization(t *testing.T) {
	pool := testPool(t)
	h := NewAutoReplyHandler(pool)
	if h.pool != pool {
		t.Error("pool not set correctly")
	}
}

// TestAutoReply_RoundTrip exercises the full PUT → GET path against a real DB.
// Identity (the target mailbox) is derived from the auth context only — never from the
// request body (R2). The body carries reply content/schedule, not identity.
func TestAutoReply_RoundTrip(t *testing.T) {
	pool := testPool(t)
	userID := createTestUser(t, pool)

	// Ensure the user has a primary mailbox (set_vacation keys on mailbox_id).
	var mbID int64
	err := pool.QueryRow(t.Context(),
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		 SELECT u.id, u.domain_id, u.email, u.display_name, 'personal', TRUE
		 FROM users u WHERE u.id = $1
		 RETURNING id`, userID).Scan(&mbID)
	if err != nil {
		t.Fatalf("create primary mailbox: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(t.Context(), `DELETE FROM vacation_settings WHERE mailbox_id = $1`, mbID)
		pool.Exec(t.Context(), `DELETE FROM mailboxes WHERE id = $1`, mbID)
	})

	h := NewAutoReplyHandler(pool)
	ctx := auth.ContextWithUser(t.Context(), &auth.Claims{UserID: userID})

	// PUT
	put := map[string]interface{}{
		"enabled":           true,
		"subject":           "Away",
		"body_internal":     "Internal body",
		"body_external":     "External body",
		"external_audience": "contacts",
	}
	pb, _ := json.Marshal(put)
	preq := httptest.NewRequest("PUT", "/user/automatic-replies", bytes.NewReader(pb)).WithContext(ctx)
	pw := httptest.NewRecorder()
	h.Set(pw, preq)
	if pw.Code != http.StatusOK {
		t.Fatalf("PUT want 200, got %d — body: %s", pw.Code, pw.Body.String())
	}

	// GET
	greq := httptest.NewRequest("GET", "/user/automatic-replies", nil).WithContext(ctx)
	gw := httptest.NewRecorder()
	h.Get(gw, greq)
	if gw.Code != http.StatusOK {
		t.Fatalf("GET want 200, got %d — body: %s", gw.Code, gw.Body.String())
	}
	var got AutoReply
	if err := json.Unmarshal(gw.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode GET: %v", err)
	}
	if !got.Enabled {
		t.Errorf("enabled = false, want true")
	}
	if got.BodyInternal != "Internal body" {
		t.Errorf("body_internal = %q, want %q", got.BodyInternal, "Internal body")
	}
	if got.BodyExternal != "External body" {
		t.Errorf("body_external = %q, want %q", got.BodyExternal, "External body")
	}
	if got.ExternalAudience != "contacts" {
		t.Errorf("external_audience = %q, want contacts", got.ExternalAudience)
	}
}
