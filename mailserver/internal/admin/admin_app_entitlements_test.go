package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestNewAppEntitlementHandler confirms the constructor does not panic.
func TestNewAppEntitlementHandler(t *testing.T) {
	h := NewAppEntitlementHandler(nil, nil)
	if h == nil {
		t.Fatal("NewAppEntitlementHandler returned nil")
	}
}

// TestAppEntitlementListBadID asserts List returns 400 for a non-numeric user id.
func TestAppEntitlementListBadID(t *testing.T) {
	h := NewAppEntitlementHandler(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/admin/users/abc/app-access", nil)
	req.SetPathValue("id", "abc")
	w := httptest.NewRecorder()
	h.List(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// TestAppEntitlementSetBadID asserts Set returns 400 for a non-numeric user id.
func TestAppEntitlementSetBadID(t *testing.T) {
	h := NewAppEntitlementHandler(nil, nil)
	body := bytes.NewBufferString(`{"enabled":true}`)
	req := httptest.NewRequest(http.MethodPut, "/admin/users/abc/app-access/calendar", body)
	req.SetPathValue("id", "abc")
	req.SetPathValue("app", "calendar")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Set(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// TestAppEntitlementSetUnknownApp asserts Set returns 422 for an unknown app name.
func TestAppEntitlementSetUnknownApp(t *testing.T) {
	h := NewAppEntitlementHandler(nil, nil)
	body := bytes.NewBufferString(`{"enabled":true}`)
	req := httptest.NewRequest(http.MethodPut, "/admin/users/1/app-access/files", body)
	req.SetPathValue("id", "1")
	req.SetPathValue("app", "files")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Set(w, req)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for unknown app, got %d", w.Code)
	}
	var prob struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &prob); err != nil {
		t.Fatalf("could not parse problem response: %v", err)
	}
	if prob.Type != "https://setjoin.com/errors/validation-failed" {
		t.Fatalf("expected validation-failed type, got %q", prob.Type)
	}
}

func TestAppEntitlementMemberCatalogGETAndPUT(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewAppEntitlementHandler(pool, mailboxTestLogger())
	domainID := ensureScopeTestDomain(t, pool, "appcatalog.example")
	targetID := createScopeTestUser(t, pool, domainID, "appcatalog.example")
	adminID := createScopeTestUser(t, pool, domainID, "appcatalog.example")
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM user_app_entitlements WHERE user_id=$1`, targetID)
	})

	getReq := httptest.NewRequest(http.MethodGet, "/admin/users/1/app-access", nil)
	getReq.SetPathValue("id", fmt.Sprintf("%d", targetID))
	getReq = adminClaimsCtx(getReq, adminID, 0)
	getRec := httptest.NewRecorder()
	h.List(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", getRec.Code, getRec.Body.String())
	}
	var got []appEntitlementRow
	if err := json.Unmarshal(getRec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode GET: %v", err)
	}
	want := []string{"mail", "calendar", "contacts", "tasks", "chat", "drive", "meet"}
	if len(got) != len(want) {
		t.Fatalf("GET returned %d apps, want %d: %#v", len(got), len(want), got)
	}
	for i, app := range want {
		if got[i].App != app || !got[i].Enabled {
			t.Errorf("GET row %d=%+v, want app=%q default enabled", i, got[i], app)
		}
	}

	putReq := httptest.NewRequest(http.MethodPut, "/admin/users/1/app-access/chat", bytes.NewBufferString(`{"enabled":false}`))
	putReq.SetPathValue("id", fmt.Sprintf("%d", targetID))
	putReq.SetPathValue("app", "chat")
	putReq = adminClaimsCtx(putReq, adminID, 0)
	putRec := httptest.NewRecorder()
	h.Set(putRec, putReq)
	if putRec.Code != http.StatusNoContent {
		t.Fatalf("PUT chat status=%d body=%s", putRec.Code, putRec.Body.String())
	}
	var enabled bool
	if err := pool.QueryRow(ctx,
		`SELECT enabled FROM user_app_entitlements WHERE user_id=$1 AND app='chat'`, targetID,
	).Scan(&enabled); err != nil {
		t.Fatalf("read stored Chat entitlement: %v", err)
	}
	if enabled {
		t.Fatal("PUT chat=false did not persist the member entitlement")
	}
}

func TestAppEntitlementGuestGETIsDerivedAndPUTReturnsClassifiedConflict(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewAppEntitlementHandler(pool, mailboxTestLogger())
	domainID := ensureScopeTestDomain(t, pool, "appguest.example")
	foreignDomainID := ensureScopeTestDomain(t, pool, "appguest-foreign.example")
	adminID := createScopeTestUser(t, pool, domainID, "appguest.example")
	ctx := context.Background()
	email := fmt.Sprintf("appguest-%d@external.example", time.Now().UnixNano())
	var guestID int64
	if err := pool.QueryRow(ctx, `INSERT INTO users(username,domain_id,email,display_name,enabled)
		SELECT $1,id,$1,'Guest',true FROM domains WHERE name='guest.invalid' RETURNING id`, email).Scan(&guestID); err != nil {
		t.Fatalf("insert guest user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM user_app_entitlements WHERE user_id=$1`, guestID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM guest_accounts WHERE user_id=$1`, guestID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, guestID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO guest_accounts
		(user_id,invited_email,invited_by_email,host_domain_id,status,expires_at)
		VALUES($1,$2,'admin@appguest.example',$3,'active',now()+interval '1 day')`, guestID, email, domainID); err != nil {
		t.Fatalf("insert guest satellite: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO user_app_entitlements(user_id,app,enabled,updated_by)
		VALUES($1,'chat',true,$2)`, guestID, adminID); err != nil {
		t.Fatalf("insert derived guest entitlement: %v", err)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/admin/users/1/app-access", nil)
	getReq.SetPathValue("id", fmt.Sprintf("%d", guestID))
	getReq = adminClaimsCtx(getReq, adminID, domainID)
	getRec := httptest.NewRecorder()
	h.List(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("guest GET status=%d body=%s", getRec.Code, getRec.Body.String())
	}
	var rows []appEntitlementRow
	if err := json.Unmarshal(getRec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode guest GET: %v", err)
	}
	if len(rows) != 7 {
		t.Fatalf("guest GET returned %d apps, want seven derived rows", len(rows))
	}
	for _, row := range rows {
		wantEnabled := row.App == "chat"
		if row.Enabled != wantEnabled {
			t.Errorf("guest GET row %q enabled=%v, want %v (only explicit Chat grant is enabled)",
				row.App, row.Enabled, wantEnabled)
		}
	}

	foreignGetReq := httptest.NewRequest(http.MethodGet, "/admin/users/1/app-access", nil)
	foreignGetReq.SetPathValue("id", fmt.Sprintf("%d", guestID))
	foreignGetReq = adminClaimsCtx(foreignGetReq, adminID, foreignDomainID)
	foreignGetRec := httptest.NewRecorder()
	h.List(foreignGetRec, foreignGetReq)
	if foreignGetRec.Code != http.StatusOK {
		t.Fatalf("foreign-scope guest GET status=%d body=%s", foreignGetRec.Code, foreignGetRec.Body.String())
	}
	var foreignRows []appEntitlementRow
	if err := json.Unmarshal(foreignGetRec.Body.Bytes(), &foreignRows); err != nil {
		t.Fatalf("decode foreign-scope guest GET: %v", err)
	}
	if len(foreignRows) != len(appEntitlementOrder) {
		t.Fatalf("foreign-scope guest GET returned %d apps, want %d", len(foreignRows), len(appEntitlementOrder))
	}
	for _, row := range foreignRows {
		if !row.Enabled {
			t.Errorf("foreign-scope guest GET leaked guest default-deny through %q", row.App)
		}
	}

	putReq := httptest.NewRequest(http.MethodPut, "/admin/users/1/app-access/chat", bytes.NewBufferString(`{"enabled":false}`))
	putReq.SetPathValue("id", fmt.Sprintf("%d", guestID))
	putReq.SetPathValue("app", "chat")
	putReq = adminClaimsCtx(putReq, adminID, domainID)
	putRec := httptest.NewRecorder()
	h.Set(putRec, putReq)
	if putRec.Code != http.StatusConflict {
		t.Fatalf("guest PUT status=%d, want 409; body=%s", putRec.Code, putRec.Body.String())
	}
	var enabled bool
	if err := pool.QueryRow(ctx,
		`SELECT enabled FROM user_app_entitlements WHERE user_id=$1 AND app='chat'`, guestID,
	).Scan(&enabled); err != nil {
		t.Fatalf("read guest entitlement after refused PUT: %v", err)
	}
	if !enabled {
		t.Fatal("BZ226 guest PUT mutated the profile-derived entitlement")
	}

	foreignPutReq := httptest.NewRequest(http.MethodPut, "/admin/users/1/app-access/chat", bytes.NewBufferString(`{"enabled":false}`))
	foreignPutReq.SetPathValue("id", fmt.Sprintf("%d", guestID))
	foreignPutReq.SetPathValue("app", "chat")
	foreignPutReq = adminClaimsCtx(foreignPutReq, adminID, foreignDomainID)
	foreignPutRec := httptest.NewRecorder()
	h.Set(foreignPutRec, foreignPutReq)
	if foreignPutRec.Code != http.StatusNotFound {
		t.Fatalf("foreign-scope guest PUT status=%d, want 404; body=%s", foreignPutRec.Code, foreignPutRec.Body.String())
	}
	if err := pool.QueryRow(ctx,
		`SELECT enabled FROM user_app_entitlements WHERE user_id=$1 AND app='chat'`, guestID,
	).Scan(&enabled); err != nil {
		t.Fatalf("read guest entitlement after foreign-scope PUT: %v", err)
	}
	if !enabled {
		t.Fatal("foreign-scope guest PUT mutated the profile-derived entitlement")
	}
}

// TestAppEntitlementSetMissingBody asserts Set returns 400 for a missing/malformed body.
func TestAppEntitlementSetMissingBody(t *testing.T) {
	h := NewAppEntitlementHandler(nil, nil)
	req := httptest.NewRequest(http.MethodPut, "/admin/users/1/app-access/calendar", nil)
	req.SetPathValue("id", "1")
	req.SetPathValue("app", "calendar")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Set(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing body, got %d", w.Code)
	}
}
