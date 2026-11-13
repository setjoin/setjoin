package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/testsupport"
	wh "setjoin.com/shared/webhook"
)

// testWebhookCodec seals secrets the same way production wires the handler
// (V260 at-rest contract); Create/RotateSecret fail closed without it.
func testWebhookCodec() *wh.SecretCodec {
	return wh.NewSecretCodec([]byte("admin-webhook-test-master-key"), cryptokey.ProfileStandard)
}

// createTestWebhook seeds a webhook subscription via the REAL Create handler
// (so id/secret/event_types match production shape exactly) and returns its
// id. Cleanup deletes the row (cascades to webhook_deliveries).
func createTestWebhook(t *testing.T, h *WebhooksHandler, pool *pgxpool.Pool, userID int64, eventTypes []string) int64 {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"url":        "https://example.invalid/hook",
		"eventTypes": eventTypes,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/webhooks", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("webhook Create: want 201, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode webhook create response: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM webhook_subscriptions WHERE id = $1`, created.ID)
	})
	return created.ID
}

// TestAdminWebhooksList_EventTypesFieldName pins the JSON key on each List
// item: it must be "eventTypes" (camelCase, matching every other admin API
// response), not the DB column name "events" (admin_webhooks.go List).
func TestAdminWebhooksList_EventTypesFieldName(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewWebhooksHandler(pool, testsupport.TestLogger(), testWebhookCodec())
	userID := seedUser(t, pool)

	wantTypes := []string{"mail.received", "mail.sent"}
	webhookID := createTestWebhook(t, h, pool, userID, wantTypes)

	req := httptest.NewRequest(http.MethodGet, "/admin/webhooks", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("List: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode list as array of objects: %v (body=%s)", err, rec.Body.String())
	}
	var found bool
	for _, item := range raw {
		var id int64
		if err := json.Unmarshal(item["id"], &id); err != nil || id != webhookID {
			continue
		}
		found = true
		etRaw, ok := item["eventTypes"]
		if !ok {
			t.Fatalf(`webhook %d: item missing "eventTypes" key (body=%s)`, webhookID, rec.Body.String())
		}
		if _, ok := item["events"]; ok {
			t.Errorf(`webhook %d: item must not use the old "events" key`, webhookID)
		}
		var got []string
		if err := json.Unmarshal(etRaw, &got); err != nil {
			t.Fatalf(`"eventTypes" is not a string array: %v`, err)
		}
		if len(got) != len(wantTypes) {
			t.Fatalf("eventTypes = %v, want %v", got, wantTypes)
		}
		for i := range wantTypes {
			if got[i] != wantTypes[i] {
				t.Errorf("eventTypes[%d] = %q, want %q", i, got[i], wantTypes[i])
			}
		}
	}
	if !found {
		t.Fatalf("seeded webhook %d not found in List response", webhookID)
	}
}

// TestAdminWebhooksDeliveries_EmptyReturnsArrayNotNull pins the null-vs-[]
// class for admin_webhooks.go Deliveries: a subscription with zero delivery
// rows must respond "[]", not JSON null.
func TestAdminWebhooksDeliveries_EmptyReturnsArrayNotNull(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewWebhooksHandler(pool, testsupport.TestLogger(), testWebhookCodec())
	userID := seedUser(t, pool)
	webhookID := createTestWebhook(t, h, pool, userID, []string{"mail.received"})

	req := httptest.NewRequest(http.MethodGet, "/admin/webhooks/"+strconv.FormatInt(webhookID, 10)+"/deliveries", nil)
	req.SetPathValue("id", strconv.FormatInt(webhookID, 10))
	rec := httptest.NewRecorder()
	h.Deliveries(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Deliveries: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	body := strings.TrimSpace(rec.Body.String())
	if body == "null" {
		t.Fatalf(`Deliveries with zero rows returned JSON null, want "[]"`)
	}
	var out []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not a JSON array: %v (body=%s)", err, body)
	}
	if len(out) != 0 {
		t.Fatalf("expected zero deliveries for a fresh webhook, got %d", len(out))
	}
}

func TestAdminWebhooksCreateRejectsUnknownAndDuplicateEventScopes(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewWebhooksHandler(pool, testsupport.TestLogger(), testWebhookCodec())
	userID := seedUser(t, pool)

	for _, eventTypes := range [][]string{{"mail.received", "shell.execute"}, {"mail.sent", "mail.sent"}} {
		body, _ := json.Marshal(map[string]any{"url": "https://example.invalid/hook", "eventTypes": eventTypes})
		req := httptest.NewRequest(http.MethodPost, "/admin/webhooks", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
		rec := httptest.NewRecorder()
		h.Create(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("eventTypes %v: want 400, got %d (%s)", eventTypes, rec.Code, rec.Body.String())
		}
	}
}

func TestAdminWebhooksCreateAllowsExplicitOrganizationScope(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewWebhooksHandler(pool, testsupport.TestLogger(), testWebhookCodec())
	userID := seedUser(t, pool)
	body := []byte(`{"url":"https://example.invalid/org","eventTypes":["user.deleted"],"scope":"organization"}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/webhooks", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("Create organization webhook: got %d (%s)", rec.Code, rec.Body.String())
	}
	var created struct {
		ID    int64  `json:"id"`
		Scope string `json:"scope"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_subscriptions WHERE id=$1`, created.ID)
	})
	var stored string
	if err := pool.QueryRow(t.Context(), `SELECT scope FROM webhook_subscriptions WHERE id=$1`, created.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if created.Scope != "organization" || stored != "organization" {
		t.Fatalf("scope response=%q stored=%q, want organization", created.Scope, stored)
	}
}

func TestAdminWebhooksCreateRejectsInvalidScope(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewWebhooksHandler(pool, testsupport.TestLogger(), testWebhookCodec())
	userID := seedUser(t, pool)
	body := []byte(`{"url":"https://example.invalid/org","eventTypes":["user.deleted"],"scope":"tenant"}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/webhooks", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Create invalid scope: got %d (%s)", rec.Code, rec.Body.String())
	}
	var stored int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM webhook_subscriptions WHERE user_id=$1`, userID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 0 {
		t.Fatalf("invalid scope persisted %d subscriptions", stored)
	}
}
