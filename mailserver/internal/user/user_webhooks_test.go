package user

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/cryptokey"
	wh "setjoin.com/shared/webhook"
)

// testWebhookCodec seals secrets the same way production wires the handler
// (V260 at-rest contract); Create fails closed without it.
func testWebhookCodec() *wh.SecretCodec {
	return wh.NewSecretCodec([]byte("user-webhook-test-master-key"), cryptokey.ProfileStandard)
}

func TestSelfServiceWebhookScopeCannotEscalate(t *testing.T) {
	pool := testPool(t)
	userID := createTestUser(t, pool)
	h := NewUserWebhooksHandler(pool, testLogger(), testWebhookCodec())

	for _, tc := range []struct {
		name  string
		scope string
		want  int
	}{
		{name: "organization rejected", scope: "organization", want: http.StatusBadRequest},
		{name: "self accepted", scope: "self", want: http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{
				"url": "https://example.invalid/self", "eventTypes": []string{"user.deleted"}, "scope": tc.scope,
			})
			req := httptest.NewRequest(http.MethodPost, "/auth/me/webhooks", bytes.NewReader(body))
			req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
			rec := httptest.NewRecorder()
			h.Create(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("Create scope %q: got %d, want %d (%s)", tc.scope, rec.Code, tc.want, rec.Body.String())
			}
			if tc.want != http.StatusCreated {
				return
			}
			var created struct {
				ID int64 `json:"id"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_subscriptions WHERE id=$1`, created.ID)
			})
			var scope string
			if err := pool.QueryRow(t.Context(), `SELECT scope FROM webhook_subscriptions WHERE id=$1`, created.ID).Scan(&scope); err != nil {
				t.Fatal(err)
			}
			if scope != "self" {
				t.Fatalf("stored scope=%q, want self", scope)
			}
		})
	}
}

func TestSelfServiceWebhookListProjectsScopeAndEventTypes(t *testing.T) {
	pool := testPool(t)
	userID := createTestUser(t, pool)
	var webhookID int64
	if err := pool.QueryRow(t.Context(), `INSERT INTO webhook_subscriptions(
		user_id,url,secret,event_types,scope,is_active)
		VALUES($1,'https://example.invalid/list','secret','["user.updated","user.deleted"]','self',true)
		RETURNING id`, userID).Scan(&webhookID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_subscriptions WHERE id=$1`, webhookID)
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/me/webhooks", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	NewUserWebhooksHandler(pool, testLogger(), testWebhookCodec()).List(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("List: got %d (%s)", rec.Code, rec.Body.String())
	}
	var rows []struct {
		ID         int64    `json:"id"`
		Scope      string   `json:"scope"`
		EventTypes []string `json:"eventTypes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != webhookID || rows[0].Scope != "self" {
		t.Fatalf("List projection=%#v", rows)
	}
	if got := rows[0].EventTypes; len(got) != 2 || got[0] != "user.updated" || got[1] != "user.deleted" {
		t.Fatalf("List eventTypes=%v", got)
	}
}

func TestSelfServiceWebhookRejectsUnknownAndDuplicateEvents(t *testing.T) {
	pool := testPool(t)
	userID := createTestUser(t, pool)
	h := NewUserWebhooksHandler(pool, testLogger(), testWebhookCodec())
	for _, tc := range []struct {
		name   string
		events []string
	}{
		{name: "unknown", events: []string{"user.deleted", "shell.execute"}},
		{name: "duplicate", events: []string{"user.deleted", "user.deleted"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{
				"url": "https://example.invalid/self", "eventTypes": tc.events,
			})
			req := httptest.NewRequest(http.MethodPost, "/auth/me/webhooks", bytes.NewReader(body))
			req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
			rec := httptest.NewRecorder()
			h.Create(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("Create events %v: got %d (%s)", tc.events, rec.Code, rec.Body.String())
			}
		})
	}
	var stored int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM webhook_subscriptions WHERE user_id=$1`, userID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 0 {
		t.Fatalf("invalid event sets persisted %d subscriptions", stored)
	}
}
