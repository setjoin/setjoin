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

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/pgxutil"
	wh "setjoin.com/shared/webhook"
)

func createUserWebhookRequest(t *testing.T, actorID int64, actorEmail, targetEmail string) *http.Request {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"email": targetEmail, "displayName": "Webhook Target", "password": "Sup3r-Str0ng-Pw!",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/users", bytes.NewReader(body))
	return req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: actorID, Email: actorEmail, IsAdmin: true}))
}

func cleanupCreatedWebhookUser(t *testing.T, userID int64) {
	t.Helper()
	pool := mailboxTestPool(t)
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = pool.Exec(ctx, `DELETE FROM webhook_publications WHERE subject_user_id=$1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM mailbox_lifecycle WHERE bound_user_id=$1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM mailbox_address_claims WHERE mailbox_id IN
			(SELECT id FROM mailboxes WHERE user_id=$1)`, userID)
		_, _ = pool.Exec(ctx, `ALTER TABLE mailboxes DISABLE TRIGGER ALL`)
		_, _ = pool.Exec(ctx, `DELETE FROM mailboxes WHERE user_id=$1`, userID)
		_, _ = pool.Exec(ctx, `ALTER TABLE mailboxes ENABLE TRIGGER ALL`)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, userID)
	})
}

func TestUsersCreateUpdateWebhookPublicationFollowsFlag(t *testing.T) {
	pool := mailboxTestPool(t)
	domainID := ensureScopeTestDomain(t, pool, "changed-webhook.example")
	actorID := createDeletionWebhookTestUser(t, pool, domainID, "changed-webhook.example")
	grantDeletionTestAdmin(t, pool, actorID)
	actorEmail := fmt.Sprintf("scope-%d@changed-webhook.example", actorID)
	suffix := time.Now().UnixNano()
	createdOnEmail := fmt.Sprintf("created-on-%d@changed-webhook.example", suffix)
	createdOffEmail := fmt.Sprintf("created-off-%d@changed-webhook.example", suffix)

	t.Run("update commit failure rolls back fact and sends no legacy event", func(t *testing.T) {
		targetID := createDeletionWebhookTestUser(t, pool, domainID, "changed-webhook.example")
		_, _ = pool.Exec(t.Context(), `INSERT INTO feature_toggles(key,enabled)
			VALUES('feature.webhook_publication_outbox',true)
			ON CONFLICT(key) DO UPDATE SET enabled=true`)
		if _, err := pool.Exec(t.Context(), `
			CREATE OR REPLACE FUNCTION webhook_test_reject_changed_user()
			RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
			  IF NEW.display_name='R4 forced rollback' THEN
			    RAISE EXCEPTION 'forced deferred rollback';
			  END IF;
			  RETURN NEW;
			END $$;
			DROP TRIGGER IF EXISTS webhook_test_reject_changed_user ON users;
			CREATE CONSTRAINT TRIGGER webhook_test_reject_changed_user
			AFTER UPDATE ON users DEFERRABLE INITIALLY DEFERRED
			FOR EACH ROW EXECUTE FUNCTION webhook_test_reject_changed_user()`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS webhook_test_reject_changed_user ON users`)
			_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS webhook_test_reject_changed_user()`)
		})
		dispatcher := &recordingUserEventDispatcher{}
		h := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: pool}, mailboxTestLogger(), nil, "", "")
		h.dispatcher = dispatcher
		req := httptest.NewRequest(http.MethodPatch, "/admin/users/"+fmt.Sprint(targetID), bytes.NewBufferString(`{"displayName":"R4 forced rollback"}`))
		req.SetPathValue("id", fmt.Sprint(targetID))
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: actorID, Email: actorEmail, IsAdmin: true}))
		rec := httptest.NewRecorder()
		h.Update(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("Update forced commit failure: got %d (%s)", rec.Code, rec.Body.String())
		}
		if events := dispatcher.snapshot(); len(events) != 0 {
			t.Fatalf("rolled-back update dispatched events: %#v", events)
		}
		var facts int
		var displayName string
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM webhook_publications
			WHERE subject_user_id=$1 AND event_type='user.updated'`, targetID).Scan(&facts); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(t.Context(), `SELECT display_name FROM users WHERE id=$1`, targetID).Scan(&displayName); err != nil {
			t.Fatal(err)
		}
		if facts != 0 || displayName == "R4 forced rollback" {
			t.Fatalf("rollback state facts=%d display=%q", facts, displayName)
		}
	})

	t.Run("enabled create and update commit facts without legacy dispatch", func(t *testing.T) {
		_, _ = pool.Exec(t.Context(), `INSERT INTO feature_toggles(key,enabled)
			VALUES('feature.webhook_publication_outbox',true)
			ON CONFLICT(key) DO UPDATE SET enabled=true`)
		dispatcher := &recordingUserEventDispatcher{}
		h := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: pool}, mailboxTestLogger(), nil, "", "")
		h.dispatcher = dispatcher
		rec := httptest.NewRecorder()
		h.Create(rec, createUserWebhookRequest(t, actorID, actorEmail, createdOnEmail))
		if rec.Code != http.StatusCreated {
			t.Fatalf("Create: got %d (%s)", rec.Code, rec.Body.String())
		}
		var created struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
			t.Fatal(err)
		}
		cleanupCreatedWebhookUser(t, created.ID)
		if events := dispatcher.snapshot(); len(events) != 0 {
			t.Fatalf("enabled create used legacy dispatch: %#v", events)
		}
		var payload map[string]any
		if err := pool.QueryRow(t.Context(), `SELECT payload FROM webhook_publications
			WHERE subject_user_id=$1 AND event_type='user.created'`, created.ID).Scan(&payload); err != nil {
			t.Fatal(err)
		}
		if len(payload) != 1 || payload["user_id"] != float64(created.ID) {
			t.Fatalf("created fact payload=%#v", payload)
		}

		update := httptest.NewRequest(http.MethodPatch, "/admin/users/"+fmt.Sprint(created.ID), bytes.NewBufferString(`{"displayName":"Updated"}`))
		update.SetPathValue("id", fmt.Sprint(created.ID))
		update = update.WithContext(auth.ContextWithUser(update.Context(), &auth.Claims{UserID: actorID, Email: actorEmail, IsAdmin: true}))
		updateRec := httptest.NewRecorder()
		h.Update(updateRec, update)
		if updateRec.Code != http.StatusNoContent {
			t.Fatalf("Update: got %d (%s)", updateRec.Code, updateRec.Body.String())
		}
		if events := dispatcher.snapshot(); len(events) != 0 {
			t.Fatalf("enabled update used legacy dispatch: %#v", events)
		}
		var facts int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM webhook_publications
			WHERE subject_user_id=$1 AND event_type='user.updated'`, created.ID).Scan(&facts); err != nil || facts != 1 {
			t.Fatalf("updated fact count=%d err=%v", facts, err)
		}
	})

	t.Run("disabled create retains exact scoped legacy payload", func(t *testing.T) {
		_, _ = pool.Exec(t.Context(), `UPDATE feature_toggles SET enabled=false
			WHERE key='feature.webhook_publication_outbox'`)
		dispatcher := &recordingUserEventDispatcher{}
		h := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: pool}, mailboxTestLogger(), nil, "", "")
		h.dispatcher = dispatcher
		rec := httptest.NewRecorder()
		h.Create(rec, createUserWebhookRequest(t, actorID, actorEmail, createdOffEmail))
		if rec.Code != http.StatusCreated {
			t.Fatalf("Create: got %d (%s)", rec.Code, rec.Body.String())
		}
		var created struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
			t.Fatal(err)
		}
		cleanupCreatedWebhookUser(t, created.ID)
		events := dispatcher.snapshot()
		if len(events) != 1 || events[0].Type != wh.EventUserCreated {
			t.Fatalf("legacy events=%#v", events)
		}
		data, ok := events[0].Data.(map[string]interface{})
		if !ok || data["user_id"] != created.ID || data["email"] != createdOffEmail || data["created_by"] != actorEmail || len(data) != 3 {
			t.Fatalf("legacy created payload=%#v", events[0].Data)
		}
		var facts int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM webhook_publications
			WHERE subject_user_id=$1`, created.ID).Scan(&facts); err != nil || facts != 0 {
			t.Fatalf("flag-OFF facts=%d err=%v", facts, err)
		}
	})
}
