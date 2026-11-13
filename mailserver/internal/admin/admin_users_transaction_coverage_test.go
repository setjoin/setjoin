package admin

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/pgxutil"
)

func adminUserUpdateRequest(actorID, targetID int64, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPatch, "/admin/users/"+fmt.Sprint(targetID), bytes.NewBufferString(body))
	req.SetPathValue("id", fmt.Sprint(targetID))
	return req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: actorID, IsAdmin: true}))
}

func TestUsersTransactionFailuresRemainAtomic(t *testing.T) {
	pool := mailboxTestPool(t)
	domainID := ensureScopeTestDomain(t, pool, "users-tx-coverage.example")
	actorID := createDeletionWebhookTestUser(t, pool, domainID, "users-tx-coverage.example")
	targetID := createDeletionWebhookTestUser(t, pool, domainID, "users-tx-coverage.example")
	grantDeletionTestAdmin(t, pool, actorID)

	closedWorker := mailboxTestPool(t)
	closedWorker.Close()
	closedHandler := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: closedWorker}, mailboxTestLogger(), nil, "", "")

	t.Run("create begin failure writes nothing", func(t *testing.T) {
		email := fmt.Sprintf("closed-create-%d@users-tx-coverage.example", time.Now().UnixNano())
		rec := httptest.NewRecorder()
		closedHandler.Create(rec, createUserWebhookRequest(t, actorID, "actor@users-tx-coverage.example", email))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("Create with closed worker: got %d (%s)", rec.Code, rec.Body.String())
		}
		var users int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM users WHERE email=$1`, email).Scan(&users); err != nil {
			t.Fatal(err)
		}
		if users != 0 {
			t.Fatalf("create begin failure persisted %d users", users)
		}
	})

	t.Run("update begin failure preserves target", func(t *testing.T) {
		var before string
		if err := pool.QueryRow(t.Context(), `SELECT display_name FROM users WHERE id=$1`, targetID).Scan(&before); err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		closedHandler.Update(rec, adminUserUpdateRequest(actorID, targetID, `{"displayName":"closed-worker"}`))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("Update with closed worker: got %d (%s)", rec.Code, rec.Body.String())
		}
		var after string
		if err := pool.QueryRow(t.Context(), `SELECT display_name FROM users WHERE id=$1`, targetID).Scan(&after); err != nil {
			t.Fatal(err)
		}
		if after != before {
			t.Fatalf("update begin failure changed display name %q -> %q", before, after)
		}
	})

	h := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: pool}, mailboxTestLogger(), nil, "", "")
	t.Run("empty update is rejected after reach check", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.Update(rec, adminUserUpdateRequest(actorID, targetID, `{}`))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("empty Update: got %d (%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("update execution failure rolls back", func(t *testing.T) {
		if _, err := pool.Exec(t.Context(), `
			CREATE OR REPLACE FUNCTION admin_users_tx_coverage_reject_update()
			RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
			  IF NEW.display_name='tx-coverage-reject' THEN
			    RAISE EXCEPTION 'planted update execution failure';
			  END IF;
			  RETURN NEW;
			END $$;
			DROP TRIGGER IF EXISTS admin_users_tx_coverage_reject_update ON users;
			CREATE TRIGGER admin_users_tx_coverage_reject_update
			BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION admin_users_tx_coverage_reject_update()`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS admin_users_tx_coverage_reject_update ON users`)
			_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS admin_users_tx_coverage_reject_update()`)
		})
		var before string
		if err := pool.QueryRow(t.Context(), `SELECT display_name FROM users WHERE id=$1`, targetID).Scan(&before); err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		h.Update(rec, adminUserUpdateRequest(actorID, targetID, `{"displayName":"tx-coverage-reject"}`))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("Update with planted execution failure: got %d (%s)", rec.Code, rec.Body.String())
		}
		var after string
		if err := pool.QueryRow(t.Context(), `SELECT display_name FROM users WHERE id=$1`, targetID).Scan(&after); err != nil {
			t.Fatal(err)
		}
		if after != before {
			t.Fatalf("failed update changed display name %q -> %q", before, after)
		}
	})

	t.Run("create commit failure rolls back user and publication", func(t *testing.T) {
		email := fmt.Sprintf("commit-create-%d@users-tx-coverage.example", time.Now().UnixNano())
		if _, err := pool.Exec(t.Context(), `
			CREATE OR REPLACE FUNCTION admin_users_tx_coverage_reject_create()
			RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
			  IF NEW.display_name='commit-create-reject' THEN
			    RAISE EXCEPTION 'planted deferred create failure';
			  END IF;
			  RETURN NEW;
			END $$;
			DROP TRIGGER IF EXISTS admin_users_tx_coverage_reject_create ON users;
			CREATE CONSTRAINT TRIGGER admin_users_tx_coverage_reject_create
			AFTER INSERT ON users DEFERRABLE INITIALLY DEFERRED
			FOR EACH ROW EXECUTE FUNCTION admin_users_tx_coverage_reject_create()`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS admin_users_tx_coverage_reject_create ON users`)
			_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS admin_users_tx_coverage_reject_create()`)
		})
		body := []byte(fmt.Sprintf(`{"email":%q,"displayName":"commit-create-reject","password":"Sup3r-Str0ng-Pw!"}`, email))
		req := httptest.NewRequest(http.MethodPost, "/admin/users", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: actorID, Email: "actor@users-tx-coverage.example", IsAdmin: true}))
		var publicationsBefore int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM webhook_publications WHERE event_type='user.created'`).Scan(&publicationsBefore); err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		h.Create(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("Create with deferred failure: got %d (%s)", rec.Code, rec.Body.String())
		}
		var users, publicationsAfter int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM users WHERE email=$1`, email).Scan(&users); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM webhook_publications WHERE event_type='user.created'`).Scan(&publicationsAfter); err != nil {
			t.Fatal(err)
		}
		if users != 0 || publicationsAfter != publicationsBefore {
			t.Fatalf("deferred create failure left users=%d or changed publications=%d->%d",
				users, publicationsBefore, publicationsAfter)
		}
	})
}

func TestUsersWebhookPublicationFailureRollsBackOwningMutation(t *testing.T) {
	pool := mailboxTestPool(t)
	domainID := ensureScopeTestDomain(t, pool, "users-publication-failure.example")
	actorID := createDeletionWebhookTestUser(t, pool, domainID, "users-publication-failure.example")
	updateTargetID := createDeletionWebhookTestUser(t, pool, domainID, "users-publication-failure.example")
	deleteTargetID := createDeletionWebhookTestUser(t, pool, domainID, "users-publication-failure.example")
	grantDeletionTestAdmin(t, pool, actorID)
	if _, err := pool.Exec(t.Context(), `INSERT INTO feature_toggles(key,enabled)
		VALUES('feature.webhook_publication_outbox',true)
		ON CONFLICT(key) DO UPDATE SET enabled=true`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `
		CREATE OR REPLACE FUNCTION admin_users_reject_webhook_publication()
		RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'planted publication enrollment failure'; END $$;
		DROP TRIGGER IF EXISTS admin_users_reject_webhook_publication ON webhook_publications;
		CREATE TRIGGER admin_users_reject_webhook_publication
		BEFORE INSERT ON webhook_publications FOR EACH ROW
		EXECUTE FUNCTION admin_users_reject_webhook_publication()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS admin_users_reject_webhook_publication ON webhook_publications`)
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS admin_users_reject_webhook_publication()`)
		_, _ = pool.Exec(context.Background(), `UPDATE feature_toggles SET enabled=false WHERE key='feature.webhook_publication_outbox'`)
	})
	h := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: pool}, mailboxTestLogger(), nil, "", "")

	t.Run("create", func(t *testing.T) {
		email := fmt.Sprintf("publication-create-%d@users-publication-failure.example", time.Now().UnixNano())
		rec := httptest.NewRecorder()
		h.Create(rec, createUserWebhookRequest(t, actorID, "actor@users-publication-failure.example", email))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("Create: got %d (%s)", rec.Code, rec.Body.String())
		}
		var users int
		_ = pool.QueryRow(t.Context(), `SELECT count(*) FROM users WHERE email=$1`, email).Scan(&users)
		if users != 0 {
			t.Fatalf("publication failure retained created user %s", email)
		}
	})

	t.Run("update", func(t *testing.T) {
		var before string
		_ = pool.QueryRow(t.Context(), `SELECT display_name FROM users WHERE id=$1`, updateTargetID).Scan(&before)
		rec := httptest.NewRecorder()
		h.Update(rec, adminUserUpdateRequest(actorID, updateTargetID, `{"displayName":"publication-update"}`))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("Update: got %d (%s)", rec.Code, rec.Body.String())
		}
		var after string
		_ = pool.QueryRow(t.Context(), `SELECT display_name FROM users WHERE id=$1`, updateTargetID).Scan(&after)
		if after != before {
			t.Fatalf("publication failure changed update target %q -> %q", before, after)
		}
	})

	t.Run("delete", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.Delete(rec, deleteUserRequest(deleteTargetID, actorID, domainID))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("Delete: got %d (%s)", rec.Code, rec.Body.String())
		}
		var users int
		_ = pool.QueryRow(t.Context(), `SELECT count(*) FROM users WHERE id=$1`, deleteTargetID).Scan(&users)
		if users != 1 {
			t.Fatal("publication failure deleted the target user")
		}
	})
}
