package admin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	wh "setjoin.com/shared/webhook"
)

type recordingUserEventDispatcher struct {
	mu     sync.Mutex
	events []wh.CloudEvent
}

func (d *recordingUserEventDispatcher) Dispatch(_ context.Context, event wh.CloudEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.events = append(d.events, event)
}

func (d *recordingUserEventDispatcher) DispatchForUser(_ context.Context, subjectUserID int64, event wh.CloudEvent) {
	_ = subjectUserID
	d.Dispatch(context.Background(), event)
}

func (d *recordingUserEventDispatcher) snapshot() []wh.CloudEvent {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]wh.CloudEvent(nil), d.events...)
}

func deleteUserRequest(userID, actorID, domainID int64) *http.Request {
	req := httptest.NewRequest(http.MethodDelete, "/admin/users/"+fmt.Sprint(userID), nil)
	req.SetPathValue("id", fmt.Sprint(userID))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: actorID, IsAdmin: true})
	ctx = middleware.ContextWithDomainScope(ctx, domainID)
	return req.WithContext(ctx)
}

func grantDeletionTestAdmin(t *testing.T, pool *pgxpool.Pool, actorID int64) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO admin_role_assignments(user_id, role_group_id, granted_by)
		VALUES ($1, 2, $1)`, actorID); err != nil {
		t.Fatalf("grant User Admin to deletion actor: %v", err)
	}
	// granted_by has a restrictive FK, so remove the assignment before the shared
	// user fixture cleanup attempts to delete this self-granting actor.
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `
			DELETE FROM admin_role_assignments
			WHERE user_id = $1 AND role_group_id = 2`, actorID)
	})
}

func createDeletionWebhookTestUser(t *testing.T, pool *pgxpool.Pool, domainID int64, domainName string) int64 {
	t.Helper()
	userID := createScopeTestUser(t, pool, domainID, domainName)
	// createScopeTestUser predates mailbox_lifecycle. Its cleanup deliberately
	// disables mailbox triggers, so remove the lifecycle satellite first or the
	// bound_user_id RESTRICT FK would retain this disposable user fixture.
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `
			DELETE FROM mailbox_lifecycle WHERE bound_user_id = $1`, userID)
	})
	return userID
}

func TestUsersDeleteWebhookFollowsTransactionOutcome(t *testing.T) {
	t.Run("rollback emits no event", func(t *testing.T) {
		pool := mailboxTestPool(t)
		domainID := ensureScopeTestDomain(t, pool, "delete-webhook-rollback.example")
		actorID := createDeletionWebhookTestUser(t, pool, domainID, "delete-webhook-rollback.example")
		targetID := createDeletionWebhookTestUser(t, pool, domainID, "delete-webhook-rollback.example")
		blockingGranteeID := createDeletionWebhookTestUser(t, pool, domainID, "delete-webhook-rollback.example")
		grantDeletionTestAdmin(t, pool, actorID)
		if _, err := pool.Exec(t.Context(), `
			INSERT INTO feature_toggles(key,enabled)
			VALUES('feature.webhook_publication_outbox',true)
			ON CONFLICT(key) DO UPDATE SET enabled=true`); err != nil {
			t.Fatalf("enable publication outbox: %v", err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), `UPDATE feature_toggles SET enabled=false WHERE key='feature.webhook_publication_outbox'`)
		})

		// The handler removes assignments owned by targetID, but this independent
		// assignment retains targetID as granted_by. Its RESTRICT FK makes the final
		// DELETE users statement fail after every preceding cascade mutation, forcing
		// the handler transaction to roll back.
		if _, err := pool.Exec(t.Context(), `
			INSERT INTO admin_role_assignments(user_id, role_group_id, granted_by)
			VALUES ($1, 3, $2)`, blockingGranteeID, targetID); err != nil {
			t.Fatalf("seed final-delete blocker: %v", err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), `
				DELETE FROM admin_role_assignments
				WHERE user_id = $1 AND role_group_id = 3`, blockingGranteeID)
		})

		dispatcher := &recordingUserEventDispatcher{}
		h := &UsersHandler{
			pool:       pool,
			workerPool: pool,
			logger:     mailboxTestLogger(),
			dispatcher: dispatcher,
		}
		rec := httptest.NewRecorder()
		h.Delete(rec, deleteUserRequest(targetID, actorID, domainID))

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("Delete with final FK failure: got %d, want 500 (body=%s)", rec.Code, rec.Body.String())
		}
		if events := dispatcher.snapshot(); len(events) != 0 {
			t.Fatalf("rolled-back deletion dispatched %d event(s), want none: %#v", len(events), events)
		}
		var facts int
		if err := pool.QueryRow(t.Context(), `
			SELECT count(*) FROM webhook_publications WHERE subject_user_id=$1`, targetID).Scan(&facts); err != nil {
			t.Fatalf("verify rolled-back publication: %v", err)
		}
		if facts != 0 {
			t.Fatalf("rolled-back deletion retained %d publication fact(s), want none", facts)
		}

		var users, mailboxes int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM users WHERE id=$1`, targetID).Scan(&users); err != nil {
			t.Fatalf("verify rolled-back user: %v", err)
		}
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM mailboxes WHERE user_id=$1`, targetID).Scan(&mailboxes); err != nil {
			t.Fatalf("verify rolled-back mailbox: %v", err)
		}
		if users != 1 || mailboxes != 1 {
			t.Fatalf("delete transaction did not roll back atomically: users=%d mailboxes=%d, want 1/1", users, mailboxes)
		}
	})

	t.Run("commit emits exactly once", func(t *testing.T) {
		pool := mailboxTestPool(t)
		domainID := ensureScopeTestDomain(t, pool, "delete-webhook-commit.example")
		actorID := createDeletionWebhookTestUser(t, pool, domainID, "delete-webhook-commit.example")
		targetID := createDeletionWebhookTestUser(t, pool, domainID, "delete-webhook-commit.example")
		grantDeletionTestAdmin(t, pool, actorID)
		if _, err := pool.Exec(t.Context(), `
			INSERT INTO feature_toggles(key,enabled)
			VALUES('feature.webhook_publication_outbox',false)
			ON CONFLICT(key) DO UPDATE SET enabled=false`); err != nil {
			t.Fatalf("disable publication outbox: %v", err)
		}

		dispatcher := &recordingUserEventDispatcher{}
		h := &UsersHandler{
			pool:       pool,
			workerPool: pool,
			logger:     mailboxTestLogger(),
			dispatcher: dispatcher,
		}
		rec := httptest.NewRecorder()
		h.Delete(rec, deleteUserRequest(targetID, actorID, domainID))

		if rec.Code != http.StatusNoContent {
			t.Fatalf("Delete: got %d, want 204 (body=%s)", rec.Code, rec.Body.String())
		}
		var users int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM users WHERE id=$1`, targetID).Scan(&users); err != nil {
			t.Fatalf("verify committed user deletion: %v", err)
		}
		if users != 0 {
			t.Fatalf("user still exists after successful Delete: count=%d", users)
		}

		events := dispatcher.snapshot()
		if len(events) != 1 {
			t.Fatalf("successful deletion dispatched %d event(s), want exactly one: %#v", len(events), events)
		}
		if events[0].Type != wh.EventUserDeleted || events[0].Source != "mailserver/auth" {
			t.Fatalf("unexpected deletion event: type=%q source=%q", events[0].Type, events[0].Source)
		}
		data, ok := events[0].Data.(map[string]interface{})
		if !ok || data["user_id"] != targetID {
			t.Fatalf("deletion event data=%#v, want user_id=%d", events[0].Data, targetID)
		}
	})

	t.Run("enabled commit queues fact and suppresses legacy dispatch", func(t *testing.T) {
		pool := mailboxTestPool(t)
		domainID := ensureScopeTestDomain(t, pool, "delete-webhook-outbox.example")
		actorID := createDeletionWebhookTestUser(t, pool, domainID, "delete-webhook-outbox.example")
		targetID := createDeletionWebhookTestUser(t, pool, domainID, "delete-webhook-outbox.example")
		grantDeletionTestAdmin(t, pool, actorID)
		if _, err := pool.Exec(t.Context(), `
			INSERT INTO feature_toggles(key,enabled)
			VALUES('feature.webhook_publication_outbox',true)
			ON CONFLICT(key) DO UPDATE SET enabled=true`); err != nil {
			t.Fatalf("enable publication outbox: %v", err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_publications WHERE subject_user_id=$1`, targetID)
			_, _ = pool.Exec(context.Background(), `UPDATE feature_toggles SET enabled=false WHERE key='feature.webhook_publication_outbox'`)
		})

		dispatcher := &recordingUserEventDispatcher{}
		h := &UsersHandler{pool: pool, workerPool: pool, logger: mailboxTestLogger(), dispatcher: dispatcher}
		rec := httptest.NewRecorder()
		h.Delete(rec, deleteUserRequest(targetID, actorID, domainID))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("Delete: got %d, want 204 (body=%s)", rec.Code, rec.Body.String())
		}
		if events := dispatcher.snapshot(); len(events) != 0 {
			t.Fatalf("outbox-enabled deletion used legacy dispatcher: %#v", events)
		}
		var eventType, state string
		var payloadUser int64
		if err := pool.QueryRow(t.Context(), `
			SELECT event_type,state,(payload->>'user_id')::bigint
			  FROM webhook_publications WHERE subject_user_id=$1`, targetID,
		).Scan(&eventType, &state, &payloadUser); err != nil {
			t.Fatalf("read committed publication fact: %v", err)
		}
		if eventType != wh.EventUserDeleted || state != "pending" || payloadUser != targetID {
			t.Fatalf("publication=(%q,%q,%d), want user.deleted,pending,%d", eventType, state, payloadUser, targetID)
		}
	})
}
