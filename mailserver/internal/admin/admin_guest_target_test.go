// admin_guest_target_test.go — Guest Accounts G0 Task 10, codex C-4 + C-2:
// DB-gated proof that the generic admin user/mailbox mutation endpoints
// refuse a guest target (409, "manage via /admin/guests") instead of
// desyncing the guest_accounts satellite or hitting the V143
// guest_mailbox_guard trigger as a raw 500. Follows the
// TestCreateUserProvisionsPrimaryMailbox fixture shape (admin_users_test.go)
// and the DB_DSN skip idiom (shared/testsupport.OpenTestPool).
//
// Run: DB_DSN="postgres://mail@localhost/mailserver_test" go test ./internal/admin/ -run 'TestGuestTarget|TestGuestsHandler'
package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/webhook"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

func TestGuestTarget_AdminMutationsRefuseGuest(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	logger := testsupport.TestLogger()

	hostDomain := ensureScopeTestDomain(t, pool, "guesttarget.example")
	memberID := createScopeTestUser(t, pool, hostDomain, "guesttarget.example")

	var guestDomainID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM domains WHERE name = 'guest.invalid'`).Scan(&guestDomainID); err != nil {
		t.Fatalf("resolve guest.invalid domain: %v", err)
	}

	suffix := mailboxRandomSuffix(t)
	guestEmail := "guesttarget-" + suffix + "@external.example"
	var guestID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash, is_local_admin, enabled, sync_source)
		 VALUES ($1, $2, $1, $1, NULL, FALSE, TRUE, 'local') RETURNING id`,
		guestEmail, guestDomainID,
	).Scan(&guestID); err != nil {
		t.Fatalf("insert guest user: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM guest_accounts WHERE user_id = $1`, guestID)
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, guestID)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO guest_accounts (user_id, invited_email, invited_by, invited_by_email, host_domain_id, status)
		 VALUES ($1, $2, NULL, $3, $4, 'active')`,
		guestID, guestEmail, "inviter-"+suffix+"@guesttarget.example", hostDomain,
	); err != nil {
		t.Fatalf("insert guest_accounts satellite: %v", err)
	}

	dispatcher := webhook.NewDispatcher(pool, logger)
	uh := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: pool}, logger, dispatcher, "", "")
	mh := NewMailboxesHandler(pool, pgxutil.WorkerPool{Pool: pool}, logger)

	assertGuestUnchanged := func(t *testing.T, label string) {
		t.Helper()
		var enabled bool
		var status string
		if err := pool.QueryRow(ctx, `SELECT enabled FROM users WHERE id = $1`, guestID).Scan(&enabled); err != nil {
			t.Fatalf("%s: re-read users.enabled: %v", label, err)
		}
		if !enabled {
			t.Errorf("%s: users.enabled flipped to FALSE — the 409 must be a no-op", label)
		}
		if err := pool.QueryRow(ctx, `SELECT status FROM guest_accounts WHERE user_id = $1`, guestID).Scan(&status); err != nil {
			t.Fatalf("%s: re-read guest_accounts.status: %v", label, err)
		}
		if status != "active" {
			t.Errorf("%s: guest_accounts.status = %q, want unchanged 'active'", label, status)
		}
	}

	// (a) Update targeting the guest → 409, nothing half-written.
	t.Run("Update refuses guest", func(t *testing.T) {
		rec := httptest.NewRecorder()
		uh.Update(rec, scopedReq(http.MethodPatch, guestID, 0, `{"enabled":false}`))
		if rec.Code != http.StatusConflict {
			t.Fatalf("Update(guest): want 409, got %d (body=%s)", rec.Code, rec.Body.String())
		}
		assertGuestUnchanged(t, "Update")
	})

	// (b) Delete targeting the guest → 409, row survives.
	t.Run("Delete refuses guest", func(t *testing.T) {
		rec := httptest.NewRecorder()
		uh.Delete(rec, scopedReq(http.MethodDelete, guestID, 0, ""))
		if rec.Code != http.StatusConflict {
			t.Fatalf("Delete(guest): want 409, got %d (body=%s)", rec.Code, rec.Body.String())
		}
		var stillThere int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE id = $1`, guestID).Scan(&stillThere); err != nil {
			t.Fatalf("re-read users after Delete attempt: %v", err)
		}
		if stillThere != 1 {
			t.Errorf("Delete(guest): guest user row was removed despite the 409")
		}
	})

	// (c) ResetPassword targeting the guest → 409.
	t.Run("ResetPassword refuses guest", func(t *testing.T) {
		rec := httptest.NewRecorder()
		uh.ResetPassword(rec, scopedReq(http.MethodPost, guestID, hostDomain, `{"password":"Sup3r-Str0ng-Pw!"}`))
		if rec.Code != http.StatusConflict {
			t.Fatalf("ResetPassword(guest): want 409, got %d (body=%s)", rec.Code, rec.Body.String())
		}
		assertGuestUnchanged(t, "ResetPassword")
	})

	t.Run("ResetPassword hides out-of-scope guest class", func(t *testing.T) {
		otherDomain := ensureScopeTestDomain(t, pool, "guesttarget-other.example")
		rec := httptest.NewRecorder()
		uh.ResetPassword(rec, scopedReq(http.MethodPost, guestID, otherDomain, `{"password":"Sup3r-Str0ng-Pw!"}`))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("ResetPassword(out-of-scope guest): want 404, got %d (body=%s)", rec.Code, rec.Body.String())
		}
		assertGuestUnchanged(t, "ResetPassword out of scope")
	})

	// (d) Update targeting the MEMBER still works — regression arm: the guard
	// must not collateral-damage the non-guest path.
	t.Run("Update still works for a member", func(t *testing.T) {
		rec := httptest.NewRecorder()
		uh.Update(rec, scopedReq(http.MethodPatch, memberID, 0, `{"displayName":"Updated Member Name"}`))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("Update(member): want 204, got %d (body=%s)", rec.Code, rec.Body.String())
		}
		var gotName string
		if err := pool.QueryRow(ctx, `SELECT display_name FROM users WHERE id = $1`, memberID).Scan(&gotName); err != nil {
			t.Fatalf("re-read member display_name: %v", err)
		}
		if gotName != "Updated Member Name" {
			t.Errorf("member display_name = %q, want %q", gotName, "Updated Member Name")
		}
	})

	// (e) POST /admin/mailboxes for the guest's user id → 409 (C-2), zero
	// mailboxes rows for the guest — the friendly 409 in front of the V143
	// guest_mailbox_guard trigger's raw BZ221.
	t.Run("Mailboxes Create refuses guest", func(t *testing.T) {
		body := `{"userId":` + strconv.FormatInt(guestID, 10) + `,"email":"mbx-` + suffix + `@external.example"}`
		req := httptest.NewRequest(http.MethodPost, "/admin/mailboxes", strings.NewReader(body))
		claims := &auth.Claims{UserID: -1, IsAdmin: true, Permissions: []string{permissions.PermUsersCreate}}
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
		rec := httptest.NewRecorder()
		mh.Create(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("Mailboxes Create(guest): want 409, got %d (body=%s)", rec.Code, rec.Body.String())
		}
		var mbCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM mailboxes WHERE user_id = $1`, guestID).Scan(&mbCount); err != nil {
			t.Fatalf("re-read mailboxes for guest: %v", err)
		}
		if mbCount != 0 {
			t.Errorf("Mailboxes Create(guest): %d mailbox row(s) created despite the 409", mbCount)
		}
	})
}
