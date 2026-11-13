// guest_scim_test.go — Guest Accounts G0 Task 14, P17: SCIM PATCH/DELETE must
// refuse a guest target and the users LIST must omit guest rows — SCIM is an
// identity-plane sync surface, and a guest is provisioned/managed only via
// the guest console (create/replace already refuses at the provision_account
// choke, BZ221, Task 3). Models patch_disable_test.go's DB-integration harness
// (DB_DSN skip idiom via testsupport.OpenTestPool) and
// admin_guest_target_test.go's guest satellite seed shape.
//
// Run: DB_DSN="postgres://mail@localhost/mailserver_test" go test ./internal/scim/... -run 'TestApplyUserPatch_.*Guest|TestApplyUserPatch_MemberStillWorks|TestDeleteUser_RefusesGuest|TestGetUsers_ListOmitsGuest'
package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/pgxutil"
)

// createSCIMGuestUser seeds a mailbox-less guest (users row + guest_accounts
// satellite, active) in the system guest domain.
func createSCIMGuestUser(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	ctx := context.Background()

	var guestDomainID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM domains WHERE name = 'guest.invalid'`).Scan(&guestDomainID); err != nil {
		t.Skipf("no guest.invalid domain in test DB (expect V143 loaded): %v", err)
	}
	var hostDomainID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM domains WHERE name != 'guest.invalid' LIMIT 1`).Scan(&hostDomainID); err != nil {
		t.Skipf("no host domain in test DB: %v", err)
	}

	suffix := scimRandomSuffix(t)
	email := "scim-guest-" + suffix + "@guest.invalid"
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, enabled)
		 VALUES ($1, $2, $1, $1, TRUE) RETURNING id`,
		email, guestDomainID,
	).Scan(&userID); err != nil {
		t.Fatalf("create guest user: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM guest_accounts WHERE user_id = $1`, userID)
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, userID)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO guest_accounts (user_id, invited_email, invited_by_email, host_domain_id, status)
		 VALUES ($1, $2, $2, $3, 'active')`,
		userID, email, hostDomainID,
	); err != nil {
		t.Fatalf("create guest_accounts satellite: %v", err)
	}
	return userID
}

func createGuestIsolationSource(t *testing.T, pool *pgxpool.Pool) (int64, int64) {
	t.Helper()
	suffix := scimRandomSuffix(t)
	var sourceID, generation int64
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO identity_sources(
			source_key,display_name,kind,capabilities,state
		) VALUES(
			$1,$2,'scim',
			'{"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,
			'active'
		)
		RETURNING id,generation`,
		"scim:guest-isolation-"+suffix, "SCIM guest isolation "+suffix,
	).Scan(&sourceID, &generation); err != nil {
		t.Fatalf("create guest isolation source: %v", err)
	}
	return sourceID, generation
}

// TestApplyUserPatch_RefusesGuest proves guests and other out-of-source user IDs
// share the same 404 response, avoiding an account-type existence oracle.
func TestApplyUserPatch_RefusesGuest(t *testing.T) {
	pool := scimTestPool(t)
	s := NewServer(pool, pgxutil.WorkerPool{Pool: pool}, scimTestLogger(), "", "")

	guestID := createSCIMGuestUser(t, pool)
	sourceID, generation := createGuestIsolationSource(t, pool)

	body := []byte(`{"Operations":[{"op":"replace","path":"active","value":false}]}`)
	req := httptest.NewRequest(http.MethodPatch,
		"/scim/v2/Users/"+strconv.FormatInt(guestID, 10), bytes.NewReader(body)).
		WithContext(normalizedSCIMContext(sourceID, generation, "soft"))
	req.SetPathValue("id", strconv.FormatInt(guestID, 10))
	rec := httptest.NewRecorder()
	s.PatchUser(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("PatchUser(guest): want 404, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	if !userEnabled(t, pool, guestID) {
		t.Fatalf("PATCH refusal was not a no-op: guest enabled flipped to FALSE")
	}
}

// TestApplyUserPatch_MemberStillWorks: regression arm — the guest guard must
// not collateral-damage a non-guest PATCH.
func TestApplyUserPatch_MemberStillWorks(t *testing.T) {
	pool := scimTestPool(t)
	s := NewServer(pool, pgxutil.WorkerPool{Pool: pool}, scimTestLogger(), "", "")

	userID, _ := createSCIMTestUser(t, pool)

	if err := applyUserPatchTest(s, context.Background(), userID, false); err != nil {
		t.Fatalf("applyUserPatch(member): %v", err)
	}
	if userEnabled(t, pool, userID) {
		t.Fatalf("PATCH active=false did not disable a non-guest member")
	}
}

// TestDeleteUser_RefusesGuest: DELETE targeting a guest is indistinguishable
// from any other out-of-source user and the row survives.
func TestDeleteUser_RefusesGuest(t *testing.T) {
	pool := scimTestPool(t)
	s := NewServer(pool, pgxutil.WorkerPool{Pool: pool}, scimTestLogger(), "", "")

	guestID := createSCIMGuestUser(t, pool)
	sourceID, generation := createGuestIsolationSource(t, pool)
	idStr := strconv.FormatInt(guestID, 10)

	req := httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/"+idStr, nil).
		WithContext(normalizedSCIMContext(sourceID, generation, "soft"))
	req.SetPathValue("id", idStr)
	rec := httptest.NewRecorder()
	s.DeleteUser(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("DeleteUser(guest): want 404, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	var stillThere int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM users WHERE id = $1`, guestID).Scan(&stillThere); err != nil {
		t.Fatalf("re-read users after DeleteUser attempt: %v", err)
	}
	if stillThere != 1 {
		t.Fatalf("DeleteUser(guest): guest row removed despite the 400")
	}
}

// TestGetUsers_ListOmitsGuest: the default (unfiltered, non-sync) list omits a
// guest row while still returning a non-guest member — the guard must not
// collateral-damage the ordinary list.
func TestGetUsers_ListOmitsGuest(t *testing.T) {
	pool := scimTestPool(t)
	s := NewServer(pool, pgxutil.WorkerPool{Pool: pool}, scimTestLogger(), "", "")

	guestID := createSCIMGuestUser(t, pool)
	memberID, _ := createSCIMTestUser(t, pool)
	suffix := scimRandomSuffix(t)
	var sourceID, generation int64
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO identity_sources(
			source_key,display_name,kind,capabilities,state
		) VALUES(
			$1,$2,'scim',
			'{"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,
			'active'
		)
		RETURNING id,generation`,
		"scim:guest-list-"+suffix, "SCIM guest list "+suffix,
	).Scan(&sourceID, &generation); err != nil {
		t.Fatalf("create list source: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO user_identity_links(
			user_id,source_id,external_subject,purposes,state,link_method
		) VALUES($1,$2,$3,ARRAY['provision'],'active','hard_anchor')`,
		memberID, sourceID, "member-"+suffix,
	); err != nil {
		t.Fatalf("link list member: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users?count=1000", nil).
		WithContext(normalizedSCIMContext(sourceID, generation, "soft"))
	rec := httptest.NewRecorder()
	s.GetUsers(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GetUsers: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	var resp ListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode ListResponse: %v", err)
	}
	var users []UserResource
	if err := json.Unmarshal(resp.Resources, &users); err != nil {
		t.Fatalf("decode Resources: %v", err)
	}

	guestStr := strconv.FormatInt(guestID, 10)
	memberStr := strconv.FormatInt(memberID, 10)
	sawGuest, sawMember := false, false
	for _, u := range users {
		if u.ID == guestStr {
			sawGuest = true
		}
		if u.ID == memberStr {
			sawMember = true
		}
	}
	if sawGuest {
		t.Fatalf("GetUsers list included the guest user id %s", guestStr)
	}
	if !sawMember {
		t.Fatalf("GetUsers list omitted the non-guest member id %s", memberStr)
	}
}
